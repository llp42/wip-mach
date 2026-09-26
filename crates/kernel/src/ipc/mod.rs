// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! IPC facilities; mirrors `ipc/`.

use crate::ipc::ipc_table::IpcTableSize;
use crate::ipc::ipc_thread::IpcThreadQueue;
use crate::kern::debug::kpanic;
use crate::kern::lock::{LockData, SimpleLock};
use crate::kern::rdxtree::{Lookup, Rdxtree, RdxtreeKey};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};

pub mod copy_user;
pub mod ipc_entry;
pub mod ipc_init;
pub mod ipc_kmsg;
pub mod ipc_marequest;
pub mod ipc_mqueue;
pub mod ipc_notify;
pub mod ipc_object;
pub mod ipc_port;
pub mod ipc_port_ffi;
pub mod ipc_pset;
pub mod ipc_right;
pub mod ipc_space;
pub mod ipc_table;
pub mod ipc_target;
pub mod ipc_thread;
pub mod mach_debug;
pub mod mach_msg;
pub mod mach_port;

/// `IOT_PORT` of <`ipc/ipc_object.h>`: the index of the port cache
/// `io_alloc()` and `io_free()` select.
pub(crate) const IOT_PORT: usize = 0;
/// `IOT_PORT_SET` of <`ipc/ipc_object.h>`: the index of the port-set cache.
pub(crate) const IOT_PORT_SET: usize = 1;
/// `IOT_NUMBER` of <`ipc/ipc_object.h>`: how many object caches there are.
pub(crate) const IOT_NUMBER: usize = 2;

/// `IO_BITS_KOTYPE` of <`ipc/ipc_object.h>`: the low half of `io_bits` names
/// the kobject type.
const IO_BITS_KOTYPE: u32 = 0x0000_ffff;
/// `IO_BITS_OTYPE` of <`ipc/ipc_object.h>`: the half-word naming the object's
/// cache.
const IO_BITS_OTYPE: u32 = 0x3fff_0000;
/// `IO_BITS_PROTECTED_PAYLOAD` of <`ipc/ipc_object.h>`: the port has a
/// protected payload.
const IO_BITS_PROTECTED_PAYLOAD: u32 = 0x4000_0000;
/// `IO_BITS_ACTIVE` of <`ipc/ipc_object.h>`: the sign bit marks a live object.
const IO_BITS_ACTIVE: u32 = 0x8000_0000;
/// `IO_DEAD` of <`ipc/ipc_object.h>`: the one non-null pointer `IP_VALID()`
/// rejects.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;
/// `IE_BITS_TYPE_MASK` of <`ipc/ipc_entry.h>`: the capability-type field.
const IE_BITS_TYPE_MASK: u32 = 0x001f_0000;
/// `IE_BITS_MAREQUEST` of <`ipc/ipc_entry.h>`: the entry has a msg-accepted
/// request pending.
const IE_BITS_MAREQUEST: u32 = 0x0020_0000;

/// `MACH_PORT_TYPE_RECEIVE` of <mach/port.h>: the entry holds receive
/// rights.
const MACH_PORT_TYPE_RECEIVE: u32 = 1 << 17;
/// `MACH_PORT_TYPE_PORT_SET` of <mach/port.h>: the entry names a port set.
const MACH_PORT_TYPE_PORT_SET: u32 = 1 << 19;

/// The `struct ipc_object` header every IPC object begins with.
#[repr(C)]
#[allow(missing_docs)]
struct IpcObject {
    lock: SimpleLock,
    references: u32,
    /// `io_bits`: the packed kobject type, cache index, protected-payload
    /// and active flags the `IO_BITS_*` constants above name.
    bits: u32,
}

const _: () = {
    assert!(size_of::<IpcObject>() == 12);
    assert!(align_of::<IpcObject>() == 4);
    assert!(offset_of!(IpcObject, lock) == 0);
    assert!(offset_of!(IpcObject, references) == 4);
    assert!(offset_of!(IpcObject, bits) == 8);
};

impl IpcObject {
    /// `io_check_unlock()` of <`ipc/ipc_object.h>`: unlock, freeing the object
    /// through its type's cache once the last reference is gone.
    ///
    /// # Safety
    ///
    /// `object` must point at a live IPC object whose lock this call holds and
    /// whose reference count was just decremented.
    pub(crate) unsafe fn check_unlock(object: *mut Self) {
        let references = unsafe { (*object).references };
        unsafe { (*object).lock.unlock() };

        if references != 0 {
            return;
        }

        // SAFETY: the object is live; `io_free()` selects the cache from the
        // type bits the same way.
        let otype = unsafe { ((*object).bits & IO_BITS_OTYPE) >> 16 };
        // The masked type field is fourteen bits, so the widening cannot
        // lose anything on either target.
        let index = otype as usize;
        // SAFETY: the caches are initialized before any object is allocated
        // from them.
        let cache = unsafe {
            (*ptr::addr_of_mut!(ipc_object::IPC_OBJECT_CACHES)).get_mut(index)
        };
        let Some(cache) = cache else {
            kpanic!("io_check_unlock", "io_check_unlock: bad object type")
        };

        unsafe { cache.free(NonNull::new_unchecked(object.cast::<u8>())) };
    }
}

/// `struct ipc_mqueue` of <`ipc/ipc_mqueue.h>`: a target's message and blocked
/// thread stacks, each one pointer.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcMqueue {
    lock: SimpleLock,
    messages: *mut c_void,
    threads: *mut c_void,
}

impl IpcMqueue {
    pub(crate) fn lock(&self) {
        self.lock.lock();
    }

    /// `simple_lock_try()` against the queue.
    pub(crate) fn try_lock(&self) -> bool {
        self.lock.try_lock()
    }

    pub(crate) fn unlock(&self) {
        self.lock.unlock();
    }

    /// The address of the embedded `struct ipc_kmsg_queue`, one pointer.
    pub(crate) const fn messages(&self) -> *mut c_void {
        ptr::addr_of!(self.messages).cast_mut().cast()
    }

    /// The address of the embedded `struct ipc_thread_queue`, one pointer.
    pub(crate) const fn threads(&self) -> *mut c_void {
        ptr::addr_of!(self.threads).cast_mut().cast()
    }
}

/// `struct ipc_target` of <`ipc/ipc_target.h>`: the common part of ports and
/// port sets, and the whole of a port set.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcTarget {
    object: IpcObject,
    name: u32,
    messages: IpcMqueue,
}

impl IpcTarget {
    /// `ips_lock()` of <`ipc/ipc_pset.h`>, which port sets share.
    pub(crate) fn lock(&self) {
        self.object.lock.lock();
    }

    /// `ips_unlock()` of <`ipc/ipc_pset.h`>.
    pub(crate) fn unlock(&self) {
        self.object.lock.unlock();
    }

    /// `ips_active()` of <`ipc/ipc_pset.h`>.
    pub(crate) const fn is_active(&self) -> bool {
        self.object.bits & IO_BITS_ACTIVE != 0
    }

    /// `ips_local_name` of <`ipc/ipc_pset.h>`: `ip_target.ipt_name`.
    pub(crate) const fn local_name(&self) -> c_uint {
        self.name
    }

    /// The `pset->ips_local_name = nname` assignment of
    /// `ipc_right_rename()`.
    pub(crate) const fn set_local_name(&mut self, name: c_uint) {
        self.name = name;
    }

    /// `&pset->ips_messages`: the address of the target's message queue.
    pub(crate) const fn messages(&self) -> *mut IpcMqueue {
        ptr::addr_of!(self.messages).cast_mut()
    }

    /// `ips_check_unlock()` of <`ipc/ipc_pset.h`>.
    ///
    /// # Safety
    ///
    /// `target` must be the target of a live port set that is locked and whose
    /// reference count was just decremented.
    pub(crate) unsafe fn check_unlock(target: *mut Self) {
        unsafe {
            IpcObject::check_unlock(ptr::addr_of_mut!((*target).object));
        }
    }

    /// The `io_reference()` macro of <`ipc/ipc_object.h`> against a target's
    /// object, which the caller already has locked.
    ///
    /// # Safety
    ///
    /// The target must be live and locked.
    pub(crate) unsafe fn increment_references(target: *mut Self) {
        unsafe {
            let references = (*target).object.references;
            (*target).object.references = references.wrapping_add(1);
        }
    }

    /// The `io_release()` macro of <`ipc/ipc_object.h`> against a target's
    /// object, which the caller already has locked.
    ///
    /// # Safety
    ///
    /// The target must be live, locked, and holding a reference.
    pub(crate) unsafe fn decrement_references(target: *mut Self) {
        unsafe {
            let references = (*target).object.references;
            (*target).object.references = references.wrapping_sub(1);
        }
    }

    /// The `ipt->ipt_object.io_bits &= ~IO_BITS_ACTIVE` of
    /// `ipc_pset_destroy()`.
    ///
    /// # Safety
    ///
    /// The target must be live and locked.
    pub(crate) unsafe fn clear_active(target: *mut Self) {
        unsafe {
            (*target).object.bits &= !IO_BITS_ACTIVE;
        }
    }
}

/// The `data` union of `struct ipc_port`: whichever of the receiver, the
/// destination and the death timestamp the port's state holds.
#[repr(C)]
#[allow(missing_docs)]
union IpcPortData {
    receiver: *mut c_void,
    destination: *mut c_void,
    timestamp: u32,
}

/// `struct ipc_port` of <`ipc/ipc_port.h>`: the whole record `ipc_port_t`
/// points at, its embedded `struct ipc_target` included.  The C's
/// `ip_object`, `ip_receiver`, `ip_messages`, `ip_references` and
/// `ip_receiver_name` names are members of that target.
#[repr(C)]
#[allow(missing_docs)]
struct IpcPortRecord {
    target: IpcTarget,
    cur_target: *mut IpcTarget,
    data: IpcPortData,
    kobject: *mut c_void,
    mscount: u32,
    srights: u32,
    sorights: u32,
    nsrequest: *mut c_void,
    pdrequest: *mut c_void,
    dnrequests: *mut IpcPortRequest,
    pset: *mut c_void,
    seqno: u32,
    msgcount: u32,
    qlimit: u32,
    blocked: *mut c_void,
    protected_payload: usize,
}

const _: () = {
    assert!(size_of::<IpcMqueue>() == 24);
    assert!(align_of::<IpcMqueue>() == 8);
    assert!(offset_of!(IpcMqueue, lock) == 0);
    assert!(offset_of!(IpcMqueue, messages) == 8);
    assert!(offset_of!(IpcMqueue, threads) == 16);

    assert!(size_of::<IpcTarget>() == 40);
    assert!(align_of::<IpcTarget>() == 8);
    assert!(offset_of!(IpcTarget, object) == 0);
    assert!(offset_of!(IpcTarget, name) == 12);
    assert!(offset_of!(IpcTarget, messages) == 16);

    assert!(size_of::<IpcPortData>() == 8);
    assert!(align_of::<IpcPortData>() == 8);

    assert!(size_of::<IpcPortRecord>() == 144);
    assert!(align_of::<IpcPortRecord>() == 8);
    assert!(offset_of!(IpcPortRecord, target) == 0);
    assert!(offset_of!(IpcPortRecord, cur_target) == 40);
    assert!(offset_of!(IpcPortRecord, data) == 48);
    assert!(offset_of!(IpcPortRecord, kobject) == 56);
    assert!(offset_of!(IpcPortRecord, mscount) == 64);
    assert!(offset_of!(IpcPortRecord, srights) == 68);
    assert!(offset_of!(IpcPortRecord, sorights) == 72);
    assert!(offset_of!(IpcPortRecord, nsrequest) == 80);
    assert!(offset_of!(IpcPortRecord, pdrequest) == 88);
    assert!(offset_of!(IpcPortRecord, dnrequests) == 96);
    assert!(offset_of!(IpcPortRecord, pset) == 104);
    assert!(offset_of!(IpcPortRecord, seqno) == 112);
    assert!(offset_of!(IpcPortRecord, msgcount) == 116);
    assert!(offset_of!(IpcPortRecord, qlimit) == 120);
    assert!(offset_of!(IpcPortRecord, blocked) == 128);
    assert!(offset_of!(IpcPortRecord, protected_payload) == 136);
};

/// The `notify` union of `struct ipc_port_request`: a port pointer or an index
/// into the table.
#[repr(C)]
#[allow(missing_docs)]
union RequestNotify {
    port: *mut c_void,
    index: c_uint,
}

/// The `name` union of `struct ipc_port_request`: a port name or the size
/// record the table is growing to.
#[repr(C)]
#[allow(missing_docs)]
union RequestName {
    name: c_uint,
    size: *mut IpcTableSize,
}

/// `struct ipc_port_request` of <`ipc/ipc_port.h>`: one dead-name request slot,
/// or, in element zero, the table's free-list head and size record.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcPortRequest {
    notify: RequestNotify,
    name: RequestName,
}

const _: () = {
    assert!(size_of::<IpcPortRequest>() == 16);
    assert!(align_of::<IpcPortRequest>() == 8);
    assert!(offset_of!(IpcPortRequest, notify) == 0);
    assert!(offset_of!(IpcPortRequest, name) == 8);
};

impl IpcPortRequest {
    /// `ipr_next` of <`ipc/ipc_port.h`>.
    const fn next(&self) -> c_uint {
        // SAFETY: the union's members share one readable word.
        unsafe { self.notify.index }
    }

    const fn set_next(&mut self, index: c_uint) {
        self.notify.index = index;
    }

    /// `ipr_size` of <`ipc/ipc_port.h`>.
    const fn size(&self) -> *mut IpcTableSize {
        // SAFETY: the union's members share one readable word.
        unsafe { self.name.size }
    }

    const fn set_size(&mut self, size: *mut IpcTableSize) {
        self.name.size = size;
    }

    /// `ipr_name` of <`ipc/ipc_port.h`>.
    const fn name(&self) -> c_uint {
        // SAFETY: the union's members share one readable word.
        unsafe { self.name.name }
    }

    const fn set_name(&mut self, name: c_uint) {
        self.name.name = name;
    }

    /// `ipr_soright` of <`ipc/ipc_port.h`>.
    const fn soright(&self) -> *mut c_void {
        // SAFETY: the union's members share one readable word.
        unsafe { self.notify.port }
    }

    const fn set_soright(&mut self, port: *mut c_void) {
        self.notify.port = port;
    }
}

/// `struct ipc_entry` of <`ipc/ipc_entry.h>`: one capability.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcEntry {
    name: c_uint,
    /// `ie_bits`: the packed capability type, msg-accepted-request flag
    /// and generation bits the `IE_BITS_*` constants above name.
    bits: u32,
    object: *mut c_void,
    /// `ie_next_free`/`ie_request`, aliased in one word: the next
    /// free-list entry, or an index into the dead-name request table.
    index: *mut c_void,
}

const _: () = {
    assert!(size_of::<IpcEntry>() == 24);
    assert!(align_of::<IpcEntry>() == 8);
    assert!(offset_of!(IpcEntry, name) == 0);
    assert!(offset_of!(IpcEntry, bits) == 4);
    assert!(offset_of!(IpcEntry, object) == 8);
    assert!(offset_of!(IpcEntry, index) == 16);
};

/// `struct ipc_marequest` of <`ipc/ipc_marequest.h>`: one pending
/// message-accepted request.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcMarequest {
    space: *mut c_void,
    name: c_uint,
    soright: *mut c_void,
    next: *mut Self,
}

const _: () = {
    assert!(size_of::<IpcMarequest>() == 32);
    assert!(align_of::<IpcMarequest>() == 8);
    assert!(offset_of!(IpcMarequest, space) == 0);
    assert!(offset_of!(IpcMarequest, name) == 8);
    assert!(offset_of!(IpcMarequest, soright) == 16);
    assert!(offset_of!(IpcMarequest, next) == 24);
};

/// `struct ipc_marequest_bucket` of `ipc/ipc_marequest.c`: one bucket of the
/// msg-accepted request hash table.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcMarequestBucket {
    lock: SimpleLock,
    head: *mut IpcMarequest,
}

const _: () = {
    assert!(size_of::<IpcMarequestBucket>() == 16);
    assert!(align_of::<IpcMarequestBucket>() == 8);
    assert!(offset_of!(IpcMarequestBucket, lock) == 0);
    assert!(offset_of!(IpcMarequestBucket, head) == 8);
};

/// `hash_info_bucket_t` of <`mach_debug/hash_info.h>`: one bucket count, as
/// `ipc_marequest_info()` reports them.
#[repr(transparent)]
pub struct HashInfoBucket {
    pub(crate) hib_count: c_uint,
}

const _: () = {
    assert!(size_of::<HashInfoBucket>() == size_of::<c_uint>());
    assert!(align_of::<HashInfoBucket>() == align_of::<c_uint>());
    assert!(offset_of!(HashInfoBucket, hib_count) == 0);
};

/// `struct ipc_space` of <`ipc/ipc_space.h>`: the capability namespace.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcSpaceRecord {
    ref_lock: SimpleLock,
    references: u32,
    lock: LockData,
    active: c_int,
    map: Rdxtree,
    size: usize,
    reverse_map: Rdxtree,
    free_list: *mut IpcEntry,
    free_list_size: usize,
}

const _: () = {
    assert!(size_of::<IpcSpaceRecord>() == 88);
    assert!(align_of::<IpcSpaceRecord>() == 8);
    assert!(offset_of!(IpcSpaceRecord, ref_lock) == 0);
    assert!(offset_of!(IpcSpaceRecord, references) == 4);
    assert!(offset_of!(IpcSpaceRecord, lock) == 8);
    assert!(offset_of!(IpcSpaceRecord, active) == 24);
    assert!(offset_of!(IpcSpaceRecord, map) == 32);
    assert!(offset_of!(IpcSpaceRecord, size) == 48);
    assert!(offset_of!(IpcSpaceRecord, reverse_map) == 56);
    assert!(offset_of!(IpcSpaceRecord, free_list) == 72);
    assert!(offset_of!(IpcSpaceRecord, free_list_size) == 80);
};

/// `mach_msg_header_t` of <mach/message.h>: its two pointer-wide unions carry
/// the remote and local ports.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct MachMsgHeader {
    bits: u32,
    size: u32,
    remote_port: usize,
    local_port: usize,
    seqno: u32,
    id: c_int,
}

const _: () = {
    assert!(size_of::<MachMsgHeader>() == 32);
    assert!(align_of::<MachMsgHeader>() == 8);
    assert!(offset_of!(MachMsgHeader, bits) == 0);
    assert!(offset_of!(MachMsgHeader, size) == 4);
    assert!(offset_of!(MachMsgHeader, remote_port) == 8);
    assert!(offset_of!(MachMsgHeader, local_port) == 16);
    assert!(offset_of!(MachMsgHeader, seqno) == 24);
    assert!(offset_of!(MachMsgHeader, id) == 28);
};

/// `mach_msg_type_t` of <mach/message.h>: the inline descriptor of one body
/// element.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub(crate) struct MachMsgType {
    /// The packed `msgt_name`, `msgt_size` and inline-flag bits;
    /// [`MachMsgType::new()`] builds it from the C initializer and
    /// [`MachMsgType::word()`] reads it back for `BAD_TYPECHECK`.
    word: u32,
    number: u32,
}

const _: () = {
    assert!(size_of::<MachMsgType>() == 8);
    assert!(align_of::<MachMsgType>() == 8);
    assert!(offset_of!(MachMsgType, word) == 0);
    assert!(offset_of!(MachMsgType, number) == 4);
};

impl MachMsgType {
    /// A descriptor built from its C initializer, with one element.
    pub(crate) const fn new(word: u32, number: u32) -> Self {
        Self { word, number }
    }

    /// The first word, the one the C's `BAD_TYPECHECK` compares.
    pub(crate) const fn word(self) -> u32 {
        self.word
    }

    /// `msgt_number`: how many elements the descriptor counts.
    pub(crate) const fn number(self) -> u32 {
        self.number
    }

    /// The C's `msgt_number = number` assignment.
    pub(crate) const fn set_number(&mut self, number: u32) {
        self.number = number;
    }
}

/// `mig_reply_header_t` of <`mach/mig_errors.h>`: the MIG reply preamble a
/// server sends back through the reply port.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct MigReplyHeader {
    pub(crate) head: MachMsgHeader,
    pub(crate) ret_code_type: MachMsgType,
    pub(crate) ret_code: c_int,
}

const _: () = {
    assert!(size_of::<MigReplyHeader>() == 48);
    assert!(align_of::<MigReplyHeader>() == 8);
    assert!(offset_of!(MigReplyHeader, head) == 0);
    assert!(offset_of!(MigReplyHeader, ret_code_type) == 32);
    assert!(offset_of!(MigReplyHeader, ret_code) == 40);
};

/// `struct ipc_kmsg` of <`ipc/ipc_kmsg.h>`: the header of a kernel message
/// buffer, whose body follows the header in the same allocation.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct IpcKmsg {
    next: *mut c_void,
    prev: *mut c_void,
    size: usize,
    marequest: *mut c_void,
    header: MachMsgHeader,
}

const _: () = {
    assert!(size_of::<IpcKmsg>() == 64);
    assert!(align_of::<IpcKmsg>() == 8);
    assert!(offset_of!(IpcKmsg, next) == 0);
    assert!(offset_of!(IpcKmsg, prev) == 8);
    assert!(offset_of!(IpcKmsg, size) == 16);
    assert!(offset_of!(IpcKmsg, marequest) == 24);
    assert!(offset_of!(IpcKmsg, header) == 32);
};

/// `ipc_port_t`: a send right to a kernel port.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcPort(NonNull<c_void>);

impl IpcPort {
    /// A port from the C side, or `None` for `IP_NULL`.
    pub(crate) fn new(port: *mut c_void) -> Option<Self> {
        NonNull::new(port).map(Self)
    }

    /// `IP_VALID(port)` of <`ipc/ipc_port.h>`: a port that is neither `IP_NULL`
    /// nor `IP_DEAD`.
    pub(crate) fn valid(port: *mut c_void) -> Option<Self> {
        if port.is_null() || ptr::eq(port, IO_DEAD) {
            return None;
        }
        // SAFETY: neither null nor dead, as `IP_VALID()` requires.
        Some(unsafe { Self::from_raw(port) })
    }

    /// A port from the C side where `IP_VALID()` already established that the
    /// pointer is live.
    ///
    /// # Safety
    ///
    /// `port` must be non-null and not `IP_DEAD`.
    pub(crate) const unsafe fn from_raw(port: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(port) })
    }

    /// A port from a non-null pointer already known live.
    ///
    /// # Safety
    ///
    /// `port` must name a live port, not `IP_DEAD`.
    pub(crate) const unsafe fn from_non_null(port: NonNull<c_void>) -> Self {
        Self(port)
    }

    pub(crate) const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The same right as a non-null pointer, for the notification senders.
    pub(crate) const fn as_non_null(self) -> NonNull<c_void> {
        self.0
    }

    /// The full `struct ipc_port` behind the handle.
    const fn record(self) -> *mut IpcPortRecord {
        self.0.as_ptr().cast()
    }

    /// `ip_lock()` of <`ipc/ipc_port.h>`: the port's `io_lock_data`, the first
    /// member of `struct ipc_port`.
    ///
    /// # Safety
    ///
    /// The port must be live, as `IP_VALID()` asserts, and this call must not
    /// already hold the port lock.
    pub(crate) unsafe fn lock(self) {
        unsafe { (*self.record()).target.object.lock.lock() };
    }

    /// `ip_unlock()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and this call must hold its lock.
    pub(crate) unsafe fn unlock(self) {
        unsafe { (*self.record()).target.object.lock.unlock() };
    }

    /// `ip_active()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn is_active(self) -> bool {
        let bits = unsafe { (*self.record()).target.object.bits };
        bits & IO_BITS_ACTIVE != 0
    }

    /// `ip_kotype()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn kotype(self) -> c_uint {
        unsafe { (*self.record()).target.object.bits & IO_BITS_KOTYPE }
    }

    /// `port->ip_kobject` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn kobject(self) -> *mut c_void {
        unsafe { (*self.record()).kobject }
    }

    /// The `port->ip_kobject = kobject` assignment of `vm_object_enter()`,
    /// which the C makes without `ipc_kobject_set()`.
    ///
    /// # Safety
    ///
    /// The port must be live, and the caller must hold whatever lock makes
    /// the update atomic as the C site did.
    pub(crate) unsafe fn set_kobject(self, kobject: *mut c_void) {
        unsafe { (*self.record()).kobject = kobject };
    }

    /// The `ipc_kobject_set_locked()` body of `kern/ipc_kobject.c`: name the
    /// kernel object and its type in the port's bits.
    ///
    /// # Safety
    ///
    /// The port must be live and locked, and the object must be one whose
    /// life the caller keeps alive while the port names it.
    pub(crate) unsafe fn set_kobject_locked(
        self,
        kobject: *mut c_void,
        type_: c_uint,
    ) {
        unsafe {
            let record = self.record();
            (*record).target.object.bits =
                ((*record).target.object.bits & !IO_BITS_KOTYPE) | type_;
            (*record).kobject = kobject;
        }
    }

    /// The `ip_reference()` macro of <`ipc/ipc_port.h>`: the bare
    /// `io_references++` the C makes with the port lock already held, as
    /// opposed to [`IpcPort::reference()`]'s locking function.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn increment_references(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.references =
                (*record).target.object.references.wrapping_add(1);
        }
    }

    /// The `port->ip_srights++` of the retrieval fast paths and the C's port
    /// routines.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held; the count is a `u32` on both
    /// ends and wraps as the C increment does.
    pub(crate) unsafe fn increment_srights(self) {
        unsafe {
            let record = self.record();
            (*record).srights = (*record).srights.wrapping_add(1);
        }
    }

    /// The `port->ip_srights--` of the C's port routines.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held, and the count must be nonzero.
    pub(crate) unsafe fn decrement_srights(self) {
        unsafe {
            let record = self.record();
            (*record).srights = (*record).srights.wrapping_sub(1);
        }
    }

    /// The `port->ip_srights = count` assignment of `ipc_port_init()`.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_srights(self, count: c_uint) {
        unsafe { (*self.record()).srights = count };
    }

    /// `ip_srights` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn srights(self) -> c_uint {
        unsafe { (*self.record()).srights }
    }

    /// The `port->ip_mscount++` of `ipc_port_make_send()`.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn increment_mscount(self) {
        unsafe {
            let record = self.record();
            (*record).mscount = (*record).mscount.wrapping_add(1);
        }
    }

    /// `ip_mscount` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn mscount(self) -> c_uint {
        unsafe { (*self.record()).mscount }
    }

    /// `ipc_port_set_mscount()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_mscount(self, mscount: c_uint) {
        unsafe { (*self.record()).mscount = mscount };
    }

    /// The `port->ip_sorights++` of `ipc_port_make_sonce()`.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn increment_sorights(self) {
        unsafe {
            let record = self.record();
            (*record).sorights = (*record).sorights.wrapping_add(1);
        }
    }

    /// The `port->ip_sorights--` of `ipc_port_release_sonce()`.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held, and the count must be
    /// nonzero.
    pub(crate) unsafe fn decrement_sorights(self) {
        unsafe {
            let record = self.record();
            (*record).sorights = (*record).sorights.wrapping_sub(1);
        }
    }

    /// The `port->ip_sorights = count` assignment of `ipc_port_init()`.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_sorights(self, count: c_uint) {
        unsafe { (*self.record()).sorights = count };
    }

    /// `ip_sorights` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn sorights(self) -> c_uint {
        unsafe { (*self.record()).sorights }
    }

    /// `ip_receiver_name` of <`ipc/ipc_port.h>`: `ip_target.ipt_name`.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn receiver_name(self) -> c_uint {
        unsafe { (*self.record()).target.name }
    }

    /// The `port->ip_receiver_name = name` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_receiver_name(self, name: c_uint) {
        unsafe { (*self.record()).target.name = name };
    }

    /// `ip_receiver` of <`ipc/ipc_port.h>`: the `data.receiver` union member.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn receiver(self) -> *mut c_void {
        unsafe { (*self.record()).data.receiver }
    }

    /// The `port->ip_receiver = space` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn set_receiver(self, space: *mut c_void) {
        unsafe { (*self.record()).data.receiver = space };
    }

    /// `ip_destination` of <`ipc/ipc_port.h>`: the `data.destination` union
    /// member.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn destination(self) -> *mut c_void {
        unsafe { (*self.record()).data.destination }
    }

    /// The `port->ip_destination = dest` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_destination(self, destination: *mut c_void) {
        unsafe { (*self.record()).data.destination = destination };
    }

    /// `ip_timestamp` of <`ipc/ipc_port.h>`: the `data.timestamp` union member.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn timestamp(self) -> c_uint {
        unsafe { (*self.record()).data.timestamp }
    }

    /// The `port->ip_timestamp = timestamp` assignment of
    /// `ipc_port_destroy()`.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_timestamp(self, timestamp: c_uint) {
        unsafe { (*self.record()).data.timestamp = timestamp };
    }

    /// `ip_nsrequest` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn nsrequest(self) -> Option<NonNull<c_void>> {
        unsafe { NonNull::new((*self.record()).nsrequest) }
    }

    /// The `port->ip_nsrequest = notify` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_nsrequest(self, notify: Option<NonNull<c_void>>) {
        unsafe {
            (*self.record()).nsrequest =
                notify.map_or(ptr::null_mut(), NonNull::as_ptr);
        }
    }

    /// `ip_pdrequest` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn pdrequest(self) -> Option<NonNull<c_void>> {
        unsafe { NonNull::new((*self.record()).pdrequest) }
    }

    /// The `port->ip_pdrequest = notify` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_pdrequest(self, notify: Option<NonNull<c_void>>) {
        unsafe {
            (*self.record()).pdrequest =
                notify.map_or(ptr::null_mut(), NonNull::as_ptr);
        }
    }

    /// `ip_dnrequests` of <`ipc/ipc_port.h>`: element zero of the table.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn dnrequests(self) -> *mut IpcPortRequest {
        unsafe { (*self.record()).dnrequests }
    }

    /// The `port->ip_dnrequests = table` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_dnrequests(self, table: *mut IpcPortRequest) {
        unsafe { (*self.record()).dnrequests = table };
    }

    /// `ip_pset` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn pset(self) -> *mut c_void {
        unsafe { (*self.record()).pset }
    }

    /// The `port->ip_pset = pset` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_pset(self, pset: *mut c_void) {
        unsafe { (*self.record()).pset = pset };
    }

    /// The `port->ip_cur_target = target` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_cur_target(self, target: *mut IpcTarget) {
        unsafe { (*self.record()).cur_target = target };
    }

    /// `ip_seqno` of <`ipc/ipc_port.h`>, which the message queue lock protects.
    ///
    /// # Safety
    ///
    /// The port must be live, its lock held, and its message queue locked.
    pub(crate) unsafe fn seqno(self) -> c_uint {
        unsafe { (*self.record()).seqno }
    }

    /// `ip_seqno` of <`ipc/ipc_port.h`>, locked by the message queue.
    ///
    /// # Safety
    ///
    /// The port must be live, its lock held, and its message queue locked.
    pub(crate) unsafe fn set_seqno(self, seqno: c_uint) {
        unsafe { (*self.record()).seqno = seqno };
    }

    /// `ip_msgcount` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn msgcount(self) -> c_uint {
        unsafe { (*self.record()).msgcount }
    }

    /// `ip_msgcount` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_msgcount(self, msgcount: c_uint) {
        unsafe { (*self.record()).msgcount = msgcount };
    }

    /// `ip_qlimit` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn qlimit(self) -> c_uint {
        unsafe { (*self.record()).qlimit }
    }

    /// The `port->ip_qlimit = qlimit` assignment.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_qlimit(self, qlimit: c_uint) {
        unsafe { (*self.record()).qlimit = qlimit };
    }

    /// `ip_protected_payload` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and its message queue locked.
    pub(crate) unsafe fn set_protected_payload(self, payload: usize) {
        unsafe { (*self.record()).protected_payload = payload };
    }

    /// `ip_protected_payload` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn protected_payload(self) -> usize {
        unsafe { (*self.record()).protected_payload }
    }

    /// `ipc_port_flag_protected_payload()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn protected_payload_flag(self) -> bool {
        let bits = unsafe { (*self.record()).target.object.bits };
        bits & IO_BITS_PROTECTED_PAYLOAD != 0
    }

    /// `ipc_port_flag_protected_payload_set()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and its message queue locked.
    pub(crate) unsafe fn set_protected_flag(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.bits |= IO_BITS_PROTECTED_PAYLOAD;
        }
    }

    /// `ipc_port_flag_protected_payload_clear()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn clear_protected_flag(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.bits &= !IO_BITS_PROTECTED_PAYLOAD;
        }
    }

    /// The `port->ip_object.io_bits &= ~IO_BITS_ACTIVE` of
    /// `ipc_port_destroy()`.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn clear_active(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.bits &= !IO_BITS_ACTIVE;
        }
    }

    /// The `port->ip_object.io_bits = bits` assignment of
    /// `ipc_port_alloc_special()`.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_bits(self, bits: c_uint) {
        unsafe { (*self.record()).target.object.bits = bits };
    }

    /// The `port->ip_references = 1` assignment of
    /// `ipc_port_alloc_special()`.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_references(self, references: c_uint) {
        unsafe { (*self.record()).target.object.references = references };
    }

    /// `ip_references` of <`ipc/ipc_port.h>`: the port's reference count.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn references(self) -> c_uint {
        unsafe { (*self.record()).target.object.references }
    }

    /// `ip_lock_init()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn init_lock(self) {
        unsafe { (*self.record()).target.object.lock.init() };
    }

    /// The `ip_release()` macro of <`ipc/ipc_port.h>`: the bare
    /// `io_references--` the C makes with the port lock already held.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held, and the count must be
    /// nonzero.
    pub(crate) unsafe fn decrement_references(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.references =
                (*record).target.object.references.wrapping_sub(1);
        }
    }

    /// `ip_lock_try()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and this call must not already hold its lock.
    pub(crate) unsafe fn try_lock(self) -> bool {
        unsafe { (*self.record()).target.object.lock.try_lock() }
    }

    /// `ip_check_unlock()` of <`ipc/ipc_port.h`>.
    ///
    /// # Safety
    ///
    /// The port must be live and locked, and its reference count was just
    /// decremented.
    pub(crate) unsafe fn check_unlock(self) {
        unsafe {
            IpcObject::check_unlock(ptr::addr_of_mut!(
                (*self.record()).target.object
            ));
        }
    }

    /// `&port->ip_messages`, the queue the port's target carries.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn messages(self) -> *mut IpcMqueue {
        unsafe { ptr::addr_of_mut!((*self.record()).target.messages) }
    }

    /// `&port->ip_blocked`, the port's queue of blocked senders.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn blocked(self) -> *mut IpcThreadQueue {
        unsafe { ptr::addr_of_mut!((*self.record()).blocked).cast() }
    }

    /// `ip_reference()` of <`ipc/ipc_port.h`>, the real `ipc_object_reference()`
    /// function.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn reference(self) {
        unsafe { ipc_object::reference(self.as_ptr()) };
    }

    /// `ip_release()` of <`ipc/ipc_port.h`>, the real `ipc_object_release()`
    /// function.
    ///
    /// # Safety
    ///
    /// The port must be live and hold a reference.
    pub(crate) unsafe fn release(self) {
        unsafe { ipc_object::release(self.as_ptr()) };
    }
}

/// `ipc_space_t`: a port namespace, opaque to Rust so far.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcSpace(NonNull<c_void>);

impl IpcSpace {
    /// A space from the C side, or `None` for `IS_NULL`.
    pub(crate) fn new(space: *mut c_void) -> Option<Self> {
        NonNull::new(space).map(Self)
    }

    /// A space from the C side where the caller knows it is live.
    ///
    /// # Safety
    ///
    /// `space` must be non-null.
    pub(crate) const unsafe fn from_raw(space: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(space) })
    }

    pub(crate) const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The full `struct ipc_space` behind the handle.
    pub(crate) const fn record(self) -> *mut IpcSpaceRecord {
        self.0.as_ptr().cast()
    }

    /// `ipc_entry_lookup()` of <`ipc/ipc_space.h>`: the named capability, or
    /// `None` when the name denotes nothing.
    ///
    /// # Safety
    ///
    /// The space must be live, active, and locked for reading or writing.
    pub(crate) unsafe fn entry_lookup(
        self,
        name: c_uint,
    ) -> Option<*mut IpcEntry> {
        let record = self.record();
        let found = unsafe {
            (*record)
                .map
                .lookup(RdxtreeKey::from_raw(name), Lookup::Value)
        }?;
        let entry = found.address().cast::<IpcEntry>();

        // SAFETY: a found address is a live entry stored in the map.
        let bits = unsafe { (*entry).bits };
        if bits & IE_BITS_TYPE_MASK == 0 {
            None
        } else {
            Some(entry)
        }
    }
}
