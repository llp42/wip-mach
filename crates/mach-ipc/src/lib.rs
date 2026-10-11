// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Mach IPC above `mach-vm`: ports and port sets, capability spaces,
//! message queues, kernel messages, notifications and the `mach_msg` paths.
//!
//! Everything IPC asks of the rest of the kernel arrives through
//! [`Platform`], a zero-sized type parameter the kernel implements.  It
//! extends [`mach_vm::Platform`], so locks, user copy, the console, `kalloc`,
//! the running thread's waits and the kernel's maps come from VM's seam;
//! IPC's own adds the running thread's IPC state and space, IPC's blocking
//! and wakeup, the task's counters and name, the kernel-object server and
//! IPC's slab caches.

#![no_std]
// These routines mirror the C's integer and pointer conversions one for
// one: the widths and alignments are known at each site, and the
// truncations, sign changes and wraps are deliberate.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss
)]
#![expect(
    clippy::missing_errors_doc,
    reason = "the error cases of the translated routines are not written up yet"
)]

use crate::ipc_table::IpcTableSize;
use crate::ipc_thread::IpcThreadQueue;
use crate::types::{EntryBits, ObjectBits};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use kmem::RadixTree;
use lock::RawRwLock;
use mach_vm::simple_lock::SimpleLock;

pub mod copy_user;
pub mod error;
pub mod ipc_entry;
pub mod ipc_init;
pub mod ipc_kmsg;
pub mod ipc_marequest;
pub mod ipc_mqueue;
pub mod ipc_notify;
pub mod ipc_object;
pub mod ipc_port;
pub mod ipc_pset;
pub mod ipc_right;
pub mod ipc_space;
pub mod ipc_table;
pub mod ipc_target;
pub mod ipc_thread;
pub mod mach_debug;
pub mod mach_msg;
pub mod mach_port;
pub mod platform;
pub mod types;

pub use platform::Platform;
pub use types::MsgOption;

/// The object type of a port.
pub(crate) const IOT_PORT: usize = 0;
/// The object type of a port set.
pub(crate) const IOT_PORT_SET: usize = 1;

/// The low half of an object's bits names its kernel-object type.
const IO_BITS_KOTYPE: u32 = 0x0000_ffff;
/// The bits naming the object's type and so its cache.
const IO_BITS_OTYPE: u32 = 0x3fff_0000;
/// The dead object value: the one non-null pointer [`IpcPort::valid`] rejects.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// The `struct ipc_object` header every IPC object begins with.
#[repr(C)]
#[allow(missing_docs)]
struct IpcObject {
    lock: SimpleLock,
    references: u32,
    bits: ObjectBits,
}

const _: () = {
    assert!(size_of::<IpcObject>() == 12);
    assert!(align_of::<IpcObject>() == 4);
    assert!(offset_of!(IpcObject, lock) == 0);
    assert!(offset_of!(IpcObject, references) == 4);
    assert!(offset_of!(IpcObject, bits) == 8);
};

impl IpcObject {
    /// Unlocks the object, freeing it through its type's cache once the last
    /// reference is gone.
    ///
    /// # Safety
    ///
    /// `object` must point at a live IPC object whose lock this call holds and
    /// whose reference count was just decremented.
    pub(crate) unsafe fn check_unlock<P: Platform>(object: *mut Self) {
        let references = unsafe { (*object).references };
        unsafe { (*object).lock.unlock() };

        if references != 0 {
            return;
        }

        // SAFETY: the object is live; `io_free()` selects the cache from the
        // type bits the same way.
        let otype = unsafe { ((*object).bits.bits() & IO_BITS_OTYPE) >> 16 };
        let Some(cache) = ipc_object::object_cache(otype) else {
            panic!("io_check_unlock: bad object type")
        };

        // SAFETY: the caches are initialized before any object is allocated
        // from them, and the object came from its type's cache.
        unsafe {
            P::ipc_cache_free(
                cache,
                NonNull::new_unchecked(object.cast::<u8>()),
            );
        }
    }
}

/// A target's message queue and blocked-thread queue, each one pointer.
#[repr(C)]
#[allow(missing_docs)]
pub struct IpcMqueue {
    lock: SimpleLock,
    messages: *mut c_void,
    threads: *mut c_void,
}

impl IpcMqueue {
    /// Takes the queue's lock.
    pub fn lock(&self) {
        self.lock.lock();
    }

    /// Tries to take the queue's lock.
    pub fn try_lock(&self) -> bool {
        self.lock.try_lock()
    }

    /// Releases the queue's lock.
    pub fn unlock(&self) {
        self.lock.unlock();
    }

    /// The address of the embedded message queue, one pointer.
    pub(crate) const fn messages(&self) -> *mut c_void {
        ptr::addr_of!(self.messages).cast_mut().cast()
    }

    /// The address of the embedded thread queue, one pointer.
    pub const fn threads(&self) -> *mut c_void {
        ptr::addr_of!(self.threads).cast_mut().cast()
    }
}

/// The common part of ports and port sets, and the whole of a port set.
#[repr(C)]
#[allow(missing_docs)]
pub struct IpcTarget {
    object: IpcObject,
    name: u32,
    messages: IpcMqueue,
}

impl IpcTarget {
    /// Takes the target's object lock.
    pub(crate) fn lock(&self) {
        self.object.lock.lock();
    }

    /// Releases the target's lock.
    pub(crate) fn unlock(&self) {
        self.object.lock.unlock();
    }

    /// Whether the target is live.
    pub(crate) const fn is_active(&self) -> bool {
        self.object.bits.contains(ObjectBits::ACTIVE)
    }

    /// The name of a port set in its space.
    pub(crate) const fn local_name(&self) -> c_uint {
        self.name
    }

    /// Sets the name of a port set in its space.
    pub(crate) const fn set_local_name(&mut self, name: c_uint) {
        self.name = name;
    }

    /// The address of the target's message queue.
    pub const fn messages(&self) -> *mut IpcMqueue {
        ptr::addr_of!(self.messages).cast_mut()
    }

    /// Unlocks the target, freeing it once the last reference is gone.
    ///
    /// # Safety
    ///
    /// `target` must be the target of a live port set that is locked and whose
    /// reference count was just decremented.
    pub(crate) unsafe fn check_unlock<P: Platform>(target: *mut Self) {
        unsafe {
            IpcObject::check_unlock::<P>(ptr::addr_of_mut!((*target).object));
        }
    }

    /// Takes a reference on the target's object, which the caller already has
    /// locked.
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

    /// Drops a reference on the target's object, which the caller already has
    /// locked.
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

    /// Marks the target's object dead.
    ///
    /// # Safety
    ///
    /// The target must be live and locked.
    pub(crate) unsafe fn clear_active(target: *mut Self) {
        unsafe {
            (*target).object.bits.remove(ObjectBits::ACTIVE);
        }
    }
}

/// Whichever of the receiver, the destination and the death timestamp the
/// port's state holds.
#[repr(C)]
#[allow(missing_docs)]
union IpcPortData {
    receiver: *mut c_void,
    destination: *mut c_void,
    timestamp: u32,
}

/// The whole port record [`IpcPort`] points at, its embedded [`IpcTarget`]
/// included; the object, receiver, message queue, reference count and receiver
/// name are members of that target.
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

/// A dead-name request's notification: a port pointer or an index into the
/// table.
#[repr(C)]
#[allow(missing_docs)]
union RequestNotify {
    port: *mut c_void,
    index: c_uint,
}

/// A dead-name request's name: a port name, or the size record the table is
/// growing to.
#[repr(C)]
#[allow(missing_docs)]
union RequestName {
    name: c_uint,
    size: *mut IpcTableSize,
}

/// One dead-name request slot, or, in element zero, the table's free-list head
/// and size record.
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
    /// The next free slot, for a free slot or element zero.
    const fn next(&self) -> c_uint {
        // SAFETY: the union's members share one readable word.
        unsafe { self.notify.index }
    }

    const fn set_next(&mut self, index: c_uint) {
        self.notify.index = index;
    }

    /// The table's size record, for element zero.
    const fn size(&self) -> *mut IpcTableSize {
        // SAFETY: the union's members share one readable word.
        unsafe { self.name.size }
    }

    const fn set_size(&mut self, size: *mut IpcTableSize) {
        self.name.size = size;
    }

    /// The name the request is for.
    const fn name(&self) -> c_uint {
        // SAFETY: the union's members share one readable word.
        unsafe { self.name.name }
    }

    const fn set_name(&mut self, name: c_uint) {
        self.name.name = name;
    }

    /// The send-once right the request notifies.
    const fn soright(&self) -> *mut c_void {
        // SAFETY: the union's members share one readable word.
        unsafe { self.notify.port }
    }

    const fn set_soright(&mut self, port: *mut c_void) {
        self.notify.port = port;
    }
}

/// One capability.
#[repr(C)]
#[allow(missing_docs)]
pub struct IpcEntry {
    name: c_uint,
    bits: EntryBits,
    object: *mut c_void,
    /// The next free entry or an index into the dead-name request table,
    /// aliased in one word.
    index: *mut c_void,
}

const _: () = {
    assert!(size_of::<IpcEntry>() == 32);
    assert!(align_of::<IpcEntry>() == 8);
    assert!(offset_of!(IpcEntry, name) == 0);
    assert!(offset_of!(IpcEntry, bits) == 4);
    assert!(offset_of!(IpcEntry, object) == 16);
    assert!(offset_of!(IpcEntry, index) == 24);
};

/// One pending message-accepted request.
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

/// One bucket of the msg-accepted request hash table.
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

/// The name table: a radix tree of entry pointers, keyed by name.
pub(crate) type NameMap<P> = RadixTree<IpcEntry, <P as Platform>::Heap>;

/// The capability namespace.
#[allow(missing_docs)]
pub(crate) struct IpcSpaceRecord<P: Platform> {
    ref_lock: SimpleLock,
    references: u32,
    lock: RawRwLock<<P as mach_vm::Platform>::Lock>,
    active: c_int,
    map: NameMap<P>,
    size: usize,
    reverse_map: NameMap<P>,
    free_list: *mut IpcEntry,
    free_list_size: usize,
}

/// `mach_msg_header_t`: its two pointer-wide unions carry the remote and local
/// ports.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachMsgHeader {
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

/// `mach_msg_type_t`: the inline descriptor of one body element.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct MachMsgType {
    /// The packed `msgt_name`, `msgt_size` and inline-flag bits;
    /// [`MachMsgType::new()`] builds it from its fields and
    /// [`MachMsgType::word()`] reads it back for the reply type check.
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
    #[must_use]
    pub const fn new(word: u32, number: u32) -> Self {
        Self { word, number }
    }

    /// The first word, the one the reply type check compares.
    #[must_use]
    pub const fn word(self) -> u32 {
        self.word
    }
}

/// `mig_reply_header_t`: the reply preamble a server sends back through the
/// reply port.
#[repr(C)]
#[allow(missing_docs)]
pub struct MigReplyHeader {
    pub head: MachMsgHeader,
    pub ret_code_type: MachMsgType,
    pub ret_code: c_int,
}

const _: () = {
    assert!(size_of::<MigReplyHeader>() == 48);
    assert!(align_of::<MigReplyHeader>() == 8);
    assert!(offset_of!(MigReplyHeader, head) == 0);
    assert!(offset_of!(MigReplyHeader, ret_code_type) == 32);
    assert!(offset_of!(MigReplyHeader, ret_code) == 40);
};

/// The header of a kernel message buffer, whose body follows the header in the
/// same allocation.
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
    pub fn new(port: *mut c_void) -> Option<Self> {
        NonNull::new(port).map(Self)
    }

    /// The port `port` is, when it is neither null nor dead.
    pub fn valid(port: *mut c_void) -> Option<Self> {
        if ptr::eq(port, IO_DEAD) {
            return None;
        }
        NonNull::new(port).map(Self)
    }

    /// A port from the C side whose validity the caller already established.
    ///
    /// # Safety
    ///
    /// `port` must be non-null and not `IP_DEAD`.
    pub const unsafe fn from_raw(port: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(port) })
    }

    /// A port from a non-null pointer; only the port's unsafe methods read
    /// through it, and each asks for a live port.
    #[must_use]
    pub const fn from_non_null(port: NonNull<c_void>) -> Self {
        Self(port)
    }

    /// The port as the C side spells it.
    #[must_use]
    pub const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The same right as a non-null pointer, for the notification senders.
    #[must_use]
    pub const fn as_non_null(self) -> NonNull<c_void> {
        self.0
    }

    /// The full port record behind the handle.
    const fn record(self) -> *mut IpcPortRecord {
        self.0.as_ptr().cast()
    }

    /// Takes the port's lock, the first member of its record.
    ///
    /// # Safety
    ///
    /// The port must be live and valid, and this call must not already hold
    /// the port lock.
    pub unsafe fn lock(self) {
        unsafe { (*self.record()).target.object.lock.lock() };
    }

    /// Releases the port's lock.
    ///
    /// # Safety
    ///
    /// The port must be live and this call must hold its lock.
    pub unsafe fn unlock(self) {
        unsafe { (*self.record()).target.object.lock.unlock() };
    }

    /// Whether the port is live.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn is_active(self) -> bool {
        let bits = unsafe { (*self.record()).target.object.bits };
        bits.contains(ObjectBits::ACTIVE)
    }

    /// The port's kernel-object type.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn kotype(self) -> c_uint {
        unsafe { (*self.record()).target.object.bits.bits() & IO_BITS_KOTYPE }
    }

    /// The port's kernel object.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn kobject(self) -> *mut c_void {
        unsafe { (*self.record()).kobject }
    }

    /// Sets the port's kernel object without touching its type.
    ///
    /// # Safety
    ///
    /// The port must be live, and the caller must hold whatever lock makes
    /// the update atomic as the C site did.
    pub unsafe fn set_kobject(self, kobject: *mut c_void) {
        unsafe { (*self.record()).kobject = kobject };
    }

    /// Names the kernel object and its type in the port's bits, with the port
    /// locked.
    ///
    /// # Safety
    ///
    /// The port must be live and locked, and the object must be one whose
    /// life the caller keeps alive while the port names it.
    pub unsafe fn set_kobject_locked(
        self,
        kobject: *mut c_void,
        type_: c_uint,
    ) {
        unsafe {
            let record = self.record();
            (*record).target.object.bits = ObjectBits::from_bits_retain(
                ((*record).target.object.bits.bits() & !IO_BITS_KOTYPE)
                    | type_,
            );
            (*record).kobject = kobject;
        }
    }

    /// Takes a reference with the port lock already held, as opposed to
    /// [`IpcPort::reference()`], which locks.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub unsafe fn increment_references(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.references =
                (*record).target.object.references.wrapping_add(1);
        }
    }

    /// Counts one more send right.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held; the count is a `u32` on both
    /// ends and wraps as the C increment does.
    pub unsafe fn increment_srights(self) {
        unsafe {
            let record = self.record();
            (*record).srights = (*record).srights.wrapping_add(1);
        }
    }

    /// Counts one send right fewer.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held, and the count must be nonzero.
    pub unsafe fn decrement_srights(self) {
        unsafe {
            let record = self.record();
            (*record).srights = (*record).srights.wrapping_sub(1);
        }
    }

    /// Sets the port's send-right count.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_srights(self, count: c_uint) {
        unsafe { (*self.record()).srights = count };
    }

    /// The port's send-right count.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn srights(self) -> c_uint {
        unsafe { (*self.record()).srights }
    }

    /// Counts one more send right made from the receive right.
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

    /// The port's make-send count.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn mscount(self) -> c_uint {
        unsafe { (*self.record()).mscount }
    }

    /// Sets the port's make-send count.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_mscount(self, mscount: c_uint) {
        unsafe { (*self.record()).mscount = mscount };
    }

    /// Counts one more send-once right.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub unsafe fn increment_sorights(self) {
        unsafe {
            let record = self.record();
            (*record).sorights = (*record).sorights.wrapping_add(1);
        }
    }

    /// Counts one send-once right fewer.
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

    /// Sets the port's send-once-right count.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_sorights(self, count: c_uint) {
        unsafe { (*self.record()).sorights = count };
    }

    /// The port's send-once-right count.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn sorights(self) -> c_uint {
        unsafe { (*self.record()).sorights }
    }

    /// The name of the port's receive right in its receiver's space.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn receiver_name(self) -> c_uint {
        unsafe { (*self.record()).target.name }
    }

    /// Sets the name of the port's receive right.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_receiver_name(self, name: c_uint) {
        unsafe { (*self.record()).target.name = name };
    }

    /// The space holding the port's receive right.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn receiver(self) -> *mut c_void {
        unsafe { (*self.record()).data.receiver }
    }

    /// Sets the space holding the port's receive right.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn set_receiver(self, space: *mut c_void) {
        unsafe { (*self.record()).data.receiver = space };
    }

    /// The port the receive right is in transit to.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn destination(self) -> *mut c_void {
        unsafe { (*self.record()).data.destination }
    }

    /// Sets the port the receive right is in transit to.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_destination(self, destination: *mut c_void) {
        unsafe { (*self.record()).data.destination = destination };
    }

    /// The timestamp of the port's death.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn timestamp(self) -> c_uint {
        unsafe { (*self.record()).data.timestamp }
    }

    /// Records the timestamp of the port's death.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_timestamp(self, timestamp: c_uint) {
        unsafe { (*self.record()).data.timestamp = timestamp };
    }

    /// The port's no-senders request.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn nsrequest(self) -> Option<NonNull<c_void>> {
        unsafe { NonNull::new((*self.record()).nsrequest) }
    }

    /// Sets the port's no-senders request.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub unsafe fn set_nsrequest(self, notify: Option<NonNull<c_void>>) {
        unsafe {
            (*self.record()).nsrequest =
                notify.map_or(ptr::null_mut(), NonNull::as_ptr);
        }
    }

    /// The port's port-destroyed request.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn pdrequest(self) -> Option<NonNull<c_void>> {
        unsafe { NonNull::new((*self.record()).pdrequest) }
    }

    /// Sets the port's port-destroyed request.
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

    /// The port's dead-name request table: element zero of it.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn dnrequests(self) -> *mut IpcPortRequest {
        unsafe { (*self.record()).dnrequests }
    }

    /// Sets the port's dead-name request table.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_dnrequests(self, table: *mut IpcPortRequest) {
        unsafe { (*self.record()).dnrequests = table };
    }

    /// The port set the port belongs to, or null.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn pset(self) -> *mut c_void {
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

    /// Sets the target whose queue the port's messages go to: its own or its
    /// set's.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_cur_target(self, target: *mut IpcTarget) {
        unsafe { (*self.record()).cur_target = target };
    }

    /// The port's sequence number, which the message queue lock protects.
    ///
    /// # Safety
    ///
    /// The port must be live, its lock held, and its message queue locked.
    pub(crate) unsafe fn seqno(self) -> c_uint {
        unsafe { (*self.record()).seqno }
    }

    /// Sets the port's sequence number, under the message queue lock.
    ///
    /// # Safety
    ///
    /// The port must be live, its lock held, and its message queue locked.
    pub(crate) unsafe fn set_seqno(self, seqno: c_uint) {
        unsafe { (*self.record()).seqno = seqno };
    }

    /// The number of messages queued on the port.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn msgcount(self) -> c_uint {
        unsafe { (*self.record()).msgcount }
    }

    /// Sets the number of messages queued on the port.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_msgcount(self, msgcount: c_uint) {
        unsafe { (*self.record()).msgcount = msgcount };
    }

    /// The port's queue limit.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn qlimit(self) -> c_uint {
        unsafe { (*self.record()).qlimit }
    }

    /// Sets the port's queue limit.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn set_qlimit(self, qlimit: c_uint) {
        unsafe { (*self.record()).qlimit = qlimit };
    }

    /// Sets the port's protected payload.
    ///
    /// # Safety
    ///
    /// The port must be live and its message queue locked.
    pub(crate) unsafe fn set_protected_payload(self, payload: usize) {
        unsafe { (*self.record()).protected_payload = payload };
    }

    /// The port's protected payload.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn protected_payload(self) -> usize {
        unsafe { (*self.record()).protected_payload }
    }

    /// Whether the port has a protected payload.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn protected_payload_flag(self) -> bool {
        let bits = unsafe { (*self.record()).target.object.bits };
        bits.contains(ObjectBits::PROTECTED_PAYLOAD)
    }

    /// Marks the port as having a protected payload.
    ///
    /// # Safety
    ///
    /// The port must be live and its message queue locked.
    pub(crate) unsafe fn set_protected_flag(self) {
        unsafe {
            let record = self.record();
            (*record)
                .target
                .object
                .bits
                .insert(ObjectBits::PROTECTED_PAYLOAD);
        }
    }

    /// Marks the port as having no protected payload.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn clear_protected_flag(self) {
        unsafe {
            let record = self.record();
            (*record)
                .target
                .object
                .bits
                .remove(ObjectBits::PROTECTED_PAYLOAD);
        }
    }

    /// Marks the port dead.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held.
    pub(crate) unsafe fn clear_active(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.bits.remove(ObjectBits::ACTIVE);
        }
    }

    /// Sets the port's object bits.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_bits(self, bits: ObjectBits) {
        unsafe { (*self.record()).target.object.bits = bits };
    }

    /// Sets the port's reference count.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn set_references(self, references: c_uint) {
        unsafe { (*self.record()).target.object.references = references };
    }

    /// The port's reference count.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn references(self) -> c_uint {
        unsafe { (*self.record()).target.object.references }
    }

    /// Initializes the port's lock.
    ///
    /// # Safety
    ///
    /// The port must be live, unlocked, and owned by this call.
    pub(crate) unsafe fn init_lock(self) {
        unsafe { (*self.record()).target.object.lock.init() };
    }

    /// Drops a reference with the port lock already held.
    ///
    /// # Safety
    ///
    /// The port must be live and its lock held, and the count must be
    /// nonzero.
    pub unsafe fn decrement_references(self) {
        unsafe {
            let record = self.record();
            (*record).target.object.references =
                (*record).target.object.references.wrapping_sub(1);
        }
    }

    /// Tries to take the port's lock.
    ///
    /// # Safety
    ///
    /// The port must be live and this call must not already hold its lock.
    #[must_use]
    pub unsafe fn try_lock(self) -> bool {
        unsafe { (*self.record()).target.object.lock.try_lock() }
    }

    /// Unlocks the port, freeing it once the last reference is gone.
    ///
    /// # Safety
    ///
    /// The port must be live and locked, and its reference count was just
    /// decremented.
    pub(crate) unsafe fn check_unlock<P: Platform>(self) {
        unsafe {
            IpcObject::check_unlock::<P>(ptr::addr_of_mut!(
                (*self.record()).target.object
            ));
        }
    }

    /// The queue the port's target carries.
    ///
    /// # Safety
    ///
    /// The port must be live.
    #[must_use]
    pub unsafe fn messages(self) -> *mut IpcMqueue {
        unsafe { ptr::addr_of_mut!((*self.record()).target.messages) }
    }

    /// The port's queue of blocked senders.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub(crate) unsafe fn blocked(self) -> *mut IpcThreadQueue {
        unsafe { ptr::addr_of_mut!((*self.record()).blocked).cast() }
    }

    /// Takes a reference on the port, under its lock.
    ///
    /// # Safety
    ///
    /// The port must be live.
    pub unsafe fn reference(self) {
        unsafe { ipc_object::reference(self.as_ptr()) };
    }

    /// Drops a reference on the port, under its lock, freeing it on the last
    /// one.
    ///
    /// # Safety
    ///
    /// The port must be live and hold a reference.
    pub unsafe fn release<P: Platform>(self) {
        unsafe { ipc_object::release::<P>(self.as_ptr()) };
    }
}

/// `ipc_space_t`: a port namespace, opaque to Rust so far.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcSpace(NonNull<c_void>);

impl IpcSpace {
    /// A space from the C side, or `None` for a null one.
    pub fn new(space: *mut c_void) -> Option<Self> {
        NonNull::new(space).map(Self)
    }

    /// A space from the C side where the caller knows it is live.
    ///
    /// # Safety
    ///
    /// `space` must be non-null.
    pub const unsafe fn from_raw(space: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(space) })
    }

    /// The space as the C side spells it.
    #[must_use]
    pub const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The full `struct ipc_space` behind the handle.
    pub(crate) const fn record<P: Platform>(self) -> *mut IpcSpaceRecord<P> {
        self.0.as_ptr().cast()
    }

    /// The named capability, or `None` when the name denotes nothing.
    ///
    /// # Safety
    ///
    /// The space must be live, active, and locked for reading or writing.
    #[must_use]
    pub unsafe fn entry_lookup<P: Platform>(
        self,
        name: c_uint,
    ) -> Option<*mut IpcEntry> {
        let record = self.record::<P>();
        let entry = unsafe { (*record).map.get(u64::from(name)) }?.as_ptr();

        // SAFETY: a found address is a live entry stored in the map.
        let bits = unsafe { (*entry).bits };
        if bits.type_.is_empty() {
            None
        } else {
            Some(entry)
        }
    }
}
