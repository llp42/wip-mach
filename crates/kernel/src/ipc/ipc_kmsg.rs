// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_kmsg.c and ipc/ipc_kmsg.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel-message routines.

use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::user_access::{self, UserFault};
use crate::config::MAX_NCPUS;
use crate::ipc::copy_user;
use crate::ipc::error::{Error, ReceiveError, SendError, Shortage};
use crate::ipc::ipc_entry;
use crate::ipc::ipc_marequest;
use crate::ipc::ipc_notify;
use crate::ipc::ipc_object;
use crate::ipc::ipc_port;
use crate::ipc::ipc_right;
use crate::ipc::mach_port;
use crate::ipc::{
    IE_BITS_TYPE_MASK, IpcEntry, IpcKmsg, IpcMarequest, IpcPort, IpcSpace,
    MachMsgHeader,
};
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::soft_debugger;
use crate::kern::slab;
use crate::kern::task;
use crate::kern::thread::IpcKmsgQueue;
use crate::vm::error::Error as VmError;
use crate::vm::vm_map::{VmMap, VmMapCopy};
use crate::vm::vm_user;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::mem::{size_of, size_of_val};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::sync::atomic::Ordering;

/// The size marking a message the network code owns.
const IKM_SIZE_NETWORK: usize = usize::MAX;
/// The allocation bytes before the message header.
pub(crate) const IKM_OVERHEAD: usize =
    size_of::<IpcKmsg>() - size_of::<MachMsgHeader>();
/// The body size of a cached message.
const IKM_SAVED_MSG_SIZE: usize = PAGE_SIZE - IKM_OVERHEAD;
/// How much a body can grow when port names widen into kernel ports.
const IKM_EXPAND_FACTOR: c_uint = size_of::<usize>().div_ceil(4) as c_uint;

/// `size` plus the allocation bytes before the message header.
pub(crate) const fn ikm_plus_overhead(size: usize) -> usize {
    size.wrapping_add(IKM_OVERHEAD)
}

const _: () = assert!(size_of::<usize>() >= size_of::<c_uint>());

/// `sizeof(mach_msg_user_header_t)`: the user and kernel headers have the
/// same size.
const MACH_MSG_HEADER_SIZE: usize = size_of::<MachMsgHeader>();
/// The alignment of a user message: one word, as user tasks are 64-bit.
const MACH_MSG_USER_ALIGNMENT: usize = size_of::<usize>();

/// The receive-right disposition: the sender held receive rights.
const MACH_MSG_TYPE_PORT_RECEIVE: c_uint = 16;
/// `MACH_MSG_TYPE_MOVE_SEND`, the wire alias `MACH_MSG_TYPE_PORT_SEND`.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`, the wire alias
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`.
const MACH_MSG_TYPE_PORT_SEND_ONCE: c_uint = 18;
/// The disposition that copies a send right.
const MACH_MSG_TYPE_COPY_SEND: c_uint = 19;
/// The disposition that makes a new send right.
const MACH_MSG_TYPE_MAKE_SEND: c_uint = 20;
/// The disposition that makes a new send-once right.
const MACH_MSG_TYPE_MAKE_SEND_ONCE: c_uint = 21;
/// The type of a protected payload in place of a reply port name.
const MACH_MSG_TYPE_PROTECTED_PAYLOAD: c_uint = 23;

/// The remote-disposition bits of a message header.
const MACH_MSGH_BITS_REMOTE_MASK: u32 = 0x0000_00ff;
/// The local-disposition bits of a message header.
const MACH_MSGH_BITS_LOCAL_MASK: u32 = 0x0000_ff00;
/// The header bit of a message that carries rights or out-of-line memory.
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
/// The header bit of a circular message, internal to the kernel.
const MACH_MSGH_BITS_CIRCULAR: u32 = 0x4000_0000;
/// The remote and local disposition bits together.
const MACH_MSGH_BITS_PORTS_MASK: u32 =
    MACH_MSGH_BITS_REMOTE_MASK | MACH_MSGH_BITS_LOCAL_MASK;

/// The type bit of a send right.
const MACH_PORT_TYPE_SEND: c_uint = 1 << 16;
/// The type bit of a receive right.
const MACH_PORT_TYPE_RECEIVE: c_uint = 1 << 17;
/// The type bit of a send-once right.
const MACH_PORT_TYPE_SEND_ONCE: c_uint = 1 << 18;
/// The most user references an entry may hold.
const MACH_PORT_UREFS_MAX: u32 = (1 << 16) - 1;
/// The user-reference count bits of an entry.
const IE_BITS_UREFS_MASK: u32 = 0x0000_ffff;
/// One generation step; zero in this configuration.
const IE_BITS_GEN_ONE: u32 = 0;
/// The null port name.
const MACH_PORT_NAME_NULL: c_uint = 0;
/// The dead port name.
const MACH_PORT_NAME_DEAD: c_uint = c_uint::MAX;
/// The kernel-object type of a pager request port.
const IKOT_PAGING_REQUEST: c_uint = 9;
/// The kernel-object type of a device port.
const IKOT_DEVICE: c_uint = 10;
/// The kernel-object type of a user device port.
const IKOT_USER_DEVICE: c_uint = 28;
/// The dead object value: the one non-null pointer [`io_valid`] rejects.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// The size of a port in a message body, in bits.
const PORT_T_SIZE_IN_BITS: c_uint = usize::BITS;
/// The size of a port name in a message body, in bits.
const PORT_NAME_T_SIZE_IN_BITS: c_uint = c_uint::BITS;

/// Rounds `x` up to the kernel message alignment.
const fn kernel_align(x: usize) -> usize {
    x.wrapping_add(size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// Whether `x` is not a multiple of the kernel message alignment.
const fn kernel_is_misaligned(x: usize) -> bool {
    x & (size_of::<usize>() - 1) != 0
}

/// Whether `x` is not a multiple of the user message alignment.
const fn user_is_misaligned(x: usize) -> bool {
    x & (MACH_MSG_USER_ALIGNMENT - 1) != 0
}

/// The header bits of a message with the `remote` and `local` dispositions.
const fn mach_msg_bits(remote: u32, local: u32) -> u32 {
    remote | (local << 8)
}

/// The remote disposition in `bits`.
const fn mach_msg_bits_remote(bits: u32) -> u32 {
    bits & MACH_MSGH_BITS_REMOTE_MASK
}

/// The local disposition in `bits`.
const fn mach_msg_bits_local(bits: u32) -> u32 {
    (bits & MACH_MSGH_BITS_LOCAL_MASK) >> 8
}

/// The two dispositions in `bits`.
const fn mach_msg_bits_ports(bits: u32) -> u32 {
    bits & MACH_MSGH_BITS_PORTS_MASK
}

/// The bits of `bits` other than the dispositions.
const fn mach_msg_bits_other(bits: u32) -> u32 {
    bits & !MACH_MSGH_BITS_PORTS_MASK
}

/// Whether `name` is a port-right type.
const fn mach_msg_type_port_any(name: c_uint) -> bool {
    name >= MACH_MSG_TYPE_PORT_RECEIVE && name <= MACH_MSG_TYPE_MAKE_SEND_ONCE
}

/// Whether `name` is a send or send-once right type.
const fn mach_msg_type_port_any_send(name: c_uint) -> bool {
    name >= MACH_MSG_TYPE_PORT_SEND && name <= MACH_MSG_TYPE_MAKE_SEND_ONCE
}

/// Whether `name` is neither null nor dead.
const fn mach_port_name_valid(name: c_uint) -> bool {
    name != MACH_PORT_NAME_NULL && name != MACH_PORT_NAME_DEAD
}

/// Whether `object` is neither null nor dead.
fn io_valid(object: *mut c_void) -> bool {
    !object.is_null() && object != IO_DEAD
}

const fn ptr_at<T>(addr: usize) -> *mut T {
    with_exposed_provenance_mut(addr)
}

/// A `mach_msg_type_number_t` as an index; the 32-bit count widens into
/// `usize` without loss.
const fn as_index(count: c_uint) -> usize {
    count as usize
}

/// Whether `one` happened before `two` across the counter's 32-bit wrap.
const fn timestamp_order(one: c_uint, two: c_uint) -> bool {
    // The C compares the `int` reinterpretation of the wrapped difference.
    (one.wrapping_sub(two) as i32) < 0
}

/// Whether out-of-line memory to a port of kernel-object type `ikot` travels
/// as a page list.
const fn kobject_vm_page_list(ikot: c_uint) -> bool {
    ikot == IKOT_PAGING_REQUEST
        || ikot == IKOT_DEVICE
        || ikot == IKOT_USER_DEVICE
}

/// Whether out-of-line memory to a port of kernel-object type `ikot` has its
/// pages stolen.
const fn kobject_vm_page_steal(ikot: c_uint) -> bool {
    ikot == IKOT_PAGING_REQUEST
}

/// The size of a `mach_msg_type_t`.
const MSG_TYPE_SIZE: usize = 8;
/// The size of a `mach_msg_type_long_t`.
const MSG_TYPE_LONG_SIZE: usize = 8;

/// The `msgt_name` field of the descriptor word.
const MSGT_NAME_MASK: u32 = 0x0000_00ff;
/// `msgt_inline` of `mach_msg_type_t`.
const MSGT_INLINE: u32 = 1 << 29;
/// `msgt_longform` of `mach_msg_type_t`.
const MSGT_LONGFORM: u32 = 1 << 30;
/// `msgt_deallocate` of `mach_msg_type_t`.
const MSGT_DEALLOCATE: u32 = 1 << 31;
/// `msgt_unused` of `mach_msg_type_t`.
const MSGT_UNUSED_SHIFT: u32 = 24;

/// One `mach_msg_type_t` or `mach_msg_type_long_t` read out of a message
/// body.
#[derive(Clone, Copy, Debug)]
struct MsgType {
    /// The `mach_msg_type_t` bit-field word the flags come from.
    word: u32,
    /// `msgt_name`, or `msgtl_name` in the long form.
    name: c_uint,
    /// `msgt_size`, or `msgtl_size` in the long form.
    size: c_uint,
    /// `msgt_number`, or `msgtl_number` in the long form.
    number: c_uint,
    is_inline: bool,
    longform: bool,
    deallocate: bool,
}

/// `msgt_size` of a short-form descriptor.
const MSGT_SIZE_SHIFT: u32 = 8;
/// `msgt_size` of a short-form descriptor.
const MSGT_SIZE_MASK: u32 = 0x0000_ffff;

impl MsgType {
    /// `msgt_unused` of the descriptor.
    const fn unused(self) -> c_uint {
        (self.word >> MSGT_UNUSED_SHIFT) & 0x1f
    }

    /// The LP64 kernel skips the long-form header check.
    const fn longform_header_bad() -> bool {
        false
    }
}

impl MsgType {
    /// The descriptor's size in bytes: the long form when it is set.
    const fn descriptor_size(self) -> usize {
        if self.longform {
            MSG_TYPE_LONG_SIZE
        } else {
            MSG_TYPE_SIZE
        }
    }

    /// The C's `((number * size) + 7) >> 3`, in the C's `unsigned int`
    /// arithmetic.
    const fn data_length(self) -> usize {
        as_index(self.number.wrapping_mul(self.size).wrapping_add(7) >> 3)
    }

    /// The C's `(((uint64_t) number * size) + 7) >> 3`, assigned to
    /// `vm_size_t`.
    fn data_length_wide(self) -> usize {
        let wide = (u64::from(self.number) * u64::from(self.size) + 7) >> 3;
        wide as usize
    }
}

/// Reads the descriptor at `addr`, flags included.
///
/// # Safety
///
/// `addr` must point at a readable `mach_msg_type_t`, and at a
/// `mach_msg_type_long_t` when its long-form bit is set.
const unsafe fn read_type(addr: usize) -> MsgType {
    let word = unsafe { ptr_at::<u32>(addr).read_unaligned() };
    unsafe { read_type_word(addr, word) }
}

/// Reads the descriptor at `addr` whose first word has already been read.
///
/// # Safety
///
/// `addr` and `word` must together name a readable descriptor, and a
/// long-form descriptor must be readable in full.
const unsafe fn read_type_word(addr: usize, word: u32) -> MsgType {
    let number = unsafe { ptr_at::<u32>(addr + 4).read_unaligned() };
    MsgType {
        word,
        name: word & MSGT_NAME_MASK,
        size: (word >> MSGT_SIZE_SHIFT) & MSGT_SIZE_MASK,
        number,
        is_inline: word & MSGT_INLINE != 0,
        longform: word & MSGT_LONGFORM != 0,
        deallocate: word & MSGT_DEALLOCATE != 0,
    }
}

/// The `msgt_name` assignment of the descriptor at `addr`.
///
/// # Safety
///
/// `addr` must point at a writable descriptor of the given form.
const unsafe fn write_type_name(addr: usize, _longform: bool, name: c_uint) {
    unsafe {
        let word = ptr_at::<u32>(addr).read_unaligned();
        ptr_at::<u32>(addr).write_unaligned(
            (word & !MSGT_NAME_MASK) | (name & MSGT_NAME_MASK),
        );
    }
}

/// The `msgt_size` assignment of the descriptor at `addr`.
///
/// # Safety
///
/// `addr` must point at a writable descriptor of the given form.
const unsafe fn write_type_size(addr: usize, _longform: bool, size: c_uint) {
    unsafe {
        let word = ptr_at::<u32>(addr).read_unaligned();
        ptr_at::<u32>(addr).write_unaligned(
            (word & !(MSGT_SIZE_MASK << MSGT_SIZE_SHIFT))
                | ((size & MSGT_SIZE_MASK) << MSGT_SIZE_SHIFT),
        );
    }
}

/// The `msgt_deallocate` assignment of the descriptor at `addr`.
///
/// # Safety
///
/// `addr` must point at a writable descriptor.
const unsafe fn write_type_deallocate(addr: usize, value: bool) {
    unsafe {
        let word = ptr_at::<u32>(addr).read_unaligned();
        let word = if value {
            word | MSGT_DEALLOCATE
        } else {
            word & !MSGT_DEALLOCATE
        };
        ptr_at::<u32>(addr).write_unaligned(word);
    }
}

impl MachMsgHeader {
    /// The header's disposition and flag bits.
    pub(crate) const fn bits(&self) -> u32 {
        self.bits
    }

    pub(crate) const fn set_bits(&mut self, bits: u32) {
        self.bits = bits;
    }

    /// The message size the header records.
    pub(crate) const fn size(&self) -> u32 {
        self.size
    }

    pub(crate) const fn set_size(&mut self, size: u32) {
        self.size = size;
    }

    /// The remote port field.
    pub(crate) const fn remote(&self) -> usize {
        self.remote_port
    }

    pub(crate) const fn set_remote(&mut self, port: usize) {
        self.remote_port = port;
    }

    /// The local port field.
    pub(crate) const fn local(&self) -> usize {
        self.local_port
    }

    pub(crate) const fn set_local(&mut self, port: usize) {
        self.local_port = port;
    }

    /// The `msgh_protected_payload` union member of `msgh_local_port`.
    const fn set_protected_payload(&mut self, payload: usize) {
        self.local_port = payload;
    }

    /// Sets the header's sequence number.
    pub(crate) const fn set_seqno(&mut self, seqno: u32) {
        self.seqno = seqno;
    }

    /// The message id.
    pub(crate) const fn id(&self) -> c_int {
        self.id
    }

    pub(crate) const fn set_id(&mut self, id: c_int) {
        self.id = id;
    }
}

/// A kernel message buffer.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kmsg(NonNull<IpcKmsg>);

impl Kmsg {
    /// A message from the C side where the caller knows it is live.
    ///
    /// # Safety
    ///
    /// `kmsg` must be a live kernel message.
    pub(crate) const unsafe fn from_raw(kmsg: *mut c_void) -> Self {
        unsafe { Self::from_record(kmsg.cast::<IpcKmsg>()) }
    }

    /// A message the caller has already established live.
    ///
    /// # Safety
    ///
    /// `kmsg` must be a live kernel message.
    const unsafe fn from_record(kmsg: *mut IpcKmsg) -> Self {
        Self(unsafe { NonNull::new_unchecked(kmsg) })
    }

    pub(crate) const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr().cast()
    }

    const fn record(self) -> *mut IpcKmsg {
        self.0.as_ptr()
    }

    /// The message's header, which the body follows.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn header(self) -> *mut MachMsgHeader {
        unsafe { ptr::addr_of_mut!((*self.record()).header) }
    }

    /// The size of the message buffer.
    ///
    /// # Safety
    ///
    /// The message must be live.
    unsafe fn size(self) -> usize {
        unsafe { (*self.record()).size }
    }

    /// Sets the size of the message buffer.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    unsafe fn set_size(self, size: usize) {
        unsafe { (*self.record()).size = size };
    }

    /// The message size the header records.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn header_size(self) -> c_uint {
        unsafe { (*self.header()).size() }
    }

    /// Sets the header's sequence number.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    pub(crate) unsafe fn set_header_seqno(self, seqno: c_uint) {
        unsafe { (*self.header()).seqno = seqno };
    }

    /// The message's msg-accepted request, or null.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn marequest(self) -> *mut c_void {
        unsafe { (*self.record()).marequest }
    }

    /// Sets the message's msg-accepted request.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    pub(crate) unsafe fn set_marequest(self, marequest: *mut c_void) {
        unsafe { (*self.record()).marequest = marequest };
    }

    /// The next message in its queue.
    ///
    /// # Safety
    ///
    /// The message must be live and queued.
    unsafe fn next(self) -> *mut IpcKmsg {
        unsafe { (*self.record()).next.cast() }
    }

    /// Sets the next message in its queue.
    ///
    /// # Safety
    ///
    /// The message must be live and uniquely owned through this call.
    unsafe fn set_next(self, next: *mut IpcKmsg) {
        unsafe { (*self.record()).next = next.cast() };
    }

    /// The previous message in its queue.
    ///
    /// # Safety
    ///
    /// The message must be live and queued.
    unsafe fn prev(self) -> *mut IpcKmsg {
        unsafe { (*self.record()).prev.cast() }
    }

    /// Sets the previous message in its queue.
    ///
    /// # Safety
    ///
    /// The message must be live and uniquely owned through this call.
    unsafe fn set_prev(self, prev: *mut IpcKmsg) {
        unsafe { (*self.record()).prev = prev.cast() };
    }

    /// Clears the remote port of a message whose destination is going away.
    ///
    /// # Safety
    ///
    /// The message must be live, and the destination right it named must
    /// already have been consumed.
    pub(crate) unsafe fn clear_remote(self) {
        unsafe { (*self.header()).set_remote(0) };
    }

    /// `msgh_size` of the message header.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn msgh_size(self) -> u32 {
        unsafe { (*self.header()).size() }
    }

    /// `msgh_bits` of the message header.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn bits(self) -> u32 {
        unsafe { (*self.header()).bits() }
    }

    /// `msgh_remote_port` of the message header.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn remote_port(self) -> usize {
        unsafe { (*self.header()).remote() }
    }

    /// Sets the remote port field.
    ///
    /// # Safety
    ///
    /// The message must be live, and the right it named must already have
    /// been consumed.
    pub(crate) unsafe fn set_remote_port(self, port: usize) {
        unsafe { (*self.header()).set_remote(port) };
    }

    /// Marks the message as one the network pool owns.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    pub(crate) unsafe fn init_network(self) {
        unsafe {
            self.set_size(IKM_SIZE_NETWORK);
            self.set_marequest(ptr::null_mut());
        }
    }
}

/// One cached message per CPU.
///
/// Each CPU touches only the slot `cpu_id()` selects, so the accesses need no
/// ordering against another CPU.
static mut IPC_KMSG_CACHE: [*mut c_void; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// The running CPU's slot in [`IPC_KMSG_CACHE`].
fn cache_slot() -> *mut *mut c_void {
    // SAFETY: `cpu_id()` is below `MAX_NCPUS`, the array's length, so the
    // element the offset reaches is inside the array.
    unsafe {
        ptr::addr_of_mut!(IPC_KMSG_CACHE)
            .cast::<*mut c_void>()
            .add(cpu_id().as_usize())
    }
}

/// Appends `kmsg` to `queue`.
///
/// # Safety
///
/// `queue` must point at a live message queue this caller owns, and `kmsg` at
/// a live message not already queued.
pub(crate) unsafe fn enqueue(queue: *mut IpcKmsgQueue, kmsg: Kmsg) {
    unsafe {
        let record = kmsg.record();
        let first = (*queue).base.cast::<IpcKmsg>();

        if first.is_null() {
            (*queue).base = record.cast();
            kmsg.set_next(record);
            kmsg.set_prev(record);
        } else {
            let last = (*first).prev.cast::<IpcKmsg>();

            kmsg.set_next(first);
            kmsg.set_prev(last);
            (*first).prev = record.cast();
            (*last).next = record.cast();
        }
    }
}

/// Removes `kmsg`, which must be the first message, from `queue`.
///
/// # Safety
///
/// `queue` must hold `kmsg` as its first element.
pub(crate) unsafe fn rmqueue_first(queue: *mut IpcKmsgQueue, kmsg: Kmsg) {
    unsafe {
        let record = kmsg.record();
        let next = (*record).next.cast::<IpcKmsg>();
        if next == record {
            (*queue).base = ptr::null_mut();
        } else {
            let prev = (*record).prev.cast::<IpcKmsg>();
            (*queue).base = next.cast();
            (*next).prev = prev.cast();
            (*prev).next = next.cast();
        }
    }
}

/// Takes the first message off `queue`.
///
/// # Safety
///
/// `queue` must point at a live message queue.
pub(crate) unsafe fn dequeue(queue: *mut IpcKmsgQueue) -> Option<Kmsg> {
    let first = unsafe { (*queue).base.cast::<IpcKmsg>() };
    if first.is_null() {
        return None;
    }

    // SAFETY: `first` is a queued live message.
    unsafe { rmqueue_first(queue, Kmsg::from_record(first)) };

    // SAFETY: `first` was the queue's live head.
    Some(unsafe { Kmsg::from_record(first) })
}

/// Removes `kmsg` from `queue`.
///
/// # Safety
///
/// `queue` must point at a live queue and `kmsg` at a live message in it.
pub(crate) unsafe fn rmqueue(queue: *mut IpcKmsgQueue, kmsg: Kmsg) {
    unsafe {
        let record = kmsg.record();
        let next = kmsg.next();
        let prev = kmsg.prev();

        if next == record {
            (*queue).base = ptr::null_mut();
        } else {
            if (*queue).base.cast::<IpcKmsg>() == record {
                (*queue).base = next.cast();
            }
            (*next).prev = prev.cast();
            (*prev).next = next.cast();
        }
    }
}

/// The message after `kmsg` in `queue`, or `None` at its end.
///
/// # Safety
///
/// `queue` must point at a live queue and `kmsg` at a live message in it.
pub(crate) unsafe fn queue_next(
    queue: *mut IpcKmsgQueue,
    kmsg: Kmsg,
) -> Option<Kmsg> {
    unsafe {
        let next = kmsg.next();
        if (*queue).base.cast::<IpcKmsg>() == next {
            None
        } else {
            Some(Kmsg::from_record(next))
        }
    }
}

/// The `kmem_cache_free`-style release of a raw kernel address.
///
/// # Safety
///
/// A non-null `data` must be a live allocation of `size` bytes from
/// `kalloc()`.
unsafe fn kfree_addr(data: usize, size: usize) {
    let Some(data) = NonNull::new(ptr_at::<u8>(data)) else {
        return;
    };

    unsafe { slab::kfree(data, size) };
}

/// Discards the copy at the raw address `copy`.
///
/// # Safety
///
/// A non-null `copy` must be a live copy the caller owns.
unsafe fn discard_copy(copy: usize) {
    let Some(copy) = NonNull::new(ptr_at::<VmMapCopy>(copy)) else {
        return;
    };

    unsafe { VmMapCopy::discard(copy) };
}

/// Releases every right and buffer the body names between `saddr` and `eaddr`.
///
/// # Safety
///
/// `saddr..eaddr` must be the body of a live message whose rights this call
/// owns.
unsafe fn clean_body(mut saddr: usize, eaddr: usize) {
    while saddr < eaddr {
        let type_ = unsafe { read_type(saddr) };
        let mut number = type_.number;
        let is_port = mach_msg_type_port_any(type_.name);

        saddr = saddr.wrapping_add(type_.descriptor_size());
        if kernel_is_misaligned(type_.descriptor_size()) {
            saddr = kernel_align(saddr);
        }

        let length = type_.data_length();

        if is_port {
            let objects: *mut *mut c_void;
            if type_.is_inline {
                objects = ptr_at(saddr);
                while eaddr
                    < saddr.wrapping_add(
                        as_index(number) * size_of::<*mut c_void>(),
                    )
                {
                    number = number.wrapping_sub(1);
                }
            } else {
                // SAFETY: the descriptor's out-of-line pointer is readable.
                objects =
                    unsafe { ptr_at(ptr_at::<usize>(saddr).read_unaligned()) };
            }

            for i in 0..number {
                // SAFETY: the array holds `number` readable objects.
                let object = unsafe { objects.add(as_index(i)).read() };
                if !io_valid(object) {
                    continue;
                }
                unsafe { ipc_object::destroy_object(object, type_.name) };
            }
        }

        if type_.is_inline {
            saddr = saddr.wrapping_add(length);
        } else {
            // SAFETY: the descriptor's out-of-line pointer is readable.
            let data = unsafe { ptr_at::<usize>(saddr).read_unaligned() };
            if length != 0 {
                if is_port {
                    unsafe { kfree_addr(data, length) };
                } else {
                    unsafe { discard_copy(data) };
                }
            }
            saddr = saddr.wrapping_add(size_of::<usize>());
        }
        saddr = kernel_align(saddr);
    }
}

/// Cleans a partially acquired message body up to the failing descriptor, and,
/// when `dolast`, the `number` rights the descriptor already copied in.
///
/// # Safety
///
/// `kmsg` must be a live message, `eaddr` the failing descriptor's address
/// in its body, and the caller must own every right and buffer before it.
unsafe fn clean_partial(
    kmsg: Kmsg,
    eaddr: usize,
    dolast: bool,
    number: c_uint,
) {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };
    let mut saddr = header.addr() + size_of::<MachMsgHeader>();

    let object = unsafe { (*header).remote() };
    unsafe {
        ipc_object::destroy_object(
            ptr_at(object),
            mach_msg_bits_remote(mbits),
        );
    };

    let object = unsafe { (*header).local() };
    if io_valid(ptr_at(object)) {
        unsafe {
            ipc_object::destroy_object(
                ptr_at(object),
                mach_msg_bits_local(mbits),
            );
        };
    }

    unsafe { clean_body(saddr, eaddr) };

    if !dolast {
        return;
    }

    let type_ = unsafe { read_type(eaddr) };
    let is_port = mach_msg_type_port_any(type_.name);

    saddr = eaddr.wrapping_add(type_.descriptor_size());
    if kernel_is_misaligned(type_.descriptor_size()) {
        saddr = kernel_align(saddr);
    }

    let length = type_.data_length();

    if is_port {
        let objects: *mut *mut c_void = if type_.is_inline {
            ptr_at(saddr)
        } else {
            // SAFETY: the descriptor's out-of-line pointer is readable.
            unsafe { ptr_at(ptr_at::<usize>(saddr).read_unaligned()) }
        };

        for i in 0..number {
            // SAFETY: the array holds `number` readable objects.
            let object = unsafe { objects.add(as_index(i)).read() };
            if !io_valid(object) {
                continue;
            }
            unsafe { ipc_object::destroy_object(object, type_.name) };
        }
    }

    if !type_.is_inline {
        // SAFETY: the descriptor's out-of-line pointer is readable.
        let data = unsafe { ptr_at::<usize>(saddr).read_unaligned() };
        if length != 0 {
            if is_port {
                unsafe { kfree_addr(data, length) };
            } else {
                unsafe { discard_copy(data) };
            }
        }
    }
}

/// Reports a bogus name.
///
/// # Safety
///
/// `header` must point at the live message header being processed.
unsafe fn entry_lookup_failed(header: *mut MachMsgHeader, port_name: c_uint) {
    if !mach_port_name_valid(port_name) {
        return;
    }

    let task = task::current_task().as_ptr();
    // SAFETY: the task is live and its name array is NUL-terminated within
    // the size the format's precision reads.
    let (name_len, task_name) = unsafe {
        (
            size_of_val(&(*task).name),
            CStrArg::from_ptr(ptr::addr_of!((*task).name).cast::<c_char>()),
        )
    };
    let header_id = unsafe { (*header).id() };
    kprint!(
        "task {:.*} looked up a bogus port {} for {}, \
         most probably a bug.\n",
        name_len,
        task_name,
        c_ulong::from(port_name),
        header_id,
    );

    if mach_port::MACH_PORT_DEALLOCATE_DEBUG.load(Ordering::Relaxed) != 0 {
        // SAFETY: the C string literal is NUL-terminated.
        unsafe { soft_debugger(c"ipc_entry_lookup".as_ptr()) };
    }
}

/// Releases every right, reference and buffer the message holds.
///
/// # Safety
///
/// `kmsg` must be a live message whose rights this call owns.
pub(crate) unsafe fn clean(kmsg: Kmsg) {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };

    let marequest = unsafe { kmsg.marequest() };
    if !marequest.is_null() {
        unsafe { ipc_marequest::destroy(marequest.cast::<IpcMarequest>()) };
    }

    let remote = unsafe { (*header).remote() };
    if io_valid(ptr_at(remote)) {
        unsafe {
            ipc_object::destroy_object(
                ptr_at(remote),
                mach_msg_bits_remote(mbits),
            );
        };
    }

    let local = unsafe { (*header).local() };
    if io_valid(ptr_at(local)) {
        unsafe {
            ipc_object::destroy_object(
                ptr_at(local),
                mach_msg_bits_local(mbits),
            );
        };
    }

    if mbits & MACH_MSGH_BITS_COMPLEX != 0 {
        let saddr = header.addr() + size_of::<MachMsgHeader>();
        let eaddr = header.addr() + as_index(unsafe { (*header).size() });

        // SAFETY: a complex message's body belongs to this message.
        unsafe { clean_body(saddr, eaddr) };
    }
}

/// Destroys a message: cleans and frees it, through a per-thread list, so that
/// a destroy nested in the cleanup appends to the list instead of recursing.
///
/// # Safety
///
/// `kmsg` must be a live message whose rights this call owns.
pub(crate) unsafe fn destroy(kmsg: Kmsg) {
    let queue =
        unsafe { ptr::addr_of_mut!((*per_cpu::thread()).ith_messages) };
    // SAFETY: the queue is the live current thread's.
    let empty = unsafe { (*queue).base.is_null() };

    // SAFETY: the queue is live and the message is not queued.
    unsafe { enqueue(queue, kmsg) };

    if empty {
        // The message stays queued while it is cleaned, so a recursive
        // destroy appends to this list instead of starting its own.
        loop {
            // SAFETY: the queue is live and this call holds it.
            let first = unsafe { (*queue).base.cast::<IpcKmsg>() };
            if first.is_null() {
                break;
            }

            // SAFETY: the head is a live queued message.
            let message = unsafe { Kmsg::from_record(first) };
            // SAFETY: the message was queued for destruction, and cleaning
            // leaves it queued.
            unsafe { clean(message) };
            // SAFETY: the message is the queue's head.
            unsafe { rmqueue(queue, message) };
            // SAFETY: the message is clean and unowned.
            unsafe { free(message) };
        }
    }
}

/// Frees a message of any variety.
///
/// # Safety
///
/// `kmsg` must be a live message whose storage this call owns.
pub(crate) unsafe fn ikm_free(kmsg: Kmsg) {
    let size = unsafe { kmsg.size() };

    // The size is tested as a truncated 32-bit signed value, so a size with
    // the top half-word set takes the `free` path.
    if (size as u32) as i32 > 0 {
        unsafe {
            slab::kfree(
                NonNull::new_unchecked(kmsg.as_ptr().cast::<u8>()),
                size,
            );
        };
    } else {
        unsafe { free(kmsg) };
    }
}

/// Frees a message: to the network pool when the pool owns it, to the
/// allocator otherwise.
///
/// # Safety
///
/// `kmsg` must be a live message whose storage this call owns.
pub(crate) unsafe fn free(kmsg: Kmsg) {
    let size = unsafe { kmsg.size() };
    if size == IKM_SIZE_NETWORK {
        // SAFETY: the network code owns this message's storage.
        unsafe { crate::device::net_io::kmsg_put(kmsg.as_ptr()) };
    } else {
        unsafe {
            slab::kfree(
                NonNull::new_unchecked(kmsg.as_ptr().cast::<u8>()),
                size,
            );
        };
    }
}

/// Allocates a message buffer for a `size`-byte message.
pub(crate) fn ikm_alloc(size: usize) -> Option<Kmsg> {
    let buf = slab::kalloc(size.wrapping_add(IKM_OVERHEAD))?;
    Some(Kmsg(buf.cast::<IpcKmsg>()))
}

/// Initializes the buffer fields of a message of `size` bytes.
///
/// # Safety
///
/// `kmsg` must be a live, freshly allocated message this call owns.
pub(crate) unsafe fn ikm_init(kmsg: Kmsg, size: usize) {
    unsafe {
        kmsg.set_size(size.wrapping_add(IKM_OVERHEAD));
        kmsg.set_marequest(ptr::null_mut());
    }
}

/// `ikm_alloc()` followed by `ikm_init()`: a fresh message for a caller that
/// builds its own header, as the notification senders do.
///
/// # Safety
///
/// The caller permits an allocation; the result, when `Some`, is a live
/// message this call owns.
pub(crate) unsafe fn alloc(size: usize) -> Option<Kmsg> {
    let kmsg = ikm_alloc(size)?;
    // SAFETY: the message is fresh and owned by this call.
    unsafe { ikm_init(kmsg, size) };
    Some(kmsg)
}

/// Allocates a page-sized message, from this CPU's cache slot when it holds
/// one.
pub(crate) fn cache_alloc() -> Option<Kmsg> {
    let slot = cache_slot();

    // SAFETY: the slot belongs to the running CPU, and a non-null slot holds
    // the live cached message.
    let cached = unsafe { *slot };
    if !cached.is_null() {
        // SAFETY: this call took the live message and empties the slot.
        unsafe { *slot = ptr::null_mut() };
        // SAFETY: the cached message is live.
        return Some(unsafe { Kmsg::from_raw(cached) });
    }

    let kmsg = ikm_alloc(IKM_SAVED_MSG_SIZE)?;
    // SAFETY: the message is fresh and owned by this call.
    unsafe { ikm_init(kmsg, IKM_SAVED_MSG_SIZE) };
    Some(kmsg)
}

/// Caches a page-sized message, or frees anything else.
///
/// # Safety
///
/// `kmsg` must be a live message whose storage this call owns.
pub(crate) unsafe fn cache_free(kmsg: Kmsg) {
    let slot = cache_slot();

    let size = unsafe { kmsg.size() };
    // SAFETY: the slot belongs to the running CPU.
    let empty = unsafe { (*slot).is_null() };

    if size == PAGE_SIZE && empty {
        // SAFETY: the slot is empty and takes ownership of the message.
        unsafe { *slot = kmsg.as_ptr() };
    } else {
        unsafe { ikm_free(kmsg) };
    }
}

/// Caches the message when the running CPU's slot is empty; the caller keeps
/// it otherwise.
///
/// # Safety
///
/// `kmsg` must be a live message whose storage this call owns.
pub(crate) unsafe fn cache_free_try(kmsg: Kmsg) -> bool {
    let slot = cache_slot();

    // SAFETY: the slot belongs to the running CPU.
    let empty = unsafe { (*slot).is_null() };
    if empty {
        // SAFETY: the slot is empty and takes ownership of the message.
        unsafe { *slot = kmsg.as_ptr() };
    }
    empty
}

/// Copies a user message of `size` bytes into a new kernel message.
///
/// # Safety
///
/// `user` must name a readable user message of `size` bytes, and the caller
/// permits an allocation.
pub(crate) unsafe fn get(
    user: *const c_void,
    size: c_uint,
) -> Result<Kmsg, SendError> {
    let ksize = size.wrapping_mul(IKM_EXPAND_FACTOR);

    if as_index(size) < MACH_MSG_HEADER_SIZE
        || user_is_misaligned(as_index(size))
    {
        return Err(SendError::MsgTooSmall);
    }

    let kmsg = if as_index(ksize) <= IKM_SAVED_MSG_SIZE {
        cache_alloc().ok_or(SendError::NoBuffer)?
    } else {
        let kmsg = ikm_alloc(as_index(ksize)).ok_or(SendError::NoBuffer)?;
        // SAFETY: the message is fresh and owned by this call.
        unsafe { ikm_init(kmsg, as_index(ksize)) };
        kmsg
    };

    let failed =
        unsafe { copy_user::copy_in(user, kmsg.header(), as_index(size)) }
            .is_err();

    if failed {
        // SAFETY: this call owns the fresh message.
        unsafe { ikm_free(kmsg) };
        return Err(SendError::InvalidData);
    }

    Ok(kmsg)
}

/// Copies a kernel message of `size` bytes into a new kernel message.
///
/// # Safety
///
/// `msg` must name a readable kernel message of `size` bytes, and the caller
/// permits an allocation.
pub(crate) unsafe fn get_from_kernel(
    msg: *const c_void,
    size: c_uint,
) -> Result<Kmsg, SendError> {
    let kmsg = ikm_alloc(as_index(size)).ok_or(SendError::NoBuffer)?;
    // SAFETY: the message is fresh and owned by this call.
    unsafe { ikm_init(kmsg, as_index(size)) };

    unsafe {
        ptr::copy_nonoverlapping(
            msg,
            kmsg.header().cast::<c_void>(),
            as_index(size),
        );
    };

    // SAFETY: the message is live and owned by this call.
    unsafe { (*kmsg.header()).set_size(size) };

    Ok(kmsg)
}

/// Copies a kernel message of `size` bytes out to the user buffer and frees
/// it.
///
/// # Safety
///
/// `user` must name a writable user message of `size` bytes, and `kmsg` must
/// be a live message whose clean header this call owns.
pub(crate) unsafe fn put(
    user: *mut c_void,
    kmsg: Kmsg,
    size: c_uint,
) -> Result<(), ReceiveError> {
    let copied = unsafe {
        user_access::copyout(kmsg.header().cast(), user, as_index(size))
    }
    .map_err(|_| ReceiveError::InvalidData);

    unsafe { cache_free(kmsg) };

    copied
}

/// `MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)`: an asynchronous send.
const BITS_ASYNC: u32 = mach_msg_bits(MACH_MSG_TYPE_COPY_SEND, 0);
/// `MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE)`:
/// a request message.
const BITS_REQUEST: u32 =
    mach_msg_bits(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
/// `MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0)`: a reply message.
const BITS_REPLY: u32 = mach_msg_bits(MACH_MSG_TYPE_PORT_SEND_ONCE, 0);

/// Translates the port names of a message header in `space` into kernel ports.
///
/// # Safety
///
/// `header` must point at a live message header, `space` must be a live
/// space, and nothing may be locked.
pub(crate) unsafe fn copyin_header(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    notify: c_uint,
) -> Result<(), SendError> {
    let mbits = unsafe { (*header).bits() } & !MACH_MSGH_BITS_CIRCULAR;
    // The C truncates the pointer-wide union fields into names; the 64-bit
    // user message already carries only the low half.
    let dest_name = unsafe { (*header).remote() as c_uint };
    let reply_name = unsafe { (*header).local() as c_uint };

    let handled = notify == MACH_PORT_NAME_NULL
        && unsafe {
            copyin_header_fast(header, space, mbits, dest_name, reply_name)
        };
    if handled {
        return Ok(());
    }

    let dest_type = mach_msg_bits_remote(mbits);
    let reply_type = mach_msg_bits_local(mbits);

    let notify_port = unsafe {
        copyin_header_notify(
            header, space, notify, reply_name, dest_type, reply_type,
        )
    }?;

    let rights = if dest_name == reply_name {
        unsafe {
            copyin_header_same_name(
                space, header, dest_name, dest_type, reply_type,
            )
        }
    } else if !mach_port_name_valid(reply_name) {
        unsafe {
            copyin_header_bad_reply(
                space, header, dest_name, reply_name, dest_type,
            )
        }
    } else {
        unsafe {
            copyin_header_distinct(
                space, header, dest_name, reply_name, dest_type, reply_type,
            )
        }
    };
    let mut rights = rights?;

    if notify != MACH_PORT_NAME_NULL && rights.dest_soright == notify_port {
        // SAFETY: the send-once right is the notify port's and nothing else
        // owns it.
        unsafe {
            ipc_port::release_sonce(IpcPort::from_raw(rights.dest_soright));
        };
        rights.dest_soright = ptr::null_mut();
    }

    // SAFETY: the space is still write-locked.
    unsafe { space.unlock_write() };

    if !rights.dest_soright.is_null() {
        // SAFETY: the copy-in left the send-once right unused.
        unsafe { ipc_notify::port_deleted(rights.dest_soright, dest_name) };
    }
    if !rights.reply_soright.is_null() {
        // SAFETY: the copy-in left the send-once right unused.
        unsafe { ipc_notify::port_deleted(rights.reply_soright, reply_name) };
    }

    let dest_type = ipc_object::copyin_type(dest_type);
    let reply_type = ipc_object::copyin_type(reply_type);

    unsafe {
        (*header).set_bits(
            mach_msg_bits_other(mbits) | mach_msg_bits(dest_type, reply_type),
        );
        (*header).set_remote(rights.dest_port.addr());
        (*header).set_local(rights.reply_port.addr());
    }

    Ok(())
}

/// The destination and reply rights [`copyin_header()`] resolves.
struct HeaderRights {
    /// The destination port, or a dead name.
    dest_port: *mut c_void,
    /// The reply port, or a dead name.
    reply_port: *mut c_void,
    /// The destination's send-once right, if one was made.
    dest_soright: *mut c_void,
    /// The reply's send-once right, if one was made.
    reply_soright: *mut c_void,
}

impl HeaderRights {
    /// No rights resolved yet.
    const fn none() -> Self {
        Self {
            dest_port: ptr::null_mut(),
            reply_port: ptr::null_mut(),
            dest_soright: ptr::null_mut(),
            reply_soright: ptr::null_mut(),
        }
    }
}

/// Dispatch the fast paths of [`copyin_header()`].
///
/// Returns `true` when the header was rewritten and the caller must return
/// success, `false` when the slow path must run.
///
/// # Safety
///
/// The same contract as [`copyin_header()`]: `header` must point at a live
/// message header, `space` must be a live space, and nothing may be locked.
unsafe fn copyin_header_fast(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest_name: c_uint,
    reply_name: c_uint,
) -> bool {
    match mach_msg_bits_ports(mbits) {
        BITS_ASYNC => unsafe {
            copyin_header_async(header, space, mbits, dest_name, reply_name)
        },
        BITS_REQUEST => unsafe {
            copyin_header_request(header, space, mbits, dest_name, reply_name)
        },
        BITS_REPLY => unsafe {
            copyin_header_reply(header, space, mbits, dest_name, reply_name)
        },
        _ => false,
    }
}

/// The `BITS_ASYNC` fast path of [`copyin_header()`].
///
/// # Safety
///
/// The same contract as [`copyin_header()`].
unsafe fn copyin_header_async(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest_name: c_uint,
    reply_name: c_uint,
) -> bool {
    if reply_name != MACH_PORT_NAME_NULL {
        return false;
    }

    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_read() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    }

    // SAFETY: the space is live, active, and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    }

    // SAFETY: a send entry names a live port.
    let dest_port = unsafe { IpcPort::from_raw((*entry).object()) };
    // SAFETY: the port is live and its lock is free.
    unsafe { dest_port.lock() };
    // SAFETY: the space lock is held.
    unsafe { space.unlock_read() };

    // SAFETY: the port is live and locked.
    if !unsafe { dest_port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { dest_port.unlock() };
        return false;
    }

    // SAFETY: the port is live, locked, and active.
    unsafe {
        dest_port.increment_srights();
        dest_port.increment_references();
        dest_port.unlock();
        (*header).set_bits(
            mach_msg_bits_other(mbits)
                | mach_msg_bits(MACH_MSG_TYPE_PORT_SEND, 0),
        );
        (*header).set_remote(dest_port.as_ptr().addr());
    }
    true
}

/// The `BITS_REQUEST` fast path of [`copyin_header()`].
///
/// # Safety
///
/// The same contract as [`copyin_header()`].
unsafe fn copyin_header_request(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest_name: c_uint,
    reply_name: c_uint,
) -> bool {
    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_read() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    }

    // SAFETY: the space is live, active, and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    }
    // SAFETY: a send entry names a live port.
    let dest_port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is live, active, and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(reply_name) }) else {
        unsafe { entry_lookup_failed(header, reply_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_RECEIVE {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    }
    // SAFETY: a receive entry names a live port.
    let reply_port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: both ports are live and their locks are free.
    unsafe { dest_port.lock() };
    // SAFETY: the ports are live and this call holds the destination's lock.
    if !unsafe { dest_port.is_active() }
        // SAFETY: both ports are live and their locks are free.
        || !unsafe { reply_port.try_lock() }
    {
        // SAFETY: the destination lock is held.
        unsafe { dest_port.unlock() };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return false;
    }
    // SAFETY: the space lock is held.
    unsafe { space.unlock_read() };

    // SAFETY: both ports are live, locked, and active.
    unsafe {
        dest_port.increment_srights();
        dest_port.increment_references();
        dest_port.unlock();

        reply_port.increment_sorights();
        reply_port.increment_references();
        reply_port.unlock();

        (*header).set_bits(
            mach_msg_bits_other(mbits)
                | mach_msg_bits(
                    MACH_MSG_TYPE_PORT_SEND,
                    MACH_MSG_TYPE_PORT_SEND_ONCE,
                ),
        );
        (*header).set_remote(dest_port.as_ptr().addr());
        (*header).set_local(reply_port.as_ptr().addr());
    }
    true
}

/// The `BITS_REPLY` fast path of [`copyin_header()`].
///
/// # Safety
///
/// The same contract as [`copyin_header()`].
unsafe fn copyin_header_reply(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest_name: c_uint,
    reply_name: c_uint,
) -> bool {
    if reply_name != MACH_PORT_NAME_NULL {
        return false;
    }

    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_write() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return false;
    }

    // SAFETY: the space is live, active, and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND_ONCE
        // SAFETY: the entry is live and the space is locked.
        || unsafe { (*entry).request() } != 0
    {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return false;
    }
    // SAFETY: a send-once entry names a live port.
    let dest_port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the port is live and its lock is free.
    unsafe { dest_port.lock() };
    // SAFETY: the port lock is held.
    if !unsafe { dest_port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { dest_port.unlock() };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return false;
    }
    // SAFETY: the port lock is held.
    unsafe { dest_port.unlock() };

    // SAFETY: the entry is live and the space is locked.
    unsafe {
        (*entry).set_object(ptr::null_mut());
        ipc_entry::dealloc(space, dest_name, entry);
        space.unlock_write();

        (*header).set_bits(
            mach_msg_bits_other(mbits)
                | mach_msg_bits(MACH_MSG_TYPE_PORT_SEND_ONCE, 0),
        );
        (*header).set_remote(dest_port.as_ptr().addr());
    }
    true
}

/// Validate the destination and reply types of [`copyin_header()`] and
/// resolve its notify port.
///
/// On success the space is write-locked; on failure nothing is locked.
///
/// # Safety
///
/// The same contract as [`copyin_header()`]: `header` must point at a live
/// message header, `space` must be a live space, and nothing may be locked.
unsafe fn copyin_header_notify(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    notify: c_uint,
    reply_name: c_uint,
    dest_type: u32,
    reply_type: u32,
) -> Result<*mut c_void, SendError> {
    if !mach_msg_type_port_any_send(dest_type) {
        return Err(SendError::InvalidHeader);
    }

    if if reply_type == 0 {
        reply_name != MACH_PORT_NAME_NULL
    } else {
        !mach_msg_type_port_any_send(reply_type)
    } {
        return Err(SendError::InvalidHeader);
    }

    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_write() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    }

    let mut notify_port: *mut c_void = ptr::null_mut();

    if notify != MACH_PORT_NAME_NULL {
        // SAFETY: the space is live, active, and write-locked.
        let entry = unsafe { space.entry_lookup(notify) };
        match entry {
            Some(entry)
                // SAFETY: the entry is live and the space is locked.
                if unsafe { (*entry).bits() } & MACH_PORT_TYPE_RECEIVE
                    != 0 =>
            {
                // SAFETY: the receive entry names a live port.
                notify_port = unsafe { (*entry).object() };
            }
            Some(_) => {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write() };
                return Err(SendError::InvalidNotify);
            }
            None => {
                unsafe { entry_lookup_failed(header, notify) };
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write() };
                return Err(SendError::InvalidNotify);
            }
        }
    }

    Ok(notify_port)
}

/// The `dest_name == reply_name` branch of [`copyin_header()`].
///
/// On success the space stays write-locked and the rights are returned; on
/// failure the helper has unlocked the space.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `header` must point
/// at a live message header.
unsafe fn copyin_header_same_name(
    space: IpcSpace,
    header: *mut MachMsgHeader,
    name: c_uint,
    dest_type: u32,
    reply_type: u32,
) -> Result<HeaderRights, SendError> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is live, active, and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup(name) }) else {
        unsafe { entry_lookup_failed(header, name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    };

    // SAFETY: the entry is live.
    if !unsafe { ipc_right::copyin_check(entry, reply_type) } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidReply);
    }

    if dest_type == MACH_MSG_TYPE_PORT_SEND_ONCE
        || reply_type == MACH_MSG_TYPE_PORT_SEND_ONCE
    {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    } else if dest_type == MACH_MSG_TYPE_MAKE_SEND
        || dest_type == MACH_MSG_TYPE_MAKE_SEND_ONCE
        || reply_type == MACH_MSG_TYPE_MAKE_SEND
        || reply_type == MACH_MSG_TYPE_MAKE_SEND_ONCE
    {
        // SAFETY: the space is write-locked and the entry is live.
        let Ok((object, soright)) = (unsafe {
            ipc_right::copyin(space, name, entry, dest_type, false)
        }) else {
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write() };
            return Err(SendError::InvalidDest);
        };
        rights.dest_port = object;
        rights.dest_soright = soright;

        // SAFETY: the space is write-locked and the entry is live.
        // The C ignores this result; `copyin_check` above makes it a
        // success.
        let copied =
            unsafe { ipc_right::copyin(space, name, entry, reply_type, true) };
        if let Ok((object, soright)) = copied {
            rights.reply_port = object;
            rights.reply_soright = soright;
        }
    } else if dest_type == MACH_MSG_TYPE_COPY_SEND
        && reply_type == MACH_MSG_TYPE_COPY_SEND
    {
        // SAFETY: the space is write-locked and the entry is live.
        let Ok((object, soright)) = (unsafe {
            ipc_right::copyin(space, name, entry, dest_type, false)
        }) else {
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write() };
            return Err(SendError::InvalidDest);
        };
        rights.dest_port = object;
        rights.dest_soright = soright;

        // SAFETY: the copy-in returned a live port.
        rights.reply_port = unsafe { ipc_port::copy_send(rights.dest_port) };
        rights.reply_soright = ptr::null_mut();
    } else if dest_type == MACH_MSG_TYPE_PORT_SEND
        && reply_type == MACH_MSG_TYPE_PORT_SEND
    {
        // SAFETY: the space is write-locked and the entry is live.
        let Ok((object, soright)) =
            (unsafe { ipc_right::copyin_two(space, name, entry) })
        else {
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write() };
            return Err(SendError::InvalidDest);
        };
        rights.dest_port = object;
        rights.dest_soright = soright;

        // SAFETY: the entry is live and the space is write-locked.
        if unsafe { (*entry).bits() } & IE_BITS_TYPE_MASK == 0 {
            // SAFETY: the space lock is held.
            unsafe { ipc_entry::dealloc(space, name, entry) };
        }

        rights.reply_port = rights.dest_port;
        rights.reply_soright = ptr::null_mut();
    } else {
        // SAFETY: the space is write-locked and the entry is live.
        return unsafe {
            copyin_header_same_mixed(space, name, entry, dest_type)
        };
    }

    Ok(rights)
}

/// The mixed send-right branch of [`copyin_header_same_name()`].
///
/// On success the space stays write-locked and the rights are returned; on
/// failure the helper has unlocked the space.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live
/// entry of it.
unsafe fn copyin_header_same_mixed(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    dest_type: u32,
) -> Result<HeaderRights, SendError> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is write-locked and the entry is live.
    let Ok((object, soright)) = (unsafe {
        ipc_right::copyin(space, name, entry, MACH_MSG_TYPE_PORT_SEND, false)
    }) else {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    };
    rights.dest_port = object;

    // SAFETY: the entry is live and the space is write-locked.
    if unsafe { (*entry).bits() } & IE_BITS_TYPE_MASK == 0 {
        // SAFETY: the space lock is held.
        unsafe { ipc_entry::dealloc(space, name, entry) };
    }

    // SAFETY: the copy-in returned a live port.
    rights.reply_port = unsafe { ipc_port::copy_send(rights.dest_port) };

    if dest_type == MACH_MSG_TYPE_PORT_SEND {
        rights.dest_soright = soright;
        rights.reply_soright = ptr::null_mut();
    } else {
        rights.dest_soright = ptr::null_mut();
        rights.reply_soright = soright;
    }

    Ok(rights)
}

/// The invalid-reply-name branch of [`copyin_header()`].
///
/// On success the space stays write-locked and the rights are returned; on
/// failure the helper has unlocked the space.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `header` must point
/// at a live message header.
unsafe fn copyin_header_bad_reply(
    space: IpcSpace,
    header: *mut MachMsgHeader,
    dest_name: c_uint,
    reply_name: c_uint,
    dest_type: u32,
) -> Result<HeaderRights, SendError> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is live, active, and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    };

    // SAFETY: the space is write-locked and the entry is live.
    let Ok((object, soright)) = (unsafe {
        ipc_right::copyin(space, dest_name, entry, dest_type, false)
    }) else {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    };
    rights.dest_port = object;
    rights.dest_soright = soright;

    // SAFETY: the entry is live and the space is write-locked.
    if unsafe { (*entry).bits() } & IE_BITS_TYPE_MASK == 0 {
        // SAFETY: the space lock is held.
        unsafe { ipc_entry::dealloc(space, dest_name, entry) };
    }

    // SAFETY: this branch is reached only because the name is null or dead.
    rights.reply_port = unsafe { ipc_port::invalid_name_to_port(reply_name) };
    rights.reply_soright = ptr::null_mut();

    Ok(rights)
}

/// The distinct destination and reply names branch of [`copyin_header()`].
///
/// On success the space stays write-locked and the rights are returned; on
/// failure the helper has unlocked the space.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `header` must point
/// at a live message header.
unsafe fn copyin_header_distinct(
    space: IpcSpace,
    header: *mut MachMsgHeader,
    dest_name: c_uint,
    reply_name: c_uint,
    dest_type: u32,
    reply_type: u32,
) -> Result<HeaderRights, SendError> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is live, active, and write-locked.
    let Some(dest_entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    };

    // SAFETY: the space is live, active, and write-locked.
    let Some(reply_entry) = (unsafe { space.entry_lookup(reply_name) }) else {
        unsafe { entry_lookup_failed(header, reply_name) };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidReply);
    };

    // SAFETY: the entry is live.
    if !unsafe { ipc_right::copyin_check(reply_entry, reply_type) } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidReply);
    }

    // SAFETY: the space is write-locked and the entry is live.
    let Ok((object, soright)) = (unsafe {
        ipc_right::copyin(space, dest_name, dest_entry, dest_type, false)
    }) else {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return Err(SendError::InvalidDest);
    };
    rights.dest_port = object;
    rights.dest_soright = soright;

    // SAFETY: the entry is live and the space is write-locked.
    let saved_reply = unsafe { (*reply_entry).object() };
    if !saved_reply.is_null() {
        // SAFETY: the entry holds a live object and the space is locked, so
        // the object cannot die.
        unsafe { ipc_object::reference(saved_reply) };
    }

    // SAFETY: the space is write-locked and the entry is live.
    // The C ignores this result; `copyin_check` above makes it a success.
    if let Ok((object, soright)) = unsafe {
        ipc_right::copyin(space, reply_name, reply_entry, reply_type, true)
    } {
        rights.reply_port = object;
        rights.reply_soright = soright;
    }

    if !saved_reply.is_null() && rights.reply_port == IO_DEAD {
        // SAFETY: the copy-in returned a live destination port.
        let dest = unsafe { IpcPort::from_raw(rights.dest_port) };
        // SAFETY: the entry holds the live saved reply.
        let saved = unsafe { IpcPort::from_raw(saved_reply) };

        // SAFETY: the ports are live and their locks are free.
        let timestamp = unsafe {
            saved.lock();
            let timestamp = saved.timestamp();
            saved.unlock();
            timestamp
        };

        // SAFETY: the destination is live and unlocked.
        let must_undo = unsafe {
            dest.lock();
            let must_undo = !dest.is_active()
                && timestamp_order(dest.timestamp(), timestamp);
            dest.unlock();
            must_undo
        };

        if must_undo {
            // SAFETY: the space is write-locked, the entries live, and the
            // copy-ins are those this call just made.
            unsafe {
                ipc_right::copyin_undo(
                    space,
                    dest_name,
                    dest_entry,
                    dest_type,
                    rights.dest_port,
                    NonNull::new(rights.dest_soright),
                );
                ipc_right::copyin_undo(
                    space,
                    reply_name,
                    reply_entry,
                    reply_type,
                    rights.reply_port,
                    NonNull::new(rights.reply_soright),
                );
                space.unlock_write();

                if !rights.dest_soright.is_null() {
                    ipc_notify::dead_name(rights.dest_soright, dest_name);
                }
                ipc_object::release(saved_reply);
            }
            return Err(SendError::InvalidDest);
        }
    }

    // SAFETY: the entries are live and the space is write-locked.
    if unsafe { (*reply_entry).bits() } & IE_BITS_TYPE_MASK == 0 {
        // SAFETY: the space lock is held.
        unsafe { ipc_entry::dealloc(space, reply_name, reply_entry) };
    }
    if unsafe { (*dest_entry).bits() } & IE_BITS_TYPE_MASK == 0 {
        // SAFETY: the space lock is held.
        unsafe { ipc_entry::dealloc(space, dest_name, dest_entry) };
    }

    if !saved_reply.is_null() {
        // SAFETY: this releases the reference taken above.
        unsafe { ipc_object::release(saved_reply) };
    }

    Ok(rights)
}

const _: () = assert!(!kernel_is_misaligned(size_of::<MachMsgHeader>()));

/// Copies one user port name into a kernel port.
///
/// # Safety
///
/// `src` must name a readable user name and `dst` a writable kernel port.
unsafe fn copyin_port(src: usize, dst: usize) -> Result<(), UserFault> {
    let mut name: u32 = 0;
    unsafe {
        user_access::copyin(
            ptr_at(src),
            ptr::from_mut(&mut name).cast::<c_void>(),
            size_of::<u32>(),
        )
    }?;
    unsafe { ptr_at::<usize>(dst).write_unaligned(as_index(name)) };
    Ok(())
}

/// Copies one kernel port into a user port name.
///
/// # Safety
///
/// `src` must name a readable kernel port and `dst` a writable user name.
unsafe fn copyout_port(src: usize, dst: usize) -> Result<(), UserFault> {
    let name = unsafe { ptr_at::<usize>(src).read_unaligned() };
    // The C truncates the pointer-wide kernel port into the user name.
    let name = name as u32;
    unsafe {
        user_access::copyout(
            ptr::from_ref(&name).cast::<c_void>(),
            ptr_at(dst),
            size_of::<u32>(),
        )
    }
}

/// Acquire the out-of-line payload of one body descriptor, copying a port
/// name array or mapping user memory.
///
/// # Safety
///
/// `kmsg` must be live and owned by the caller, `map` the live map the
/// message came from, `addr` the readable user payload of `length` bytes,
/// and the caller permits an allocation.
unsafe fn copyin_body_payload(
    kmsg: Kmsg,
    map: &mut VmMap,
    taddr: usize,
    addr: usize,
    type_: MsgType,
    use_page_lists: bool,
    steal_pages: bool,
) -> Result<*mut c_void, SendError> {
    let length = type_.data_length_wide();
    let is_port = mach_msg_type_port_any(type_.name);
    let deallocate = type_.deallocate;
    let data: *mut c_void;
    if is_port {
        let user_length = length;
        let kernel_length = if size_of::<c_uint>() == size_of::<usize>() {
            length
        } else {
            // SAFETY: the descriptor is writable.
            unsafe {
                write_type_size(taddr, type_.longform, PORT_T_SIZE_IN_BITS);
            };
            size_of::<usize>() * as_index(type_.number)
        };

        if kernel_length == 0 {
            data = ptr::null_mut();
        } else {
            let Some(buf) = slab::kalloc(kernel_length) else {
                unsafe { clean_partial(kmsg, taddr, false, 0) };
                return Err(SendError::InvalidMemory);
            };
            data = buf.as_ptr().cast::<c_void>();

            let mut copy_failed = false;
            if user_length != kernel_length {
                for i in 0..type_.number {
                    let offset = as_index(i);
                    // SAFETY: each user name is readable and each kernel
                    // slot is writable.
                    if unsafe {
                        copyin_port(
                            addr + offset * size_of::<c_uint>(),
                            data.addr() + offset * size_of::<usize>(),
                        )
                    }
                    .is_err()
                    {
                        copy_failed = true;
                        break;
                    }
                }
            // SAFETY: `data` and the user body are `kernel_length` bytes.
            } else if unsafe {
                crate::vm::vm_kern::copyinmap(
                    map,
                    ptr_at::<c_char>(addr),
                    data.cast::<c_char>(),
                    kernel_length as c_int,
                )
            }
            .is_err()
            {
                copy_failed = true;
            }

            if !copy_failed
                && deallocate
                && vm_user::deallocate(map, addr, user_length).is_err()
            {
                copy_failed = true;
            }

            if copy_failed {
                // SAFETY: the fresh buffer is owned by this call.
                unsafe { kfree_addr(data.addr(), kernel_length) };
                unsafe { clean_partial(kmsg, taddr, false, 0) };
                return Err(SendError::InvalidMemory);
            }
        }
    } else if length == 0 {
        data = ptr::null_mut();
    } else {
        let copy = if use_page_lists {
            map.copyin_page_list(addr, length, deallocate, steal_pages, false)
                .map(|copy| {
                    copy.map_or(ptr::null_mut(), |copy| {
                        copy.as_ptr().cast::<c_void>()
                    })
                })
        } else {
            map.copyin(addr, length, deallocate)
                .map(|copy| copy.as_ptr().cast::<c_void>())
        };

        if let Ok(copy) = copy {
            data = copy;
        } else {
            unsafe { clean_partial(kmsg, taddr, false, 0) };
            return Err(SendError::InvalidMemory);
        }
    }

    Ok(data)
}

/// Rewrite the port names of one body descriptor into kernel objects.
///
/// # Safety
///
/// `kmsg` must be live and owned by the caller, `header` live, `space` live
/// and unlocked, `data` the writable kernel slot array, `dest` the message's
/// live destination, and `taddr` the descriptor's readable address.
unsafe fn copyin_body_ports(
    kmsg: Kmsg,
    header: *mut MachMsgHeader,
    space: IpcSpace,
    data: *mut c_void,
    type_: MsgType,
    taddr: usize,
    dest: *mut c_void,
) -> Result<(), SendError> {
    let newname = ipc_object::copyin_type(type_.name);
    // SAFETY: the descriptor is writable.
    unsafe { write_type_name(taddr, type_.longform, newname) };

    let slots = data.cast::<*mut c_void>();
    for i in 0..type_.number {
        let index = as_index(i);
        // SAFETY: the slot holds one kernel port or a widened name.  The C
        // reads the pointer-sized `mach_port_t` slot and truncates it into
        // the name.
        let port = unsafe { slots.add(index).read() }.addr() as c_uint;

        if !mach_port_name_valid(port) {
            // SAFETY: the name is null or dead.
            let object = unsafe { ipc_port::invalid_name_to_port(port) };
            unsafe { slots.add(index).write(object) };
            continue;
        }

        // SAFETY: the space is live and unlocked; success returns a live
        // object holding a reference.
        let copied = unsafe { ipc_object::copyin(space, port, type_.name) };
        if let Ok(object) = copied {
            if newname == MACH_MSG_TYPE_PORT_RECEIVE {
                // SAFETY: the copy-in returned a live port.
                let object_port = unsafe { IpcPort::from_raw(object) };
                // SAFETY: the port is live and no port lock is held.
                if unsafe { ipc_port::check_circularity(object_port, dest) } {
                    // SAFETY: the message is live and owned by this call.
                    unsafe {
                        (*header).set_bits(
                            (*header).bits() | MACH_MSGH_BITS_CIRCULAR,
                        );
                    };
                }
            }
            unsafe { slots.add(index).write(object) };
        } else {
            // SAFETY: the failing right index bounds the rights copied in
            // so far.
            unsafe { clean_partial(kmsg, taddr, true, i) };
            return Err(SendError::InvalidRight);
        }
    }

    Ok(())
}

/// Translates the rights and out-of-line memory of a message body in `space`
/// and `map`.
///
/// # Safety
///
/// `kmsg` must be a live message whose header names a live destination port
/// and was successfully copied in, `space` must be live and unlocked, and
/// `map` must be the live map the message came from.
unsafe fn copyin_body(
    kmsg: Kmsg,
    space: IpcSpace,
    map: &mut VmMap,
) -> Result<(), SendError> {
    let header = unsafe { kmsg.header() };
    let dest = ptr_at::<c_void>(unsafe { (*header).remote() });
    let dest_port = unsafe { IpcPort::from_raw(dest) };
    let use_page_lists = kobject_vm_page_list(unsafe { dest_port.kotype() });
    let steal_pages = kobject_vm_page_steal(unsafe { dest_port.kotype() });

    let mut saddr = header.addr() + size_of::<MachMsgHeader>();
    let eaddr = header.addr() + as_index(unsafe { (*header).size() });
    let mut complex = false;

    while saddr < eaddr {
        let taddr = saddr;
        let remaining = eaddr.wrapping_sub(saddr);

        if remaining < MSG_TYPE_SIZE {
            unsafe { clean_partial(kmsg, taddr, false, 0) };
            return Err(SendError::MsgTooSmall);
        }

        // SAFETY: the descriptor's first word is readable.
        let word = unsafe { ptr_at::<u32>(taddr).read_unaligned() };
        if word & MSGT_LONGFORM != 0 && remaining < MSG_TYPE_LONG_SIZE {
            unsafe { clean_partial(kmsg, taddr, false, 0) };
            return Err(SendError::MsgTooSmall);
        }

        // SAFETY: the descriptor is readable in full.
        let type_ = unsafe { read_type_word(taddr, word) };
        let is_port = mach_msg_type_port_any(type_.name);
        let deallocate = type_.deallocate;

        if (type_.size != PORT_T_SIZE_IN_BITS || !type_.is_inline)
            && (type_.size != PORT_NAME_T_SIZE_IN_BITS || type_.is_inline)
            && is_port
            || MsgType::longform_header_bad()
            || type_.unused() != 0
            || (deallocate && type_.is_inline)
        {
            unsafe { clean_partial(kmsg, taddr, false, 0) };
            return Err(SendError::InvalidType);
        }

        let length = type_.data_length_wide();

        saddr = saddr.wrapping_add(type_.descriptor_size());
        if kernel_is_misaligned(type_.descriptor_size()) {
            saddr = kernel_align(saddr);
        }

        let data: *mut c_void;
        if type_.is_inline {
            if eaddr.wrapping_sub(saddr) < length {
                unsafe { clean_partial(kmsg, taddr, false, 0) };
                return Err(SendError::MsgTooSmall);
            }

            data = ptr_at(saddr);
            saddr = saddr.wrapping_add(length);
        } else {
            if eaddr.wrapping_sub(saddr) < size_of::<usize>() {
                unsafe { clean_partial(kmsg, taddr, false, 0) };
                return Err(SendError::MsgTooSmall);
            }

            // SAFETY: the descriptor's out-of-line pointer is readable.
            let addr = unsafe { ptr_at::<usize>(saddr).read_unaligned() };

            data = unsafe {
                copyin_body_payload(
                    kmsg,
                    map,
                    taddr,
                    addr,
                    type_,
                    use_page_lists,
                    steal_pages,
                )?
            };

            // SAFETY: the descriptor's out-of-line slot is writable.
            unsafe { ptr_at::<usize>(saddr).write_unaligned(data.addr()) };
            saddr = saddr.wrapping_add(size_of::<usize>());
            complex = true;
        }

        if is_port {
            unsafe {
                copyin_body_ports(
                    kmsg, header, space, data, type_, taddr, dest,
                )?;
            };
            complex = true;
        }

        saddr = kernel_align(saddr);
    }

    if !complex {
        // SAFETY: the message is live and owned by this call.
        unsafe {
            (*header).set_bits((*header).bits() & !MACH_MSGH_BITS_COMPLEX);
        };
    }

    Ok(())
}

/// Translates a whole user message in `space` and `map`.
///
/// # Safety
///
/// `kmsg` must be a live message whose right the caller owns, `space` must
/// be live and unlocked, `map` must be the live map the message came from,
/// and the caller permits an allocation.
pub(crate) unsafe fn copyin(
    kmsg: Kmsg,
    space: IpcSpace,
    map: &mut VmMap,
    notify: c_uint,
) -> Result<(), SendError> {
    let header = unsafe { kmsg.header() };

    unsafe { copyin_header(header, space, notify) }?;

    if unsafe { (*header).bits() } & MACH_MSGH_BITS_COMPLEX == 0 {
        return Ok(());
    }

    unsafe { copyin_body(kmsg, space, map) }
}

/// Translates the rights of a message the kernel built, which it already
/// holds.
///
/// # Safety
///
/// `kmsg` must be a live message whose rights this call owns.
pub(crate) unsafe fn copyin_from_kernel(kmsg: Kmsg) {
    let header = unsafe { kmsg.header() };
    let mut bits = unsafe { (*header).bits() };
    let rname = mach_msg_bits_remote(bits);
    let lname = mach_msg_bits_local(bits);
    let remote = ptr_at::<c_void>(unsafe { (*header).remote() });
    let local = ptr_at::<c_void>(unsafe { (*header).local() });

    // SAFETY: the message came from the kernel, so the destination is live.
    unsafe { ipc_object::copyin_from_kernel(remote, rname) };
    if io_valid(local) {
        // SAFETY: the local right came from the kernel too.
        unsafe { ipc_object::copyin_from_kernel(local, lname) };
    }

    if bits == (MACH_MSGH_BITS_COMPLEX | BITS_ASYNC) {
        bits =
            MACH_MSGH_BITS_COMPLEX | mach_msg_bits(MACH_MSG_TYPE_PORT_SEND, 0);
        // SAFETY: the message is live and owned by this call.
        unsafe { (*header).set_bits(bits) };
    } else {
        bits = mach_msg_bits_other(bits)
            | mach_msg_bits(
                ipc_object::copyin_type(rname),
                ipc_object::copyin_type(lname),
            );
        unsafe { (*header).set_bits(bits) };
        if bits & MACH_MSGH_BITS_COMPLEX == 0 {
            return;
        }
    }

    let mut saddr = header.addr() + size_of::<MachMsgHeader>();
    let eaddr = header.addr() + as_index(unsafe { (*header).size() });

    while saddr < eaddr {
        let taddr = saddr;
        let type_ = unsafe { read_type(taddr) };
        saddr = saddr.wrapping_add(type_.descriptor_size());
        if kernel_is_misaligned(type_.descriptor_size()) {
            saddr = kernel_align(saddr);
        }

        let length = type_.data_length();
        let is_port = mach_msg_type_port_any(type_.name);

        let data;
        if type_.is_inline {
            data = ptr_at::<c_void>(saddr);
            saddr = saddr.wrapping_add(length);
        } else {
            // SAFETY: the descriptor's out-of-line pointer is readable.
            data = ptr_at::<c_void>(unsafe {
                ptr_at::<usize>(saddr).read_unaligned()
            });
            saddr = saddr.wrapping_add(size_of::<usize>());
        }

        if is_port {
            let newname = ipc_object::copyin_type(type_.name);
            // SAFETY: the descriptor is writable.
            unsafe { write_type_name(taddr, type_.longform, newname) };

            let objects = data.cast::<*mut c_void>();
            for i in 0..type_.number {
                // SAFETY: the array holds `number` readable objects.
                let object = unsafe { objects.add(as_index(i)).read() };
                if !io_valid(object) {
                    continue;
                }

                // SAFETY: the message came from the kernel, so the right is
                // this call's.
                unsafe { ipc_object::copyin_from_kernel(object, type_.name) };

                if newname == MACH_MSG_TYPE_PORT_RECEIVE {
                    // SAFETY: the object is a live port.
                    let object_port = unsafe { IpcPort::from_raw(object) };
                    // SAFETY: the port is live and no port lock is held.
                    if unsafe {
                        ipc_port::check_circularity(object_port, remote)
                    } {
                        // SAFETY: the message is live and owned by this
                        // call.
                        unsafe {
                            (*header).set_bits(
                                (*header).bits() | MACH_MSGH_BITS_CIRCULAR,
                            );
                        };
                    }
                }
            }
        }

        saddr = kernel_align(saddr);
    }
}

/// Consumes the destination send right and returns its name and the port's
/// protected payload, the fast path of [`copyout_header`].
///
/// # Safety
///
/// The port must be live, locked, and active, and the caller must own the
/// send right the message held.
unsafe fn copyout_dest_fast(
    dest_port: IpcPort,
    space: IpcSpace,
) -> (c_uint, usize) {
    unsafe {
        dest_port.decrement_references();
        let dest_name = if dest_port.receiver() == space.as_ptr() {
            dest_port.receiver_name()
        } else {
            MACH_PORT_NAME_NULL
        };
        let payload = dest_port.protected_payload();

        dest_port.decrement_srights();
        if dest_port.srights() == 0 {
            if let Some(nsrequest) = dest_port.nsrequest() {
                dest_port.set_nsrequest(None);
                let mscount = dest_port.mscount();
                dest_port.unlock();
                ipc_notify::no_senders(nsrequest, mscount);
            } else {
                dest_port.unlock();
            }
        } else {
            dest_port.unlock();
        }

        (dest_name, payload)
    }
}

/// Translates the ports of a message header into names in `space`.
///
/// # Safety
///
/// `header` must point at a live message header, `space` must be a live
/// space, and nothing may be locked.
pub(crate) unsafe fn copyout_header(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    notify: c_uint,
) -> Result<(), ReceiveError> {
    let mbits = unsafe { (*header).bits() };
    let dest = ptr_at::<c_void>(unsafe { (*header).remote() });

    let handled = notify == MACH_PORT_NAME_NULL
        && unsafe { copyout_header_fast(header, space, mbits, dest) };
    if handled {
        return Ok(());
    }

    let reply_type = mach_msg_bits_local(mbits);
    let reply = ptr_at::<c_void>(unsafe { (*header).local() });

    // SAFETY: the header names a live destination.
    let dest_port = unsafe { IpcPort::from_raw(dest) };

    let reply_name;
    let mut final_reply = reply;

    if io_valid(reply) {
        // SAFETY: both ports in the header are live.
        let reply_port = unsafe { IpcPort::from_raw(reply) };

        // SAFETY: the space is live and nothing is locked.
        unsafe { space.lock_write() };

        let state = unsafe {
            copyout_header_loop(
                space,
                dest_port,
                reply_port,
                reply_type,
                notify,
                CopyoutHeaderState {
                    reply,
                    reply_name: 0,
                    entry: ptr::null_mut(),
                    need_copyout: true,
                    notify_port: None,
                },
            )
        }?;

        final_reply = state.reply;
        reply_name = state.reply_name;

        if state.need_copyout {
            // SAFETY: the space is write-locked and the ports are live.
            unsafe {
                copyout_header_need_copyout(
                    space, dest_port, reply_port, &state, reply_type,
                );
            };
        }
    } else {
        reply_name = unsafe {
            copyout_header_bad_reply(header, space, notify, reply, dest_port)
        }?;
    }

    unsafe {
        copyout_header_finish(
            header,
            mbits,
            space,
            dest_port,
            final_reply,
            reply_name,
        );
    }

    Ok(())
}

/// The state [`copyout_header()`]'s reply lookup carries through its loop.
struct CopyoutHeaderState {
    /// The header's reply value, which may become `IO_DEAD`.
    reply: *mut c_void,
    /// The reply name the loop settled on.
    reply_name: c_uint,
    /// The allocated entry for the reply, when one was made.
    entry: *mut c_void,
    /// Whether the recipient still needs the reply copied out.
    need_copyout: bool,
    /// The notify port the loop still holds, if any.
    notify_port: Option<IpcPort>,
}

/// Dispatch the fast paths of [`copyout_header()`].
///
/// Returns `true` when the header was rewritten and the caller must return
/// success, `false` when the slow path must run.
///
/// # Safety
///
/// The same contract as [`copyout_header()`]: `header` must point at a live
/// message header, `space` must be a live space, and nothing may be locked.
unsafe fn copyout_header_fast(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest: *mut c_void,
) -> bool {
    match mach_msg_bits_ports(mbits) {
        BITS_ASYNC => unsafe {
            copyout_header_async(header, space, mbits, dest)
        },
        BITS_REQUEST => unsafe {
            copyout_header_request(header, space, mbits, dest)
        },
        BITS_REPLY => unsafe {
            copyout_header_reply(header, space, mbits, dest)
        },
        _ => false,
    }
}

/// The `BITS_ASYNC` fast path of [`copyout_header()`].
///
/// # Safety
///
/// The same contract as [`copyout_header()`].
unsafe fn copyout_header_async(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest: *mut c_void,
) -> bool {
    // SAFETY: the header names a live destination.
    let dest_port = unsafe { IpcPort::from_raw(dest) };
    // SAFETY: the port lock is free.
    unsafe { dest_port.lock() };
    // SAFETY: the port lock is held.
    if !unsafe { dest_port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { dest_port.unlock() };
        return false;
    }

    // SAFETY: the port is live, locked, and active.
    let (dest_name, payload) = unsafe { copyout_dest_fast(dest_port, space) };

    // SAFETY: the header is live and this call owns its right.
    unsafe {
        if dest_port.protected_payload_flag() {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(0, MACH_MSG_TYPE_PROTECTED_PAYLOAD),
            );
            (*header).set_protected_payload(payload);
        } else {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(0, MACH_MSG_TYPE_PORT_SEND),
            );
            (*header).set_local(as_index(dest_name));
        }
        (*header).set_remote(0);
    }
    true
}

/// The `BITS_REQUEST` fast path of [`copyout_header()`].
///
/// # Safety
///
/// The same contract as [`copyout_header()`].
unsafe fn copyout_header_request(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest: *mut c_void,
) -> bool {
    let reply = ptr_at::<c_void>(unsafe { (*header).local() });
    if !io_valid(reply) {
        return false;
    }

    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_write() };
    // SAFETY: the space lock is held.
    let inactive = !unsafe { space.is_active() };
    // The message asks for a receive right in an entry.
    let no_reply_entry =
        // SAFETY: the space lock is held.
        unsafe { (*space.record()).free_list.is_null() };
    if inactive || no_reply_entry {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return false;
    }

    // SAFETY: the header and the message name live ports.
    let dest_port = unsafe { IpcPort::from_raw(dest) };
    // SAFETY: the header and the message name live ports.
    let reply_port = unsafe { IpcPort::from_raw(reply) };

    // SAFETY: both ports are live and their locks are free.
    unsafe { dest_port.lock() };
    // SAFETY: the destination lock is held.
    if !unsafe { dest_port.is_active() }
        // SAFETY: the reply port is live and its lock is free.
        || !unsafe { reply_port.try_lock() }
    {
        // SAFETY: the destination lock is held.
        unsafe { dest_port.unlock() };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
        return false;
    }
    // SAFETY: the reply lock is held.
    if !unsafe { reply_port.is_active() } {
        // SAFETY: both locks are held.
        unsafe {
            reply_port.unlock();
            dest_port.unlock();
            space.unlock_write();
        }
        return false;
    }
    // SAFETY: the reply lock is held.
    unsafe { reply_port.unlock() };

    // SAFETY: the space is live, active, and write-locked.
    let Some((reply_name, entry)) = (unsafe { ipc_entry::entry_get(space) })
    else {
        // The C unlocks the already-unlocked reply port here a second time;
        // this drops that unlock.
        // SAFETY: the destination lock and the space lock are held.
        unsafe {
            dest_port.unlock();
            space.unlock_write();
        }
        return false;
    };
    // The generation step and the send-once type.
    // SAFETY: the entry is live and the space is write-locked.
    unsafe {
        let generation = (*entry).bits().wrapping_add(IE_BITS_GEN_ONE);
        (*entry).set_bits(generation | (MACH_PORT_TYPE_SEND_ONCE | 1));
        (*entry).set_object(reply);
        space.unlock_write();
    }

    // SAFETY: the destination is live, locked, and active.
    let (dest_name, payload) = unsafe { copyout_dest_fast(dest_port, space) };

    // SAFETY: the header is live and this call owns its rights.
    unsafe {
        if dest_port.protected_payload_flag() {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(
                        MACH_MSG_TYPE_PORT_SEND_ONCE,
                        MACH_MSG_TYPE_PROTECTED_PAYLOAD,
                    ),
            );
            (*header).set_protected_payload(payload);
        } else {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(
                        MACH_MSG_TYPE_PORT_SEND_ONCE,
                        MACH_MSG_TYPE_PORT_SEND,
                    ),
            );
            (*header).set_local(as_index(dest_name));
        }
        (*header).set_remote(as_index(reply_name));
    }
    true
}

/// The `BITS_REPLY` fast path of [`copyout_header()`].
///
/// # Safety
///
/// The same contract as [`copyout_header()`].
unsafe fn copyout_header_reply(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    mbits: u32,
    dest: *mut c_void,
) -> bool {
    // SAFETY: the header names a live destination.
    let dest_port = unsafe { IpcPort::from_raw(dest) };
    // SAFETY: the port lock is free.
    unsafe { dest_port.lock() };
    // SAFETY: the port lock is held.
    if !unsafe { dest_port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { dest_port.unlock() };
        return false;
    }

    // SAFETY: the port is live and locked.
    let payload = unsafe { dest_port.protected_payload() };
    // SAFETY: the port is live and locked.
    let dest_name = if unsafe { dest_port.receiver() == space.as_ptr() } {
        // SAFETY: the port is live and locked.
        unsafe {
            dest_port.decrement_references();
            dest_port.decrement_sorights();
        }
        // SAFETY: the port is live and locked.
        let name = unsafe { dest_port.receiver_name() };
        // SAFETY: the port lock is held.
        unsafe { dest_port.unlock() };
        name
    } else {
        // SAFETY: the port lock is held.
        unsafe { dest_port.unlock() };
        // SAFETY: the send-once right is being received.
        unsafe { ipc_notify::send_once(dest_port.as_non_null()) };
        MACH_PORT_NAME_NULL
    };

    // SAFETY: the header is live and this call owns its right.
    unsafe {
        if dest_port.protected_payload_flag() {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(0, MACH_MSG_TYPE_PROTECTED_PAYLOAD),
            );
            (*header).set_protected_payload(payload);
        } else {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(0, MACH_MSG_TYPE_PORT_SEND_ONCE),
            );
            (*header).set_local(as_index(dest_name));
        }
        (*header).set_remote(0);
    }
    true
}

/// The reply lookup loop of [`copyout_header()`]'s slow path.
///
/// # Safety
///
/// The same contract as [`copyout_header()`], with `state` the loop's
/// starting values; on success the destination is locked and the space
/// unlocked, matching the loop's exits.
unsafe fn copyout_header_loop(
    space: IpcSpace,
    dest_port: IpcPort,
    reply_port: IpcPort,
    reply_type: u32,
    notify: c_uint,
    mut state: CopyoutHeaderState,
) -> Result<CopyoutHeaderState, ReceiveError> {
    loop {
        // SAFETY: the space lock is held.
        if !unsafe { space.is_active() } {
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write() };
            return Err(ReceiveError::Header(Shortage::IPC_SPACE));
        }

        state.notify_port = if notify == MACH_PORT_NAME_NULL {
            None
        } else {
            // SAFETY: the space is live, active, and write-locked.
            if let Some(port) =
                // SAFETY: the space is live, active, and write-locked.
                unsafe { ipc_port::lookup_notify(space, notify) }
            {
                Some(port)
            } else {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write() };
                return Err(ReceiveError::InvalidNotify);
            }
        };

        let reversed = if reply_type == MACH_MSG_TYPE_PORT_SEND_ONCE {
            None
        } else {
            // SAFETY: the space is write-locked and the reply is live.
            unsafe { ipc_right::reverse(space, state.reply) }
        };
        if let Some((name, found)) = reversed {
            state.reply_name = name;
            state.entry = found.cast();
            break;
        }

        // SAFETY: the reply port is live and its lock is free.
        unsafe { reply_port.lock() };
        // SAFETY: the reply lock is held.
        if !unsafe { reply_port.is_active() } {
            // SAFETY: the reply lock is held.
            unsafe {
                reply_port.decrement_references();
                reply_port.check_unlock();
            }
            if let Some(port) = state.notify_port {
                // SAFETY: the lookup took the send-once right.
                unsafe { ipc_port::release_sonce(port) };
            }
            // SAFETY: the destination is live and unlocked.
            unsafe { dest_port.lock() };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write() };
            state.reply = IO_DEAD;
            state.reply_name = MACH_PORT_NAME_DEAD;
            state.need_copyout = false;
            break;
        }

        // SAFETY: the space is write-locked and the reply port is live.
        let done =
            unsafe { copyout_header_entry(space, reply_port, &mut state) }?;
        if done {
            break;
        }
    }

    Ok(state)
}

/// Allocate the reply entry of [`copyout_header_loop()`] and finish the
/// notify handshake for one iteration.
///
/// Returns `true` when the loop must break and `false` when it must run
/// another iteration; the space is write-locked on both.  On failure the
/// locks are released.
///
/// # Safety
///
/// The same contract as [`copyout_header_loop()`]: the space must be live,
/// active, and write-locked, and the reply port live.
unsafe fn copyout_header_entry(
    space: IpcSpace,
    reply_port: IpcPort,
    state: &mut CopyoutHeaderState,
) -> Result<bool, ReceiveError> {
    // SAFETY: the space is live, active, and write-locked.
    let (name, allocated) = match unsafe { ipc_entry::alloc(space) } {
        Ok(found) => found,
        Err(error) => {
            // SAFETY: the locks are held.
            unsafe {
                reply_port.unlock();
                if let Some(port) = state.notify_port {
                    ipc_port::release_sonce(port);
                }
                space.unlock_write();
            }
            return Err(if error == Error::ResourceShortage {
                ReceiveError::Header(Shortage::IPC_KERNEL)
            } else {
                ReceiveError::Header(Shortage::IPC_SPACE)
            });
        }
    };
    state.reply_name = name;
    state.entry = allocated.cast();

    let Some(port) = state.notify_port else {
        // SAFETY: the entry is live and the space is write-locked.
        unsafe { (*(state.entry.cast::<IpcEntry>())).set_object(state.reply) };
        return Ok(true);
    };

    // SAFETY: the reply port is live and locked, and the space is
    // write-locked.
    if let Ok(request) = unsafe {
        ipc_port::dnrequest(
            IpcPort::from_raw(state.reply),
            state.reply_name,
            port.as_non_null(),
        )
    } {
        state.notify_port = None;
        // SAFETY: the entry is live and the space is write-locked.
        unsafe {
            (*(state.entry.cast::<IpcEntry>())).set_object(state.reply);
            (*(state.entry.cast::<IpcEntry>())).set_request(request);
        }
        return Ok(true);
    }
    // SAFETY: the reply lock and the space lock are held.
    unsafe {
        reply_port.unlock();
        ipc_port::release_sonce(port);
        ipc_entry::dealloc(space, state.reply_name, state.entry.cast());
        space.unlock_write();
        reply_port.lock();
    }

    // SAFETY: the reply lock is held.
    if !unsafe { reply_port.is_active() } {
        // SAFETY: the reply lock is held.
        unsafe {
            reply_port.unlock();
            space.lock_write();
        }
        return Ok(false);
    }

    // SAFETY: the reply port is live and locked; the call unlocks it.
    if unsafe { ipc_port::dngrow(reply_port) }.is_err() {
        return Err(ReceiveError::Header(Shortage::IPC_KERNEL));
    }

    // SAFETY: the space is live and nothing else is locked.
    unsafe { space.lock_write() };
    Ok(false)
}

/// The copyout tail of [`copyout_header()`]'s reply path.
///
/// # Safety
///
/// The space must be write-locked, the destination and reply ports live,
/// and `state` the loop's result.
unsafe fn copyout_header_need_copyout(
    space: IpcSpace,
    dest_port: IpcPort,
    reply_port: IpcPort,
    state: &CopyoutHeaderState,
    reply_type: u32,
) {
    // SAFETY: the reply port is live and locked.
    unsafe { reply_port.increment_references() };

    // SAFETY: the space is write-locked and the reply port is live and
    // locked.  The C ignores this result.
    let _ = unsafe {
        ipc_right::copyout(
            space,
            state.reply_name,
            state.entry.cast(),
            reply_type,
            true,
            state.reply,
        )
    };

    if let Some(port) = state.notify_port {
        // SAFETY: the lookup took the send-once right.
        unsafe { ipc_port::release_sonce(port) };
    }

    // SAFETY: the destination is live and unlocked.
    unsafe { dest_port.lock() };
    unsafe { space.unlock_write() };
}

/// The invalid-reply branch of [`copyout_header()`]: read-lock the space,
/// check the notify port, and name the dead reply.
///
/// On success the destination is locked and the space is unlocked.
///
/// # Safety
///
/// The same contract as [`copyout_header()`]: `header` must point at a live
/// message header, `space` must be a live space, and nothing may be locked.
unsafe fn copyout_header_bad_reply(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    notify: c_uint,
    reply: *mut c_void,
    dest_port: IpcPort,
) -> Result<c_uint, ReceiveError> {
    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_read() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_read() };
        return Err(ReceiveError::Header(Shortage::IPC_SPACE));
    }

    if notify != MACH_PORT_NAME_NULL {
        // SAFETY: the space is live, active, and read-locked.
        let entry = unsafe { space.entry_lookup(notify) };
        let receive = entry.is_some_and(|entry| {
            // SAFETY: the entry is live and the space is locked.
            let bits = unsafe { (*entry).bits() };
            bits & MACH_PORT_TYPE_RECEIVE != 0
        });
        if !receive {
            if entry.is_none() {
                unsafe { entry_lookup_failed(header, notify) };
            }
            // SAFETY: the space lock is held.
            unsafe { space.unlock_read() };
            return Err(ReceiveError::InvalidNotify);
        }
    }

    // SAFETY: the header names a live destination.
    unsafe { dest_port.lock() };
    // SAFETY: the space lock is held.
    unsafe { space.unlock_read() };
    // SAFETY: the reply is null or dead.
    Ok(unsafe { ipc_port::invalid_port_to_name(reply) })
}

/// The epilogue of [`copyout_header()`]: name the destination and rewrite
/// the header.
///
/// # Safety
///
/// `header` must be a live header whose destination and reply rights this
/// call owns, `dest_port` live and locked, and the reply consumed.
unsafe fn copyout_header_finish(
    header: *mut MachMsgHeader,
    mbits: u32,
    space: IpcSpace,
    dest_port: IpcPort,
    reply: *mut c_void,
    reply_name: c_uint,
) {
    let dest = ptr_at::<c_void>(unsafe { (*header).remote() });
    let dest_type = mach_msg_bits_remote(mbits);
    let reply_type = mach_msg_bits_local(mbits);

    // SAFETY: the destination is live and locked.
    let payload = unsafe { dest_port.protected_payload() };

    // SAFETY: the destination is live and locked.
    let dest_name = if unsafe { dest_port.is_active() } {
        // SAFETY: the destination is live, active, and locked.
        unsafe { ipc_object::copyout_dest(space, dest, dest_type) }
    } else {
        // SAFETY: the destination is live and locked.
        let timestamp = unsafe { dest_port.timestamp() };
        // SAFETY: the destination is live and locked, and this consumes the
        // message's reference.
        unsafe {
            dest_port.decrement_references();
            dest_port.check_unlock();
        }

        if io_valid(reply) {
            let reply_port = unsafe { IpcPort::from_raw(reply) };
            // SAFETY: the reply port lock is free.
            unsafe { reply_port.lock() };
            // SAFETY: the reply port is live and locked.
            let name = if unsafe { reply_port.is_active() }
                // SAFETY: the reply port is live and locked.
                || timestamp_order(timestamp, unsafe {
                    reply_port.timestamp()
                }) {
                MACH_PORT_NAME_DEAD
            } else {
                MACH_PORT_NAME_NULL
            };
            // SAFETY: the reply port lock is held.
            unsafe { reply_port.unlock() };
            name
        } else {
            MACH_PORT_NAME_DEAD
        }
    };

    if io_valid(reply) {
        // SAFETY: the live reply holds the message's reference.
        unsafe { ipc_object::release(reply) };
    }

    // SAFETY: the header is live and this call owns its rights.
    unsafe {
        if dest_port.protected_payload_flag() {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(
                        reply_type,
                        MACH_MSG_TYPE_PROTECTED_PAYLOAD,
                    ),
            );
            (*header).set_protected_payload(payload);
        } else {
            (*header).set_bits(
                mach_msg_bits_other(mbits)
                    | mach_msg_bits(reply_type, dest_type),
            );
            (*header).set_local(as_index(dest_name));
        }
        (*header).set_remote(as_index(reply_name));
    }
}

/// Copies out a port right, always returning a name, and consuming the
/// supplied object; a right the receiver had no room for comes back as the
/// [`Shortage`] that destroyed it.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; the caller must own the
/// right `object` holds.
pub(crate) unsafe fn copyout_object(
    space: IpcSpace,
    object: *mut c_void,
    msgt_name: c_uint,
) -> (Shortage, c_uint) {
    if !io_valid(object) {
        // SAFETY: the object is null or dead, the only tags the C accepts.
        return (Shortage::NONE, unsafe {
            ipc_port::invalid_port_to_name(object)
        });
    }

    if msgt_name == MACH_MSG_TYPE_PORT_SEND {
        // SAFETY: the object is a live port.
        let port = unsafe { IpcPort::from_raw(object) };
        let mut name = MACH_PORT_NAME_NULL;
        let mut fast = false;

        unsafe { space.lock_write() };
        // SAFETY: the space lock is held.
        if unsafe { space.is_active() } {
            // SAFETY: the port is live and its lock is free.
            unsafe { port.lock() };

            // SAFETY: the space is write-locked, so the reverse map is
            // serialized.
            let found = unsafe { space.reverse_lookup(object) };
            match found {
                // SAFETY: the port is live and locked.
                Some(entry) if unsafe { port.is_active() } => {
                    // SAFETY: the port is live, locked, and active, and the
                    // entry is live in the locked space.
                    unsafe {
                        name = (*entry).name();
                        port.decrement_srights();
                        port.decrement_references();
                        port.unlock();

                        let bits = (*entry).bits().wrapping_add(1);
                        if bits & IE_BITS_UREFS_MASK < MACH_PORT_UREFS_MAX {
                            (*entry).set_bits(bits);
                        }
                        space.unlock_write();
                    }
                    fast = true;
                }
                _ => {
                    // SAFETY: the port lock is held.
                    unsafe { port.unlock() };
                }
            }
        }

        if fast {
            return (Shortage::NONE, name);
        }

        // SAFETY: the space lock is held.
        unsafe { space.unlock_write() };
    }

    match unsafe { ipc_object::copyout(space, object, msgt_name, true) } {
        Ok(name) => (Shortage::NONE, name),
        Err(error) => {
            // SAFETY: the failed copyout leaves the right to this call.
            unsafe { ipc_object::destroy_object(object, msgt_name) };

            if error == Error::InvalidCapability {
                (Shortage::NONE, MACH_PORT_NAME_DEAD)
            } else if error == Error::ResourceShortage {
                (Shortage::IPC_KERNEL, MACH_PORT_NAME_NULL)
            } else {
                (Shortage::IPC_SPACE, MACH_PORT_NAME_NULL)
            }
        }
    }
}

/// Allocate the user buffer for one out-of-line port array of
/// [`copyout_body()`].
///
/// On failure the body before `saddr` is cleaned and the allocation's error
/// is returned.
///
/// # Safety
///
/// `map` must be the live, unlocked map; `type_` the descriptor at `taddr`,
/// which must be an out-of-line port array; and the caller must own the
/// rights before `saddr`.
unsafe fn copyout_body_alloc(
    map: &mut VmMap,
    type_: MsgType,
    taddr: usize,
    saddr: usize,
) -> Result<usize, VmError> {
    let mut addr: usize = 0;
    let length = type_.data_length_wide();
    if length != 0 {
        let user_length = if size_of::<c_uint>() == size_of::<usize>() {
            length
        } else {
            size_of::<c_uint>() * as_index(type_.number)
        };

        if let Err(error) =
            vm_user::allocate(map, &mut addr, user_length, true)
        {
            unsafe { clean_body(taddr, saddr) };
            return Err(error);
        }
    }

    if size_of::<c_uint>() != size_of::<usize>() {
        // SAFETY: the descriptor is writable.
        unsafe {
            write_type_size(taddr, type_.longform, PORT_NAME_T_SIZE_IN_BITS);
        };
    }

    Ok(addr)
}

/// Rewrite the objects of one port array of [`copyout_body()`] into user
/// names.
///
/// # Safety
///
/// The caller must own the message's rights and the array must hold
/// `type_.number` readable objects.
unsafe fn copyout_body_objects(
    space: IpcSpace,
    type_: MsgType,
    saddr: usize,
) -> Shortage {
    let objects = if type_.is_inline {
        ptr_at::<*mut c_void>(saddr)
    } else {
        // SAFETY: the descriptor's out-of-line pointer is readable.
        ptr_at::<*mut c_void>(unsafe {
            ptr_at::<usize>(saddr).read_unaligned()
        })
    };

    let mut lost = Shortage::NONE;
    for i in 0..type_.number {
        let index = as_index(i);
        // SAFETY: the array holds `number` readable objects.
        let object = unsafe { objects.add(index).read() };
        let (object_lost, name) =
            unsafe { copyout_object(space, object, type_.name) };
        lost |= object_lost;
        // SAFETY: the slot is writable.
        unsafe { objects.add(index).write(ptr_at(as_index(name))) };
    }
    lost
}

/// The [`Shortage`] that destroyed the memory of a [`copyout_body()`]
/// descriptor whose mapping failed with `error`.
fn memory_shortage(error: VmError) -> Shortage {
    if error == VmError::ResourceShortage {
        Shortage::VM_KERNEL
    } else {
        Shortage::VM_SPACE
    }
}

/// Copies out the rights and out-of-line memory of a message body; returns
/// what the copyout had to destroy.
///
/// # Safety
///
/// `kmsg` must be a live complex message whose rights this call owns,
/// `space` must be live and unlocked, and `map` must be the live map the
/// message is being received into.
pub(crate) unsafe fn copyout_body(
    kmsg: Kmsg,
    space: IpcSpace,
    map: &mut VmMap,
) -> Shortage {
    let header = unsafe { kmsg.header() };
    let mut saddr = header.addr() + size_of::<MachMsgHeader>();
    let eaddr = header.addr() + as_index(unsafe { (*header).size() });
    let mut lost = Shortage::NONE;

    while saddr < eaddr {
        let taddr = saddr;
        let type_ = unsafe { read_type(taddr) };
        let length = type_.data_length_wide();
        let is_port = mach_msg_type_port_any(type_.name);

        saddr = saddr.wrapping_add(type_.descriptor_size());
        if kernel_is_misaligned(type_.descriptor_size()) {
            saddr = kernel_align(saddr);
        }

        let mut addr: usize = 0;
        let mut failure = None;

        if is_port && !type_.is_inline {
            match unsafe { copyout_body_alloc(map, type_, taddr, saddr) } {
                Ok(allocated) => addr = allocated,
                Err(error) => failure = Some(memory_shortage(error)),
            }
        }

        if is_port && failure.is_none() {
            lost |= unsafe { copyout_body_objects(space, type_, saddr) };
        }

        if type_.is_inline {
            // SAFETY: the descriptor is writable.
            unsafe { write_type_deallocate(taddr, false) };
            saddr = saddr.wrapping_add(length);
        } else {
            // SAFETY: the descriptor's out-of-line pointer is readable.
            let data = unsafe { ptr_at::<usize>(saddr).read_unaligned() };

            if length == 0 {
                addr = 0;
            } else if is_port {
                if failure.is_none() {
                    if size_of::<c_uint>() == size_of::<usize>() {
                        let _ = unsafe {
                            crate::vm::vm_kern::copyoutmap(
                                map,
                                ptr_at::<c_char>(data),
                                ptr_at::<c_char>(addr),
                                length as c_int,
                            )
                        };
                    } else {
                        let mut copy_failed = false;
                        for i in 0..type_.number {
                            let offset = as_index(i);
                            // SAFETY: each kernel name is readable and each
                            // user slot is writable.
                            if unsafe {
                                copyout_port(
                                    data + offset * size_of::<usize>(),
                                    addr + offset * size_of::<c_uint>(),
                                )
                            }
                            .is_err()
                            {
                                copy_failed = true;
                                break;
                            }
                        }
                        if copy_failed {
                            failure = Some(Shortage::VM_SPACE);
                        }
                    }

                    // SAFETY: the port data came from `kalloc()`.
                    unsafe { kfree_addr(data, length) };
                }
            } else if failure.is_none() {
                if let Some(copy) = NonNull::new(ptr_at::<VmMapCopy>(data)) {
                    // SAFETY: the map is live and unlocked, and the copy
                    // came from the sender.
                    match unsafe { map.copyout(copy) } {
                        Ok(address) => addr = address,
                        Err(error) => {
                            // SAFETY: the failed copyout leaves the copy
                            // to this call.
                            unsafe { VmMapCopy::discard(copy) };
                            failure = Some(memory_shortage(error));
                        }
                    }
                } else {
                    failure = Some(Shortage::VM_SPACE);
                }
            }

            if let Some(shortage) = failure {
                addr = 0;
                // SAFETY: the descriptor is writable.
                unsafe { write_type_size(taddr, type_.longform, 0) };
                lost |= shortage;
            }

            // SAFETY: the descriptor is writable.
            unsafe { write_type_deallocate(taddr, true) };
            // SAFETY: the descriptor's out-of-line slot is writable.
            unsafe { ptr_at::<usize>(saddr).write_unaligned(addr) };
            saddr = saddr.wrapping_add(size_of::<usize>());
        }

        saddr = kernel_align(saddr);
    }

    lost
}

/// Translates a whole message into `space` and `map` for its receiver.
///
/// # Safety
///
/// `kmsg` must be a live message whose rights this call owns, `space` must
/// be live and unlocked, `map` must be the live map the message is being
/// received into, and `notify` must be a name in `space` or
/// `MACH_PORT_NULL`.
pub(crate) unsafe fn copyout(
    kmsg: Kmsg,
    space: IpcSpace,
    map: &mut VmMap,
    notify: c_uint,
) -> Result<(), ReceiveError> {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };

    unsafe { copyout_header(header, space, notify) }?;

    if mbits & MACH_MSGH_BITS_COMPLEX != 0 {
        // SAFETY: the header copied out, so the body belongs to this call.
        let lost = unsafe { copyout_body(kmsg, space, map) };
        if !lost.is_none() {
            return Err(ReceiveError::Body(lost));
        }
    }

    Ok(())
}

/// Copies out a message the sender gets back after a failed send; returns what
/// the copyout had to destroy.
///
/// # Safety
///
/// `kmsg` must be a live message whose rights this call owns, `space` must
/// be live and unlocked, and `map` must be the live map the message is being
/// received into.
pub(crate) unsafe fn copyout_pseudo(
    kmsg: Kmsg,
    space: IpcSpace,
    map: &mut VmMap,
) -> Shortage {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };
    let dest = ptr_at::<c_void>(unsafe { (*header).remote() });
    let reply = ptr_at::<c_void>(unsafe { (*header).local() });
    let dest_type = mach_msg_bits_remote(mbits);
    let reply_type = mach_msg_bits_local(mbits);

    // Both calls always run; both names are wanted.
    let (dest_lost, dest_name) =
        unsafe { copyout_object(space, dest, dest_type) };
    let (reply_lost, reply_name) =
        unsafe { copyout_object(space, reply, reply_type) };
    let mut lost = dest_lost | reply_lost;

    // SAFETY: the header is live and owned by this call.
    unsafe {
        (*header).set_bits(mbits & !MACH_MSGH_BITS_CIRCULAR);
        (*header).set_remote(as_index(dest_name));
        (*header).set_local(as_index(reply_name));
    }

    if mbits & MACH_MSGH_BITS_COMPLEX != 0 {
        // SAFETY: the header copied out, so the body belongs to this call.
        lost |= unsafe { copyout_body(kmsg, space, map) };
    }

    lost
}

/// Copies out the destination and reply rights of a message without a
/// receiver, quietly.
///
/// # Safety
///
/// `kmsg` must be a live message whose rights this call owns, and `space`
/// must be live and unlocked.
pub(crate) unsafe fn copyout_dest(kmsg: Kmsg, space: IpcSpace) {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };
    let dest = ptr_at::<c_void>(unsafe { (*header).remote() });
    let reply = ptr_at::<c_void>(unsafe { (*header).local() });
    let dest_type = mach_msg_bits_remote(mbits);
    let reply_type = mach_msg_bits_local(mbits);

    // SAFETY: the header names a live destination.
    let dest_port = unsafe { IpcPort::from_raw(dest) };
    // SAFETY: the port lock is free.
    unsafe { dest_port.lock() };

    // SAFETY: the destination is live and locked.
    let dest_name = if unsafe { dest_port.is_active() } {
        // SAFETY: the destination is live, active, and locked.
        unsafe { ipc_object::copyout_dest(space, dest, dest_type) }
    } else {
        // SAFETY: the destination is live and locked, and this consumes the
        // message's reference.
        unsafe {
            dest_port.decrement_references();
            dest_port.check_unlock();
        }
        MACH_PORT_NAME_DEAD
    };

    let reply_name = if io_valid(reply) {
        unsafe { ipc_object::destroy_object(reply, reply_type) };
        MACH_PORT_NAME_NULL
    } else {
        // SAFETY: the reply is null or dead.
        unsafe { ipc_port::invalid_port_to_name(reply) }
    };

    // SAFETY: the header is live and owned by this call.
    unsafe {
        (*header).set_bits(
            mach_msg_bits_other(mbits) | mach_msg_bits(reply_type, dest_type),
        );
        (*header).set_local(as_index(dest_name));
        (*header).set_remote(as_index(reply_name));
    }

    if mbits & MACH_MSGH_BITS_COMPLEX != 0 {
        let saddr = header.addr() + size_of::<MachMsgHeader>();
        let eaddr = header.addr() + as_index(unsafe { (*header).size() });

        unsafe { clean_body(saddr, eaddr) };
    }
}
