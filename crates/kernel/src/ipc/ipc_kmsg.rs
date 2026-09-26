// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_kmsg.c and ipc/ipc_kmsg.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel-message routines, which `ipc/ipc_kmsg.c` used to define and
//! `ipc/ipc_kmsg.h` declares.

use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::user_access;
use crate::config::MAX_NCPUS;
use crate::ipc::copy_user;
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
use crate::kern::types::KernError;
use crate::vm::vm_map::{VmMap, VmMapCopy};
use crate::vm::vm_user;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::mem::{size_of, size_of_val};
use core::ops::{BitOr, BitOrAssign};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};

/// `IKM_SIZE_NETWORK` of <`ipc/ipc_kmsg.h>`: the size marking a message the
/// network code owns.
const IKM_SIZE_NETWORK: usize = usize::MAX;
/// `IKM_OVERHEAD` of <`ipc/ipc_kmsg.h>`: the allocation bytes before the
/// message header.
pub(crate) const IKM_OVERHEAD: usize =
    size_of::<IpcKmsg>() - size_of::<MachMsgHeader>();
/// `IKM_SAVED_MSG_SIZE` of <`ipc/ipc_kmsg.h>`: the body of a cached message.
const IKM_SAVED_MSG_SIZE: usize = PAGE_SIZE - IKM_OVERHEAD;
/// `IKM_EXPAND_FACTOR` of <`ipc/ipc_kmsg.h>`: how much a body can grow when
/// port names widen into kernel ports.
const IKM_EXPAND_FACTOR: c_uint = size_of::<usize>().div_ceil(4) as c_uint;

/// `ikm_plus_overhead()` of <`ipc/ipc_kmsg.h`>.
pub(crate) const fn ikm_plus_overhead(size: usize) -> usize {
    size.wrapping_add(IKM_OVERHEAD)
}

const _: () = assert!(size_of::<usize>() >= size_of::<c_uint>());

/// `sizeof(mach_msg_user_header_t)`: the user and kernel headers have the
/// same size.
const MACH_MSG_HEADER_SIZE: usize = size_of::<MachMsgHeader>();
/// `MACH_MSG_USER_ALIGNMENT` of <mach/message.h> without `USER32`.
const MACH_MSG_USER_ALIGNMENT: usize = size_of::<usize>();

/// `MACH_MSG_TYPE_MOVE_RECEIVE` of <mach/message.h>: the sender held receive
/// rights.
const MACH_MSG_TYPE_PORT_RECEIVE: c_uint = 16;
/// `MACH_MSG_TYPE_MOVE_SEND`, the wire alias `MACH_MSG_TYPE_PORT_SEND`.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`, the wire alias
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`.
const MACH_MSG_TYPE_PORT_SEND_ONCE: c_uint = 18;
/// `MACH_MSG_TYPE_COPY_SEND` of <mach/message.h>: a copy of a send right.
const MACH_MSG_TYPE_COPY_SEND: c_uint = 19;
/// `MACH_MSG_TYPE_MAKE_SEND` of <mach/message.h>: a new send right.
const MACH_MSG_TYPE_MAKE_SEND: c_uint = 20;
/// `MACH_MSG_TYPE_MAKE_SEND_ONCE` of <mach/message.h>: a new send-once
/// right.
const MACH_MSG_TYPE_MAKE_SEND_ONCE: c_uint = 21;
/// `MACH_MSG_TYPE_PROTECTED_PAYLOAD` of <mach/message.h>.
const MACH_MSG_TYPE_PROTECTED_PAYLOAD: c_uint = 23;

/// `MACH_MSGH_BITS_REMOTE_MASK` of <mach/message.h>.
const MACH_MSGH_BITS_REMOTE_MASK: u32 = 0x0000_00ff;
/// `MACH_MSGH_BITS_LOCAL_MASK` of <mach/message.h>.
const MACH_MSGH_BITS_LOCAL_MASK: u32 = 0x0000_ff00;
/// `MACH_MSGH_BITS_COMPLEX` of <mach/message.h>.
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
/// `MACH_MSGH_BITS_CIRCULAR` of <mach/message.h>: internal use only.
const MACH_MSGH_BITS_CIRCULAR: u32 = 0x4000_0000;
/// `MACH_MSGH_BITS_PORTS_MASK` of <mach/message.h>.
const MACH_MSGH_BITS_PORTS_MASK: u32 =
    MACH_MSGH_BITS_REMOTE_MASK | MACH_MSGH_BITS_LOCAL_MASK;

/// `MACH_PORT_TYPE_SEND` of <mach/port.h>.
const MACH_PORT_TYPE_SEND: c_uint = 1 << 16;
/// `MACH_PORT_TYPE_RECEIVE` of <mach/port.h>.
const MACH_PORT_TYPE_RECEIVE: c_uint = 1 << 17;
/// `MACH_PORT_TYPE_SEND_ONCE` of <mach/port.h>.
const MACH_PORT_TYPE_SEND_ONCE: c_uint = 1 << 18;
/// `MACH_PORT_UREFS_MAX` of <ipc/port.h>.
const MACH_PORT_UREFS_MAX: u32 = (1 << 16) - 1;
/// `IE_BITS_UREFS_MASK` of <`ipc/ipc_entry.h`>.
const IE_BITS_UREFS_MASK: u32 = 0x0000_ffff;
/// `IE_BITS_GEN_ONE` of <`ipc/ipc_entry.h>`: one generation step; zero in this
/// configuration.
const IE_BITS_GEN_ONE: u32 = 0;
/// `MACH_PORT_NAME_NULL` of <mach/port.h>.
const MACH_PORT_NAME_NULL: c_uint = 0;
/// `MACH_PORT_NAME_DEAD` of <mach/port.h>.
const MACH_PORT_NAME_DEAD: c_uint = c_uint::MAX;
/// `IKOT_PAGING_REQUEST` of <`kern/ipc_kobject.h`>.
const IKOT_PAGING_REQUEST: c_uint = 9;
/// `IKOT_DEVICE` of <`kern/ipc_kobject.h`>.
const IKOT_DEVICE: c_uint = 10;
/// `IKOT_USER_DEVICE` of <`kern/ipc_kobject.h`>.
const IKOT_USER_DEVICE: c_uint = 28;
/// `KERN_FAILURE` of <`mach/kern_return.h`>.
const KERN_FAILURE: c_int = 5;
/// `IO_DEAD` of <`ipc/ipc_object.h>`: the one non-null pointer `IO_VALID()`
/// rejects.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// `PORT_T_SIZE_IN_BITS` of <`ipc/ipc_machdep.h`>.
const PORT_T_SIZE_IN_BITS: c_uint = usize::BITS;
/// `PORT_NAME_T_SIZE_IN_BITS` of <`ipc/ipc_machdep.h`>.
const PORT_NAME_T_SIZE_IN_BITS: c_uint = c_uint::BITS;

/// `mach_msg_kernel_align()` of <mach/message.h>.
const fn kernel_align(x: usize) -> usize {
    x.wrapping_add(size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// `mach_msg_kernel_is_misaligned()` of <mach/message.h>.
const fn kernel_is_misaligned(x: usize) -> bool {
    x & (size_of::<usize>() - 1) != 0
}

/// `mach_msg_user_is_misaligned()` of <mach/message.h>.
const fn user_is_misaligned(x: usize) -> bool {
    x & (MACH_MSG_USER_ALIGNMENT - 1) != 0
}

/// `MACH_MSGH_BITS()` of <mach/message.h>.
const fn mach_msg_bits(remote: u32, local: u32) -> u32 {
    remote | (local << 8)
}

/// `MACH_MSGH_BITS_REMOTE()` of <mach/message.h>.
const fn mach_msg_bits_remote(bits: u32) -> u32 {
    bits & MACH_MSGH_BITS_REMOTE_MASK
}

/// `MACH_MSGH_BITS_LOCAL()` of <mach/message.h>.
const fn mach_msg_bits_local(bits: u32) -> u32 {
    (bits & MACH_MSGH_BITS_LOCAL_MASK) >> 8
}

/// `MACH_MSGH_BITS_PORTS()` of <mach/message.h>.
const fn mach_msg_bits_ports(bits: u32) -> u32 {
    bits & MACH_MSGH_BITS_PORTS_MASK
}

/// `MACH_MSGH_BITS_OTHER()` of <mach/message.h>.
const fn mach_msg_bits_other(bits: u32) -> u32 {
    bits & !MACH_MSGH_BITS_PORTS_MASK
}

/// `MACH_MSG_TYPE_PORT_ANY()` of <mach/message.h>.
const fn mach_msg_type_port_any(name: c_uint) -> bool {
    name >= MACH_MSG_TYPE_PORT_RECEIVE && name <= MACH_MSG_TYPE_MAKE_SEND_ONCE
}

/// `MACH_MSG_TYPE_PORT_ANY_SEND()` of <mach/message.h>.
const fn mach_msg_type_port_any_send(name: c_uint) -> bool {
    name >= MACH_MSG_TYPE_PORT_SEND && name <= MACH_MSG_TYPE_MAKE_SEND_ONCE
}

/// `MACH_PORT_NAME_VALID()` of <mach/port.h>.
const fn mach_port_name_valid(name: c_uint) -> bool {
    name != MACH_PORT_NAME_NULL && name != MACH_PORT_NAME_DEAD
}

/// `IO_VALID()` of <`ipc/ipc_object.h`>.
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

/// `IP_TIMESTAMP_ORDER()` of <`ipc/ipc_port.h`>.
const fn timestamp_order(one: c_uint, two: c_uint) -> bool {
    // The C compares the `int` reinterpretation of the wrapped difference.
    (one.wrapping_sub(two) as i32) < 0
}

/// `ipc_kobject_vm_page_list()` of <`kern/ipc_kobject.h`>.
const fn kobject_vm_page_list(ikot: c_uint) -> bool {
    ikot == IKOT_PAGING_REQUEST
        || ikot == IKOT_DEVICE
        || ikot == IKOT_USER_DEVICE
}

/// `ipc_kobject_vm_page_steal()` of <`kern/ipc_kobject.h`>.
const fn kobject_vm_page_steal(ikot: c_uint) -> bool {
    ikot == IKOT_PAGING_REQUEST
}

/// `mach_msg_return_t` of <mach/message.h>: a result code, or a set of
/// special bits the copyout functions accumulate.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MsgReturn(c_int);

impl MsgReturn {
    /// `MACH_MSG_SUCCESS`.
    pub(crate) const SUCCESS: Self = Self(0);
    /// `MACH_SEND_IN_PROGRESS`.
    pub(crate) const SEND_IN_PROGRESS: Self = Self(0x1000_0001);
    /// `MACH_SEND_INVALID_DATA`.
    pub(crate) const SEND_INVALID_DATA: Self = Self(0x1000_0002);
    /// `MACH_SEND_INVALID_DEST`.
    pub(crate) const SEND_INVALID_DEST: Self = Self(0x1000_0003);
    /// `MACH_SEND_TIMED_OUT`.
    pub(crate) const SEND_TIMED_OUT: Self = Self(0x1000_0004);
    /// `MACH_SEND_WILL_NOTIFY`.
    pub(crate) const SEND_WILL_NOTIFY: Self = Self(0x1000_0005);
    /// `MACH_SEND_NOTIFY_IN_PROGRESS`.
    pub(crate) const SEND_NOTIFY_IN_PROGRESS: Self = Self(0x1000_0006);
    /// `MACH_SEND_INTERRUPTED`.
    pub(crate) const SEND_INTERRUPTED: Self = Self(0x1000_0007);
    /// `MACH_SEND_MSG_TOO_SMALL`.
    pub(crate) const SEND_MSG_TOO_SMALL: Self = Self(0x1000_0008);
    /// `MACH_SEND_INVALID_REPLY`.
    pub(crate) const SEND_INVALID_REPLY: Self = Self(0x1000_0009);
    /// `MACH_SEND_INVALID_RIGHT`.
    pub(crate) const SEND_INVALID_RIGHT: Self = Self(0x1000_000a);
    /// `MACH_SEND_INVALID_NOTIFY`.
    pub(crate) const SEND_INVALID_NOTIFY: Self = Self(0x1000_000b);
    /// `MACH_SEND_INVALID_MEMORY`.
    pub(crate) const SEND_INVALID_MEMORY: Self = Self(0x1000_000c);
    /// `MACH_SEND_NO_BUFFER`.
    pub(crate) const SEND_NO_BUFFER: Self = Self(0x1000_000d);
    /// `MACH_SEND_NO_NOTIFY`.
    pub(crate) const SEND_NO_NOTIFY: Self = Self(0x1000_000e);
    /// `MACH_SEND_INVALID_TYPE`.
    pub(crate) const SEND_INVALID_TYPE: Self = Self(0x1000_000f);
    /// `MACH_SEND_INVALID_HEADER`.
    pub(crate) const SEND_INVALID_HEADER: Self = Self(0x1000_0010);
    /// `MACH_RCV_IN_PROGRESS`.
    pub(crate) const RCV_IN_PROGRESS: Self = Self(0x1000_4001);
    /// `MACH_RCV_INVALID_NAME`.
    pub(crate) const RCV_INVALID_NAME: Self = Self(0x1000_4002);
    /// `MACH_RCV_TIMED_OUT`.
    pub(crate) const RCV_TIMED_OUT: Self = Self(0x1000_4003);
    /// `MACH_RCV_TOO_LARGE`.
    pub(crate) const RCV_TOO_LARGE: Self = Self(0x1000_4004);
    /// `MACH_RCV_INTERRUPTED`.
    pub(crate) const RCV_INTERRUPTED: Self = Self(0x1000_4005);
    /// `MACH_RCV_PORT_CHANGED`.
    pub(crate) const RCV_PORT_CHANGED: Self = Self(0x1000_4006);
    /// `MACH_RCV_INVALID_NOTIFY`.
    pub(crate) const RCV_INVALID_NOTIFY: Self = Self(0x1000_4007);
    /// `MACH_RCV_INVALID_DATA`.
    pub(crate) const RCV_INVALID_DATA: Self = Self(0x1000_4008);
    /// `MACH_RCV_PORT_DIED`.
    pub(crate) const RCV_PORT_DIED: Self = Self(0x1000_4009);
    /// `MACH_RCV_IN_SET`.
    pub(crate) const RCV_IN_SET: Self = Self(0x1000_400a);
    /// `MACH_RCV_HEADER_ERROR`.
    pub(crate) const RCV_HEADER_ERROR: Self = Self(0x1000_400b);
    /// `MACH_RCV_BODY_ERROR`.
    pub(crate) const RCV_BODY_ERROR: Self = Self(0x1000_400c);
    /// `MACH_MSG_IPC_SPACE`: no room in the space for the right.
    pub(crate) const MSG_IPC_SPACE: Self = Self(0x0000_2000);
    /// `MACH_MSG_VM_SPACE`: no room in the map for the memory.
    pub(crate) const MSG_VM_SPACE: Self = Self(0x0000_1000);
    /// `MACH_MSG_IPC_KERNEL`: a kernel resource shortage handling the
    /// right.
    pub(crate) const MSG_IPC_KERNEL: Self = Self(0x0000_0800);
    /// `MACH_MSG_VM_KERNEL`: a kernel resource shortage handling the
    /// memory.
    pub(crate) const MSG_VM_KERNEL: Self = Self(0x0000_0400);

    /// The `mach_msg_return_t` a C caller sees.
    pub(crate) const fn raw(self) -> c_int {
        self.0
    }

    /// The code a C `mach_msg_return_t` stands for.
    pub(crate) const fn from_raw(code: c_int) -> Self {
        Self(code)
    }
}

impl BitOr for MsgReturn {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOrAssign for MsgReturn {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// `sizeof(mach_msg_type_t)` of <mach/message.h>.
const MSG_TYPE_SIZE: usize = 8;
/// `sizeof(mach_msg_type_long_t)` of <mach/message.h>.
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
    /// `msgh_bits` of <mach/message.h>.
    pub(crate) const fn bits(&self) -> u32 {
        self.bits
    }

    pub(crate) const fn set_bits(&mut self, bits: u32) {
        self.bits = bits;
    }

    /// `msgh_size` of <mach/message.h>.
    pub(crate) const fn size(&self) -> u32 {
        self.size
    }

    pub(crate) const fn set_size(&mut self, size: u32) {
        self.size = size;
    }

    /// `msgh_remote_port` of <mach/message.h>.
    pub(crate) const fn remote(&self) -> usize {
        self.remote_port
    }

    pub(crate) const fn set_remote(&mut self, port: usize) {
        self.remote_port = port;
    }

    /// `msgh_local_port` of <mach/message.h>.
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

    /// `msgh_seqno` of <mach/message.h>.
    pub(crate) const fn set_seqno(&mut self, seqno: u32) {
        self.seqno = seqno;
    }

    /// `msgh_id` of <mach/message.h>.
    pub(crate) const fn id(&self) -> c_int {
        self.id
    }

    pub(crate) const fn set_id(&mut self, id: c_int) {
        self.id = id;
    }
}

/// `ipc_kmsg_t` of <`ipc/ipc_kmsg.h>`: a kernel message buffer.
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

    /// `&kmsg->ikm_header` of <`ipc/ipc_kmsg.h`>.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn header(self) -> *mut MachMsgHeader {
        unsafe { ptr::addr_of_mut!((*self.record()).header) }
    }

    /// `ikm_size` of <`ipc/ipc_kmsg.h`>.
    ///
    /// # Safety
    ///
    /// The message must be live.
    unsafe fn size(self) -> usize {
        unsafe { (*self.record()).size }
    }

    /// The `kmsg->ikm_size = size` assignment of `ikm_init()`.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    unsafe fn set_size(self, size: usize) {
        unsafe { (*self.record()).size = size };
    }

    /// `kmsg->ikm_header.msgh_size` of <mach/message.h>.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn header_size(self) -> c_uint {
        unsafe { (*self.header()).size() }
    }

    /// The `kmsg->ikm_header.msgh_seqno = seqno` assignment of `mach_msg()`.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    pub(crate) unsafe fn set_header_seqno(self, seqno: c_uint) {
        unsafe { (*self.header()).seqno = seqno };
    }

    /// `ikm_marequest` of <`ipc/ipc_kmsg.h`>.
    ///
    /// # Safety
    ///
    /// The message must be live.
    pub(crate) unsafe fn marequest(self) -> *mut c_void {
        unsafe { (*self.record()).marequest }
    }

    /// The `kmsg->ikm_marequest = marequest` assignment of `ikm_init()`.
    ///
    /// # Safety
    ///
    /// The message must be live and this call must own it.
    pub(crate) unsafe fn set_marequest(self, marequest: *mut c_void) {
        unsafe { (*self.record()).marequest = marequest };
    }

    /// `ikm_next` of <`ipc/ipc_kmsg.h`>.
    ///
    /// # Safety
    ///
    /// The message must be live and queued.
    unsafe fn next(self) -> *mut IpcKmsg {
        unsafe { (*self.record()).next.cast() }
    }

    /// The `kmsg->ikm_next = next` assignment.
    ///
    /// # Safety
    ///
    /// The message must be live and uniquely owned through this call.
    unsafe fn set_next(self, next: *mut IpcKmsg) {
        unsafe { (*self.record()).next = next.cast() };
    }

    /// `ikm_prev` of <`ipc/ipc_kmsg.h`>.
    ///
    /// # Safety
    ///
    /// The message must be live and queued.
    unsafe fn prev(self) -> *mut IpcKmsg {
        unsafe { (*self.record()).prev.cast() }
    }

    /// The `kmsg->ikm_prev = prev` assignment.
    ///
    /// # Safety
    ///
    /// The message must be live and uniquely owned through this call.
    unsafe fn set_prev(self, prev: *mut IpcKmsg) {
        unsafe { (*self.record()).prev = prev.cast() };
    }

    /// The `kmsg->ikm_header.msgh_remote_port = 0` of
    /// `ipc_port_destroy()`.
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

    /// The `kmsg->ikm_header.msgh_remote_port = port` assignment of
    /// `ipc_mqueue_send()`'s dead-port path.
    ///
    /// # Safety
    ///
    /// The message must be live, and the right it named must already have
    /// been consumed.
    pub(crate) unsafe fn set_remote_port(self, port: usize) {
        unsafe { (*self.header()).set_remote(port) };
    }

    /// The `ikm_init_special(kmsg, IKM_SIZE_NETWORK)` of `device/net_io.c`:
    /// mark the message as one the network pool owns.
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

/// `ipc_kmsg_cache` of `ipc/ipc_kmsg.c`: one cached message per CPU.
///
/// Each CPU touches only the slot `cpu_id()` selects, so the accesses
/// need no ordering against another CPU.  The C half reads and writes the
/// same array with the `ikm_cache()` macros.
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

/// `ipc_kmsg_enqueue()` in C.
///
/// # Safety
///
/// `queue` must point at a live `struct ipc_kmsg_queue` this caller owns,
/// and `kmsg` at a live message not already queued.
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

/// The `ipc_kmsg_rmqueue_first_macro()` of <`ipc/ipc_kmsg.h`>.
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

/// `ipc_kmsg_dequeue()` in C.
///
/// # Safety
///
/// `queue` must point at a live `struct ipc_kmsg_queue`.
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

/// `ipc_kmsg_rmqueue()` in C.
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

/// `ipc_kmsg_queue_next()` in C.
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

/// `vm_map_copy_discard()` against a raw address.
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

/// `ipc_kmsg_clean_body()` in C: release every right and buffer the body
/// names between `saddr` and `eaddr`.
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

/// `ipc_kmsg_clean_partial()` in C: clean a partially acquired message body
/// up to the failing descriptor, and, when `dolast`, the `number` rights the
/// descriptor already copied in.
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

/// `ipc_entry_lookup_failed()` of <`ipc/ipc_space.h>`: report a bogus name.
///
/// # Safety
///
/// `header` must point at the live message header being processed, and the
/// call must run in thread context.
unsafe fn entry_lookup_failed(header: *mut MachMsgHeader, port_name: c_uint) {
    if !mach_port_name_valid(port_name) {
        return;
    }

    let task = unsafe { task::current_task() };
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

    // SAFETY: the debug switch is written only by the debugger.
    if unsafe { mach_port::MACH_PORT_DEALLOCATE_DEBUG } != 0 {
        // SAFETY: the C string literal is NUL-terminated.
        unsafe { soft_debugger(c"ipc_entry_lookup".as_ptr()) };
    }
}

/// `ipc_kmsg_clean()` in C: release every right, reference and buffer the
/// message holds.
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

/// `ipc_kmsg_destroy()` in C.
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

/// `ikm_free()` of <`ipc/ipc_kmsg.h>`: free a message of any variety.
///
/// # Safety
///
/// `kmsg` must be a live message whose storage this call owns.
pub(crate) unsafe fn ikm_free(kmsg: Kmsg) {
    let size = unsafe { kmsg.size() };

    // The C tests the truncated `integer_t`, so a size with the top half
    // word set takes the `ipc_kmsg_free()` path.
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

/// `ipc_kmsg_free()` in C.
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

/// `ikm_alloc()` of <`ipc/ipc_kmsg.h`>.
pub(crate) fn ikm_alloc(size: usize) -> Option<Kmsg> {
    let buf = slab::kalloc(size.wrapping_add(IKM_OVERHEAD))?;
    Some(Kmsg(buf.cast::<IpcKmsg>()))
}

/// `ikm_init()` of <`ipc/ipc_kmsg.h`>.
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

/// `ikm_cache_alloc()` of <`ipc/ipc_kmsg.h`>.
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

/// `ikm_cache_free()` of <`ipc/ipc_kmsg.h>`: cache a page-sized message, or
/// free anything else.
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

/// `ikm_cache_free_try()` of <`ipc/ipc_kmsg.h>`: cache the message when the
/// running CPU's slot is empty; the caller keeps it otherwise.
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

/// `ipc_kmsg_get()` in C.
///
/// # Safety
///
/// `user` must name a readable user message of `size` bytes, and the caller
/// permits an allocation.
pub(crate) unsafe fn get(
    user: *const c_void,
    size: c_uint,
) -> Result<Kmsg, MsgReturn> {
    let ksize = size.wrapping_mul(IKM_EXPAND_FACTOR);

    if as_index(size) < MACH_MSG_HEADER_SIZE
        || user_is_misaligned(as_index(size))
    {
        return Err(MsgReturn::SEND_MSG_TOO_SMALL);
    }

    let kmsg = if as_index(ksize) <= IKM_SAVED_MSG_SIZE {
        cache_alloc().ok_or(MsgReturn::SEND_NO_BUFFER)?
    } else {
        let kmsg =
            ikm_alloc(as_index(ksize)).ok_or(MsgReturn::SEND_NO_BUFFER)?;
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
        return Err(MsgReturn::SEND_INVALID_DATA);
    }

    Ok(kmsg)
}

/// `ipc_kmsg_get_from_kernel()` in C.
///
/// # Safety
///
/// `msg` must name a readable kernel message of `size` bytes, and the caller
/// permits an allocation.
pub(crate) unsafe fn get_from_kernel(
    msg: *const c_void,
    size: c_uint,
) -> Result<Kmsg, MsgReturn> {
    let kmsg = ikm_alloc(as_index(size)).ok_or(MsgReturn::SEND_NO_BUFFER)?;
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

/// `ipc_kmsg_put()` in C.
///
/// # Safety
///
/// `user` must name a writable user message of `size` bytes, and `kmsg` must
/// be a live message whose clean header this call owns.
pub(crate) unsafe fn put(
    user: *mut c_void,
    kmsg: Kmsg,
    size: c_uint,
) -> MsgReturn {
    let mr = if unsafe {
        user_access::copyout(kmsg.header().cast(), user, as_index(size))
    } != 0
    {
        MsgReturn::RCV_INVALID_DATA
    } else {
        MsgReturn::SUCCESS
    };

    unsafe { cache_free(kmsg) };

    mr
}

/// `ipc_kmsg_put_to_kernel()` in C.
///
/// # Safety
///
/// `msg` must name a writable kernel message of `size` bytes, and `kmsg` a
/// live message whose clean header this call owns.
pub(crate) unsafe fn put_to_kernel(
    msg: *mut c_void,
    kmsg: Kmsg,
    size: c_uint,
) {
    unsafe {
        ptr::copy_nonoverlapping(
            kmsg.header().cast::<c_void>(),
            msg,
            as_index(size),
        );
    };

    unsafe { ikm_free(kmsg) };
}

/// `MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)`: an asynchronous send.
const BITS_ASYNC: u32 = mach_msg_bits(MACH_MSG_TYPE_COPY_SEND, 0);
/// `MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE)`:
/// a request message.
const BITS_REQUEST: u32 =
    mach_msg_bits(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
/// `MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0)`: a reply message.
const BITS_REPLY: u32 = mach_msg_bits(MACH_MSG_TYPE_PORT_SEND_ONCE, 0);

/// `ipc_kmsg_copyin_header()` in C.
///
/// # Safety
///
/// `header` must point at a live message header, `space` must be a live
/// space, and nothing may be locked.
pub(crate) unsafe fn copyin_header(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    notify: c_uint,
) -> Result<(), MsgReturn> {
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
    unsafe { space.lock_done() };

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
        unsafe { space.lock_done() };
        return false;
    }

    // SAFETY: the space is live, active, and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return false;
    }

    // SAFETY: a send entry names a live port.
    let dest_port = unsafe { IpcPort::from_raw((*entry).object()) };
    // SAFETY: the port is live and its lock is free.
    unsafe { dest_port.lock() };
    // SAFETY: the space lock is held.
    unsafe { space.lock_done() };

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
        unsafe { space.lock_done() };
        return false;
    }

    // SAFETY: the space is live, active, and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return false;
    }
    // SAFETY: a send entry names a live port.
    let dest_port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is live, active, and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(reply_name) }) else {
        unsafe { entry_lookup_failed(header, reply_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_RECEIVE {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
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
        unsafe { space.lock_done() };
        return false;
    }
    // SAFETY: the space lock is held.
    unsafe { space.lock_done() };

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
        unsafe { space.lock_done() };
        return false;
    }

    // SAFETY: the space is live, active, and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return false;
    };
    // SAFETY: the entry is live and the space is locked.
    let bits = unsafe { (*entry).bits() };
    if bits & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND_ONCE
        // SAFETY: the entry is live and the space is locked.
        || unsafe { (*entry).request() } != 0
    {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
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
        unsafe { space.lock_done() };
        return false;
    }
    // SAFETY: the port lock is held.
    unsafe { dest_port.unlock() };

    // SAFETY: the entry is live and the space is locked.
    unsafe {
        (*entry).set_object(ptr::null_mut());
        ipc_entry::dealloc(space, dest_name, entry);
        space.lock_done();

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
) -> Result<*mut c_void, MsgReturn> {
    if !mach_msg_type_port_any_send(dest_type) {
        return Err(MsgReturn::SEND_INVALID_HEADER);
    }

    if if reply_type == 0 {
        reply_name != MACH_PORT_NAME_NULL
    } else {
        !mach_msg_type_port_any_send(reply_type)
    } {
        return Err(MsgReturn::SEND_INVALID_HEADER);
    }

    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_write() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
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
                unsafe { space.lock_done() };
                return Err(MsgReturn::SEND_INVALID_NOTIFY);
            }
            None => {
                unsafe { entry_lookup_failed(header, notify) };
                // SAFETY: the space lock is held.
                unsafe { space.lock_done() };
                return Err(MsgReturn::SEND_INVALID_NOTIFY);
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
) -> Result<HeaderRights, MsgReturn> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is live, active, and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup(name) }) else {
        unsafe { entry_lookup_failed(header, name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
    };

    // SAFETY: the entry is live.
    if !unsafe { ipc_right::copyin_check(entry, reply_type) } {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_REPLY);
    }

    if dest_type == MACH_MSG_TYPE_PORT_SEND_ONCE
        || reply_type == MACH_MSG_TYPE_PORT_SEND_ONCE
    {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
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
            unsafe { space.lock_done() };
            return Err(MsgReturn::SEND_INVALID_DEST);
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
            unsafe { space.lock_done() };
            return Err(MsgReturn::SEND_INVALID_DEST);
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
            unsafe { space.lock_done() };
            return Err(MsgReturn::SEND_INVALID_DEST);
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
) -> Result<HeaderRights, MsgReturn> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is write-locked and the entry is live.
    let Ok((object, soright)) = (unsafe {
        ipc_right::copyin(space, name, entry, MACH_MSG_TYPE_PORT_SEND, false)
    }) else {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
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
) -> Result<HeaderRights, MsgReturn> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is live, active, and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
    };

    // SAFETY: the space is write-locked and the entry is live.
    let Ok((object, soright)) = (unsafe {
        ipc_right::copyin(space, dest_name, entry, dest_type, false)
    }) else {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
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
) -> Result<HeaderRights, MsgReturn> {
    let mut rights = HeaderRights::none();

    // SAFETY: the space is live, active, and write-locked.
    let Some(dest_entry) = (unsafe { space.entry_lookup(dest_name) }) else {
        unsafe { entry_lookup_failed(header, dest_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
    };

    // SAFETY: the space is live, active, and write-locked.
    let Some(reply_entry) = (unsafe { space.entry_lookup(reply_name) }) else {
        unsafe { entry_lookup_failed(header, reply_name) };
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_REPLY);
    };

    // SAFETY: the entry is live.
    if !unsafe { ipc_right::copyin_check(reply_entry, reply_type) } {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_REPLY);
    }

    // SAFETY: the space is write-locked and the entry is live.
    let Ok((object, soright)) = (unsafe {
        ipc_right::copyin(space, dest_name, dest_entry, dest_type, false)
    }) else {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::SEND_INVALID_DEST);
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
                space.lock_done();

                if !rights.dest_soright.is_null() {
                    ipc_notify::dead_name(rights.dest_soright, dest_name);
                }
                ipc_object::release(saved_reply);
            }
            return Err(MsgReturn::SEND_INVALID_DEST);
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

/// `copyin_port()` of <`ipc/copy_user.h>`: copy one user port name into a
/// kernel port.
///
/// # Safety
///
/// `src` must name a readable user name and `dst` a writable kernel port.
unsafe fn copyin_port(src: usize, dst: usize) -> c_int {
    let mut name: u32 = 0;
    if unsafe {
        user_access::copyin(
            ptr_at(src),
            ptr::from_mut(&mut name).cast::<c_void>(),
            size_of::<u32>(),
        )
    } != 0
    {
        return 1;
    }
    unsafe { ptr_at::<usize>(dst).write_unaligned(as_index(name)) };
    0
}

/// `copyout_port()` of <`ipc/copy_user.h>`: copy one kernel port into a user
/// port name.
///
/// # Safety
///
/// `src` must name a readable kernel port and `dst` a writable user name.
unsafe fn copyout_port(src: usize, dst: usize) -> c_int {
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
) -> Result<*mut c_void, MsgReturn> {
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
                return Err(MsgReturn::SEND_INVALID_MEMORY);
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
                    } != 0
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
            } != 0
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
                return Err(MsgReturn::SEND_INVALID_MEMORY);
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
            return Err(MsgReturn::SEND_INVALID_MEMORY);
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
) -> Result<(), MsgReturn> {
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
            return Err(MsgReturn::SEND_INVALID_RIGHT);
        }
    }

    Ok(())
}

/// `ipc_kmsg_copyin_body()` in C.
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
) -> Result<(), MsgReturn> {
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
            return Err(MsgReturn::SEND_MSG_TOO_SMALL);
        }

        // SAFETY: the descriptor's first word is readable.
        let word = unsafe { ptr_at::<u32>(taddr).read_unaligned() };
        if word & MSGT_LONGFORM != 0 && remaining < MSG_TYPE_LONG_SIZE {
            unsafe { clean_partial(kmsg, taddr, false, 0) };
            return Err(MsgReturn::SEND_MSG_TOO_SMALL);
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
            return Err(MsgReturn::SEND_INVALID_TYPE);
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
                return Err(MsgReturn::SEND_MSG_TOO_SMALL);
            }

            data = ptr_at(saddr);
            saddr = saddr.wrapping_add(length);
        } else {
            if eaddr.wrapping_sub(saddr) < size_of::<usize>() {
                unsafe { clean_partial(kmsg, taddr, false, 0) };
                return Err(MsgReturn::SEND_MSG_TOO_SMALL);
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

/// `ipc_kmsg_copyin()` in C.
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
) -> Result<(), MsgReturn> {
    let header = unsafe { kmsg.header() };

    unsafe { copyin_header(header, space, notify) }?;

    if unsafe { (*header).bits() } & MACH_MSGH_BITS_COMPLEX == 0 {
        return Ok(());
    }

    unsafe { copyin_body(kmsg, space, map) }
}

/// `ipc_kmsg_copyin_from_kernel()` in C.
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

/// `KERN_RESOURCE_SHORTAGE` of <`mach/kern_return.h`>.
const KERN_RESOURCE_SHORTAGE: c_int = 6;

/// The `optimized ipc_object_copyout_dest` of `ipc_kmsg_copyout_header()`:
/// consume the destination send right and return its name and the port's
/// protected payload.
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

/// `ipc_kmsg_copyout_header()` in C.
///
/// # Safety
///
/// `header` must point at a live message header, `space` must be a live
/// space, and nothing may be locked.
pub(crate) unsafe fn copyout_header(
    header: *mut MachMsgHeader,
    space: IpcSpace,
    notify: c_uint,
) -> Result<(), MsgReturn> {
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
        unsafe { space.lock_done() };
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
        unsafe { space.lock_done() };
        return false;
    }
    // SAFETY: the reply lock is held.
    if !unsafe { reply_port.is_active() } {
        // SAFETY: both locks are held.
        unsafe {
            reply_port.unlock();
            dest_port.unlock();
            space.lock_done();
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
            space.lock_done();
        }
        return false;
    };
    // The C's `gen = entry->ie_bits + IE_BITS_GEN_ONE` and the send-once
    // type.
    // SAFETY: the entry is live and the space is write-locked.
    unsafe {
        let generation = (*entry).bits().wrapping_add(IE_BITS_GEN_ONE);
        (*entry).set_bits(generation | (MACH_PORT_TYPE_SEND_ONCE | 1));
        (*entry).set_object(reply);
        space.lock_done();
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
) -> Result<CopyoutHeaderState, MsgReturn> {
    loop {
        // SAFETY: the space lock is held.
        if !unsafe { space.is_active() } {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            return Err(MsgReturn::RCV_HEADER_ERROR | MsgReturn::MSG_IPC_SPACE);
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
                unsafe { space.lock_done() };
                return Err(MsgReturn::RCV_INVALID_NOTIFY);
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
            unsafe { space.lock_done() };
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
) -> Result<bool, MsgReturn> {
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
                space.lock_done();
            }
            return Err(if error == KernError::ResourceShortage {
                MsgReturn::RCV_HEADER_ERROR | MsgReturn::MSG_IPC_KERNEL
            } else {
                MsgReturn::RCV_HEADER_ERROR | MsgReturn::MSG_IPC_SPACE
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
        space.lock_done();
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
        return Err(MsgReturn::RCV_HEADER_ERROR | MsgReturn::MSG_IPC_KERNEL);
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
    unsafe { space.lock_done() };
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
) -> Result<c_uint, MsgReturn> {
    // SAFETY: the space is live and nothing is locked.
    unsafe { space.lock_read() };
    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(MsgReturn::RCV_HEADER_ERROR | MsgReturn::MSG_IPC_SPACE);
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
            unsafe { space.lock_done() };
            return Err(MsgReturn::RCV_INVALID_NOTIFY);
        }
    }

    // SAFETY: the header names a live destination.
    unsafe { dest_port.lock() };
    // SAFETY: the space lock is held.
    unsafe { space.lock_done() };
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

/// `ipc_kmsg_copyout_object()` in C: copy out a port right, always returning
/// a name, and consuming the supplied object.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; the caller must own the
/// right `object` holds.
pub(crate) unsafe fn copyout_object(
    space: IpcSpace,
    object: *mut c_void,
    msgt_name: c_uint,
) -> (MsgReturn, c_uint) {
    if !io_valid(object) {
        // SAFETY: the object is null or dead, the only tags the C accepts.
        return (MsgReturn::SUCCESS, unsafe {
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
                        space.lock_done();
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
            return (MsgReturn::SUCCESS, name);
        }

        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
    }

    match unsafe { ipc_object::copyout(space, object, msgt_name, true) } {
        Ok(name) => (MsgReturn::SUCCESS, name),
        Err(error) => {
            // SAFETY: the failed copyout leaves the right to this call.
            unsafe { ipc_object::destroy_object(object, msgt_name) };

            if error == KernError::InvalidCapability {
                (MsgReturn::SUCCESS, MACH_PORT_NAME_DEAD)
            } else if error == KernError::ResourceShortage {
                (MsgReturn::MSG_IPC_KERNEL, MACH_PORT_NAME_NULL)
            } else {
                (MsgReturn::MSG_IPC_SPACE, MACH_PORT_NAME_NULL)
            }
        }
    }
}

/// Allocate the user buffer for one out-of-line port array of
/// [`copyout_body()`].
///
/// On failure the body before `saddr` is cleaned and the kernel return the
/// caller must report is returned.
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
) -> Result<usize, c_int> {
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
            return Err(error.as_kern_return());
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
) -> MsgReturn {
    let objects = if type_.is_inline {
        ptr_at::<*mut c_void>(saddr)
    } else {
        // SAFETY: the descriptor's out-of-line pointer is readable.
        ptr_at::<*mut c_void>(unsafe {
            ptr_at::<usize>(saddr).read_unaligned()
        })
    };

    let mut mr = MsgReturn::SUCCESS;
    for i in 0..type_.number {
        let index = as_index(i);
        // SAFETY: the array holds `number` readable objects.
        let object = unsafe { objects.add(index).read() };
        let (object_mr, name) =
            unsafe { copyout_object(space, object, type_.name) };
        mr |= object_mr;
        // SAFETY: the slot is writable.
        unsafe { objects.add(index).write(ptr_at(as_index(name))) };
    }
    mr
}

/// The `MsgReturn` bits a failed [`copyout_body()`] descriptor reports.
const fn copyout_body_failure_mr(failure_kr: c_int) -> MsgReturn {
    if failure_kr == KERN_RESOURCE_SHORTAGE {
        MsgReturn::MSG_VM_KERNEL
    } else {
        MsgReturn::MSG_VM_SPACE
    }
}

/// `ipc_kmsg_copyout_body()` in C.
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
) -> MsgReturn {
    let header = unsafe { kmsg.header() };
    let mut saddr = header.addr() + size_of::<MachMsgHeader>();
    let eaddr = header.addr() + as_index(unsafe { (*header).size() });
    let mut mr = MsgReturn::SUCCESS;

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
        let mut failed = false;
        let mut failure_kr: c_int = 0;

        if is_port && !type_.is_inline {
            match unsafe { copyout_body_alloc(map, type_, taddr, saddr) } {
                Ok(allocated) => addr = allocated,
                Err(kr) => {
                    failed = true;
                    failure_kr = kr;
                }
            }
        }

        if is_port && !failed {
            mr |= unsafe { copyout_body_objects(space, type_, saddr) };
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
                if !failed {
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
                            } != 0
                            {
                                copy_failed = true;
                                break;
                            }
                        }
                        if copy_failed {
                            failed = true;
                            failure_kr = KERN_FAILURE;
                        }
                    }

                    // SAFETY: the port data came from `kalloc()`.
                    unsafe { kfree_addr(data, length) };
                }
            } else if !failed {
                if let Some(copy) = NonNull::new(ptr_at::<VmMapCopy>(data)) {
                    // SAFETY: the map is live and unlocked, and the copy
                    // came from the sender.
                    match unsafe { map.copyout(copy) } {
                        Ok(address) => addr = address,
                        Err(error) => {
                            // SAFETY: the failed copyout leaves the copy
                            // to this call.
                            unsafe { VmMapCopy::discard(copy) };
                            failed = true;
                            failure_kr = error.as_kern_return();
                        }
                    }
                } else {
                    failed = true;
                    failure_kr = KERN_FAILURE;
                }
            }

            if failed {
                addr = 0;
                // SAFETY: the descriptor is writable.
                unsafe { write_type_size(taddr, type_.longform, 0) };
                mr |= copyout_body_failure_mr(failure_kr);
            }

            // SAFETY: the descriptor is writable.
            unsafe { write_type_deallocate(taddr, true) };
            // SAFETY: the descriptor's out-of-line slot is writable.
            unsafe { ptr_at::<usize>(saddr).write_unaligned(addr) };
            saddr = saddr.wrapping_add(size_of::<usize>());
        }

        saddr = kernel_align(saddr);
    }

    mr
}

/// `ipc_kmsg_copyout()` in C.
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
) -> MsgReturn {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };

    if let Err(error) = unsafe { copyout_header(header, space, notify) } {
        return error;
    }

    let mut mr = MsgReturn::SUCCESS;
    if mbits & MACH_MSGH_BITS_COMPLEX != 0 {
        // SAFETY: the header copied out, so the body belongs to this call.
        mr = unsafe { copyout_body(kmsg, space, map) };
        if mr != MsgReturn::SUCCESS {
            mr |= MsgReturn::RCV_BODY_ERROR;
        }
    }

    mr
}

/// `ipc_kmsg_copyout_pseudo()` in C.
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
) -> MsgReturn {
    let header = unsafe { kmsg.header() };
    let mbits = unsafe { (*header).bits() };
    let dest = ptr_at::<c_void>(unsafe { (*header).remote() });
    let reply = ptr_at::<c_void>(unsafe { (*header).local() });
    let dest_type = mach_msg_bits_remote(mbits);
    let reply_type = mach_msg_bits_local(mbits);

    // Both calls always run; both names are wanted.
    let (dest_mr, dest_name) =
        unsafe { copyout_object(space, dest, dest_type) };
    let (reply_mr, reply_name) =
        unsafe { copyout_object(space, reply, reply_type) };
    let mut mr = dest_mr | reply_mr;

    // SAFETY: the header is live and owned by this call.
    unsafe {
        (*header).set_bits(mbits & !MACH_MSGH_BITS_CIRCULAR);
        (*header).set_remote(as_index(dest_name));
        (*header).set_local(as_index(reply_name));
    }

    if mbits & MACH_MSGH_BITS_COMPLEX != 0 {
        // SAFETY: the header copied out, so the body belongs to this call.
        mr |= unsafe { copyout_body(kmsg, space, map) };
    }

    mr
}

/// `ipc_kmsg_copyout_dest()` in C.
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
