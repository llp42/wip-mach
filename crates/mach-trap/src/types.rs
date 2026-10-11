// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The data-only records of the traps and the up-call.

use core::ffi::{c_int, c_long, c_uint};
use core::mem::{align_of, offset_of, size_of};
use mach_ipc::{MachMsgHeader, MachMsgType};
use mach_vm::param::{VmOffset, VmSize};

/// The arguments of `syscall_vm_map()`, which the trap passes as eleven
/// words.
pub struct VmMapRequest {
    /// The name of the task whose map receives the mapping.
    pub target_map: c_uint,
    /// Where the caller wants the mapping and the kernel writes where it went.
    pub address: *mut VmOffset,
    /// The size of the mapping, in bytes.
    pub size: VmSize,
    /// The alignment mask the chosen address must clear.
    pub mask: VmOffset,
    /// Nonzero to let the kernel choose the address.
    pub anywhere: c_int,
    /// The name of the memory object to map, or null for zero-fill memory.
    pub memory_object: c_uint,
    /// The offset in the memory object the mapping starts at.
    pub offset: VmOffset,
    /// Nonzero to map a copy of the object's data.
    pub copy: c_int,
    /// The protection the mapping starts with.
    pub cur_protection: c_int,
    /// The highest protection the mapping may be raised to.
    pub max_protection: c_int,
    /// What a child task inherits of the mapping.
    pub inheritance: c_int,
}

/// The `exception_raise` request message the up-call builds for an
/// exception server.
#[repr(C)]
pub(crate) struct MachException {
    pub(crate) head: MachMsgHeader,
    pub(crate) thread_type: MachMsgType,
    pub(crate) thread: usize,
    pub(crate) task_type: MachMsgType,
    pub(crate) task: usize,
    pub(crate) exception_type: MachMsgType,
    pub(crate) exception: c_int,
    pub(crate) code_type: MachMsgType,
    pub(crate) code: c_int,
    pub(crate) subcode_type: MachMsgType,
    pub(crate) subcode: c_long,
}

const _: () = {
    assert!(size_of::<MachException>() == 112);
    assert!(align_of::<MachException>() == 8);
    assert!(offset_of!(MachException, head) == 0);
    assert!(offset_of!(MachException, thread_type) == 32);
    assert!(offset_of!(MachException, thread) == 40);
    assert!(offset_of!(MachException, task_type) == 48);
    assert!(offset_of!(MachException, task) == 56);
    assert!(offset_of!(MachException, exception_type) == 64);
    assert!(offset_of!(MachException, exception) == 72);
    assert!(offset_of!(MachException, code_type) == 80);
    assert!(offset_of!(MachException, code) == 88);
    assert!(offset_of!(MachException, subcode_type) == 96);
    assert!(offset_of!(MachException, subcode) == 104);
};
