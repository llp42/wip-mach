// SPDX-License-Identifier: CMU-Mach
// Derived from kern/syscall_sw.c and kern/syscall_sw.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer Systems
//   Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The system-call trap table, which `kern/syscall_sw.c` used to define for
//! <`kern/syscall_sw.h`>.
//!
//! The assembly syscall entry points index `mach_trap_table` at the stride
//! the header's `mach_trap_t` fixes, so the table and its entries keep the C
//! layout exactly.

use crate::ipc::mach_msg::mach_msg_trap;
use crate::kern::debug::soft_debugger;
use crate::kern::error::Error;
use crate::kern::eventcount::{evc_wait, evc_wait_clear};
use crate::kern::ipc_host::mach_host_self_entry;
use crate::kern::ipc_mig::{
    syscall_device_write_request_entry, syscall_device_writev_request_entry,
    syscall_mach_port_allocate_entry, syscall_mach_port_allocate_name_entry,
    syscall_mach_port_deallocate_entry, syscall_mach_port_insert_right_entry,
    syscall_task_create_entry, syscall_task_set_special_port_entry,
    syscall_task_suspend_entry, syscall_task_terminate_entry,
    syscall_thread_depress_abort_entry, syscall_vm_allocate_entry,
    syscall_vm_deallocate_entry, syscall_vm_map_entry, thread_set_self_state,
};
use crate::kern::ipc_tt::{
    mach_reply_port_entry, mach_task_self_entry, mach_thread_self_entry,
};
use crate::kern::syscall_subr::{
    mach_print, swtch_entry, swtch_pri_entry, thread_switch_entry,
};
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of, transmute};
use core::sync::atomic::{AtomicI32, Ordering};

/// `MACH_PORT_NULL` in <mach/port.h>: the null name `null_port()` returns.
const MACH_PORT_NULL: c_uint = 0;

/// `mach_trap_t` of <`kern/syscall_sw.h>`: one entry of the syscall table the
/// assembly indexes and `syscall_trace_print()` names.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachTrap {
    pub mach_trap_arg_count: c_int,
    pub mach_trap_function: Option<unsafe extern "C" fn()>,
    pub mach_trap_stack: c_int,
    pub mach_trap_name: *const c_char,
}

const _: () = {
    assert!(size_of::<MachTrap>() == 32);
    assert!(align_of::<MachTrap>() == align_of::<u64>());
    assert!(offset_of!(MachTrap, mach_trap_arg_count) == 0);
    assert!(offset_of!(MachTrap, mach_trap_function) == 8);
    assert!(offset_of!(MachTrap, mach_trap_stack) == 16);
    assert!(offset_of!(MachTrap, mach_trap_name) == 24);
};

// SAFETY: The table and every function and string it points at are immutable
// once the static is initialized, so sharing an entry between CPUs only ever
// reads it.
unsafe impl Sync for MachTrap {}

/// `kern_invalid_debug` of `kern/syscall_sw.c`: trap into the debugger when an
/// invalid system call runs.
///
/// The C read and wrote the flag without synchronization; `Relaxed` is that
/// plain access, and the flag gates a debugger message and nothing else.
static KERN_INVALID_DEBUG: AtomicI32 = AtomicI32::new(0);

/// `null_port` of `kern/syscall_sw.c`: the entry for the reserved port traps
/// 10 through 13 and 55 through 56.
unsafe extern "C" fn null_port() -> c_uint {
    if KERN_INVALID_DEBUG.load(Ordering::Relaxed) != 0 {
        // SAFETY: `SoftDebugger` accepts a NUL-terminated message and only
        // prints it.
        unsafe { soft_debugger(c"null_port mach trap".as_ptr()) };
    }
    MACH_PORT_NULL
}

/// `kern_invalid` of `kern/syscall_sw.c`: the entry for every unimplemented
/// system call.
unsafe extern "C" fn kern_invalid() -> c_int {
    if KERN_INVALID_DEBUG.load(Ordering::Relaxed) != 0 {
        // SAFETY: `SoftDebugger` accepts a NUL-terminated message and only
        // prints it.
        unsafe { soft_debugger(c"kern_invalid mach trap".as_ptr()) };
    }
    c_int::from(Error::InvalidArgument)
}

/// The `MACH_TRAP`/`MACH_TRAP_STACK` macros of <`kern/syscall_sw.h>`: one table
/// entry, with the routine cast to the type-erased `generic_trap_function`
/// the macros cast it to.
const fn trap(
    function: *const c_void,
    arg_count: c_int,
    stack: c_int,
    name: *const c_char,
) -> MachTrap {
    MachTrap {
        mach_trap_arg_count: arg_count,
        // SAFETY: Every caller passes the address of a function with the C
        // calling convention, and a function address is a non-null pointer of
        // the erased function pointer's width.
        mach_trap_function: unsafe {
            transmute::<*const c_void, Option<unsafe extern "C" fn()>>(
                function,
            )
        },
        mach_trap_stack: stack,
        mach_trap_name: name,
    }
}

/// The C `sizeof(mach_trap_table) / sizeof(mach_trap_table[0])`, and the
/// table's length.
const MACH_TRAP_TABLE_LEN: usize = 130;

const _: () = assert!(MACH_TRAP_TABLE_LEN <= c_int::MAX as usize);

/// `mach_trap_table` of `kern/syscall_sw.c`: one entry per syscall number, read
/// by the `x86_64` system-call entries and by `syscall_trace_print()`.
pub static MACH_TRAP_TABLE: [MachTrap; MACH_TRAP_TABLE_LEN] = [
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(null_port as *const c_void, 0, 0, c"null_port".as_ptr()),
    trap(null_port as *const c_void, 0, 0, c"null_port".as_ptr()),
    trap(null_port as *const c_void, 0, 0, c"null_port".as_ptr()),
    trap(null_port as *const c_void, 0, 0, c"null_port".as_ptr()),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(evc_wait as *const c_void, 1, 1, c"evc_wait".as_ptr()),
    trap(
        evc_wait_clear as *const c_void,
        1,
        1,
        c"evc_wait_clear".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        mach_msg_trap as *const c_void,
        7,
        1,
        c"mach_msg_trap".as_ptr(),
    ),
    trap(
        mach_reply_port_entry as *const c_void,
        0,
        0,
        c"mach_reply_port".as_ptr(),
    ),
    trap(
        mach_thread_self_entry as *const c_void,
        0,
        0,
        c"mach_thread_self".as_ptr(),
    ),
    trap(
        mach_task_self_entry as *const c_void,
        0,
        0,
        c"mach_task_self".as_ptr(),
    ),
    trap(
        mach_host_self_entry as *const c_void,
        0,
        0,
        c"mach_host_self".as_ptr(),
    ),
    trap(mach_print as *const c_void, 1, 1, c"mach_print".as_ptr()),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        syscall_device_writev_request_entry as *const c_void,
        6,
        0,
        c"syscall_device_writev_request".as_ptr(),
    ),
    trap(
        syscall_device_write_request_entry as *const c_void,
        6,
        0,
        c"syscall_device_write_request".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(null_port as *const c_void, 0, 0, c"null_port".as_ptr()),
    trap(null_port as *const c_void, 0, 0, c"null_port".as_ptr()),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        swtch_pri_entry as *const c_void,
        1,
        1,
        c"swtch_pri".as_ptr(),
    ),
    trap(swtch_entry as *const c_void, 0, 1, c"swtch".as_ptr()),
    trap(
        thread_switch_entry as *const c_void,
        3,
        1,
        c"thread_switch".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        syscall_vm_map_entry as *const c_void,
        11,
        0,
        c"syscall_vm_map".as_ptr(),
    ),
    trap(
        syscall_vm_allocate_entry as *const c_void,
        4,
        0,
        c"syscall_vm_allocate".as_ptr(),
    ),
    trap(
        syscall_vm_deallocate_entry as *const c_void,
        3,
        0,
        c"syscall_vm_deallocate".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        syscall_task_create_entry as *const c_void,
        3,
        0,
        c"syscall_task_create".as_ptr(),
    ),
    trap(
        syscall_task_terminate_entry as *const c_void,
        1,
        0,
        c"syscall_task_terminate".as_ptr(),
    ),
    trap(
        syscall_task_suspend_entry as *const c_void,
        1,
        0,
        c"syscall_task_suspend".as_ptr(),
    ),
    trap(
        syscall_task_set_special_port_entry as *const c_void,
        3,
        0,
        c"syscall_task_set_special_port".as_ptr(),
    ),
    trap(
        syscall_mach_port_allocate_entry as *const c_void,
        3,
        0,
        c"syscall_mach_port_allocate".as_ptr(),
    ),
    trap(
        syscall_mach_port_deallocate_entry as *const c_void,
        2,
        0,
        c"syscall_mach_port_deallocate".as_ptr(),
    ),
    trap(
        syscall_mach_port_insert_right_entry as *const c_void,
        4,
        0,
        c"syscall_mach_port_insert_right".as_ptr(),
    ),
    trap(
        syscall_mach_port_allocate_name_entry as *const c_void,
        3,
        0,
        c"syscall_mach_port_allocate_name".as_ptr(),
    ),
    trap(
        syscall_thread_depress_abort_entry as *const c_void,
        1,
        0,
        c"syscall_thread_depress_abort".as_ptr(),
    ),
    trap(
        thread_set_self_state as *const c_void,
        3,
        0,
        c"thread_set_self_state".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
    trap(
        kern_invalid as *const c_void,
        0,
        0,
        c"kern_invalid".as_ptr(),
    ),
];

const _: () = assert!(MACH_TRAP_TABLE.len() == MACH_TRAP_TABLE_LEN);

/// `mach_trap_count` of `kern/syscall_sw.c`: the number of syscall entries.
pub static MACH_TRAP_COUNT: c_int = MACH_TRAP_TABLE_LEN as c_int;
