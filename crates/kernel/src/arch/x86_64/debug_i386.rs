// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/debug_i386.c and i386/i386/debug.h:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The saved-state dump and the debug trace, which `i386/i386/debug_i386.c`
//! used to define and `i386/i386/debug.h` declares.
//!
//! The C kept the trace under `#ifdef DEBUG`, which no configured kernel
//! defines, and the assembly stub that filled the buffer is deleted; the
//! Rust build keeps the buffer and its dump.

use crate::arch::x86_64::pcb::I386SavedState;
use crate::arch::x86_64::trap;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::task::Task;
use core::ffi::{c_char, c_int, c_long, c_uint};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;

/// `DEBUG_TRACE_LEN` of <i386/debug.h>: the entries after which the trace
/// buffer wraps.
const DEBUG_TRACE_LEN: usize = 512;

/// `struct debug_trace_entry` of `i386/i386/debug_i386.c`.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct DebugTraceEntry {
    pub filename: *mut c_char,
    pub linenum: c_int,
}

const _: () = {
    assert!(size_of::<DebugTraceEntry>() == 16);
    assert!(align_of::<DebugTraceEntry>() == align_of::<*mut c_char>());
    assert!(offset_of!(DebugTraceEntry, filename) == 0);
    assert!(offset_of!(DebugTraceEntry, linenum) == 8);
};

/// `debug_trace_buf` of `i386/i386/debug_i386.c`.
pub static mut DEBUG_TRACE_BUF: [DebugTraceEntry; DEBUG_TRACE_LEN] =
    [DebugTraceEntry {
        filename: ptr::null_mut(),
        linenum: 0,
    }; DEBUG_TRACE_LEN];

/// `debug_trace_pos` of `i386/i386/debug_i386.c`.
pub static mut DEBUG_TRACE_POS: c_int = 0;

/// `syscall_trace` of `i386/i386/debug_i386.c`.
pub static mut SYSCALL_TRACE: c_int = 0;

/// `syscall_trace_task` of `i386/i386/debug_i386.c`.
pub static mut SYSCALL_TRACE_TASK: *mut Task = ptr::null_mut();

/// `dump_ss()` of <i386/debug.h>.
///
/// # Safety
///
/// `st` must point at a live `I386SavedState`.
pub(crate) unsafe fn dump_ss(st: *const I386SavedState) {
    let st = unsafe { &*st };
    kprint!(
        "Dump of i386_saved_state {:x}:\n",
        ptr::from_ref(st).expose_provenance(),
    );

    kprint!(
        "RAX {:016x} RBX {:016x} RCX {:016x} RDX {:016x}\n",
        st.eax,
        st.ebx,
        st.ecx,
        st.edx,
    );
    kprint!(
        "RSI {:016x} RDI {:016x} RBP {:016x} RSP {:016x}\n",
        st.esi,
        st.edi,
        st.ebp,
        st.uesp,
    );
    kprint!(
        "R8  {:016x} R9  {:016x} R10 {:016x} R11 {:016x}\n",
        st.r8,
        st.r9,
        st.r10,
        st.r11,
    );
    kprint!(
        "R12 {:016x} R13 {:016x} R14 {:016x} R15 {:016x}\n",
        st.r12,
        st.r13,
        st.r14,
        st.r15,
    );
    kprint!("RIP {:016x} EFLAGS {:08x}\n", st.eip, st.efl);

    kprint!(
        "trapno {}: {}, error {:08x}\n",
        st.trapno as c_long,
        CStrArg::from(trap::trap_name(st.trapno as c_uint)),
        st.err,
    );
}
