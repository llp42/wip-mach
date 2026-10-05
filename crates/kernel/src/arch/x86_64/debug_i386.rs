// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/debug_i386.c and i386/i386/debug.h:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The saved-state dump.

use crate::arch::x86_64::pcb::I386SavedState;
use crate::arch::x86_64::trap;
use crate::kern::console::{CStrArg, kprint};
use core::ffi::{c_long, c_uint};
use core::ptr;

/// Prints the saved registers at `st`.
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
