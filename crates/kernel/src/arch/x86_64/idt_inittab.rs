// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/idt_inittab.S and x86_64/idt_inittab.S:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   All Rights Reserved.
//
//   Permission to use, copy, modify and distribute this software and its
//   documentation is hereby granted, provided that both the copyright
//   notice and this permission notice appear in all copies of the
//   software, derivative works or modified versions, and any portions
//   thereof, and that both notices appear in supporting documentation.
//
//   CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
//   CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
//   ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
//
//   Carnegie Mellon requests users of this software to return to
//
//    Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
//    School of Computer Science
//    Carnegie Mellon University
//    Pittsburgh PA 15213-3890
//
//   any improvements or extensions that they make and grant Carnegie Mellon
//   the rights to redistribute these changes.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The IDT init table, which `i386/i386/idt_inittab.S` and
//! `x86_64/idt_inittab.S` used to define.

use crate::arch::x86_64::idt::IdtInitEntry;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::seg;
use core::arch::naked_asm;
use core::ffi::c_ushort;

/// The table's length: the 31 vectors the assembly tables carried plus the
/// terminator entry.
const IDT_INITTAB_LEN: usize = 32;

// The gate type of `EXCEPTION`/`EXCEP_USR`/`EXCEP_ERR` in <i386/seg.h>.
// The C field is an `unsigned short`, and `From` is not a `const fn`, so
// the access byte is widened here.
/// `ACC_PL_K | ACC_TRAP_GATE`, the kernel trap gate.
const EXCEPTION: c_ushort = (seg::ACC_PL_K | seg::ACC_TRAP_GATE) as c_ushort;
/// `ACC_PL_U | ACC_TRAP_GATE`, the user-accessible trap gate.
const EXCEP_USR: c_ushort = (seg::ACC_PL_U | seg::ACC_TRAP_GATE) as c_ushort;
/// `ACC_PL_K | ACC_INTR_GATE`, the kernel interrupt gate.
const EXCEP_ERR: c_ushort = (seg::ACC_PL_K | seg::ACC_INTR_GATE) as c_ushort;

/// The `ENTRY()` body of the `EXCEPTION` and `EXCEP_USR` macros: clear the
/// error-code slot, push the vector, and join the common trap path.
macro_rules! trap_stub {
    ($($vector:expr => $name:ident),+ $(,)?) => {
        $(
            /// # Safety
            ///
            /// Entered only by the CPU through the gate whose vector names
            /// this stub.
            #[unsafe(naked)]
            unsafe extern "C" fn $name() {
                naked_asm!(
                    "pushq $0",
                    "pushq ${vector}",
                    "jmp {alltraps}",
                    vector = const $vector,
                    alltraps = sym locore::alltraps,
                    options(att_syntax),
                );
            }
        )+
    };
}

/// The `ENTRY()` body of the `EXCEP_ERR` macro: the CPU already pushed the
/// error code, so only the vector is missing from the frame.
macro_rules! error_stub {
    ($vector:expr => $name:ident $(,)?) => {
        /// # Safety
        ///
        /// Entered only by the CPU through the gate whose vector names
        /// this stub.
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "pushq ${vector}",
                "jmp {alltraps}",
                vector = const $vector,
                alltraps = sym locore::alltraps,
                options(att_syntax),
            );
        }
    };
}

trap_stub! {
    0x00 => t_zero_div,
    0x03 => t_int3,
    0x04 => t_into,
    0x05 => t_bounds,
    0x06 => t_invop,
    0x07 => t_nofpu,
    0x09 => a_fpu_over,
    0x0a => a_inv_tss,
    0x0f => t_trap_0f,
    0x10 => t_fpu_err,
    0x11 => t_trap_11,
    0x12 => t_trap_12,
    0x13 => t_trap_13,
    0x14 => t_trap_14,
    0x15 => t_trap_15,
    0x16 => t_trap_16,
    0x17 => t_trap_17,
    0x18 => t_trap_18,
    0x19 => t_trap_19,
    0x1a => t_trap_1a,
    0x1b => t_trap_1b,
    0x1c => t_trap_1c,
    0x1d => t_trap_1d,
    0x1e => t_trap_1e,
    0x1f => t_trap_1f,
}

error_stub! {
    0x0c => t_stack_fault,
}

/// The `EXCEP_SPC(0x08, ...)` entry: it points at `t_dbl_fault` of
/// `x86_64/locore.S` with IST 1.
const DBL_FAULT: IdtInitEntry =
    IdtInitEntry::with_ist(locore::t_dbl_fault, 0x08, EXCEPTION, 1);

/// The gate table `idt_fill()` walks, terminated by an all-zero entry.
pub(crate) static IDT_INITTAB: [IdtInitEntry; IDT_INITTAB_LEN] = [
    IdtInitEntry::new(t_zero_div, 0x00, EXCEPTION),
    IdtInitEntry::new(locore::t_debug, 0x01, EXCEPTION),
    IdtInitEntry::new(t_int3, 0x03, EXCEP_USR),
    IdtInitEntry::new(t_into, 0x04, EXCEP_USR),
    IdtInitEntry::new(t_bounds, 0x05, EXCEP_USR),
    IdtInitEntry::new(t_invop, 0x06, EXCEPTION),
    IdtInitEntry::new(t_nofpu, 0x07, EXCEPTION),
    DBL_FAULT,
    IdtInitEntry::new(a_fpu_over, 0x09, EXCEPTION),
    IdtInitEntry::new(a_inv_tss, 0x0a, EXCEPTION),
    IdtInitEntry::new(locore::t_segnp, 0x0b, EXCEPTION),
    IdtInitEntry::new(t_stack_fault, 0x0c, EXCEP_ERR),
    IdtInitEntry::new(locore::t_gen_prot, 0x0d, EXCEPTION),
    IdtInitEntry::new(locore::t_page_fault, 0x0e, EXCEPTION),
    IdtInitEntry::new(t_trap_0f, 0x0f, EXCEPTION),
    IdtInitEntry::new(t_fpu_err, 0x10, EXCEPTION),
    IdtInitEntry::new(t_trap_11, 0x11, EXCEPTION),
    IdtInitEntry::new(t_trap_12, 0x12, EXCEPTION),
    IdtInitEntry::new(t_trap_13, 0x13, EXCEPTION),
    IdtInitEntry::new(t_trap_14, 0x14, EXCEPTION),
    IdtInitEntry::new(t_trap_15, 0x15, EXCEPTION),
    IdtInitEntry::new(t_trap_16, 0x16, EXCEPTION),
    IdtInitEntry::new(t_trap_17, 0x17, EXCEPTION),
    IdtInitEntry::new(t_trap_18, 0x18, EXCEPTION),
    IdtInitEntry::new(t_trap_19, 0x19, EXCEPTION),
    IdtInitEntry::new(t_trap_1a, 0x1a, EXCEPTION),
    IdtInitEntry::new(t_trap_1b, 0x1b, EXCEPTION),
    IdtInitEntry::new(t_trap_1c, 0x1c, EXCEPTION),
    IdtInitEntry::new(t_trap_1d, 0x1d, EXCEPTION),
    IdtInitEntry::new(t_trap_1e, 0x1e, EXCEPTION),
    IdtInitEntry::new(t_trap_1f, 0x1f, EXCEPTION),
    IdtInitEntry::terminator(),
];
