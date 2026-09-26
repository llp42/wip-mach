// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/int_init.c:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt gate setup, which `i386/i386at/int_init.c` used to define and
//! `i386/i386at/int_init.h` declares.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::apic;
use crate::arch::x86_64::idt;
use crate::arch::x86_64::int_stubs::INT_ENTRY_TABLE;
use crate::arch::x86_64::mp_desc::{self, RealGate};
use crate::arch::x86_64::seg;
use crate::config::NINTR;
use core::ffi::c_int;
use core::ptr;

/// `IOAPIC_INT_BASE` of <i386at/idt.h>: the first IOAPIC vector.
const IOAPIC_INT_BASE: usize = 0x30;
/// `CALL_AST_CHECK` of <i386at/idt.h>: the remote AST request vector.
pub(crate) const CALL_AST_CHECK: usize = 0xfa;
/// `CALL_PMAP_UPDATE` of <i386at/idt.h>: the TLB shootdown vector.
pub(crate) const CALL_PMAP_UPDATE: usize = 0xfb;

/// The installation address of `int_entry_table[i]`, or zero when `i` is
/// outside the table.
fn entry_address(i: usize) -> VmOffset {
    INT_ENTRY_TABLE
        .get(i)
        .copied()
        .flatten()
        .map_or(0, |stub| stub as VmOffset)
}

/// `int_fill()` of `i386/i386at/int_init.c`.
///
/// # Safety
///
/// `myidt` must be valid for `NINTR` interrupt gates and the three vectors
/// after them.
unsafe fn int_fill(myidt: *mut RealGate) {
    for i in 0..NINTR {
        // SAFETY: the generated table holds `NINTR` interrupt entries, and
        // the IOAPIC vectors are inside the IDT.
        unsafe {
            seg::fill_idt_gate(
                myidt,
                IOAPIC_INT_BASE as c_int + i as c_int,
                entry_address(i),
                seg::KERNEL_CS,
                seg::ACC_PL_K | seg::ACC_INTR_GATE,
                0,
            );
        }
    }

    // SAFETY: the generated table holds the three service entries after the
    // interrupt lines, and each vector is inside the IDT.
    unsafe {
        seg::fill_idt_gate(
            myidt,
            CALL_AST_CHECK as c_int,
            entry_address(NINTR),
            seg::KERNEL_CS,
            seg::ACC_PL_K | seg::ACC_INTR_GATE,
            0,
        );
        seg::fill_idt_gate(
            myidt,
            CALL_PMAP_UPDATE as c_int,
            entry_address(NINTR + 1),
            seg::KERNEL_CS,
            seg::ACC_PL_K | seg::ACC_INTR_GATE,
            0,
        );
        seg::fill_idt_gate(
            myidt,
            apic::IOAPIC_SPURIOUS_BASE as c_int,
            entry_address(NINTR + 2),
            seg::KERNEL_CS,
            seg::ACC_PL_K | seg::ACC_INTR_GATE,
            0,
        );
    }
}

/// `int_init()` of <`i386at/int_init.h`>.
pub(crate) fn int_init() {
    // SAFETY: `idt` is the boot CPU's table, valid for the vectors installed.
    unsafe { int_fill(ptr::addr_of_mut!(idt::IDT).cast::<RealGate>()) };
}

/// `ap_int_init()` of <`i386at/int_init.h`>.
pub(crate) fn ap_int_init(cpu: c_int) {
    // SAFETY: `mp_desc_init()` stored this CPU's table before any CPU ran
    // `ap_int_init()` on it.
    let myidt =
        unsafe { (*ptr::addr_of!(mp_desc::MP_DESC_TABLE))[cpu as usize] };
    // SAFETY: `myidt` is this CPU's full table.
    unsafe { int_fill(ptr::addr_of_mut!((*myidt).idt).cast::<RealGate>()) };
}
