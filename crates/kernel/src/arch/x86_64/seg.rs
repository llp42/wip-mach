// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/seg.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
// Derived from i386/i386/gdt.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory (CSL).
// Derived from i386/i386/ldt.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory (CSL).
// Derived from i386/i386at/idt-gen.h:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The descriptor table constants and fillers of `i386/i386/seg.h`, with
//! the selector constants of `i386/i386/gdt.h`, `i386/i386/ldt.h` and
//! `i386/i386at/idt-gen.h`.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::mp_desc::RealGate;
use crate::arch::x86_64::pcb::RealDescriptor;
use core::arch::asm;
use core::ffi::{c_int, c_ulong, c_ushort};
use core::mem::{align_of, offset_of, size_of};

/// `SZ_64` of <i386/seg.h>: a 64-bit segment.
pub(crate) const SZ_64: u8 = 0x2;
/// `SZ_32` of <i386/seg.h>: a 32-bit segment.
pub(crate) const SZ_32: u8 = 0x4;
/// `SZ_G` of <i386/seg.h>: a 4K granularity limit field.
pub(crate) const SZ_G: u8 = 0x8;

/// `ACC_A` of <i386/seg.h>: the accessed bit.
pub(crate) const ACC_A: u8 = 0x01;
/// `ACC_TYPE_USER` of <i386/seg.h>: the user descriptor type bit.
pub(crate) const ACC_TYPE_USER: u8 = 0x10;

/// `ACC_LDT` of <i386/seg.h>: a local descriptor table.
pub(crate) const ACC_LDT: u8 = 0x02;
/// `ACC_CALL_GATE_16` of <i386/seg.h>: a 16-bit call gate.
pub(crate) const ACC_CALL_GATE_16: u8 = 0x04;
/// `ACC_TSS` of <i386/seg.h>: a task state segment.
pub(crate) const ACC_TSS: u8 = 0x09;
/// `ACC_CALL_GATE` of <i386/seg.h>: a call gate.
pub(crate) const ACC_CALL_GATE: u8 = 0x0c;
/// `ACC_INTR_GATE` of <i386/seg.h>: an interrupt gate.
pub(crate) const ACC_INTR_GATE: u8 = 0x0e;
/// `ACC_TRAP_GATE` of <i386/seg.h>: a trap gate.
pub(crate) const ACC_TRAP_GATE: u8 = 0x0f;

/// `ACC_DATA` of <i386/seg.h>: a data segment.
pub(crate) const ACC_DATA: u8 = 0x10;
/// `ACC_DATA_W` of <i386/seg.h>: a writable data segment.
pub(crate) const ACC_DATA_W: u8 = 0x12;
/// `ACC_DATA_E` of <i386/seg.h>: an expand-down data segment.
pub(crate) const ACC_DATA_E: u8 = 0x14;
/// `ACC_DATA_EW` of <i386/seg.h>: an expand-down writable data segment.
pub(crate) const ACC_DATA_EW: u8 = 0x16;
/// `ACC_CODE` of <i386/seg.h>: a code segment.
pub(crate) const ACC_CODE: u8 = 0x18;
/// `ACC_CODE_R` of <i386/seg.h>: a readable code segment.
pub(crate) const ACC_CODE_R: u8 = 0x1a;
/// `ACC_CODE_C` of <i386/seg.h>: a conforming code segment.
pub(crate) const ACC_CODE_C: u8 = 0x1c;
/// `ACC_CODE_CR` of <i386/seg.h>: a conforming readable code segment.
pub(crate) const ACC_CODE_CR: u8 = 0x1e;

/// `ACC_PL` of <i386/seg.h>: the privilege-level mask.
pub(crate) const ACC_PL: u8 = 0x60;
/// `ACC_PL_K` of <i386/seg.h>: kernel access only.
pub(crate) const ACC_PL_K: u8 = 0;
/// `ACC_PL_U` of <i386/seg.h>: user access.
pub(crate) const ACC_PL_U: u8 = 0x60;
/// `ACC_P` of <i386/seg.h>: the segment-present bit.
pub(crate) const ACC_P: u8 = 0x80;

/// `SEL_LDT` of <i386/seg.h>: the local selector bit.
pub(crate) const SEL_LDT: c_int = 0x04;
/// `SEL_PL` of <i386/seg.h>: the privilege-level mask.
pub(crate) const SEL_PL: c_int = 0x03;
/// `SEL_PL_U` of <i386/seg.h>: the user privilege level.
pub(crate) const SEL_PL_U: c_int = 0x03;

/// `KERNEL_CS` of <i386/gdt.h>.
pub(crate) const KERNEL_CS: c_int = 0x08;
/// `KERNEL_DS` of <i386/gdt.h>.
pub(crate) const KERNEL_DS: c_int = 0x10;
/// `KERNEL_LDT` of <i386/gdt.h>.
pub(crate) const KERNEL_LDT: c_int = 0x18;
/// `KERNEL_TSS` of <i386/gdt.h>; the 64-bit TSS descriptor takes two entries.
pub(crate) const KERNEL_TSS: c_int = 0x40;
/// `LINEAR_DS` of <i386/gdt.h>.
pub(crate) const LINEAR_DS: c_int = 0x38;
/// `USER_GDT` of <i386/gdt.h>: the per-thread GDT entries.
pub(crate) const USER_GDT: c_int = 0x48;
/// `USER_GDT_SLOTS` of <i386/gdt.h>.
pub(crate) const USER_GDT_SLOTS: usize = 2;

/// `USER_SCALL` of <i386/ldt.h>.
pub(crate) const USER_SCALL: c_int = 0x07;
/// `USER_CS` of <i386/ldt.h>.
pub(crate) const USER_CS: c_int = 0x1f;
/// `USER_DS` of <i386/ldt.h>.
pub(crate) const USER_DS: c_int = 0x17;
/// `LDTSZ` of <i386/ldt.h>.
pub(crate) const LDTSZ: usize = 4;

/// `struct real_descriptor64` of <i386/seg.h>: the two-word descriptor plus
/// the extension an `x86_64` system descriptor carries.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub(crate) struct RealDescriptor64 {
    pub limit_low_base_low: u32,
    pub access_and_base_high: u32,
    pub base_ext: u32,
    pub reserved: u32,
}

const _: () = {
    assert!(size_of::<RealDescriptor64>() == 16);
    assert!(align_of::<RealDescriptor64>() == align_of::<u32>());
    assert!(offset_of!(RealDescriptor64, limit_low_base_low) == 0);
    assert!(offset_of!(RealDescriptor64, access_and_base_high) == 4);
    assert!(offset_of!(RealDescriptor64, base_ext) == 8);
    assert!(offset_of!(RealDescriptor64, reserved) == 12);
};

/// `struct pseudo_descriptor` of <i386/seg.h>: the operand `LGDT` and `LIDT`
/// read.  The C's trailing `pad` is not part of that operand.
#[repr(C, packed)]
#[allow(missing_docs)]
pub(crate) struct PseudoDescriptor {
    pub limit: c_ushort,
    pub linear_base: c_ulong,
}

const _: () = assert!(align_of::<PseudoDescriptor>() == 1);

const _: () = {
    assert!(size_of::<PseudoDescriptor>() == 10);
    assert!(offset_of!(PseudoDescriptor, limit) == 0);
    assert!(offset_of!(PseudoDescriptor, linear_base) == 2);
};

/// `sel_idx()` of <i386/seg.h>.
pub(crate) const fn sel_idx(selector: c_int) -> usize {
    // Every caller passes a segment constant or a hardware selector, so the
    // arithmetic shift is never negative.
    (selector >> 3) as usize
}

/// `fill_descriptor()` of <i386/seg.h>.
pub(crate) fn fill_descriptor(
    desc: &mut RealDescriptor,
    base: VmOffset,
    mut limit: VmOffset,
    access: u8,
    mut sizebits: u8,
) {
    if limit > 0xfffff {
        limit >>= 12;
        sizebits |= SZ_G;
    }

    let limit_low = (limit & 0xffff) as u32;
    let base_low = (base & 0xffff) as u32;
    let base_med = ((base >> 16) & 0xff) as u32;
    let limit_high = ((limit >> 16) & 0xf) as u32;
    let base_high = ((base >> 24) & 0xff) as u32;

    desc.limit_low_base_low = limit_low | (base_low << 16);
    desc.access_and_base_high = base_med
        | (u32::from(access | ACC_P) << 8)
        | (limit_high << 16)
        | (u32::from(sizebits) << 20)
        | (base_high << 24);
}

/// `fill_descriptor64()` of <i386/seg.h>.
pub(crate) fn fill_descriptor64(
    desc: &mut RealDescriptor64,
    base: VmOffset,
    mut limit: u32,
    access: u8,
    mut sizebits: u8,
) {
    if limit > 0xfffff {
        limit >>= 12;
        sizebits |= SZ_G;
    }

    let limit_low = limit & 0xffff;
    let base_low = (base & 0xffff) as u32;
    let base_med = ((base >> 16) & 0xff) as u32;
    let limit_high = (limit >> 16) & 0xf;
    let base_high = ((base >> 24) & 0xff) as u32;

    desc.limit_low_base_low = limit_low | (base_low << 16);
    desc.access_and_base_high = base_med
        | (u32::from(access | ACC_P) << 8)
        | (limit_high << 16)
        | (u32::from(sizebits) << 20)
        | (base_high << 24);
    desc.base_ext = (base >> 32) as u32;
    desc.reserved = 0;
}

/// `fill_gate()` of <i386/seg.h>.
pub(crate) fn fill_gate(
    gate: &mut RealGate,
    offset: VmOffset,
    selector: c_ushort,
    access: u8,
    word_count: u8,
) {
    gate.offset_low_selector =
        (offset & 0xffff) as u32 | (u32::from(selector) << 16);
    gate.word_count_access_offset_high = u32::from(word_count)
        | (u32::from(access | ACC_P) << 8)
        | ((((offset >> 16) & 0xffff) as u32) << 16);

    gate.offset_ext = (offset >> 32) as u32;
    gate.reserved = 0;
}

/// `_fill_gdt_descriptor()` of <i386/gdt.h>.
///
/// # Safety
///
/// `gdt` must be valid for `sel_idx(segment) + 1` descriptors.
pub(crate) unsafe fn fill_gdt_descriptor(
    gdt: *mut RealDescriptor,
    segment: c_int,
    base: VmOffset,
    limit: VmOffset,
    access: u8,
    sizebits: u8,
) {
    let desc = unsafe { &mut *gdt.add(sel_idx(segment)) };
    fill_descriptor(desc, base, limit, access, sizebits);
}

/// `_fill_gdt_sys_descriptor()` of <i386/gdt.h>.
///
/// # Safety
///
/// `gdt` must be valid for the two entries a 64-bit system descriptor takes.
pub(crate) unsafe fn fill_gdt_sys_descriptor(
    gdt: *mut RealDescriptor,
    segment: c_int,
    base: VmOffset,
    limit: VmOffset,
    access: u8,
    sizebits: u8,
) {
    let desc =
        unsafe { &mut *gdt.add(sel_idx(segment)).cast::<RealDescriptor64>() };

    // `TaskTss` is 8297 bytes, far below the 32-bit limit `fill_descriptor64`
    // takes.
    fill_descriptor64(desc, base, limit as u32, access, sizebits);
}

/// `fill_ldt_descriptor()` of <i386/ldt.h>.
///
/// # Safety
///
/// `ldt` must be valid for `sel_idx(selector) + 1` descriptors.
pub(crate) unsafe fn fill_ldt_descriptor(
    ldt: *mut RealDescriptor,
    selector: c_int,
    base: VmOffset,
    limit: VmOffset,
    access: u8,
    sizebits: u8,
) {
    let desc = unsafe { &mut *ldt.add(sel_idx(selector)) };
    fill_descriptor(desc, base, limit, access, sizebits);
}

/// `fill_idt_gate()` of <i386/i386at/idt-gen.h>.
///
/// # Safety
///
/// `idt` must be valid for `int_num + 1` gates.
pub(crate) unsafe fn fill_idt_gate(
    idt: *mut RealGate,
    int_num: c_int,
    entry: VmOffset,
    selector: c_int,
    access: u8,
    dword_count: u8,
) {
    let gate = unsafe { &mut *idt.add(int_num as usize) };
    fill_gate(gate, entry, selector as c_ushort, access, dword_count);
}

/// `lgdt()` of <i386/seg.h>.
pub(crate) fn lgdt(pdesc: &PseudoDescriptor) {
    // SAFETY: `lgdt` reads the operand at CPL0; the reference guarantees the
    // record is live for the load.
    unsafe {
        asm!("lgdt [{p}]", p = in(reg) pdesc, options(nostack, readonly));
    };
}

/// `lidt()` of <i386/seg.h>.
pub(crate) fn lidt(pdesc: &PseudoDescriptor) {
    // SAFETY: `lidt` reads the operand at CPL0; the reference guarantees the
    // record is live for the load.
    unsafe {
        asm!("lidt [{p}]", p = in(reg) pdesc, options(nostack, readonly));
    };
}

/// `lldt()` of <i386/seg.h>.
pub(crate) fn lldt(selector: c_ushort) {
    // SAFETY: `lldt` loads the LDT register with a selector the kernel built
    // in its GDT.
    unsafe {
        asm!("lldt {selector:x}", selector = in(reg) selector, options(nostack));
    };
}

/// `ltr()` of <i386/tss.h>.
pub(crate) fn ltr(selector: c_ushort) {
    // SAFETY: `ltr` loads the task register with a selector the kernel built
    // in its GDT.
    unsafe {
        asm!("ltr {selector:x}", selector = in(reg) selector, options(nostack));
    };
}
