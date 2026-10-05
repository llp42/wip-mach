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

//! The descriptor table constants, selectors and fillers.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::mp_desc::RealGate;
use crate::arch::x86_64::pcb::RealDescriptor;
use core::arch::asm;
use core::ffi::{c_int, c_ulong, c_ushort};
use core::mem::{align_of, offset_of, size_of};

/// A 64-bit segment.
pub(crate) const SZ_64: u8 = 0x2;
/// A 32-bit segment.
pub(crate) const SZ_32: u8 = 0x4;
/// A 4K granularity limit field.
pub(crate) const SZ_G: u8 = 0x8;

/// The accessed bit.
pub(crate) const ACC_A: u8 = 0x01;
/// The user descriptor type bit.
pub(crate) const ACC_TYPE_USER: u8 = 0x10;

/// A local descriptor table.
pub(crate) const ACC_LDT: u8 = 0x02;
/// A 16-bit call gate.
pub(crate) const ACC_CALL_GATE_16: u8 = 0x04;
/// A task state segment.
pub(crate) const ACC_TSS: u8 = 0x09;
/// A call gate.
pub(crate) const ACC_CALL_GATE: u8 = 0x0c;
/// An interrupt gate.
pub(crate) const ACC_INTR_GATE: u8 = 0x0e;
/// A trap gate.
pub(crate) const ACC_TRAP_GATE: u8 = 0x0f;

/// A data segment.
pub(crate) const ACC_DATA: u8 = 0x10;
/// A writable data segment.
pub(crate) const ACC_DATA_W: u8 = 0x12;
/// An expand-down data segment.
pub(crate) const ACC_DATA_E: u8 = 0x14;
/// An expand-down writable data segment.
pub(crate) const ACC_DATA_EW: u8 = 0x16;
/// A code segment.
pub(crate) const ACC_CODE: u8 = 0x18;
/// A readable code segment.
pub(crate) const ACC_CODE_R: u8 = 0x1a;
/// A conforming code segment.
pub(crate) const ACC_CODE_C: u8 = 0x1c;
/// A conforming readable code segment.
pub(crate) const ACC_CODE_CR: u8 = 0x1e;

/// The privilege-level mask.
pub(crate) const ACC_PL: u8 = 0x60;
/// Kernel access only.
pub(crate) const ACC_PL_K: u8 = 0;
/// User access.
pub(crate) const ACC_PL_U: u8 = 0x60;
/// The segment-present bit.
pub(crate) const ACC_P: u8 = 0x80;

/// The local selector bit.
pub(crate) const SEL_LDT: c_int = 0x04;
/// The privilege-level mask.
pub(crate) const SEL_PL: c_int = 0x03;
/// The user privilege level.
pub(crate) const SEL_PL_U: c_int = 0x03;

/// The kernel code selector.
pub(crate) const KERNEL_CS: c_int = 0x08;
/// The kernel data selector.
pub(crate) const KERNEL_DS: c_int = 0x10;
/// The selector of the kernel's LDT.
pub(crate) const KERNEL_LDT: c_int = 0x18;
/// The selector of the kernel TSS; the 64-bit TSS descriptor takes two
/// entries.
pub(crate) const KERNEL_TSS: c_int = 0x40;
/// The linear data selector.
pub(crate) const LINEAR_DS: c_int = 0x38;
/// The first of the per-thread GDT entries.
pub(crate) const USER_GDT: c_int = 0x48;
/// The number of per-thread GDT entries.
pub(crate) const USER_GDT_SLOTS: usize = 2;

/// The user system-call gate selector.
pub(crate) const USER_SCALL: c_int = 0x07;
/// The user code selector.
pub(crate) const USER_CS: c_int = 0x1f;
/// The user data selector.
pub(crate) const USER_DS: c_int = 0x17;
/// The number of LDT descriptors.
pub(crate) const LDTSZ: usize = 4;

/// The two-word descriptor plus the extension an `x86_64` system descriptor
/// carries.
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

/// The operand LGDT and LIDT read.
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

/// The descriptor index of `selector`.
pub(crate) const fn sel_idx(selector: c_int) -> usize {
    // Every caller passes a segment constant or a hardware selector, so the
    // arithmetic shift is never negative.
    (selector >> 3) as usize
}

/// Fills `desc` with a base, a limit, an access byte and size bits.
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

/// Fills the 16-byte system descriptor `desc` with a base, a limit, an access
/// byte and size bits.
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

/// Fills `gate` with an entry `offset`, a selector, an access byte and a word
/// count.
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

/// Fills the descriptor `segment` of the GDT at `gdt`.
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

/// Fills the system descriptor `segment` of the GDT at `gdt`.
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

/// Fills the descriptor `selector` of the LDT at `ldt`.
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

/// Fills the gate `int_num` of the IDT at `idt`.
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

/// Loads the GDT `pdesc` describes.
pub(crate) fn lgdt(pdesc: &PseudoDescriptor) {
    // SAFETY: `lgdt` reads the operand at CPL0; the reference guarantees the
    // record is live for the load.
    unsafe {
        asm!("lgdt [{p}]", p = in(reg) pdesc, options(nostack, readonly));
    };
}

/// Loads the IDT `pdesc` describes.
pub(crate) fn lidt(pdesc: &PseudoDescriptor) {
    // SAFETY: `lidt` reads the operand at CPL0; the reference guarantees the
    // record is live for the load.
    unsafe {
        asm!("lidt [{p}]", p = in(reg) pdesc, options(nostack, readonly));
    };
}

/// Loads the LDT `selector` names.
pub(crate) fn lldt(selector: c_ushort) {
    // SAFETY: `lldt` loads the LDT register with a selector the kernel built
    // in its GDT.
    unsafe {
        asm!("lldt {selector:x}", selector = in(reg) selector, options(nostack));
    };
}

/// Loads the task register with `selector`.
pub(crate) fn ltr(selector: c_ushort) {
    // SAFETY: `ltr` loads the task register with a selector the kernel built
    // in its GDT.
    unsafe {
        asm!("ltr {selector:x}", selector = in(reg) selector, options(nostack));
    };
}
