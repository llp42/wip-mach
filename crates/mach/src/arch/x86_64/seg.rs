// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The descriptor table constants, selectors and fillers.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::mp_desc::RealGate;
use crate::arch::x86_64::pcb::RealDescriptor;
use core::ffi::{c_int, c_ushort};
use core::mem::{align_of, offset_of, size_of};

bitflags::bitflags! {
    /// The size nibble of a segment descriptor.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SegSize: u8 {
        /// A 64-bit segment.
        const LONG = 0x2;
        /// A 32-bit segment.
        const DEFAULT_32 = 0x4;
        /// A 4K granularity limit field.
        const GRANULARITY = 0x8;
        // The available bit.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// A descriptor's access byte: the present and accessed bits, the
    /// privilege-level field and the descriptor type.  The types are values
    /// of the low nibble and the user-type bit, not flags of their own.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Access: u8 {
        /// The accessed bit.
        const A = 0x01;
        /// A local descriptor table.
        const LDT = 0x02;
        /// A 16-bit call gate.
        const CALL_GATE_16 = 0x04;
        /// A task state segment.
        const TSS = 0x09;
        /// A call gate.
        const CALL_GATE = 0x0c;
        /// An interrupt gate.
        const INTR_GATE = 0x0e;
        /// A trap gate.
        const TRAP_GATE = 0x0f;
        /// The user descriptor type bit.
        const TYPE_USER = 0x10;
        /// A data segment.
        const DATA = 0x10;
        /// A writable data segment.
        const DATA_W = 0x12;
        /// An expand-down data segment.
        const DATA_E = 0x14;
        /// An expand-down writable data segment.
        const DATA_EW = 0x16;
        /// A code segment.
        const CODE = 0x18;
        /// A readable code segment.
        const CODE_R = 0x1a;
        /// A conforming code segment.
        const CODE_C = 0x1c;
        /// A conforming readable code segment.
        const CODE_CR = 0x1e;
        /// The privilege-level field.
        const PL = 0x60;
        /// User access.
        const PL_U = 0x60;
        /// The segment-present bit.
        const P = 0x80;
        // The type bits the kernel does not name.
        const _ = !0;
    }
}

impl Access {
    /// Kernel access only: privilege level 0.
    pub(crate) const PL_K: Self = Self::empty();
}

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

/// The descriptor index of `selector`.
pub(crate) const fn sel_idx(selector: c_int) -> usize {
    // Every caller passes a segment constant or a hardware selector, so the
    // arithmetic shift is never negative.
    (selector >> 3) as usize
}

bitfield::bitfield! {
    /// A segment descriptor's first word: the low 16 bits of the limit and
    /// of the base.
    struct DescriptorLow(u32);
    u32;
    limit_low, set_limit_low: 15, 0;
    base_low, set_base_low: 31, 16;
}

bitfield::bitfield! {
    /// A segment descriptor's second word: the base's middle byte, the access
    /// byte, the limit's high nibble, the size bits and the base's high byte.
    struct DescriptorHigh(u32);
    u32;
    base_med, set_base_med: 7, 0;
    access, set_access: 15, 8;
    limit_high, set_limit_high: 19, 16;
    size_bits, set_size_bits: 23, 20;
    base_high, set_base_high: 31, 24;
}

bitfield::bitfield! {
    /// A gate's first word: the low 16 bits of the entry offset, and the
    /// selector.
    struct GateLow(u32);
    u32;
    offset_low, set_offset_low: 15, 0;
    selector, set_selector: 31, 16;
}

bitfield::bitfield! {
    /// A gate's second word: the word count, the access byte and bits 16 to
    /// 31 of the entry offset.
    struct GateHigh(u32);
    u32;
    word_count, set_word_count: 7, 0;
    access, set_access: 15, 8;
    offset_high, set_offset_high: 31, 16;
}

/// The two words of a descriptor for `base`, a page-granular or byte-granular
/// `limit` (its low 20 bits), `access` and `sizebits`.
fn descriptor_words(
    base: VmOffset,
    limit: u32,
    access: Access,
    sizebits: SegSize,
) -> (u32, u32) {
    let mut low = DescriptorLow(0);
    low.set_limit_low(limit);
    low.set_base_low(base as u32);

    let mut high = DescriptorHigh(0);
    high.set_base_med((base >> 16) as u32);
    high.set_access(u32::from(access.union(Access::P).bits()));
    high.set_limit_high(limit >> 16);
    high.set_size_bits(u32::from(sizebits.bits()));
    high.set_base_high((base >> 24) as u32);

    (low.0, high.0)
}

/// Fills `desc` with a base, a limit, an access byte and size bits.
pub(crate) fn fill_descriptor(
    desc: &mut RealDescriptor,
    base: VmOffset,
    mut limit: VmOffset,
    access: Access,
    mut sizebits: SegSize,
) {
    if limit > 0xfffff {
        limit >>= 12;
        sizebits |= SegSize::GRANULARITY;
    }

    // The descriptor keeps the low 20 bits of the limit, as the C's masks
    // did, so the narrowing loses nothing it keeps.
    (desc.limit_low_base_low, desc.access_and_base_high) =
        descriptor_words(base, limit as u32, access, sizebits);
}

/// Fills the 16-byte system descriptor `desc` with a base, a limit, an access
/// byte and size bits.
pub(crate) fn fill_descriptor64(
    desc: &mut RealDescriptor64,
    base: VmOffset,
    mut limit: u32,
    access: Access,
    mut sizebits: SegSize,
) {
    if limit > 0xfffff {
        limit >>= 12;
        sizebits |= SegSize::GRANULARITY;
    }

    (desc.limit_low_base_low, desc.access_and_base_high) =
        descriptor_words(base, limit, access, sizebits);
    desc.base_ext = (base >> 32) as u32;
    desc.reserved = 0;
}

/// Fills `gate` with an entry `offset`, a selector, an access byte and a word
/// count.
pub(crate) fn fill_gate(
    gate: &mut RealGate,
    offset: VmOffset,
    selector: c_ushort,
    access: Access,
    word_count: u8,
) {
    let mut low = GateLow(0);
    low.set_offset_low(offset as u32);
    low.set_selector(u32::from(selector));
    gate.offset_low_selector = low.0;

    let mut high = GateHigh(0);
    high.set_word_count(u32::from(word_count));
    high.set_access(u32::from(access.union(Access::P).bits()));
    high.set_offset_high((offset >> 16) as u32);
    gate.word_count_access_offset_high = high.0;

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
    access: Access,
    sizebits: SegSize,
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
    access: Access,
    sizebits: SegSize,
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
    access: Access,
    sizebits: SegSize,
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
    access: Access,
    dword_count: u8,
) {
    let gate = unsafe { &mut *idt.add(int_num as usize) };
    fill_gate(gate, entry, selector as c_ushort, access, dword_count);
}
