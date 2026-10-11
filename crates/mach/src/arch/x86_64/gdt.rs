// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The global descriptor table.

use crate::arch::x86_64::mp_desc::{self, GDTSZ};
use crate::arch::x86_64::pcb::{DescriptorTable, RealDescriptor};
use crate::arch::x86_64::{per_cpu, seg};
use core::ffi::c_int;
use core::mem::size_of;
use core::ptr;
use mach_thread::smp::CpuId;
use x86_64::VirtAddr;
use x86_64::instructions::tables;
use x86_64::registers::model_specific::{GsBase, KernelGsBase};
use x86_64::structures::DescriptorTablePointer;

/// The boot CPU's table, which the other CPUs get copies of through `MP_GDT`.
pub(crate) static mut GDT: DescriptorTable<GDTSZ> =
    DescriptorTable([RealDescriptor::ZERO; GDTSZ]);

/// The `limit` of the pseudo-descriptor [`gdt_fill`] loads, a 16-bit field.
const GDT_LIMIT: usize = GDTSZ * size_of::<RealDescriptor>() - 1;

const _: () = assert!(GDT_LIMIT <= u16::MAX as usize);

/// Fills the kernel descriptors of `mygdt` and loads it.
///
/// # Safety
///
/// `mygdt` must be valid for `GDTSZ` descriptors.
unsafe fn gdt_fill(mygdt: *mut RealDescriptor) {
    unsafe {
        seg::fill_gdt_descriptor(
            mygdt,
            seg::KERNEL_CS,
            0,
            0,
            seg::Access::PL_K | seg::Access::CODE_R,
            seg::SegSize::LONG,
        );
        seg::fill_gdt_descriptor(
            mygdt,
            seg::KERNEL_DS,
            0,
            0,
            seg::Access::PL_K | seg::Access::DATA_W,
            seg::SegSize::LONG,
        );
        seg::fill_gdt_descriptor(
            mygdt,
            seg::LINEAR_DS,
            0,
            0,
            seg::Access::PL_K | seg::Access::DATA_W,
            seg::SegSize::LONG,
        );
    }

    let pdesc = DescriptorTablePointer {
        limit: GDT_LIMIT as u16,
        base: VirtAddr::from_ptr(mygdt),
    };
    // SAFETY: the caller's table holds `GDTSZ` descriptors and outlives the
    // CPU's use of it, and its code and data selectors are the ones loaded.
    unsafe { tables::lgdt(&pdesc) };
}

/// Points `%gs` at `cpu`'s per-CPU block, and clears the swapped base.
fn reload_gs_base(cpu: CpuId) {
    // SAFETY: the writes run on `cpu` itself, before it runs anything that
    // reads the bases; a CPU's block is a static that outlives it, and the
    // base a `swapgs` swaps in is the thread's, which `switch_ktss` writes
    // before the thread runs.
    unsafe {
        GsBase::write(VirtAddr::from_ptr(per_cpu::per_cpu_at(cpu)));
        KernelGsBase::write(VirtAddr::zero());
    }
}

/// Loads the boot CPU's table and its `%gs` base.
pub(crate) fn gdt_init() {
    // SAFETY: `gdt` is the boot CPU's table, valid for `GDTSZ` descriptors.
    unsafe { gdt_fill(ptr::addr_of_mut!(GDT).cast::<RealDescriptor>()) };
    reload_gs_base(CpuId::BOOT);
}

/// Loads the table of the application processor `cpu` and its `%gs` base.
pub(crate) fn ap_gdt_init(cpu: c_int) {
    // SAFETY: `mp_desc_init()` stored this CPU's `MP_GDT[cpu]` entry, a full
    // table, before any CPU ran `ap_gdt_init()` on it.
    let mygdt = unsafe { (*ptr::addr_of!(mp_desc::MP_GDT))[cpu as usize] };
    // SAFETY: `mygdt` is this CPU's full table.
    unsafe { gdt_fill(mygdt) };
    // SAFETY: the AP boot path passes its own `cpu_id()`, which
    // `init()` recorded below `MAX_NCPUS`.
    reload_gs_base(unsafe { CpuId::from_c_int(cpu) });
}
