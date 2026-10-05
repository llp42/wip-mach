// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/gdt.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The global descriptor table.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::mp_desc::{self, GDTSZ};
use crate::arch::x86_64::pcb;
use crate::arch::x86_64::pcb::{DescriptorTable, RealDescriptor};
use crate::arch::x86_64::{per_cpu, seg};
use crate::kern::smp::CpuId;
use core::ffi::{c_int, c_ulong, c_ushort};
use core::mem::size_of;
use core::ptr;

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
            seg::ACC_PL_K | seg::ACC_CODE_R,
            seg::SZ_64,
        );
        seg::fill_gdt_descriptor(
            mygdt,
            seg::KERNEL_DS,
            0,
            0,
            seg::ACC_PL_K | seg::ACC_DATA_W,
            seg::SZ_64,
        );
        seg::fill_gdt_descriptor(
            mygdt,
            seg::LINEAR_DS,
            0,
            0,
            seg::ACC_PL_K | seg::ACC_DATA_W,
            seg::SZ_64,
        );
    }

    let pdesc = seg::PseudoDescriptor {
        limit: GDT_LIMIT as c_ushort,
        linear_base: mygdt as VmOffset as c_ulong,
    };
    seg::lgdt(&pdesc);
}

/// Points `%gs` at `cpu`'s per-CPU block, and clears the swapped base.
fn reload_gs_base(cpu: CpuId) {
    // Kernel addresses fit in the 64-bit MSR of the LP64 target.
    let base = ptr::from_ref(per_cpu::per_cpu_at(cpu)) as usize as u64;
    pcb::write_msr(pcb::MSR_REG_GSBASE, base);
    pcb::write_msr(pcb::MSR_REG_KGSBASE, 0);
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
