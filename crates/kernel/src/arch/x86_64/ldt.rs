// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/ldt.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The default local descriptor table.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::VM_MAX_USER_ADDRESS;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::mp_desc;
use crate::arch::x86_64::pcb;
use crate::arch::x86_64::pcb::{DescriptorTable, RealDescriptor};
use crate::arch::x86_64::pmap;
use crate::arch::x86_64::seg;
use crate::kern::debug::kpanic;
use core::ffi::c_int;
use core::mem::size_of;
use core::ptr;

/// The lowest user address.
const VM_MIN_USER_ADDRESS: VmOffset = 0;

/// The default table every thread starts with.
pub(crate) static mut LDT: DescriptorTable<{ seg::LDTSZ }> =
    DescriptorTable([RealDescriptor::ZERO; seg::LDTSZ]);

/// `EFL_IF` and `EFL_IOPL_USER`: the flags mask programmed into
/// `MSR_REG_FMASK`.
const EFL_IF: u64 = 0x0000_0200;
const EFL_IOPL_USER: u64 = 0x0000_3000;

/// The size bits of the user code and data segments.
const USER_SEGMENT_SIZEBITS: u8 = seg::SZ_64;

/// The `limit` of the LDT's own GDT descriptor.
const LDT_LIMIT: usize = seg::LDTSZ * size_of::<RealDescriptor>() - 1;

const _: () = assert!(LDT_LIMIT <= u16::MAX as usize);

/// The `i`th entry of the default LDT.
///
/// # Safety
///
/// `index` must be below `LDTSZ`.
pub(crate) unsafe fn entry(index: usize) -> RealDescriptor {
    unsafe {
        ptr::addr_of!(LDT)
            .cast::<RealDescriptor>()
            .add(index)
            .read()
    }
}

/// Enables the SYSCALL instruction and points it at the kernel's entry.
fn enable_syscall() {
    if !pmap::cpu_has_feature(pmap::CPU_FEATURE_SEP) {
        kpanic!("ldt_fill", "syscall support is missing on 64 bit")
    }

    let efer = pcb::read_msr(pcb::MSR_REG_EFER) | pcb::MSR_EFER_SCE;
    pcb::write_msr(pcb::MSR_REG_EFER, efer);
    // The kernel addresses fit the 64-bit MSR of the LP64 target.
    let syscall64 = locore::syscall64 as *const () as usize as u64;
    pcb::write_msr(pcb::MSR_REG_LSTAR, syscall64);
    let star = ((u64::from(seg::USER_CS as u16) - 16) << 16
        | u64::from(seg::KERNEL_CS as u16))
        << 32;
    pcb::write_msr(pcb::MSR_REG_STAR, star);
    pcb::write_msr(pcb::MSR_REG_FMASK, EFL_IF | EFL_IOPL_USER);
}

/// Installs `myldt` in `gdt_table` with the user code and data segments,
/// enables SYSCALL, and loads it.
///
/// # Safety
///
/// `myldt` must be a live LDT and `gdt_table` a table with a `KERNEL_LDT`
/// descriptor.
unsafe fn ldt_fill(
    myldt: *mut RealDescriptor,
    gdt_table: *mut RealDescriptor,
) {
    unsafe {
        seg::fill_gdt_sys_descriptor(
            gdt_table,
            seg::KERNEL_LDT,
            myldt as VmOffset,
            LDT_LIMIT,
            seg::ACC_PL_K | seg::ACC_LDT,
            0,
        );
    }

    enable_syscall();

    let user_limit = VM_MAX_USER_ADDRESS - VM_MIN_USER_ADDRESS - 4096;
    unsafe {
        seg::fill_ldt_descriptor(
            myldt,
            seg::USER_CS,
            VM_MIN_USER_ADDRESS,
            user_limit,
            seg::ACC_PL_U | seg::ACC_CODE_R,
            USER_SEGMENT_SIZEBITS,
        );
        seg::fill_ldt_descriptor(
            myldt,
            seg::USER_DS,
            VM_MIN_USER_ADDRESS,
            user_limit,
            seg::ACC_PL_U | seg::ACC_DATA_W,
            USER_SEGMENT_SIZEBITS,
        );
    }

    seg::lldt(seg::KERNEL_LDT as u16);
}

/// Loads the default table on the boot CPU.
pub(crate) fn ldt_init() {
    // SAFETY: `ldt` is the default table and `gdt` the boot CPU's full one.
    unsafe {
        ldt_fill(
            ptr::addr_of_mut!(LDT).cast::<RealDescriptor>(),
            ptr::addr_of_mut!(gdt::GDT).cast::<RealDescriptor>(),
        );
    }
}

/// Loads the default table on the application processor `cpu`.
pub(crate) fn ap_ldt_init(cpu: c_int) {
    // SAFETY: `mp_desc_init()` stored this CPU's table set before any CPU ran
    // `ap_ldt_init()` on it.
    let table =
        unsafe { (*ptr::addr_of!(mp_desc::MP_DESC_TABLE))[cpu as usize] };
    // SAFETY: `mp_desc_init()` stored this CPU's table set before any CPU ran
    // `ap_ldt_init()` on it.
    let mygdt = unsafe { (*ptr::addr_of!(mp_desc::MP_GDT))[cpu as usize] };
    // SAFETY: both are this CPU's live records.
    unsafe {
        ldt_fill(
            ptr::addr_of_mut!((*table).ldt).cast::<RealDescriptor>(),
            mygdt,
        );
    }
}
