// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kernel task state segment.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::mp_desc;
use crate::arch::x86_64::pcb::{RealDescriptor, TaskTss};
use crate::arch::x86_64::seg;
use core::ffi::{c_int, c_ushort};
use core::mem::size_of;
use core::ptr;
use mach_page::smp::{CpuId, MAX_NCPUS};
use x86_64::instructions::tables;
use x86_64::structures::gdt::SegmentSelector;

/// An offset outside the permission bitmap, which disables all permission.
const IOPB_INVAL: c_ushort = 0x2fff;

/// The boot CPU's TSS, which the other CPUs get copies of through `MP_KTSS`.
pub(crate) static mut KTSS: TaskTss =
    // SAFETY: every field is an integer, a byte, or a byte array, so the
    // all-zero pattern is a valid `TaskTss`.
    unsafe { core::mem::zeroed() };

/// The ring-0 stack each CPU's TSS names until a thread's pcb replaces it.
/// One per CPU: two exceptions at once on two CPUs must not meet on one
/// stack.
static mut EXCEPTION_STACK: [[c_int; 1024]; MAX_NCPUS] =
    [[0; 1024]; MAX_NCPUS];

/// The `IST1` stack each CPU switches to on a double fault. One per CPU, for
/// the same reason; this one is never replaced by a thread's.
static mut DOUBLE_FAULT_STACK: [[c_int; 1024]; MAX_NCPUS] =
    [[0; 1024]; MAX_NCPUS];

/// The one-past-the-end address of a stack array.
fn stack_top(stack: *mut [c_int; 1024]) -> VmOffset {
    // SAFETY: the array has 1024 `c_int`s, so the element past its end is
    // the one-past-the-end pointer Rust allows.
    unsafe { stack.cast::<c_int>().add(1024) as VmOffset }
}

/// Installs `myktss` in `mygdt` with CPU `cpu`'s stacks and no I/O
/// permission, and loads it.
///
/// # Safety
///
/// `myktss` must be a live TSS and `mygdt` a table with a `KERNEL_TSS`
/// descriptor, and `cpu` must name a CPU that is coming up.
unsafe fn ktss_fill(
    myktss: *mut TaskTss,
    mygdt: *mut RealDescriptor,
    cpu: c_int,
) {
    unsafe {
        seg::fill_gdt_sys_descriptor(
            mygdt,
            seg::KERNEL_TSS,
            myktss as VmOffset,
            size_of::<TaskTss>() - 1,
            seg::Access::PL_K | seg::Access::TSS,
            seg::SegSize::empty(),
        );
    }

    unsafe {
        (*myktss).tss.rsp0 =
            stack_top(ptr::addr_of_mut!(EXCEPTION_STACK[cpu as usize])) as u64;
        (*myktss).tss.ist1 =
            stack_top(ptr::addr_of_mut!(DOUBLE_FAULT_STACK[cpu as usize]))
                as u64;
    }

    unsafe {
        (*myktss).tss.io_bit_map_offset = IOPB_INVAL;
        // Set the last byte in the I/O bitmap to all 1's.
        (*myktss).barrier = 0xff;
    }

    // SAFETY: `KERNEL_TSS` names the descriptor filled above, which points at
    // the caller's TSS.
    unsafe { tables::load_tss(SegmentSelector(seg::KERNEL_TSS as u16)) };
}

/// Loads the boot CPU's TSS.
pub(crate) fn ktss_init() {
    // SAFETY: `ktss` is the boot CPU's TSS and `gdt` its full table.
    unsafe {
        ktss_fill(
            ptr::addr_of_mut!(KTSS),
            ptr::addr_of_mut!(gdt::GDT).cast::<RealDescriptor>(),
            CpuId::BOOT.bits() as c_int,
        );
    }
}

/// Loads the TSS of the application processor `cpu`.
pub(crate) fn ap_ktss_init(cpu: c_int) {
    // SAFETY: `mp_desc_init()` stored this CPU's TSS and GDT before any CPU
    // ran `ap_ktss_init()` on them.
    let table =
        unsafe { (*ptr::addr_of!(mp_desc::MP_DESC_TABLE))[cpu as usize] };
    // SAFETY: `mp_desc_init()` stored this CPU's TSS and GDT before any CPU
    // ran `ap_ktss_init()` on them.
    let mygdt = unsafe { (*ptr::addr_of!(mp_desc::MP_GDT))[cpu as usize] };
    // SAFETY: both are this CPU's live records.
    unsafe { ktss_fill(ptr::addr_of_mut!((*table).ktss), mygdt, cpu) };
}
