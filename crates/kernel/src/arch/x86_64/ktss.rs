// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/ktss.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel task state segment.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::mp_desc;
use crate::arch::x86_64::pcb::{RealDescriptor, TaskTss};
use crate::arch::x86_64::seg;
use core::ffi::{c_int, c_ushort};
use core::mem::size_of;
use core::ptr;

/// An offset outside the permission bitmap, which disables all permission.
const IOPB_INVAL: c_ushort = 0x2fff;

/// The boot CPU's TSS, which the other CPUs get copies of through `MP_KTSS`.
pub(crate) static mut KTSS: TaskTss =
    // SAFETY: every field is an integer, a byte, or a byte array, so the
    // all-zero pattern is a valid `TaskTss`.
    unsafe { core::mem::zeroed() };

/// The ring-0 stack the TSS names until a thread's pcb replaces it.
static mut EXCEPTION_STACK: [c_int; 1024] = [0; 1024];

/// The `IST1` stack, which a double fault switches to.
static mut DOUBLE_FAULT_STACK: [c_int; 1024] = [0; 1024];

/// The one-past-the-end address of a stack array.
fn stack_top(stack: *mut [c_int; 1024]) -> VmOffset {
    // SAFETY: the array has 1024 `c_int`s, so the element past its end is
    // the one-past-the-end pointer Rust allows.
    unsafe { stack.cast::<c_int>().add(1024) as VmOffset }
}

/// Installs `myktss` in `mygdt` with its stacks and no I/O permission, and
/// loads it.
///
/// # Safety
///
/// `myktss` must be a live TSS and `mygdt` a table with a `KERNEL_TSS`
/// descriptor.
unsafe fn ktss_fill(myktss: *mut TaskTss, mygdt: *mut RealDescriptor) {
    unsafe {
        seg::fill_gdt_sys_descriptor(
            mygdt,
            seg::KERNEL_TSS,
            myktss as VmOffset,
            size_of::<TaskTss>() - 1,
            seg::ACC_PL_K | seg::ACC_TSS,
            0,
        );
    }

    unsafe {
        (*myktss).tss.rsp0 =
            stack_top(ptr::addr_of_mut!(EXCEPTION_STACK)) as u64;
        (*myktss).tss.ist1 =
            stack_top(ptr::addr_of_mut!(DOUBLE_FAULT_STACK)) as u64;
    }

    unsafe {
        (*myktss).tss.io_bit_map_offset = IOPB_INVAL;
        // Set the last byte in the I/O bitmap to all 1's.
        (*myktss).barrier = 0xff;
    }

    seg::ltr(seg::KERNEL_TSS as c_ushort);
}

/// Loads the boot CPU's TSS.
pub(crate) fn ktss_init() {
    // SAFETY: `ktss` is the boot CPU's TSS and `gdt` its full table.
    unsafe {
        ktss_fill(
            ptr::addr_of_mut!(KTSS),
            ptr::addr_of_mut!(gdt::GDT).cast::<RealDescriptor>(),
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
    unsafe { ktss_fill(ptr::addr_of_mut!((*table).ktss), mygdt) };
}
