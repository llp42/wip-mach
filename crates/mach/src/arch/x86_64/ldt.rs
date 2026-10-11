// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The default local descriptor table.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::VM_MAX_USER_ADDRESS;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::mp_desc;
use crate::arch::x86_64::pcb::{DescriptorTable, RealDescriptor};
use crate::arch::x86_64::seg;
use crate::kern::debug::kpanic;
use core::ffi::c_int;
use core::mem::size_of;
use core::ptr;
use raw_cpuid::{CpuId, ExtendedProcessorFeatureIdentifiers};
use x86_64::VirtAddr;
use x86_64::instructions::tables;
use x86_64::registers::model_specific::{
    Efer, EferFlags, LStar, SFMask, Star,
};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::SegmentSelector;

/// The lowest user address.
const VM_MIN_USER_ADDRESS: VmOffset = 0;

/// The default table every thread starts with.
pub(crate) static mut LDT: DescriptorTable<{ seg::LDTSZ }> =
    DescriptorTable([RealDescriptor::ZERO; seg::LDTSZ]);

/// The size bits of the user code and data segments.
const USER_SEGMENT_SIZEBITS: seg::SegSize = seg::SegSize::LONG;

/// The `limit` of the LDT's own GDT descriptor.
const LDT_LIMIT: usize = seg::LDTSZ * size_of::<RealDescriptor>() - 1;

const _: () = assert!(LDT_LIMIT <= u16::MAX as usize);

/// Enables the SYSCALL instruction and points it at the kernel's entry.
fn enable_syscall() {
    if !CpuId::new()
        .get_extended_processor_and_feature_identifiers()
        .as_ref()
        .is_some_and(ExtendedProcessorFeatureIdentifiers::has_syscall_sysret)
    {
        kpanic!("ldt_fill", "syscall support is missing on 64 bit")
    }

    // SAFETY: SCE only turns SYSCALL on, and no task runs before the writes
    // below give it its entry and selectors.
    unsafe {
        Efer::update(|flags| {
            flags.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
        });
    }
    LStar::write(VirtAddr::from_ptr(locore::syscall64 as *const ()));
    if Star::write(
        SegmentSelector(seg::USER_CS as u16),
        SegmentSelector(seg::USER_DS as u16),
        SegmentSelector(seg::KERNEL_CS as u16),
        SegmentSelector(seg::KERNEL_DS as u16),
    )
    .is_err()
    {
        kpanic!("ldt_fill", "the GDT's selectors do not fit SYSCALL")
    }
    // A system call enters with interrupts off and the I/O privilege level
    // cleared.
    SFMask::write(
        RFlags::INTERRUPT_FLAG | RFlags::IOPL_HIGH | RFlags::IOPL_LOW,
    );
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
            seg::Access::PL_K | seg::Access::LDT,
            seg::SegSize::empty(),
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
            seg::Access::PL_U | seg::Access::CODE_R,
            USER_SEGMENT_SIZEBITS,
        );
        seg::fill_ldt_descriptor(
            myldt,
            seg::USER_DS,
            VM_MIN_USER_ADDRESS,
            user_limit,
            seg::Access::PL_U | seg::Access::DATA_W,
            USER_SEGMENT_SIZEBITS,
        );
    }

    // SAFETY: `KERNEL_LDT` names the GDT entry this filled with the table
    // just written, which outlives the CPU's use of it.
    unsafe { tables::lldt(SegmentSelector(seg::KERNEL_LDT as u16)) };
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
