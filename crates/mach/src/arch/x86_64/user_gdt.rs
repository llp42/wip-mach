// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The two per-thread GDT entries, and the `mach_i386` calls on them.  The
//! kernel keeps no thread-programmable LDT, so `i386_set_ldt()` and
//! `i386_get_ldt()` answer deprecated instead.
//!
//! The MIG server entries are in [`crate::mig::mach_i386`].

use crate::arch::x86_64::pcb::{self, RealDescriptor};
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::seg;
use crate::kern::error::Error;
use core::ffi::{c_int, c_uint};
use core::ptr::NonNull;
use mach_thread::thread::Thread;

/// `struct descriptor`: the MIG view of a descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct Descriptor {
    pub low_word: c_uint,
    pub high_word: c_uint,
}

const _: () = {
    assert!(size_of::<Descriptor>() == 8);
    assert!(align_of::<Descriptor>() == align_of::<c_uint>());
    assert!(core::mem::offset_of!(Descriptor, low_word) == 0);
    assert!(core::mem::offset_of!(Descriptor, high_word) == 4);
};

/// The descriptor index of a signed selector.
const fn sel_idx(selector: c_int) -> c_int {
    selector >> 3
}

/// `i386_set_gdt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be a live thread.  On return `selector` is written
/// when it was `-1` and a slot was free.
pub(crate) unsafe fn set_gdt(
    thread: NonNull<Thread<MachPlatform>>,
    selector: *mut c_int,
    descriptor: Descriptor,
) -> Result<(), Error> {
    let pcb = unsafe { (*thread.as_ptr()).pcb };
    let user_gdt = unsafe { &mut (*pcb).ims.user_gdt };
    let selector_value = unsafe { *selector };
    let idx;

    if selector_value == -1 {
        let Some(free) = user_gdt
            .iter()
            .position(|entry| !entry.access().contains(seg::Access::P))
        else {
            return Err(Error::NoSpace);
        };
        idx = free;
        // The slot index is below `USER_GDT_SLOTS`, so this widens exactly.
        let selector_int = free as c_int + sel_idx(seg::USER_GDT);
        unsafe { *selector = (selector_int << 3) | seg::SEL_PL_U };
    } else if (selector_value & (seg::SEL_LDT | seg::SEL_PL)) != seg::SEL_PL_U
        || sel_idx(selector_value) < sel_idx(seg::USER_GDT)
        || sel_idx(selector_value)
            >= sel_idx(seg::USER_GDT) + seg::USER_GDT_SLOTS as c_int
    {
        return Err(Error::InvalidArgument);
    } else {
        let index = sel_idx(selector_value) - sel_idx(seg::USER_GDT);
        // The bound above keeps the index inside `USER_GDT_SLOTS`.
        idx = index as usize;
    }

    let desc = RealDescriptor {
        limit_low_base_low: descriptor.low_word,
        access_and_base_high: descriptor.high_word,
    };
    if !desc.access().contains(seg::Access::P) {
        user_gdt[idx] = RealDescriptor::ZERO;
    } else if desc
        .access()
        .intersection(seg::Access::TYPE_USER | seg::Access::PL)
        != seg::Access::TYPE_USER | seg::Access::PL_U
        || desc.granularity().contains(seg::SegSize::LONG)
    {
        return Err(Error::InvalidArgument);
    } else {
        user_gdt[idx] = desc;
    }

    if thread.as_ptr() == per_cpu::thread() {
        unsafe { pcb::switch_ktss(pcb) };
    }
    Ok(())
}

/// `i386_get_gdt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be a live thread, and `descriptor` writable.
pub(crate) unsafe fn get_gdt(
    thread: NonNull<Thread<MachPlatform>>,
    selector: c_int,
    descriptor: *mut Descriptor,
) -> Result<(), Error> {
    if (selector & (seg::SEL_LDT | seg::SEL_PL)) != seg::SEL_PL_U
        || sel_idx(selector) < sel_idx(seg::USER_GDT)
        || sel_idx(selector)
            >= sel_idx(seg::USER_GDT) + seg::USER_GDT_SLOTS as c_int
    {
        return Err(Error::InvalidArgument);
    }

    let pcb = unsafe { (*thread.as_ptr()).pcb };
    let index = (sel_idx(selector) - sel_idx(seg::USER_GDT)) as usize;
    // SAFETY: the bound check above keeps the index inside `user_gdt`.
    let entry = unsafe { (*pcb).ims.user_gdt[index] };
    unsafe {
        *descriptor = Descriptor {
            low_word: entry.limit_low_base_low,
            high_word: entry.access_and_base_high,
        };
    }
    Ok(())
}
