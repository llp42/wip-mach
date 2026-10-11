// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The TLB: the CPUs a map is active on, the invalidations queued for
//! each, and the interrupt that asks a CPU to run its queue.

use crate::cpu_set::CpuSet;
use crate::param::{
    UPDATE_LIST_SIZE, VM_MAX_KERNEL_ADDRESS, VM_MIN_USER_ADDRESS, kvtolin,
};
use crate::phys::kvtophys;
use crate::platform::Platform;
use crate::pmap::{Pmap, kernel_pmap_ptr};
use crate::types::PmapUpdateItem;
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering, fence};
use mach_page::param::{PAGE_SIZE, VmOffset};
use mach_page::smp::{CpuId, MAX_NCPUS};
use x86_64::instructions::tlb;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::PhysFrame;
use x86_64::{PhysAddr, VirtAddr};

/// The CPUs that may use a pmap.
pub static CPUS_ACTIVE: CpuSet = CpuSet::new();

/// The CPUs that are idle but will want the kernel pmap updates when they
/// wake.
pub static CPUS_IDLE: CpuSet = CpuSet::new();

/// The CPUs with queued invalidations.
pub static CPU_UPDATE_NEEDED: [AtomicI32; MAX_NCPUS] =
    [const { AtomicI32::new(0) }; MAX_NCPUS];

/// Writes CR3 with the page tables at `physical`.
pub(crate) fn write_cr3(physical: VmOffset) {
    let frame =
        PhysFrame::containing_address(PhysAddr::new_truncate(physical as u64));
    // SAFETY: the caller passes page tables that map the kernel as the
    // running ones do.
    unsafe { Cr3::write(frame, Cr3Flags::empty()) };
}

/// Loads `pmap`'s page tables into CR3.
fn set_pmap(pmap: *mut Pmap) {
    // SAFETY: the caller passes a live map whose `l4base` the kernel built.
    unsafe { write_cr3(kvtophys((*pmap).l4base as VmOffset)) };
}

/// Makes `pmap` current on `cpu` and adds the CPU to its active set.
///
/// # Safety
///
/// `pmap` must be live, and `cpu` must be the calling CPU with interrupts
/// blocked, as the context switch has them.
pub unsafe fn activate_user(pmap: *mut Pmap, cpu: c_int) {
    if pmap == kernel_pmap_ptr() {
        set_pmap(pmap);
        return;
    }

    CPUS_ACTIVE.clear(cpu);
    unsafe {
        (*pmap).lock.lock();
        set_pmap(pmap);
        (*pmap).cpus_using.set(cpu);
    }
    CPUS_ACTIVE.set(cpu);
    unsafe { (*pmap).lock.unlock() };
}

/// Removes `cpu` from `pmap`'s active set.
///
/// # Safety
///
/// `pmap` must be live, and `cpu` must be the calling CPU.
pub unsafe fn deactivate_user(pmap: *mut Pmap, cpu: c_int) {
    if pmap != kernel_pmap_ptr() {
        unsafe { (*pmap).cpus_using.clear(cpu) };
    }
}

/// Removes `cpu` from the kernel map's active set.
///
/// # Safety
///
/// `cpu` must be the calling CPU.
pub unsafe fn deactivate_kernel(cpu: c_int) {
    // SAFETY: the kernel map is live from `pmap_bootstrap()`, and the C macro
    // cleared the bit without the lock.
    unsafe { (*kernel_pmap_ptr()).cpus_using.clear(cpu) };
}

/// Makes the kernel pmap current on `cpu` and flushes its queued updates.
///
/// # Safety
///
/// `cpu` must be the calling CPU with interrupts blocked, as the boot and
/// context-switch paths have them.
pub unsafe fn activate_kernel<P: Platform>(cpu: c_int) {
    CPUS_ACTIVE.clear(cpu);
    // SAFETY: the kernel map is live from `pmap_bootstrap()`, and the lock
    // protects the queued updates and `cpus_using`.
    unsafe {
        (*kernel_pmap_ptr()).lock.lock();

        if CPU_UPDATE_NEEDED[cpu as usize].load(Ordering::Relaxed) != 0 {
            process_pmap_updates::<P>(kernel_pmap_ptr());
        }

        (*kernel_pmap_ptr()).cpus_using.set(cpu);
        CPUS_ACTIVE.set(cpu);

        (*kernel_pmap_ptr()).lock.unlock();
    }
}

/// Invalidates the TLB of this CPU for `s..e` of `pmap`: one INVLPG for a
/// single page, a CR3 reload for anything wider.
///
/// # Safety
///
/// `pmap` must be live, and `[s, e)` must be the linear range just
/// unmapped or remapped on the calling CPU, as the C's callers held.
pub(crate) unsafe fn invalidate_tlb(
    pmap: *mut Pmap,
    s: VmOffset,
    e: VmOffset,
) {
    if e.wrapping_sub(s) == PAGE_SIZE {
        let addr = if pmap == kernel_pmap_ptr() {
            kvtolin(s)
        } else {
            s
        };
        tlb::flush(VirtAddr::new_truncate(addr as u64));
    } else {
        tlb::flush_all();
    }
}

/// Signals every other CPU using the map, waits for them to acknowledge, then
/// invalidates locally.
///
/// # Safety
///
/// `pmap` must be live and locked, and the caller must be at `splvm` or above
/// with interrupts blocked.
pub(crate) unsafe fn update_tlbs<P: Platform>(
    pmap: *mut Pmap,
    s: VmOffset,
    e: VmOffset,
) {
    let cpu_mask = CpuSet::mask(P::current_cpu().bits() as c_int);
    let users = unsafe { (*pmap).cpus_using.bits() } & !cpu_mask;
    if users != 0 {
        unsafe { signal_cpus::<P>(users, pmap, s, e) };
        while unsafe { (*pmap).cpus_using.bits() }
            & CPUS_ACTIVE.bits()
            & !cpu_mask
            != 0
        {
            core::hint::spin_loop();
        }
    }
    if unsafe {
        (*pmap)
            .cpus_using
            .contains(P::current_cpu().bits() as c_int)
    } {
        // SAFETY: `pmap` is live and locked; the range is the one entered.
        unsafe { invalidate_tlb(pmap, s, e) };
    }
}

/// The one-based index of the lowest set bit, or zero.
const fn ffs(value: isize) -> u32 {
    if value == 0 {
        0
    } else {
        value.trailing_zeros() + 1
    }
}

/// Queues an invalidation for every CPU in `use_list` and interrupts the ones
/// that are awake.
///
/// # Safety
///
/// `pmap` must be a live, locked map and the range one it was changed in, as
/// [`update_tlbs`] requires.
unsafe fn signal_cpus<P: Platform>(
    use_list: isize,
    pmap: *mut Pmap,
    start: VmOffset,
    end: VmOffset,
) {
    let mut use_list = use_list;
    loop {
        let which = ffs(use_list);
        if which == 0 {
            break;
        }
        let which_cpu = (which - 1) as c_int;

        let mut list = P::pmap_state().update_lists[which_cpu as usize].lock();
        if list.count >= UPDATE_LIST_SIZE {
            // The last entry becomes the whole-space flush, as the C made it.
            list.item[UPDATE_LIST_SIZE - 1] = PmapUpdateItem {
                pmap: kernel_pmap_ptr().addr(),
                start: VM_MIN_USER_ADDRESS,
                end: VM_MAX_KERNEL_ADDRESS,
            };
        } else {
            let j = list.count;
            list.item[j] = PmapUpdateItem {
                pmap: pmap.addr(),
                start,
                end,
            };
            list.count = j + 1;
        }
        CPU_UPDATE_NEEDED[which_cpu as usize].store(1, Ordering::Relaxed);
        drop(list);

        fence(Ordering::SeqCst);
        if CPUS_IDLE.bits() & CpuSet::mask(which_cpu) == 0 {
            // SAFETY: a map's `cpus_using` holds only the bits of running
            // CPUs' numbers, each below `MAX_NCPUS`.
            P::interrupt_processor(unsafe { CpuId::from_c_int(which_cpu) });
        }
        use_list &= !CpuSet::mask(which_cpu);
    }
}

/// Flushes the calling CPU's queued invalidations.
///
/// # Safety
///
/// Must be called at `splvm`, with the caller's pmap live if it is not the
/// kernel map.
unsafe fn process_pmap_updates<P: Platform>(my_pmap: *mut Pmap) {
    // The C `pmap` routines take the CPU number as an `int`.
    let my_cpu = P::current_cpu().bits() as c_int;
    let kernel = kernel_pmap_ptr();

    let mut list = P::pmap_state().update_lists[my_cpu as usize].lock();
    let count = list.count;
    for item in list.item.iter().take(count) {
        let pmap = if item.pmap == kernel.addr() {
            kernel
        } else if item.pmap == my_pmap.addr() {
            my_pmap
        } else {
            continue;
        };
        // SAFETY: the queued range belongs to `pmap`, which the queueing CPU
        // held locked.
        unsafe { invalidate_tlb(pmap, item.start, item.end) };
    }
    list.count = 0;
    CPU_UPDATE_NEEDED[my_cpu as usize].store(0, Ordering::Relaxed);
    drop(list);
}

/// The interprocessor handler that flushes this CPU's TLB for another.
pub extern "C" fn pmap_update_interrupt<P: Platform>() {
    // The C `pmap` routines take the CPU number as an `int`.
    let my_cpu = P::current_cpu().bits() as c_int;

    if CPUS_IDLE.bits() & CpuSet::mask(my_cpu) != 0 {
        return;
    }

    let mut my_pmap = kernel_pmap_ptr();
    // SAFETY: a thread the interrupt reaches belongs to a task with a map,
    // as the C's interrupt path ensured.
    if let Some(pmap) = unsafe { P::current_pmap() } {
        my_pmap = pmap.as_ptr();
        // SAFETY: the pmap came from a live map, and the interrupt runs at
        // `SPLIP` so the field cannot change under it.
        if !unsafe { (*my_pmap).cpus_using.contains(my_cpu) } {
            my_pmap = kernel_pmap_ptr();
        }
    }

    // SAFETY: raising to `splvm` has no precondition.
    let s = unsafe { P::splvm() };
    loop {
        CPUS_ACTIVE.clear(my_cpu);
        // SAFETY: both maps are the kernel's and a live user map; the spin
        // is the C's, waiting for updates in progress.
        while unsafe {
            (*my_pmap).lock.is_locked()
                || (*kernel_pmap_ptr()).lock.is_locked()
        } {
            core::hint::spin_loop();
        }
        // SAFETY: this runs at `splvm` with the interrupt blocked.
        unsafe { process_pmap_updates::<P>(my_pmap) };
        CPUS_ACTIVE.set(my_cpu);
        if CPU_UPDATE_NEEDED[my_cpu as usize].load(Ordering::Relaxed) == 0 {
            break;
        }
    }
    // SAFETY: `s` came from `splvm()`.
    unsafe { P::splx(s) };
}
