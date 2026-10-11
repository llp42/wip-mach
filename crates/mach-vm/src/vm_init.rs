// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The virtual memory bootstrap.

use crate::memory_object_proxy;
use crate::platform::Platform;
use crate::vm_fault;
use crate::vm_kern;
use crate::vm_map::VmMap;
use crate::vm_object;
use crate::vm_page;
use crate::vm_resident;
use core::ptr::NonNull;

/// Brings up the VM packages in boot order: the resident pages, objects,
/// maps, the kernel map, the physical maps, the slab allocator, `kalloc`,
/// faults and the default manager.
fn bootstrap<P: Platform>() {
    let (start, end) = vm_resident::bootstrap::<P>();

    // SAFETY: the boot caller runs the sequence once and in this order, and
    // each callee requires the packages before it to be up.
    unsafe {
        vm_object::bootstrap::<P>();
        VmMap::<P>::init_module();
        if let Err(error) = vm_kern::kmem_init(
            NonNull::new_unchecked(P::state().kernel_map()),
            P::kernel_pmap(),
            start,
            end,
        ) {
            panic!("vm_map_enter failed ({error:?})");
        }
        P::pmap_init();
        P::allocators_init();
        vm_fault::init_module::<P>();
        vm_resident::module_init::<P>();
    }
}

/// Starts the parts of the VM system that need the scheduler: the object
/// cache, the page statistics and the proxies.
fn init<P: Platform>() {
    // The boot caller runs this after `bootstrap`, once, when the scheduler
    // is alive; each callee requires the state it left.
    vm_object::init::<P>();
    vm_page::info_all::<P>();
    memory_object_proxy::init::<P>();
}

/// Brings up the virtual memory system at boot.
///
/// # Safety
///
/// Must be called exactly once, by the first CPU to come up, before any other
/// VM package is used.
pub unsafe fn vm_mem_bootstrap<P: Platform>() {
    bootstrap::<P>();
}

/// Finishes the virtual memory bring-up once the scheduler runs.
///
/// # Safety
///
/// Must be called once, after `vm_mem_bootstrap()`, when the scheduler is
/// running.
pub unsafe fn vm_mem_init<P: Platform>() {
    init::<P>();
}
