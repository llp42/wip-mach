// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_init.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The virtual memory bootstrap.

use crate::arch::x86_64::pmap::kernel_pmap_ptr;
use crate::arch::x86_64::pmap::pmap_init;
use crate::kern::debug::kpanic;
use crate::kern::slab::{kalloc_init, slab_bootstrap, slab_init};
use crate::vm::memory_object_proxy;
use crate::vm::vm_fault;
use crate::vm::vm_kern::{self, KERNEL_MAP};
use crate::vm::vm_map::VmMap;
use crate::vm::vm_object;
use crate::vm::vm_page;
use crate::vm::vm_resident;
use core::ptr::NonNull;

/// Brings up the VM packages in boot order: the resident pages, the slab
/// allocator, objects, maps, the kernel map, the physical maps, `kalloc`,
/// faults and the default manager.
fn bootstrap() {
    let (start, end) = vm_resident::bootstrap();

    // SAFETY: the boot caller runs the sequence once and in this order, and
    // each callee requires the packages before it to be up.
    unsafe {
        slab_bootstrap();
        vm_object::bootstrap();
        VmMap::init_module();
        if let Err(error) = vm_kern::kmem_init(
            NonNull::new_unchecked(KERNEL_MAP),
            kernel_pmap_ptr(),
            start,
            end,
        ) {
            kpanic!("kmem_init", "vm_map_enter failed ({:?})\n", error);
        }
        pmap_init();
        slab_init();
        kalloc_init();
        vm_fault::init_module();
        vm_resident::module_init();
    }
}

/// Starts the parts of the VM system that need the scheduler: the object
/// cache, the page statistics and the proxies.
fn init() {
    // The boot caller runs this after `bootstrap`, once, when the scheduler
    // is alive; each callee requires the state it left.
    vm_object::init();
    vm_page::info_all();
    memory_object_proxy::init();
}

/// Brings up the virtual memory system at boot.
///
/// # Safety
///
/// Must be called exactly once, by the first CPU to come up, before any other
/// VM package is used.
pub(crate) unsafe fn vm_mem_bootstrap() {
    bootstrap();
}

/// Finishes the virtual memory bring-up once the scheduler runs.
///
/// # Safety
///
/// Must be called once, after `vm_mem_bootstrap()`, when the scheduler is
/// running.
pub(crate) unsafe fn vm_mem_init() {
    init();
}
