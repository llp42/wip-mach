// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_init.c and ipc/ipc_init.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The IPC initialization routines, which `ipc/ipc_init.c` defines and
//! `ipc/ipc_init.h` declares.

use crate::arch::types::VmSize;
use crate::ipc::{
    ipc_entry, ipc_marequest, ipc_notify, ipc_object, ipc_port, ipc_space,
};
use crate::kern::debug::kpanic;
use crate::vm::vm_kern::{self, KERNEL_MAP};
use crate::vm::vm_map::VmMap;
use core::ptr::{self, NonNull};

/// `ipc_kernel_map_store` of `ipc/ipc_init.c`: the storage for the kernel's IPC
/// submap.
static mut IPC_KERNEL_MAP_STORE: VmMap =
    // SAFETY: `VmMap` is a plain structure; the map is built in place by
    // `kmem_submap()` before anything reads it.
    unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

/// `ipc_kernel_map` of `ipc/ipc_init.c`: the kernel's IPC submap.
static mut IPC_KERNEL_MAP: *mut VmMap =
    ptr::addr_of_mut!(IPC_KERNEL_MAP_STORE);

/// `ipc_kernel_map_size` of `ipc/ipc_init.c`: the submap's fixed size.
static IPC_KERNEL_MAP_SIZE: VmSize = 8 * 1024 * 1024;

/// The kernel's IPC submap.
pub(crate) fn ipc_kernel_map() -> *mut VmMap {
    // SAFETY: the initializer is the only writer, and every accessor only
    // reads the pointer.
    unsafe { IPC_KERNEL_MAP }
}

/// `ipc_bootstrap()` in C.
fn bootstrap() {
    ipc_port::init_static_locks();
    ipc_space::init_cache();
    ipc_entry::init_cache();
    ipc_object::init_caches();

    ipc_space::create_specials();

    // SAFETY: the boot path runs this once, before the table is used.
    unsafe { crate::ipc::ipc_table::ipc_table_init() };

    ipc_notify::init();

    // SAFETY: `ipc_marequest_init` only builds the message-accepted table;
    // the boot caller runs this once.
    unsafe { ipc_marequest::init() };
}

/// `ipc_init()` in C.
fn init() {
    // SAFETY: `IPC_KERNEL_MAP` and `kernel_map` are the live maps the boot
    // path has already built, and `ipc_kernel_map_size` is the constant size
    // of the submap.
    unsafe {
        vm_kern::kmem_submap(
            &mut *ipc_kernel_map(),
            NonNull::new_unchecked(KERNEL_MAP),
            IPC_KERNEL_MAP_SIZE,
        )
        .unwrap_or_else(|_| kpanic!("kmem_submap", "kmem_submap"));
    }

    // SAFETY: `ipc_host::init()` takes no arguments and only builds the
    // host's special ports; the boot caller runs this once.
    unsafe { crate::kern::ipc_host::init() };
}

/// `ipc_bootstrap()` of `ipc/ipc_init.c`.
///
/// # Safety
///
/// The boot path must call this once, before the kernel task can be created.
pub(crate) unsafe fn ipc_bootstrap() {
    bootstrap();
}

/// `ipc_init()` of `ipc/ipc_init.c`.
///
/// # Safety
///
/// The boot path must have built `kernel_map` and the IPC bootstrap
/// structures, and must call this once, after them.
pub(crate) unsafe fn ipc_init() {
    init();
}
