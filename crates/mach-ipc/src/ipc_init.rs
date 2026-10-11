// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The IPC initialization routines.

use crate::platform::Platform;
use crate::{
    ipc_entry, ipc_marequest, ipc_notify, ipc_object, ipc_port, ipc_space,
};
use core::ptr::NonNull;
use mach_vm::param::VmSize;
use mach_vm::vm_kern;

/// The submap's fixed size.
static IPC_KERNEL_MAP_SIZE: VmSize = 8 * 1024 * 1024;

/// Sets up the IPC caches, the kernel's special spaces, the dead-name request
/// table sizes, notifications and the message-accepted table.
fn bootstrap<P: Platform>() {
    ipc_port::init_static_locks();
    ipc_space::init_cache::<P>();
    ipc_entry::init_cache::<P>();
    ipc_object::init_caches::<P>();

    ipc_space::create_specials::<P>();

    // SAFETY: the boot path runs this once, before the table is used.
    unsafe { crate::ipc_table::ipc_table_init::<P>() };

    ipc_notify::init();

    // SAFETY: `ipc_marequest::init` only builds the message-accepted table;
    // the boot caller runs this once.
    unsafe { ipc_marequest::init::<P>() };
}

/// Builds the kernel's IPC submap.
fn init<P: Platform>() {
    // SAFETY: `P::state().ipc_kernel_map()` is the empty submap and
    // `P::state().kernel_map()` the live map the boot path has already built,
    // and `IPC_KERNEL_MAP_SIZE` is the constant size of the submap.
    unsafe {
        vm_kern::kmem_submap(
            &mut *P::state().ipc_kernel_map(),
            NonNull::new_unchecked(P::state().kernel_map()),
            IPC_KERNEL_MAP_SIZE,
        )
        .unwrap_or_else(|_| panic!("kmem_submap"));
    }
}

/// Sets up IPC at boot, before the kernel task exists.
///
/// # Safety
///
/// The boot path must call this once, before the kernel task can be created.
pub unsafe fn ipc_bootstrap<P: Platform>() {
    bootstrap::<P>();
}

/// Finishes the IPC setup once the kernel map exists.
///
/// # Safety
///
/// The boot path must have built `kernel_map` and the IPC bootstrap
/// structures, and must call this once, after them.
pub unsafe fn ipc_init<P: Platform>() {
    init::<P>();
}
