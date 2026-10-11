// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`VmState`]: VM's global state whose types name the platform.
//!
//! A Rust `static` cannot be generic, so the platform declares the one
//! `VmState` and returns it from [`Platform::state`].

use crate::cell::SyncCell;
use crate::memory_object::default_manager::ManagerPort;
use crate::platform::Platform;
use crate::vm_map::VmMap;
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use lock::TicketLock;

/// VM's global state whose types name the platform.
pub struct VmState<P: Platform> {
    /// The storage of the boot kernel map.
    kernel_map: SyncCell<VmMap<P>>,
    /// The storage of the kernel's IPC submap.
    ipc_kernel_map: SyncCell<VmMap<P>>,
    /// The published default-manager port.
    pub(crate) default_manager: TicketLock<ManagerPort>,
}

impl<P: Platform> VmState<P> {
    /// The state before boot: empty kernel and IPC maps and no default
    /// manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            kernel_map: SyncCell(UnsafeCell::new(VmMap::<P>::zeroed())),
            ipc_kernel_map: SyncCell(UnsafeCell::new(VmMap::<P>::zeroed())),
            default_manager: TicketLock::new(ManagerPort(null_mut())),
        }
    }

    /// The kernel map, which the boot path fills.
    #[must_use]
    pub const fn kernel_map(&self) -> *mut VmMap<P> {
        self.kernel_map.0.get()
    }

    /// The kernel's IPC submap, which IPC's boot fills.
    #[must_use]
    pub const fn ipc_kernel_map(&self) -> *mut VmMap<P> {
        self.ipc_kernel_map.0.get()
    }
}

impl<P: Platform> Default for VmState<P> {
    fn default() -> Self {
        Self::new()
    }
}
