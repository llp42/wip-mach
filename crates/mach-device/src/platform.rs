// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the device service asks of the rest of the kernel.

use crate::state::DeviceState;
use crate::types::{DeviceCache, Message};
use core::ptr::NonNull;

/// The kernel services device dispatch needs beyond the task platform's.
///
/// The kernel implements it on the same zero-sized type as the VM, IPC and
/// task platforms. Tasks, threads, the scheduler, IPC, VM, user copy and
/// the console come from those seams; this one adds the device service's
/// state, its slab caches and the messages it sends.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform: mach_thread::platform::Platform {
    /// The device service's state, which the kernel keeps in a static.
    fn device_state() -> &'static DeviceState<Self>;

    /// Sets up `cache` for records of `size` bytes, reported as `name`.
    ///
    /// # Safety
    ///
    /// Once per cache, before its first allocation.
    unsafe fn device_cache_init(
        cache: DeviceCache,
        name: &'static [u8],
        size: usize,
    );
    /// Allocates a record from `cache`, or `None` when memory is short.
    ///
    /// # Safety
    ///
    /// [`Self::device_cache_init`] must have set `cache` up.
    unsafe fn device_cache_alloc(cache: DeviceCache) -> Option<NonNull<u8>>;
    /// Returns a record to `cache`.
    ///
    /// # Safety
    ///
    /// `record` must have come from `cache` and not be used again.
    unsafe fn device_cache_free(cache: DeviceCache, record: NonNull<u8>);

    /// Sends `message`: a device reply, or a device pager's memory-object
    /// call.
    ///
    /// # Errors
    ///
    /// Returns why the kernel could not send it.
    ///
    /// # Safety
    ///
    /// The ports and data of `message` must be what its variant documents.
    unsafe fn send(message: Message) -> Result<(), Self::SendError>;
}
