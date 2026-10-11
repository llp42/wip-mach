// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The device service's platform: what device dispatch asks of the `x86_64`
//! kernel.

use crate::arch::x86_64::conf::{DEV_INDIRECT_LIST, DEV_NAME_LIST};
use crate::arch::x86_64::platform::MachPlatform;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::mig;
use core::ptr::NonNull;
use mach_device::platform::Platform;
use mach_device::state::DeviceState;
use mach_device::types::{DeviceCache, Message};
use mach_ipc::error::SendError;

/// The device service's tables, maps and locks.
static DEVICE_STATE: DeviceState<MachPlatform> =
    DeviceState::new(&DEV_NAME_LIST, &DEV_INDIRECT_LIST);

/// The slab cache behind each of the device service's [`DeviceCache`]s.
static DEVICE_CACHES: [KmemCache; DeviceCache::COUNT] =
    [const { KmemCache::zeroed() }; DeviceCache::COUNT];

/// The slab cache behind `cache`.
fn device_cache(cache: DeviceCache) -> &'static KmemCache {
    &DEVICE_CACHES[cache as usize]
}

// SAFETY: each item keeps its documented contract: the state is the one
// static, each cache is its own slab cache, and a message goes out through
// its MIG user stub.
unsafe impl Platform for MachPlatform {
    fn device_state() -> &'static DeviceState<Self> {
        &DEVICE_STATE
    }

    unsafe fn device_cache_init(
        cache: DeviceCache,
        name: &'static [u8],
        size: usize,
    ) {
        device_cache(cache).init(name, size, 0, None, CacheInitFlags::empty());
    }

    unsafe fn device_cache_alloc(cache: DeviceCache) -> Option<NonNull<u8>> {
        device_cache(cache).alloc()
    }

    unsafe fn device_cache_free(cache: DeviceCache, record: NonNull<u8>) {
        // SAFETY: the record came from this cache, as the caller promises.
        unsafe { device_cache(cache).free(record) };
    }

    unsafe fn send(message: Message) -> Result<(), SendError> {
        // SAFETY: the message's ports and data are what its variant
        // documents, as the caller promises.
        unsafe { mig::send(message) }
    }
}
