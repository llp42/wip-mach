// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The device pager.
//!
//! A record carries only what the pager reads back, and its reference count is
//! an atomic.

use crate::dev_lookup;
use crate::dev_name::nomap;
use crate::ds_routines::{MachDevice, driver_unit};
use crate::io_req::DevT;
use crate::platform::Platform;
use crate::r#return::DeviceError;
use crate::types::{DeviceCache, Message};
use collections::list::{self, List};
use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicI32, Ordering};
use mach_ipc::{IpcPort, ipc_port, ipc_space};
use mach_vm::error::Error;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::types::PAGE_SHIFT;
use mach_vm::vm_object;
use mach_vm::vm_resident::VM_PAGE_FICTITIOUS_ADDR;

/// The number of buckets in both tables.
pub(crate) const DEV_HASH_COUNT: usize = 127;

/// The copy strategy of a device's memory: none.
const MEMORY_OBJECT_COPY_NONE: c_int = 0;

/// The switch that turns on the pager's trace prints, for a debugger to set.
pub static DEVICE_PAGER_DEBUG: AtomicI32 = AtomicI32::new(0);

const _: () = assert!(size_of::<AtomicI32>() == size_of::<c_int>());
const _: () = assert!(align_of::<AtomicI32>() == align_of::<c_int>());

/// One device pager record.
pub struct DevPager<P: Platform> {
    ref_count: AtomicI32,
    pager: IpcPort,
    pager_request: Option<IpcPort>,
    device: *mut MachDevice<P>,
    offset: VmOffset,
    prot: c_int,
}

/// One entry of the table of pagers by port.
pub struct DevPagerEntry<P: Platform> {
    links: list::Link,
    name: Option<IpcPort>,
    pager: NonNull<DevPager<P>>,
}

/// One entry of the table of pagers by device and offset.
pub struct DevDeviceEntry<P: Platform> {
    links: list::Link,
    device: *mut MachDevice<P>,
    offset: VmOffset,
    pager: NonNull<DevPager<P>>,
}

list::adapter!(
    /// The adapter for a pager entry's `links` in the port-name table.
    pub DevPagerEntryAdapter<P: Platform> = DevPagerEntry<P> { links }
);

list::adapter!(
    /// The adapter for a device entry's `links` in the device table.
    pub DevDeviceEntryAdapter<P: Platform> = DevDeviceEntry<P> { links }
);

/// A bucket of the port-name table. Keys are unique, so the order within a
/// bucket is unobservable.
pub(crate) type PagerBucket<P> = List<'static, DevPagerEntryAdapter<P>>;

/// A bucket of the device-and-offset table, unordered like [`PagerBucket`].
pub(crate) type DeviceBucket<P> = List<'static, DevDeviceEntryAdapter<P>>;

/// The bucket of `value`, a pointer or a pointer plus offset: its low 24 bits,
/// modulo the bucket count.
const fn dev_hash(value: usize) -> usize {
    (value & 0x00ff_ffff) % DEV_HASH_COUNT
}

/// The port-name bucket the C's `dev_hash()` selected.
///
/// # Safety
///
/// The caller must hold the port-name lock for as long as it uses the
/// bucket.
unsafe fn pager_bucket<P: Platform>(
    name: Option<IpcPort>,
) -> Pin<&'static mut PagerBucket<P>> {
    let value = name.map_or(0, |port| port.as_ptr().addr());
    // SAFETY: `dev_hash()` is below the array bound, so the element is in
    // bounds; the static never moves, and the lock the caller holds keeps
    // anything else from reaching the bucket.
    unsafe {
        Pin::new_unchecked(
            &mut *P::device_state()
                .pager_hash
                .get()
                .cast::<PagerBucket<P>>()
                .add(dev_hash(value)),
        )
    }
}

/// The device-and-offset bucket the C's `dev_hash()` selected.
///
/// # Safety
///
/// The caller must hold the device-and-offset lock for as long as it uses the
/// bucket.
unsafe fn device_bucket<P: Platform>(
    device: *mut MachDevice<P>,
    offset: VmOffset,
) -> Pin<&'static mut DeviceBucket<P>> {
    let value = device.addr().wrapping_add(offset);
    // SAFETY: `dev_hash()` is below the array bound, so the element is in
    // bounds; the static never moves, and the lock the caller holds keeps
    // anything else from reaching the bucket.
    unsafe {
        Pin::new_unchecked(
            &mut *P::device_state()
                .device_hash
                .get()
                .cast::<DeviceBucket<P>>()
                .add(dev_hash(value)),
        )
    }
}

/// The first entry of `head` whose name is `name`.
fn find_pager_entry<P: Platform>(
    head: &PagerBucket<P>,
    name: Option<IpcPort>,
) -> Option<NonNull<DevPagerEntry<P>>> {
    let mut cursor = head.cursor_front();
    while let Some(entry) = cursor.current() {
        if entry.name == name {
            return cursor.current_ptr();
        }
        cursor.move_next();
    }
    None
}

/// The first entry of `head` for `device` and `offset`.
fn find_device_entry<P: Platform>(
    head: &DeviceBucket<P>,
    device: *mut MachDevice<P>,
    offset: VmOffset,
) -> Option<NonNull<DevDeviceEntry<P>>> {
    let mut cursor = head.cursor_front();
    while let Some(entry) = cursor.current() {
        if entry.device == device && entry.offset == offset {
            return cursor.current_ptr();
        }
        cursor.move_next();
    }
    None
}

/// Take a reference on `rec`.
///
/// # Safety
///
/// `rec` must be a live record whose count is nonzero.
unsafe fn reference<P: Platform>(
    rec: NonNull<DevPager<P>>,
) -> NonNull<DevPager<P>> {
    // The increment is `Relaxed`: the caller already holds a reference, so
    // no other thread can free the record, and the count needs atomicity
    // rather than publication.
    unsafe { (*rec.as_ptr()).ref_count.fetch_add(1, Ordering::Relaxed) };
    rec
}

/// Drop a reference on `rec`, freeing the record when it was the last.
///
/// # Safety
///
/// `rec` must be a live record this call owns a reference on, and nothing
/// else may access it once the count reaches zero.
unsafe fn deallocate<P: Platform>(rec: NonNull<DevPager<P>>) {
    // `AcqRel` on the decrement releases this thread's writes and acquires
    // the other releases, so the free below sees a complete record.
    let last =
        unsafe { (*rec.as_ptr()).ref_count.fetch_sub(1, Ordering::AcqRel) }
            == 1;
    if last {
        // SAFETY: no reference remains, so nothing else can reach the
        // record's cache object.
        unsafe {
            P::device_cache_free(DeviceCache::Pager, rec.cast::<u8>());
        }
    }
}

/// Enters `rec` in the port-name table under `name`.
///
/// # Safety
///
/// The package must be initialized, `rec` must be a live record, and nothing
/// may hold the port-name lock.
unsafe fn pager_hash_insert<P: Platform>(
    name: Option<IpcPort>,
    rec: NonNull<DevPager<P>>,
) {
    // SAFETY: the cache is live after `init()`, and the fresh buffer is
    // linked nowhere.
    let Some(buf) =
        (unsafe { P::device_cache_alloc(DeviceCache::PagerEntry) })
    else {
        panic!("dev_pager_hash_insert: no memory");
    };
    let entry = buf.cast::<DevPagerEntry<P>>();
    // SAFETY: the cache object is sized and aligned for a whole entry.
    unsafe {
        entry.write(DevPagerEntry::<P> {
            links: list::Link::new(),
            name,
            pager: rec,
        });
    }

    let _guard = P::device_state().pager_hash_lock.lock();
    // SAFETY: the lock is held.
    let mut head = unsafe { pager_bucket(name) };
    // SAFETY: the entry is a stable, unlinked cache object that only this
    // table reaches until `pager_hash_delete()` unlinks and frees it.
    unsafe { head.as_mut().push_front_ptr(entry) };
}

/// Removes the entry for `name` from the port-name table.
///
/// # Safety
///
/// The package must be initialized, and only the C protocol's own entry for
/// `name` may exist.
unsafe fn pager_hash_delete<P: Platform>(name: Option<IpcPort>) {
    let found = {
        let _guard = P::device_state().pager_hash_lock.lock();
        // SAFETY: the lock is held.
        let head = unsafe { pager_bucket(name) };
        let entry = find_pager_entry(&head, name);
        if let Some(entry) = entry {
            // SAFETY: `entry` is on this bucket, and the lock keeps
            // anything else from reaching it.
            unsafe { PagerBucket::<P>::remove_ptr(entry) };
        }
        entry
    };

    let Some(entry) = found else {
        return;
    };
    // SAFETY: the entry was just unlinked and owns its cache object.
    unsafe {
        P::device_cache_free(DeviceCache::PagerEntry, entry.cast::<u8>());
    }
}

/// The record the port-name table holds for `name`, with a reference taken on
/// it.
///
/// # Safety
///
/// The package must be initialized.
unsafe fn pager_hash_lookup<P: Platform>(
    name: Option<IpcPort>,
) -> Option<NonNull<DevPager<P>>> {
    let _guard = P::device_state().pager_hash_lock.lock();
    // SAFETY: the lock is held.
    let head = unsafe { pager_bucket(name) };
    let entry = find_pager_entry(&head, name)?;
    // SAFETY: the table holds the record's initial reference, and the entry
    // keeps the record alive while the lock is held.
    Some(unsafe { reference((*entry.as_ptr()).pager) })
}

/// Enters `rec` in the device-and-offset table.
///
/// # Safety
///
/// The package must be initialized, `rec` must be a live record, and nothing
/// may hold the device lock.
unsafe fn device_hash_insert<P: Platform>(
    device: *mut MachDevice<P>,
    offset: VmOffset,
    rec: NonNull<DevPager<P>>,
) {
    // SAFETY: the cache is live after `init()`, and the fresh buffer is
    // linked nowhere.
    let Some(buf) =
        (unsafe { P::device_cache_alloc(DeviceCache::DeviceEntry) })
    else {
        panic!("dev_device_hash_insert: no memory");
    };
    let entry = buf.cast::<DevDeviceEntry<P>>();
    // SAFETY: the cache object is sized and aligned for a whole entry.
    unsafe {
        entry.write(DevDeviceEntry::<P> {
            links: list::Link::new(),
            device,
            offset,
            pager: rec,
        });
    }

    let _guard = P::device_state().device_hash_lock.lock();
    // SAFETY: the lock is held.
    let mut head = unsafe { device_bucket(device, offset) };
    // SAFETY: the entry is a stable, unlinked cache object that only this
    // table reaches until `device_hash_delete()` unlinks and frees it.
    unsafe { head.as_mut().push_front_ptr(entry) };
}

/// Removes the entry for `device` and `offset` from the device-and-offset
/// table.
///
/// # Safety
///
/// The package must be initialized, and only the C protocol's own entry for
/// `device` and `offset` may exist.
unsafe fn device_hash_delete<P: Platform>(
    device: *mut MachDevice<P>,
    offset: VmOffset,
) {
    let found = {
        let _guard = P::device_state().device_hash_lock.lock();
        // SAFETY: the lock is held.
        let head = unsafe { device_bucket(device, offset) };
        let entry = find_device_entry(&head, device, offset);
        if let Some(entry) = entry {
            // SAFETY: `entry` is on this bucket, and the lock keeps
            // anything else from reaching it.
            unsafe { DeviceBucket::<P>::remove_ptr(entry) };
        }
        entry
    };

    let Some(entry) = found else {
        return;
    };
    // SAFETY: the entry was just unlinked and owns its cache object.
    unsafe {
        P::device_cache_free(DeviceCache::DeviceEntry, entry.cast::<u8>());
    }
}

/// The record the device-and-offset table holds, with a reference taken on it.
///
/// # Safety
///
/// The package must be initialized.
unsafe fn device_hash_lookup<P: Platform>(
    device: *mut MachDevice<P>,
    offset: VmOffset,
) -> Option<NonNull<DevPager<P>>> {
    let _guard = P::device_state().device_hash_lock.lock();
    // SAFETY: the lock is held.
    let head = unsafe { device_bucket(device, offset) };
    let entry = find_device_entry(&head, device, offset)?;
    // SAFETY: the table holds the record's initial reference, and the entry
    // keeps the record alive while the lock is held.
    Some(unsafe { reference((*entry.as_ptr()).pager) })
}

/// The physical address of the page at `offset` of the device the record `dsp`
/// maps, the callback `vm_object::page_map` calls.
///
/// # Safety
///
/// `dsp` must be the live record [`data_request()`] passes.
pub(crate) unsafe fn device_map_page<P: Platform>(
    dsp: *mut c_void,
    offset: VmOffset,
) -> VmOffset {
    let Some(rec) = NonNull::new(dsp.cast::<DevPager<P>>()) else {
        return VM_PAGE_FICTITIOUS_ADDR;
    };

    unsafe {
        let record = &*rec.as_ptr();
        let device = &*record.device;
        let Some(d_mmap) = (*device.dev_ops).d_mmap else {
            return VM_PAGE_FICTITIOUS_ADDR;
        };
        let pagenum = d_mmap(
            driver_unit(device.dev_number),
            record.offset.wrapping_add(offset),
            record.prot,
        );
        if pagenum == VmOffset::MAX {
            return VM_PAGE_FICTITIOUS_ADDR;
        }
        // The frame-to-address shift drops what does not fit.
        pagenum.wrapping_shl(PAGE_SHIFT)
    }
}

/// The pager port for `offset` of `device` with protection `prot`, made on
/// first use and shared after.
///
/// # Errors
///
/// Returns [`DeviceError::InvalidOperation`] when the driver cannot map, and
/// [`DeviceError::ResourceShortage`] when the record or its port cannot be
/// allocated.
///
/// # Safety
///
/// `device` must be a live, referenced mach device whose `dev_ops` is live,
/// and the package must be initialized.
pub(crate) unsafe fn setup<P: Platform>(
    device: *mut MachDevice<P>,
    prot: c_int,
    offset: VmOffset,
) -> Result<IpcPort, DeviceError> {
    let ops = unsafe { (*device).dev_ops };
    if ops.is_null() {
        return Err(DeviceError::InvalidOperation);
    }
    // SAFETY: `ops` belongs to the live device.
    let Some(d_mmap) = (unsafe { (*ops).d_mmap }) else {
        return Err(DeviceError::InvalidOperation);
    };
    if ptr::fn_addr_eq(
        d_mmap,
        nomap as unsafe fn(DevT, VmOffset, c_int) -> VmOffset,
    ) {
        return Err(DeviceError::InvalidOperation);
    }

    // SAFETY: the package is initialized, and a found record is referenced
    // by the lookup.
    if let Some(rec) = unsafe { device_hash_lookup(device, offset) } {
        // SAFETY: the record's pager port stays live until termination.
        let port = unsafe { ipc_port::make_send((*rec.as_ptr()).pager) };
        // SAFETY: this drops the reference the lookup took.
        unsafe { deallocate(rec) };
        return Ok(port);
    }

    // SAFETY: the cache is live after `init()`, and the fresh buffer is
    // unshared.
    let Some(buf) = (unsafe { P::device_cache_alloc(DeviceCache::Pager) })
    else {
        return Err(DeviceError::ResourceShortage);
    };
    let rec = buf.as_ptr().cast::<DevPager<P>>();
    // SAFETY: the kernel space is live and the port cache is initialized, as
    // port allocation requires.
    let Some(pager) =
        (unsafe { ipc_port::alloc_special::<P>(ipc_space::kernel()) })
    else {
        // SAFETY: the fresh cache object owns nothing yet.
        unsafe {
            P::device_cache_free(
                DeviceCache::Pager,
                NonNull::new_unchecked(rec.cast::<u8>()),
            );
        }
        return Err(DeviceError::ResourceShortage);
    };

    // SAFETY: the cache object is uninitialized and owned here; the device
    // reference is taken before the record becomes reachable.
    unsafe {
        ptr::write(
            rec,
            DevPager::<P> {
                ref_count: AtomicI32::new(1),
                pager,
                pager_request: None,
                device,
                offset,
                prot,
            },
        );
        dev_lookup::reference(device);
        let rec = NonNull::new_unchecked(rec);
        pager_hash_insert(Some(pager), rec);
        device_hash_insert(device, offset, rec);
    }
    Ok(pager)
}

/// Supplies the pages of `offset..offset + length` to the kernel: maps the
/// device memory into the object.
///
/// # Safety
///
/// `pager` must be the live port of a set-up pager record, `pager_request`
/// the live control port the kernel bound to it, and the package must be
/// initialized.
///
/// # Panics
///
/// When `pager` names no pager, or `pager_request` is not the port its
/// init bound.
pub unsafe fn data_request<P: Platform>(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    offset: VmOffset,
    length: VmSize,
) {
    if DEVICE_PAGER_DEBUG.load(Ordering::Relaxed) != 0 {
        P::print(format_args!(
            "(device_pager)data_request: pager={:x}, offset=0x{:x}, length=0x{:x}\n",
            pager
                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                .expose_provenance(),
            offset,
            length,
        ));
    }

    let Some(rec) = (unsafe { pager_hash_lookup::<P>(pager) }) else {
        panic!("(device_pager)data_request: lookup failed");
    };

    // SAFETY: the lookup referenced the record, and the device reference it
    // holds keeps the record's fields live.
    unsafe {
        let record = rec.as_ptr();
        assert!(
            (*record).pager_request == pager_request,
            "(device_pager)data_request: bad pager_request"
        );

        let control = pager_request.map_or(ptr::null_mut(), IpcPort::as_ptr);
        let Some(object) = vm_object::lookup::<P>(control) else {
            let _ = P::send(Message::DataError {
                memory_control: control,
                offset,
                size: length,
                error: Error::Failure,
            });
            deallocate(rec);
            return;
        };

        // SAFETY: the object is the live object of the request, and the
        // callback takes the record the lookup referenced.
        let result = vm_object::page_map::<P>(
            object.as_ptr(),
            offset,
            length,
            Some(device_map_page::<P>),
            record.cast::<c_void>(),
        );
        if let Err(error) = result {
            let _ = P::send(Message::DataError {
                memory_control: control,
                offset,
                size: length,
                error,
            });
        }
        vm_object::deallocate::<P>(object.as_ptr());
        deallocate(rec);
    }
}

/// Records the kernel's ports for the pager and readies its object.
///
/// # Safety
///
/// The MIG server calls this once for the pager `pager` denotes, before any
/// data request, and the package must be initialized.
///
/// # Panics
///
/// When `pager` names no pager.
pub unsafe fn init_pager<P: Platform>(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    pager_name: Option<IpcPort>,
) {
    if DEVICE_PAGER_DEBUG.load(Ordering::Relaxed) != 0 {
        P::print(format_args!(
            "(device_pager)init: pager={:x}, request={:x}, name={:x}\n",
            pager
                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                .expose_provenance(),
            pager_request
                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                .expose_provenance(),
            pager_name
                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                .expose_provenance(),
        ));
    }

    let Some(rec) = (unsafe { pager_hash_lookup::<P>(pager) }) else {
        panic!("(device_pager)init: lookup failed");
    };

    // SAFETY: the lookup referenced the record, and the MIG protocol runs
    // this once before any data request.
    unsafe {
        (*rec.as_ptr()).pager_request = pager_request;
        let _ = P::send(Message::Ready {
            memory_control: pager_request
                .map_or(ptr::null_mut(), IpcPort::as_ptr),
            may_cache: false,
            copy_strategy: MEMORY_OBJECT_COPY_NONE,
        });
        deallocate(rec);
    }
}

/// Drops the pager's records and ports once the kernel is done with it.
///
/// # Safety
///
/// The MIG server calls this once after a completed init, with the ports of
/// that init, and the package must be initialized.
///
/// # Panics
///
/// When `pager` names no pager, or one of the three ports is null.
pub unsafe fn terminate<P: Platform>(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    pager_name: Option<IpcPort>,
) {
    let Some(rec) = (unsafe { pager_hash_lookup::<P>(pager) }) else {
        panic!("(device_pager)terminate: lookup failed");
    };

    let (Some(pager), Some(pager_request), Some(pager_name)) =
        (pager, pager_request, pager_name)
    else {
        panic!("(device_pager)terminate: null port");
    };

    // SAFETY: the lookup's reference keeps the record and its device alive,
    // and the protocol paired this with one `init_pager()`, so the saved
    // send rights and the naked receive rights are live.
    unsafe {
        let record = rec.as_ptr();
        pager_hash_delete::<P>(Some((*record).pager));
        device_hash_delete((*record).device, (*record).offset);
        dev_lookup::deallocate((*record).device);

        ipc_port::release_send::<P>(pager_request);
        ipc_port::release_send::<P>(pager_name);
        ipc_port::release_receive::<P>(pager_request);
        ipc_port::release_receive::<P>(pager_name);
        ipc_port::dealloc_special::<P>(pager);

        deallocate(rec);
        deallocate(rec);
    }
}

/// Creates the pager caches and the two tables.
///
/// # Safety
///
/// Runs once from the boot sequence, before any pager exists.
pub(crate) unsafe fn init<P: Platform>() {
    // SAFETY: this call builds the caches before any pager is created.
    unsafe {
        P::device_cache_init(
            DeviceCache::Pager,
            b"dev_pager",
            size_of::<DevPager<P>>(),
        );
        P::device_cache_init(
            DeviceCache::PagerEntry,
            b"dev_pager_entry",
            size_of::<DevPagerEntry<P>>(),
        );
        P::device_cache_init(
            DeviceCache::DeviceEntry,
            b"dev_device_entry",
            size_of::<DevDeviceEntry<P>>(),
        );
    }
}
