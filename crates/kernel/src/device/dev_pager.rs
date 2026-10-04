// SPDX-License-Identifier: CMU-Mach
// Derived from device/dev_pager.c:
//   Copyright (c) 1993-1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The device pager, which `device/dev_pager.c` used to define and
//! <`device/dev_pager.h`> used to declare.
//!
//! The C record's `client_count`, `pager_name` and `size` fields were
//! written and never read, so the Rust record does not carry them; its
//! reference count is an atomic where the C held a per-record lock.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SHIFT;
use crate::arch::x86_64::io_req::DevT;
use crate::arch::x86_64::platform::MachPlatform;
use crate::device::dev_lookup;
use crate::device::dev_name::nomap;
use crate::device::ds_routines::{MachDevice, driver_unit};
use crate::device::r#return::DeviceError;
use crate::glue;
use crate::ipc::{IpcPort, ipc_port, ipc_space};
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::vm::error::Error;
use crate::vm::vm_object;
use crate::vm::vm_resident::VM_PAGE_FICTITIOUS_ADDR;
use collections::list::{self, List};
use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicI32, Ordering};
use lock::SpinLock;

/// `DEV_HASH_COUNT` of `device/dev_pager.c`: the number of buckets in both
/// tables.
const DEV_HASH_COUNT: usize = 127;

/// `KERN_RESOURCE_SHORTAGE` of <`mach/kern_return.h`>.
const KERN_RESOURCE_SHORTAGE: c_int = 6;

/// `MEMORY_OBJECT_COPY_NONE` of <`mach/memory_object.h`>.
const MEMORY_OBJECT_COPY_NONE: c_int = 0;

/// `device_pager_debug` of `device/dev_pager.c`: the switch the C checked
/// before its two trace prints, kept for a debugger to set.
pub static DEVICE_PAGER_DEBUG: AtomicI32 = AtomicI32::new(0);

const _: () = assert!(size_of::<AtomicI32>() == size_of::<c_int>());
const _: () = assert!(align_of::<AtomicI32>() == align_of::<c_int>());

/// One device pager record, the C `struct dev_pager`.
struct DevPager {
    ref_count: AtomicI32,
    pager: IpcPort,
    pager_request: Option<IpcPort>,
    device: *mut MachDevice,
    offset: VmOffset,
    prot: c_int,
}

/// The failure `device_pager_setup()` reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupError {
    /// The `D_INVALID_OPERATION` of a device whose driver cannot map.
    InvalidOperation,
    /// The `KERN_RESOURCE_SHORTAGE` of a failed record or port allocation.
    ResourceShortage,
}

impl SetupError {
    /// The code the C returned for this failure: the `D_*` code goes to the
    /// device map caller, the `kern_return_t` to `device_pager_setup()`.
    pub(crate) const fn code(self) -> c_int {
        match self {
            Self::InvalidOperation => DeviceError::InvalidOperation as i32,
            Self::ResourceShortage => KERN_RESOURCE_SHORTAGE,
        }
    }
}

/// `dev_pager_cache` of `device/dev_pager.c`: the `struct dev_pager` slab
/// cache.
static mut DEV_PAGER_CACHE: KmemCache = KmemCache::zeroed();

/// `dev_pager_hashtable` of `device/dev_pager.c`: one bucket per
/// `dev_hash()` result, keyed by the pager port.
static mut DEV_PAGER_HASHTABLE: [PagerBucket; DEV_HASH_COUNT] =
    [const { PagerBucket::new() }; DEV_HASH_COUNT];

/// `dev_pager_hash_lock`: serializes the port-name table.
static DEV_PAGER_HASH_LOCK: SpinLock<(), MachPlatform> = SpinLock::new(());

/// `dev_pager_hash_cache`: the `struct dev_pager_entry` slab cache.
static mut DEV_PAGER_HASH_CACHE: KmemCache = KmemCache::zeroed();

/// One entry of `dev_pager_hashtable`, the C `struct dev_pager_entry`.
pub(crate) struct DevPagerEntry {
    links: list::Link,
    name: Option<IpcPort>,
    pager: NonNull<DevPager>,
}

/// `dev_device_hashtable` of `device/dev_pager.c`: one bucket per
/// `dev_hash()` result, keyed by device and offset.
static mut DEV_DEVICE_HASHTABLE: [DeviceBucket; DEV_HASH_COUNT] =
    [const { DeviceBucket::new() }; DEV_HASH_COUNT];

/// `dev_device_hash_lock`: serializes the device-and-offset table.
static DEV_DEVICE_HASH_LOCK: SpinLock<(), MachPlatform> = SpinLock::new(());

/// `dev_device_hash_cache`: the `struct dev_device_entry` slab cache.
static mut DEV_DEVICE_HASH_CACHE: KmemCache = KmemCache::zeroed();

/// One entry of `dev_device_hashtable`, the C `struct dev_device_entry`.
pub(crate) struct DevDeviceEntry {
    links: list::Link,
    device: *mut MachDevice,
    offset: VmOffset,
    pager: NonNull<DevPager>,
}

list::adapter!(
    /// The adapter for a pager entry's `links` in the port-name table.
    DevPagerEntryAdapter = DevPagerEntry { links }
);

list::adapter!(
    /// The adapter for a device entry's `links` in the device table.
    DevDeviceEntryAdapter = DevDeviceEntry { links }
);

/// A bucket of the port-name table. Keys are unique, so the order within a
/// bucket is unobservable.
type PagerBucket = List<'static, DevPagerEntryAdapter>;

/// A bucket of the device-and-offset table, unordered like [`PagerBucket`].
type DeviceBucket = List<'static, DevDeviceEntryAdapter>;

/// `dev_hash()` of `device/dev_pager.c`: the C masked the low 24 bits of the
/// whole value, a pointer or a pointer plus offset, and reduced it modulo the
/// bucket count.
const fn dev_hash(value: usize) -> usize {
    (value & 0x00ff_ffff) % DEV_HASH_COUNT
}

/// The port-name bucket the C's `dev_hash()` selected.
///
/// # Safety
///
/// The caller must hold `DEV_PAGER_HASH_LOCK` for as long as it uses the
/// bucket.
unsafe fn pager_bucket(
    name: Option<IpcPort>,
) -> Pin<&'static mut PagerBucket> {
    let value = name.map_or(0, |port| port.as_ptr().addr());
    // SAFETY: `dev_hash()` is below the array bound, so the element is in
    // bounds; the static never moves, and the lock the caller holds keeps
    // anything else from reaching the bucket.
    unsafe {
        Pin::new_unchecked(
            &mut *ptr::addr_of_mut!(DEV_PAGER_HASHTABLE)
                .cast::<PagerBucket>()
                .add(dev_hash(value)),
        )
    }
}

/// The device-and-offset bucket the C's `dev_hash()` selected.
///
/// # Safety
///
/// The caller must hold `DEV_DEVICE_HASH_LOCK` for as long as it uses the
/// bucket.
unsafe fn device_bucket(
    device: *mut MachDevice,
    offset: VmOffset,
) -> Pin<&'static mut DeviceBucket> {
    let value = device.addr().wrapping_add(offset);
    // SAFETY: `dev_hash()` is below the array bound, so the element is in
    // bounds; the static never moves, and the lock the caller holds keeps
    // anything else from reaching the bucket.
    unsafe {
        Pin::new_unchecked(
            &mut *ptr::addr_of_mut!(DEV_DEVICE_HASHTABLE)
                .cast::<DeviceBucket>()
                .add(dev_hash(value)),
        )
    }
}

/// The first entry of `head` whose name is `name`.
fn find_pager_entry(
    head: &PagerBucket,
    name: Option<IpcPort>,
) -> Option<NonNull<DevPagerEntry>> {
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
fn find_device_entry(
    head: &DeviceBucket,
    device: *mut MachDevice,
    offset: VmOffset,
) -> Option<NonNull<DevDeviceEntry>> {
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
unsafe fn reference(rec: NonNull<DevPager>) -> NonNull<DevPager> {
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
unsafe fn deallocate(rec: NonNull<DevPager>) {
    // `AcqRel` on the decrement releases this thread's writes and acquires
    // the other releases, so the free below sees a complete record.
    let last =
        unsafe { (*rec.as_ptr()).ref_count.fetch_sub(1, Ordering::AcqRel) }
            == 1;
    if last {
        // SAFETY: no reference remains, so nothing else can reach the
        // record's cache object.
        unsafe {
            (*ptr::addr_of_mut!(DEV_PAGER_CACHE)).free(rec.cast::<u8>());
        }
    }
}

/// `dev_pager_hash_insert()` of `device/dev_pager.c`.
///
/// # Safety
///
/// The package must be initialized, `rec` must be a live record, and nothing
/// may hold the port-name lock.
unsafe fn pager_hash_insert(name: Option<IpcPort>, rec: NonNull<DevPager>) {
    // SAFETY: the cache is live after `init()`, and the fresh buffer is
    // linked nowhere.
    let Some(buf) =
        (unsafe { (*ptr::addr_of_mut!(DEV_PAGER_HASH_CACHE)).alloc() })
    else {
        kpanic!("dev_pager_hash_insert", "dev_pager_hash_insert: no memory");
    };
    let entry = buf.cast::<DevPagerEntry>();
    // SAFETY: the cache object is sized and aligned for a whole entry.
    unsafe {
        entry.write(DevPagerEntry {
            links: list::Link::new(),
            name,
            pager: rec,
        });
    }

    let _guard = DEV_PAGER_HASH_LOCK.lock();
    // SAFETY: the lock is held.
    let mut head = unsafe { pager_bucket(name) };
    // SAFETY: the entry is a stable, unlinked cache object that only this
    // table reaches until `pager_hash_delete()` unlinks and frees it.
    unsafe { head.as_mut().push_front_ptr(entry) };
}

/// `dev_pager_hash_delete()` of `device/dev_pager.c`.
///
/// # Safety
///
/// The package must be initialized, and only the C protocol's own entry for
/// `name` may exist.
unsafe fn pager_hash_delete(name: Option<IpcPort>) {
    let found = {
        let _guard = DEV_PAGER_HASH_LOCK.lock();
        // SAFETY: the lock is held.
        let head = unsafe { pager_bucket(name) };
        let entry = find_pager_entry(&head, name);
        if let Some(entry) = entry {
            // SAFETY: `entry` is on this bucket, and the lock keeps
            // anything else from reaching it.
            unsafe { PagerBucket::remove_ptr(entry) };
        }
        entry
    };

    let Some(entry) = found else {
        return;
    };
    // SAFETY: the entry was just unlinked and owns its cache object.
    unsafe {
        (*ptr::addr_of_mut!(DEV_PAGER_HASH_CACHE)).free(entry.cast::<u8>());
    }
}

/// `dev_pager_hash_lookup()` of `device/dev_pager.c`: the record an entry
/// names, with a reference taken on it.
///
/// # Safety
///
/// The package must be initialized.
unsafe fn pager_hash_lookup(
    name: Option<IpcPort>,
) -> Option<NonNull<DevPager>> {
    let _guard = DEV_PAGER_HASH_LOCK.lock();
    // SAFETY: the lock is held.
    let head = unsafe { pager_bucket(name) };
    let entry = find_pager_entry(&head, name)?;
    // SAFETY: the table holds the record's initial reference, and the entry
    // keeps the record alive while the lock is held.
    Some(unsafe { reference((*entry.as_ptr()).pager) })
}

/// `dev_device_hash_insert()` of `device/dev_pager.c`.
///
/// # Safety
///
/// The package must be initialized, `rec` must be a live record, and nothing
/// may hold the device lock.
unsafe fn device_hash_insert(
    device: *mut MachDevice,
    offset: VmOffset,
    rec: NonNull<DevPager>,
) {
    // SAFETY: the cache is live after `init()`, and the fresh buffer is
    // linked nowhere.
    let Some(buf) =
        (unsafe { (*ptr::addr_of_mut!(DEV_DEVICE_HASH_CACHE)).alloc() })
    else {
        kpanic!(
            "dev_device_hash_insert",
            "dev_device_hash_insert: no memory"
        );
    };
    let entry = buf.cast::<DevDeviceEntry>();
    // SAFETY: the cache object is sized and aligned for a whole entry.
    unsafe {
        entry.write(DevDeviceEntry {
            links: list::Link::new(),
            device,
            offset,
            pager: rec,
        });
    }

    let _guard = DEV_DEVICE_HASH_LOCK.lock();
    // SAFETY: the lock is held.
    let mut head = unsafe { device_bucket(device, offset) };
    // SAFETY: the entry is a stable, unlinked cache object that only this
    // table reaches until `device_hash_delete()` unlinks and frees it.
    unsafe { head.as_mut().push_front_ptr(entry) };
}

/// `dev_device_hash_delete()` of `device/dev_pager.c`.
///
/// # Safety
///
/// The package must be initialized, and only the C protocol's own entry for
/// `device` and `offset` may exist.
unsafe fn device_hash_delete(device: *mut MachDevice, offset: VmOffset) {
    let found = {
        let _guard = DEV_DEVICE_HASH_LOCK.lock();
        // SAFETY: the lock is held.
        let head = unsafe { device_bucket(device, offset) };
        let entry = find_device_entry(&head, device, offset);
        if let Some(entry) = entry {
            // SAFETY: `entry` is on this bucket, and the lock keeps
            // anything else from reaching it.
            unsafe { DeviceBucket::remove_ptr(entry) };
        }
        entry
    };

    let Some(entry) = found else {
        return;
    };
    // SAFETY: the entry was just unlinked and owns its cache object.
    unsafe {
        (*ptr::addr_of_mut!(DEV_DEVICE_HASH_CACHE)).free(entry.cast::<u8>());
    }
}

/// `dev_device_hash_lookup()` of `device/dev_pager.c`: the record an entry
/// names, with a reference taken on it.
///
/// # Safety
///
/// The package must be initialized.
unsafe fn device_hash_lookup(
    device: *mut MachDevice,
    offset: VmOffset,
) -> Option<NonNull<DevPager>> {
    let _guard = DEV_DEVICE_HASH_LOCK.lock();
    // SAFETY: the lock is held.
    let head = unsafe { device_bucket(device, offset) };
    let entry = find_device_entry(&head, device, offset)?;
    // SAFETY: the table holds the record's initial reference, and the entry
    // keeps the record alive while the lock is held.
    Some(unsafe { reference((*entry.as_ptr()).pager) })
}

/// `device_map_page()` of `device/dev_pager.c`, the callback
/// `vm_object_page_map()` calls.
///
/// # Safety
///
/// `dsp` must be the live record [`data_request()`] passes.
pub(crate) unsafe fn device_map_page(
    dsp: *mut c_void,
    offset: VmOffset,
) -> VmOffset {
    let Some(rec) = NonNull::new(dsp.cast::<DevPager>()) else {
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
        // `pmap_phys_address(frame)` of <i386/intel/pmap.h> is the
        // `intel_ptob()` shift of the frame cast to `phys_addr_t`; the
        // shift drops what does not fit, as the C's did.
        pagenum.wrapping_shl(PAGE_SHIFT)
    }
}

/// `device_pager_setup()` of `device/dev_pager.c`.
///
/// # Safety
///
/// `device` must be a live, referenced mach device whose `dev_ops` is live,
/// and the package must be initialized.
pub(crate) unsafe fn setup(
    device: *mut MachDevice,
    prot: c_int,
    offset: VmOffset,
) -> Result<IpcPort, SetupError> {
    let ops = unsafe { (*device).dev_ops };
    if ops.is_null() {
        return Err(SetupError::InvalidOperation);
    }
    // SAFETY: `ops` belongs to the live device.
    let Some(d_mmap) = (unsafe { (*ops).d_mmap }) else {
        return Err(SetupError::InvalidOperation);
    };
    if ptr::fn_addr_eq(
        d_mmap,
        nomap as unsafe fn(DevT, VmOffset, c_int) -> VmOffset,
    ) {
        return Err(SetupError::InvalidOperation);
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
    let Some(buf) = (unsafe { (*ptr::addr_of_mut!(DEV_PAGER_CACHE)).alloc() })
    else {
        return Err(SetupError::ResourceShortage);
    };
    let rec = buf.as_ptr().cast::<DevPager>();
    // SAFETY: the kernel space is live and the port cache is initialized,
    // as the C's `ipc_port_alloc_kernel()` required.
    let Some(pager) =
        (unsafe { ipc_port::alloc_special(ipc_space::kernel()) })
    else {
        // SAFETY: the fresh cache object owns nothing yet.
        unsafe {
            (*ptr::addr_of_mut!(DEV_PAGER_CACHE))
                .free(NonNull::new_unchecked(rec.cast::<u8>()));
        }
        return Err(SetupError::ResourceShortage);
    };

    // SAFETY: the cache object is uninitialized and owned here; the device
    // reference is taken before the record becomes reachable.
    unsafe {
        ptr::write(
            rec,
            DevPager {
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

/// `device_pager_data_request()` of `device/dev_pager.c`.
///
/// # Safety
///
/// `pager` must be the live port of a set-up pager record, `pager_request`
/// the live control port the kernel bound to it, and the package must be
/// initialized.
pub(crate) unsafe fn data_request(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    offset: VmOffset,
    length: VmSize,
) {
    if DEVICE_PAGER_DEBUG.load(Ordering::Relaxed) != 0 {
        kprint!(
            "(device_pager)data_request: pager={:x}, offset=0x{:x}, length=0x{:x}\n",
            pager
                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                .expose_provenance(),
            offset,
            length,
        );
    }

    let Some(rec) = (unsafe { pager_hash_lookup(pager) }) else {
        kpanic!(
            "device_pager_data_request",
            "(device_pager)data_request: lookup failed"
        );
    };

    // SAFETY: the lookup referenced the record, and the device reference it
    // holds keeps the record's fields live.
    unsafe {
        let record = rec.as_ptr();
        if (*record).pager_request != pager_request {
            kpanic!(
                "device_pager_data_request",
                "(device_pager)data_request: bad pager_request"
            );
        }

        let control = pager_request.map_or(ptr::null_mut(), IpcPort::as_ptr);
        let Some(object) = vm_object::lookup(control) else {
            let _ = glue::r_memory_object_data_error(
                control,
                offset,
                length,
                Error::Failure.as_kern_return(),
            );
            deallocate(rec);
            return;
        };

        // SAFETY: the object is the live object of the request, and the
        // callback takes the record the lookup referenced.
        let result = vm_object::page_map(
            object.as_ptr(),
            offset,
            length,
            Some(device_map_page),
            record.cast::<c_void>(),
        );
        if let Err(error) = result {
            let _ = glue::r_memory_object_data_error(
                control,
                offset,
                length,
                error.as_kern_return(),
            );
        }
        vm_object::deallocate(object.as_ptr());
        deallocate(rec);
    }
}

/// `device_pager_init_pager()` of `device/dev_pager.c`.
///
/// # Safety
///
/// The MIG server calls this once for the pager `pager` denotes, before any
/// data request, and the package must be initialized.
pub(crate) unsafe fn init_pager(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    pager_name: Option<IpcPort>,
) {
    if DEVICE_PAGER_DEBUG.load(Ordering::Relaxed) != 0 {
        kprint!(
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
        );
    }

    let Some(rec) = (unsafe { pager_hash_lookup(pager) }) else {
        kpanic!(
            "device_pager_init_pager",
            "(device_pager)init: lookup failed"
        );
    };

    // SAFETY: the lookup referenced the record, and the MIG protocol runs
    // this once before any data request.
    unsafe {
        (*rec.as_ptr()).pager_request = pager_request;
        let _ = glue::r_memory_object_ready(
            pager_request.map_or(ptr::null_mut(), IpcPort::as_ptr),
            c_int::from(false),
            MEMORY_OBJECT_COPY_NONE,
        );
        deallocate(rec);
    }
}

/// `device_pager_terminate()` of `device/dev_pager.c`.
///
/// # Safety
///
/// The MIG server calls this once after a completed init, with the ports of
/// that init, and the package must be initialized.
pub(crate) unsafe fn terminate(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    pager_name: Option<IpcPort>,
) {
    let Some(rec) = (unsafe { pager_hash_lookup(pager) }) else {
        kpanic!(
            "device_pager_terminate",
            "(device_pager)terminate: lookup failed"
        );
    };

    let (Some(pager), Some(pager_request), Some(pager_name)) =
        (pager, pager_request, pager_name)
    else {
        kpanic!(
            "device_pager_terminate",
            "(device_pager)terminate: null port"
        );
    };

    // SAFETY: the lookup's reference keeps the record and its device alive,
    // and the protocol paired this with one `init_pager()`, so the saved
    // send rights and the naked receive rights are live.
    unsafe {
        let record = rec.as_ptr();
        pager_hash_delete(Some((*record).pager));
        device_hash_delete((*record).device, (*record).offset);
        dev_lookup::deallocate((*record).device);

        ipc_port::release_send(pager_request);
        ipc_port::release_send(pager_name);
        ipc_port::release_receive(pager_request);
        ipc_port::release_receive(pager_name);
        ipc_port::dealloc_special(pager);

        deallocate(rec);
        deallocate(rec);
    }
}

/// `device_pager_init()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Runs once from the boot sequence, before any pager exists.
pub(crate) unsafe fn init() {
    // SAFETY: this call builds the caches and the queue heads before any
    // pager is created.
    unsafe {
        (*ptr::addr_of_mut!(DEV_PAGER_CACHE)).init(
            b"dev_pager",
            size_of::<DevPager>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
        (*ptr::addr_of_mut!(DEV_PAGER_HASH_CACHE)).init(
            b"dev_pager_entry",
            size_of::<DevPagerEntry>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
        (*ptr::addr_of_mut!(DEV_DEVICE_HASH_CACHE)).init(
            b"dev_device_entry",
            size_of::<DevDeviceEntry>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}
