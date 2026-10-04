// SPDX-License-Identifier: CMU-Mach
// Derived from device/dev_lookup.c and device/dev_hdr.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The device lookup table, which `device/dev_lookup.c` used to define and
//! <`device/dev_hdr.h`> declares.
//!
//! The C table's number lock was a file `static`; the Rust one is a
//! [`SpinLock`], still held before any device's `ref_lock`.

use crate::arch::x86_64::platform::MachPlatform;
use crate::device::dev_name;
use crate::device::ds_routines::{
    DevOps, Device, MACH_DEVICE_EMULATION_OPS, MachDevice,
    MachDeviceNumberAdapter,
};
use crate::ipc::IpcPort;
use crate::kern::ipc_kobject::set;
use crate::kern::lock::SimpleLock;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use collections::list::{self, List};
use core::ffi::{c_char, c_int, c_short, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use lock::SpinLock;

/// `NDEVHASH` of `device/dev_lookup.c`: the device-number buckets.
const NDEVHASH: usize = 8;

/// `DEV_BSIZE` of <device/param.h>.
const DEV_BSIZE: c_int = 512;

/// `DEV_STATE_INIT` of <`device/dev_hdr.h`>.
const DEV_STATE_INIT: c_short = 0;

/// `IKOT_DEVICE` of <`kern/ipc_kobject.h`>.
const IKOT_DEVICE: c_uint = 10;

/// `IKOT_NONE` of <`kern/ipc_kobject.h`>.
const IKOT_NONE: c_uint = 0;

/// `dev_number_hash_table` of `device/dev_lookup.c`: one bucket per
/// `DEV_NUMBER_HASH()` result.
static mut DEV_NUMBER_HASH_TABLE: [NumberBucket; NDEVHASH] =
    [const { NumberBucket::new() }; NDEVHASH];

/// A bucket of the device-number table. Keys are unique, so the order within
/// a bucket is unobservable.
type NumberBucket = List<'static, MachDeviceNumberAdapter>;

/// `dev_number_lock`: serializes the table, and is held before any device's
/// `ref_lock`, as <`device/dev_hdr.h`> requires.
static DEV_NUMBER_LOCK: SpinLock<(), MachPlatform> = SpinLock::new(());

/// `dev_hdr_cache`: the `struct mach_device` slab cache.
static mut DEV_HDR_CACHE: KmemCache = KmemCache::zeroed();

/// `DEV_NUMBER_HASH()` of `device/dev_lookup.c`.
const fn number_hash(dev_number: c_int) -> usize {
    // The mask leaves a value below `NDEVHASH`, so the cast cannot lose
    // anything that matters.
    (dev_number & (NDEVHASH as c_int - 1)) as usize
}

/// The bucket `dev_number` hashes to.
///
/// # Safety
///
/// The caller must hold [`DEV_NUMBER_LOCK`] for as long as it uses the
/// bucket.
unsafe fn number_bucket(dev_number: c_int) -> Pin<&'static mut NumberBucket> {
    // SAFETY: `number_hash()` is below the array bound, so the element is in
    // bounds; the static never moves, and the lock the caller holds keeps
    // anything else from reaching the bucket.
    unsafe {
        Pin::new_unchecked(
            &mut *ptr::addr_of_mut!(DEV_NUMBER_HASH_TABLE)
                .cast::<NumberBucket>()
                .add(number_hash(dev_number)),
        )
    }
}

/// `kmem_cache_alloc(&dev_hdr_cache)` and the field writes the C ran after
/// it.
///
/// # Safety
///
/// The cache must be initialized, and the caller must not hold
/// [`DEV_NUMBER_LOCK`].
unsafe fn alloc_device(
    dev_ops: *mut DevOps,
    dev_number: c_int,
) -> Option<NonNull<MachDevice>> {
    // SAFETY: the cache is live after `init()`.
    let buf = unsafe { (*ptr::addr_of_mut!(DEV_HDR_CACHE)).alloc() }?;
    let device = buf.as_ptr().cast::<MachDevice>();
    // SAFETY: the cache object is a fresh, unshared `struct mach_device`,
    // and the C wrote every field the mirror carries.
    unsafe {
        ptr::write(
            device,
            MachDevice {
                ref_lock: SimpleLock::new(),
                ref_count: 1,
                lock: SimpleLock::new(),
                state: DEV_STATE_INIT,
                flag: 0,
                open_count: 0,
                io_in_progress: 0,
                io_wait: 0,
                port: ptr::null_mut(),
                number_chain: list::Link::new(),
                dev_number,
                bsize: DEV_BSIZE,
                dev_ops,
                dev: Device {
                    emul_ops: ptr::null_mut(),
                    emul_data: ptr::null_mut(),
                },
            },
        );
    }
    NonNull::new(device)
}

/// `kmem_cache_free(&dev_hdr_cache, device)` of the C.
///
/// # Safety
///
/// `device` must be a dead device from [`alloc_device()`] with no holder
/// left.
unsafe fn free_device(device: *mut MachDevice) {
    unsafe {
        (*ptr::addr_of_mut!(DEV_HDR_CACHE))
            .free(NonNull::new_unchecked(device.cast::<u8>()));
    }
}

/// `dev_number_enter()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// [`DEV_NUMBER_LOCK`] must be held, and `device` must be live and not
/// linked into the table.
unsafe fn number_enter(device: *mut MachDevice) {
    // SAFETY: the table lock is held.
    let mut head = unsafe { number_bucket((*device).dev_number) };
    // SAFETY: `device` is live and unlinked, and only the table reaches it
    // until `number_remove()` unlinks it.
    unsafe { head.as_mut().push_front_ptr(NonNull::new_unchecked(device)) };
}

/// `dev_number_remove()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// [`DEV_NUMBER_LOCK`] must be held, and `device` must be linked into the
/// table.
unsafe fn number_remove(device: *mut MachDevice) {
    // SAFETY: `device` is on its bucket, and the table lock keeps anything
    // else from reaching it.
    unsafe { NumberBucket::remove_ptr(NonNull::new_unchecked(device)) };
}

/// `dev_number_lookup()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// [`DEV_NUMBER_LOCK`] must be held, and every linked device live.
unsafe fn number_lookup(
    dev_ops: *mut DevOps,
    dev_number: c_int,
) -> *mut MachDevice {
    // SAFETY: the table lock is held.
    let head = unsafe { number_bucket(dev_number) };
    let mut cursor = head.cursor_front();
    while let Some(device) = cursor.current() {
        if device.dev_ops == dev_ops && device.dev_number == dev_number {
            return cursor
                .current_ptr()
                .map_or(ptr::null_mut(), NonNull::as_ptr);
        }
        cursor.move_next();
    }
    ptr::null_mut()
}

/// `device_lookup()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `name` must be a NUL-terminated string readable by the caller, and the
/// device package must be initialized. The returned device carries one
/// reference.
pub(crate) unsafe fn lookup(
    name: *const c_char,
) -> Option<NonNull<MachDevice>> {
    let (dev_ops, dev_number) = unsafe { dev_name::lookup(name) }?;
    let dev_ops = dev_ops.as_ptr();

    let mut new_device: *mut MachDevice = ptr::null_mut();
    loop {
        let guard = DEV_NUMBER_LOCK.lock();
        // SAFETY: the lock is held and the table initialized.
        let found = unsafe { number_lookup(dev_ops, dev_number) };
        if !found.is_null() {
            // SAFETY: the found device is live under the lock.
            unsafe {
                reference(found);
                drop(guard);
                if !new_device.is_null() {
                    free_device(new_device);
                }
            }
            return NonNull::new(found);
        }
        if !new_device.is_null() {
            // SAFETY: the fresh device is unshared and the lock is held.
            unsafe {
                number_enter(new_device);
                drop(guard);
            }
            return NonNull::new(new_device);
        }
        drop(guard);

        // SAFETY: the cache is initialized, and the C allocated without the
        // table lock too.
        let device = (unsafe { alloc_device(dev_ops, dev_number) })?;
        new_device = device.as_ptr();
    }
}

/// `mach_device_reference()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be a live mach device.
pub(crate) unsafe fn reference(device: *mut MachDevice) {
    unsafe {
        (*device).ref_lock.lock();
        (*device).ref_count += 1;
        (*device).ref_lock.unlock();
    }
}

/// `mach_device_deallocate()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be a live mach device the caller holds a reference on, and
/// nothing may touch it once its last reference goes.
pub(crate) unsafe fn deallocate(device: *mut MachDevice) {
    unsafe {
        (*device).ref_lock.lock();
        (*device).ref_count -= 1;
        if (*device).ref_count > 0 {
            (*device).ref_lock.unlock();
            return;
        }
        (*device).ref_count = 1;
        (*device).ref_lock.unlock();

        let guard = DEV_NUMBER_LOCK.lock();
        (*device).ref_lock.lock();
        (*device).ref_count -= 1;
        if (*device).ref_count > 0 {
            (*device).ref_lock.unlock();
            drop(guard);
            return;
        }
        number_remove(device);
        (*device).ref_lock.unlock();
        drop(guard);
    }

    // SAFETY: the last reference is gone, and the caller must not touch the
    // device again.
    unsafe { free_device(device) };
}

/// `mach_device_reference()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be a live mach device.
pub(crate) unsafe fn mach_device_reference(device: *mut c_void) {
    unsafe { reference(device.cast()) };
}

/// `mach_device_deallocate()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be a live mach device the caller holds a reference on.
pub(crate) unsafe fn mach_device_deallocate(device: *mut c_void) {
    unsafe { deallocate(device.cast()) };
}

/// `dev_port_enter()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be a live device whose port is a live port, and the caller
/// must own a device reference for the mapping to take.
pub(crate) unsafe fn port_enter(device: *mut MachDevice) {
    unsafe {
        reference(device);
        set(
            (*device).port,
            ptr::addr_of_mut!((*device).dev).addr(),
            IKOT_DEVICE,
        );
        (*device).dev.emul_data = device.cast::<c_void>();
        (*device).dev.emul_ops = ptr::addr_of_mut!(MACH_DEVICE_EMULATION_OPS);
    }
}

/// `dev_port_remove()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be a live device whose port carries the mapping, and the
/// caller's reference moves into the call.
pub(crate) unsafe fn port_remove(device: *mut MachDevice) {
    unsafe {
        set((*device).port, 0, IKOT_NONE);
        deallocate(device);
    }
}

/// `dev_port_lookup()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
pub(crate) unsafe fn port_lookup(port: *mut c_void) -> *mut Device {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    // SAFETY: the live port's lock serializes the kobject read, and a
    // `IKOT_DEVICE` kobject is the embedded `struct device` of a live
    // `mach_device`.
    unsafe {
        port.lock();
        let device = if port.is_active() && port.kotype() == IKOT_DEVICE {
            let device = port.kobject().cast::<Device>();
            let ops = (*device).emul_ops;
            if !ops.is_null()
                && let Some(reference) = (*ops).reference
            {
                reference((*device).emul_data);
            }
            device
        } else {
            ptr::null_mut()
        };
        port.unlock();
        device
    }
}

/// `convert_device_to_port()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// A non-null `device` must name a live `struct device`, and its emulation
/// must be one whose `dev_to_port` takes the reference the caller consumed.
pub(crate) unsafe fn convert_to_port(
    device: Option<NonNull<Device>>,
) -> *mut c_void {
    let Some(device) = device else {
        return ptr::null_mut();
    };
    let device = device.as_ptr();

    unsafe {
        let ops = (*device).emul_ops;
        if ops.is_null() {
            return ptr::null_mut();
        }
        (*ops).dev_to_port.map_or(ptr::null_mut(), |dev_to_port| {
            dev_to_port((*device).emul_data)
        })
    }
}

/// `dev_lookup_init()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// Runs once from the boot sequence, before any device exists.
pub(crate) unsafe fn init() {
    // SAFETY: this call builds the cache and the queue heads before any
    // device is looked up.
    unsafe {
        (*ptr::addr_of_mut!(DEV_HDR_CACHE)).init(
            b"mach_device",
            size_of::<MachDevice>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}
