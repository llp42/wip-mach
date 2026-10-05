// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_marequest.c and ipc/ipc_marequest.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The msg-accepted request routines, which `ipc/ipc_marequest.c` used to
//! define and `ipc/ipc_marequest.h` declares.

use crate::ipc::error::SendError;
use crate::ipc::ipc_notify;
use crate::ipc::ipc_port;
use crate::ipc::ipc_right;
use crate::ipc::ipc_space;
use crate::ipc::{
    HashInfoBucket, IE_BITS_MAREQUEST, IpcMarequest, IpcMarequestBucket,
    IpcPort, IpcSpace,
};
use crate::kern::debug::kpanic;
use crate::kern::slab::{self, CacheInitFlags, KmemCache};
use core::ffi::c_uint;
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// `IPC_MAREQUEST_SIZE` of <`ipc/ipc_marequest.h`>.
const IPC_MAREQUEST_SIZE: c_uint = 16;
/// `MACH_PORT_NAME_NULL` of <mach/port.h>: the name no entry holds.
const MACH_PORT_NAME_NULL: c_uint = 0;

/// `ipc_marequest_cache` of `ipc/ipc_marequest.c`: the request slab cache.
static mut IPC_MAREQUEST_CACHE: KmemCache = KmemCache::zeroed();

/// `ipc_marequest_size` of `ipc/ipc_marequest.c`: the number of hash buckets.
static MAREQUEST_SIZE: AtomicU32 = AtomicU32::new(0);
/// `ipc_marequest_mask` of `ipc/ipc_marequest.c`: the bucket-index mask.
static MAREQUEST_MASK: AtomicU32 = AtomicU32::new(0);
/// `ipc_marequest_table` of `ipc/ipc_marequest.c`: the bucket array.
static MAREQUEST_TABLE: AtomicPtr<IpcMarequestBucket> =
    AtomicPtr::new(ptr::null_mut());

/// `IMAR_HASH()` of `ipc/ipc_marequest.c`.
///
/// The loads are `Relaxed`: `ipc_marequest_init()` writes the state before
/// any request can exist, so no ordering is needed, only an atomic for the
/// shared `static`.
fn hash(space: IpcSpace, name: c_uint) -> usize {
    let mask = MAREQUEST_MASK.load(Ordering::Relaxed);
    // The C truncated the kernel address to `ipc_marequest_index_t` before
    // shifting, `MACH_PORT_INDEX` is the name, and `MACH_PORT_NGEN` is zero
    // in this configuration.
    let key = ((space.as_ptr().addr() as u32) >> 4).wrapping_add(name) & mask;
    // Both targets address at least 32 bits, so the widening cannot lose
    // anything.
    key as usize
}

/// The bucket `space` and `name` hash to.
///
/// # Safety
///
/// `ipc_marequest_init()` must have run.
unsafe fn bucket(space: IpcSpace, name: c_uint) -> *mut IpcMarequestBucket {
    unsafe {
        MAREQUEST_TABLE
            .load(Ordering::Relaxed)
            .add(hash(space, name))
    }
}

/// `imar_alloc()` of `ipc/ipc_marequest.c`.
fn alloc() -> Option<*mut IpcMarequest> {
    // SAFETY: `ipc_bootstrap()` initialized the cache before any request.
    let buf = unsafe { (*ptr::addr_of_mut!(IPC_MAREQUEST_CACHE)).alloc()? };
    // SAFETY: the cache's buffers are `struct ipc_marequest` sized, as its
    // init recorded from the C size.
    Some(buf.as_ptr().cast())
}

/// `imar_free()` of `ipc/ipc_marequest.c`.
///
/// # Safety
///
/// `marequest` must be a live allocation from the cache that nothing uses.
unsafe fn free(marequest: *mut IpcMarequest) {
    unsafe {
        (*ptr::addr_of_mut!(IPC_MAREQUEST_CACHE))
            .free(NonNull::new_unchecked(marequest.cast::<u8>()));
    }
}

/// The unlink walk both `ipc_marequest_cancel()` and `rename()` use: find
/// `(space, name)` in `bucket` and return the node with its predecessor's
/// link still pointing at it.
///
/// # Safety
///
/// `bucket` must be live and locked.
unsafe fn find_locked(
    bucket: *mut IpcMarequestBucket,
    space: IpcSpace,
    name: c_uint,
) -> (*mut IpcMarequest, *mut *mut IpcMarequest) {
    unsafe {
        let mut last = ptr::addr_of_mut!((*bucket).head);
        loop {
            let current = *last;
            if current.is_null() {
                return (ptr::null_mut(), last);
            }

            if (*current).space == space.as_ptr() && (*current).name == name {
                return (current, last);
            }

            last = ptr::addr_of_mut!((*current).next);
        }
    }
}

/// `ipc_marequest_init()` in C.
///
/// # Safety
///
/// `ipc_bootstrap()` must call this once, before any request is created.
pub(crate) unsafe fn init() {
    let mut size = IPC_MAREQUEST_SIZE;
    let mut mask = size - 1;

    if size & mask != 0 {
        let mut bit = 1;
        loop {
            mask |= bit;
            size = mask.wrapping_add(1);
            if size & mask == 0 {
                break;
            }
            bit <<= 1;
        }
    }

    // Both targets address at least 32 bits, so the widening cannot lose
    // anything.
    let bytes = size as usize * size_of::<IpcMarequestBucket>();
    // The boot path runs this once, before any request exists.
    let Some(table) = slab::kalloc(bytes) else {
        kpanic!(
            "ipc_marequest_init",
            "ipc_marequest_init: no memory for the table"
        )
    };
    let table = table.cast::<IpcMarequestBucket>().as_ptr();

    // Both targets address at least 32 bits, so the widening cannot lose
    // anything.
    for i in 0..size as usize {
        // SAFETY: the allocation holds `size` buckets.
        unsafe {
            let bucket = table.add(i);
            (*bucket).lock.init();
            (*bucket).head = ptr::null_mut();
        }
    }

    MAREQUEST_SIZE.store(size, Ordering::Relaxed);
    MAREQUEST_MASK.store(mask, Ordering::Relaxed);
    MAREQUEST_TABLE.store(table, Ordering::Relaxed);

    // SAFETY: the boot path runs this once, and the cache is this call's to
    // initialize.
    unsafe {
        (*ptr::addr_of_mut!(IPC_MAREQUEST_CACHE)).init(
            b"ipc_marequest",
            size_of::<IpcMarequest>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}

/// `ipc_marequest_create()` in C.
///
/// # Safety
///
/// `space` must be live with nothing locked, `port` a live port, and `notify`
/// a name in `space`; may allocate memory.  On success the returned request
/// is initialized.
pub(crate) unsafe fn create(
    space: IpcSpace,
    port: IpcPort,
    notify: c_uint,
) -> Result<*mut IpcMarequest, SendError> {
    let Some(marequest) = alloc() else {
        return Err(SendError::NoNotify);
    };

    unsafe { space.lock_write() };

    // SAFETY: the space is live and locked.
    if !unsafe { space.is_active() } {
        // SAFETY: the space is live and locked.
        unsafe { space.lock_done() };
        // SAFETY: the request is the fresh allocation from above.
        unsafe { free(marequest) };
        return Err(SendError::InvalidNotify);
    }

    let reversed = unsafe { ipc_right::reverse(space, port.as_ptr()) };

    if let Some((name, entry)) = reversed {
        // SAFETY: the success path leaves the port locked.
        unsafe { port.unlock() };

        if entry.is_null() {
            // The C dereferenced the missing entry here; without it the
            // port's receiver has nothing to mark, so the notify name cannot
            // be honoured.
            // SAFETY: the space is live and write-locked.
            unsafe { space.lock_done() };
            // SAFETY: the request is the fresh allocation from above.
            unsafe { free(marequest) };
            return Err(SendError::InvalidNotify);
        }

        // SAFETY: the entry is live.
        let bits = unsafe { (*entry).bits() };
        if bits & IE_BITS_MAREQUEST != 0 {
            // SAFETY: the space is live and write-locked.
            unsafe { space.lock_done() };
            // SAFETY: the request is the fresh allocation from above.
            unsafe { free(marequest) };
            return Err(SendError::NotifyInProgress);
        }

        // SAFETY: the space is live and write-locked.
        let Some(soright) =
            (unsafe { ipc_port::lookup_notify(space, notify) })
        else {
            // SAFETY: the space is live and write-locked.
            unsafe { space.lock_done() };
            // SAFETY: the request is the fresh allocation from above.
            unsafe { free(marequest) };
            return Err(SendError::InvalidNotify);
        };

        // SAFETY: the entry is live and the space lock is held.
        unsafe { (*entry).set_bits(bits | IE_BITS_MAREQUEST) };
        // SAFETY: the space is live, active, and write-locked.
        unsafe { ipc_space::reference(space) };

        // SAFETY: the request is the fresh allocation from above.
        unsafe {
            (*marequest).space = space.as_ptr();
            (*marequest).name = name;
            (*marequest).soright = soright.as_ptr();
        }

        // SAFETY: the table was initialized at bootstrap.
        unsafe {
            let bucket = bucket(space, name);
            (*bucket).lock.lock();
            (*marequest).next = (*bucket).head;
            (*bucket).head = marequest;
            (*bucket).lock.unlock();
        }
    } else {
        // SAFETY: the space is live and write-locked.
        let Some(soright) =
            (unsafe { ipc_port::lookup_notify(space, notify) })
        else {
            // SAFETY: the space is live and write-locked.
            unsafe { space.lock_done() };
            // SAFETY: the request is the fresh allocation from above.
            unsafe { free(marequest) };
            return Err(SendError::InvalidNotify);
        };

        // SAFETY: the space is live, active, and write-locked.
        unsafe { ipc_space::reference(space) };

        // SAFETY: the request is the fresh allocation from above.
        unsafe {
            (*marequest).space = space.as_ptr();
            (*marequest).name = MACH_PORT_NAME_NULL;
            (*marequest).soright = soright.as_ptr();
        }
    }

    // SAFETY: the space is live and write-locked.
    unsafe { space.lock_done() };

    Ok(marequest)
}

/// `ipc_marequest_cancel()` in C.
///
/// # Safety
///
/// `space` must be live, write-locked, and active.
pub(crate) unsafe fn cancel(space: IpcSpace, name: c_uint) {
    // SAFETY: the table was initialized at bootstrap.
    unsafe {
        let bucket = bucket(space, name);
        (*bucket).lock.lock();

        let (found, last) = find_locked(bucket, space, name);
        if !found.is_null() {
            *last = (*found).next;
        }

        (*bucket).lock.unlock();

        if !found.is_null() {
            (*found).name = MACH_PORT_NAME_NULL;
        }
    }
}

/// `ipc_marequest_rename()` in C.
///
/// # Safety
///
/// `space` must be live, write-locked, and active.
pub(crate) unsafe fn rename(space: IpcSpace, old: c_uint, new: c_uint) {
    // SAFETY: the table was initialized at bootstrap.
    unsafe {
        let old_bucket = bucket(space, old);
        (*old_bucket).lock.lock();

        let (found, last) = find_locked(old_bucket, space, old);
        if !found.is_null() {
            *last = (*found).next;
        }

        (*old_bucket).lock.unlock();

        if found.is_null() {
            // The C dereferenced the missing request here.
            return;
        }

        (*found).name = new;

        let new_bucket = bucket(space, new);
        (*new_bucket).lock.lock();
        (*found).next = (*new_bucket).head;
        (*new_bucket).head = found;
        (*new_bucket).lock.unlock();
    }
}

/// `ipc_marequest_destroy()` in C.
///
/// # Safety
///
/// `marequest` must be a live request that nothing else can reach; nothing
/// may be locked.
pub(crate) unsafe fn destroy(marequest: *mut IpcMarequest) {
    let space = unsafe { IpcSpace::from_raw((*marequest).space) };

    // SAFETY: the request's space is live and unlocked.
    unsafe { space.lock_write() };

    // SAFETY: the request is live.
    let mut name = unsafe { (*marequest).name };
    let soright = unsafe { (*marequest).soright };

    if name != MACH_PORT_NAME_NULL {
        // SAFETY: the table was initialized at bootstrap.
        unsafe {
            let bucket = bucket(space, name);
            (*bucket).lock.lock();

            let (found, last) = find_locked(bucket, space, name);
            if !found.is_null() {
                *last = (*found).next;
            }

            (*bucket).lock.unlock();
        }

        // SAFETY: the space is live and write-locked.
        if unsafe { space.is_active() } {
            // SAFETY: the space is live, active, and write-locked.
            if let Some(entry) = unsafe { space.entry_lookup(name) } {
                // SAFETY: the entry is live.
                unsafe {
                    let bits = (*entry).bits();
                    (*entry).set_bits(bits & !IE_BITS_MAREQUEST);
                }
            }
        } else {
            name = MACH_PORT_NAME_NULL;
        }
    }

    // SAFETY: the space is live and write-locked.
    unsafe { space.lock_done() };
    // SAFETY: the request holds a reference to the space.
    unsafe { ipc_space::release(space) };

    // SAFETY: the request is live and no bucket holds it now.
    unsafe { free(marequest) };

    // SAFETY: the request held a send-once right for the notification, which
    // the C passes on to the notify routine; it is null in compat mode only.
    unsafe { ipc_notify::msg_accepted(soright, name) };
}

/// `ipc_marequest_info()` in C.
///
/// # Safety
///
/// `maxp` must be writable storage for one count, and `info` writable
/// storage for `count` bucket records.
pub(crate) unsafe fn info(
    maxp: *mut c_uint,
    info: *mut HashInfoBucket,
    count: c_uint,
) -> c_uint {
    let size = MAREQUEST_SIZE.load(Ordering::Relaxed);
    let count = count.min(size);

    let table = MAREQUEST_TABLE.load(Ordering::Relaxed);

    for i in 0..count as usize {
        // SAFETY: the table holds `size` buckets and `i` is below `count`,
        // which is at most `size`.
        let bucket = unsafe { table.add(i) };
        let mut bucket_count: c_uint = 0;

        // SAFETY: the bucket is live.
        unsafe {
            (*bucket).lock.lock();

            let mut marequest = (*bucket).head;
            while !marequest.is_null() {
                bucket_count = bucket_count.wrapping_add(1);
                marequest = (*marequest).next;
            }

            (*bucket).lock.unlock();
        }

        // The C filled pageable memory only after dropping the bucket lock.
        unsafe { (*info.add(i)).hib_count = bucket_count };
    }

    unsafe { *maxp = c_uint::MAX };
    size
}
