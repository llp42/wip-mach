// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from device/kmsg.c:
//   Copyright (C) 1998, 1999, 2007 Free Software Foundation, Inc.
//   Written by OKUJI Yoshinori.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel message device, which `device/kmsg.c` used to define and
//! <device/kmsg.h> declares.

use crate::arch::types::VmSize;
use crate::arch::x86_64::io_req::{
    D_NOWAIT, DEV_GET_SIZE, DEV_GET_SIZE_COUNT, DEV_GET_SIZE_DEVICE_SIZE,
    DEV_GET_SIZE_RECORD_SIZE, DevT, IoReq, IoReqQueue, KERN_SUCCESS,
};
use crate::arch::x86_64::ioapic;
use crate::arch::x86_64::spl;
use crate::device::ds_routines;
use crate::device::r#return::{DeviceError, DeviceSuccess, IoResultExt};
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_long, c_uint};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;
use spin::{Mutex, MutexGuard};

/// `KMSGBUFSIZE` of `device/kmsg.c`.
const KMSGBUFSIZE: usize = 16 * 1024;

/// `kmsg_buffer`, `kmsg_write_offset`, `kmsg_read_offset` and
/// `kmsg_in_use` of `device/kmsg.c`: the ring of message bytes and whether the
/// device is open.
struct Ring {
    buffer: [u8; KMSGBUFSIZE],
    write: usize,
    read: usize,
    in_use: bool,
}

/// `kmsg_lock` of `device/kmsg.c`, holding the ring it guards.
static KMSG: Mutex<Ring> = Mutex::new(Ring {
    buffer: [0; KMSGBUFSIZE],
    write: 0,
    read: 0,
    in_use: false,
});

/// `kmsg_read_queue` of `device/kmsg.c`: the blocked reads.
static KMSG_READ_QUEUE: SyncCell<IoReqQueue> =
    SyncCell(UnsafeCell::new(IoReqQueue::new()));

/// The live blocked-read queue head.
///
/// # Safety
///
/// The caller must hold `KMSG`'s lock for as long as it uses the queue.
unsafe fn read_queue() -> Pin<&'static mut IoReqQueue> {
    // SAFETY: the static never moves, and the caller has exclusive access to
    // the queue.
    unsafe { Pin::new_unchecked(&mut *KMSG_READ_QUEUE.0.get()) }
}

/// The `DEV_GET_SIZE` reply: the device size is unknown (zero), and the record
/// size is one, which marks the device as sequential.
const GET_SIZE_REPLY: [c_int; DEV_GET_SIZE_COUNT as usize] = {
    let mut reply = [0; DEV_GET_SIZE_COUNT as usize];
    reply[DEV_GET_SIZE_DEVICE_SIZE] = 0;
    reply[DEV_GET_SIZE_RECORD_SIZE] = 1;
    reply
};

/// The two error families a read can return: the raw `kern_return_t`
/// `device_read_alloc()` produced, or a `D_*` code of the device layer.
#[derive(Clone, Copy)]
pub(crate) enum KmsgError {
    Kern(c_int),
    Device(DeviceError),
}

impl KmsgError {
    pub(crate) const fn as_io_return(self) -> c_int {
        match self {
            Self::Kern(code) => code,
            Self::Device(error) => error as c_int,
        }
    }
}

/// Take the lock at `splhigh`, as the `simple_lock_irq()` macro did.
fn lock_irq() -> (MutexGuard<'static, Ring>, c_int) {
    // SAFETY: `splhigh()` is the real asm routine <machine/spl.h> declares,
    // and its result is only handed back to `splx()`.
    let level = unsafe { spl::splhigh() };
    (KMSG.lock(), level)
}

/// Release the lock and restore `level`, as `simple_unlock_irq()` did.
fn unlock_irq(guard: MutexGuard<'static, Ring>, level: c_int) {
    drop(guard);
    // SAFETY: `level` is the value [`lock_irq()`] returned for this lock.
    unsafe { spl::splx(level) };
}

/// `kmsgopen()` of `device/kmsg.c`.
pub(crate) fn open() -> Result<DeviceSuccess, DeviceError> {
    let (mut ring, level) = lock_irq();
    if ring.in_use {
        unlock_irq(ring, level);
        return Err(DeviceError::AlreadyOpen);
    }
    ring.in_use = true;
    unlock_irq(ring, level);
    Ok(DeviceSuccess::Success)
}

/// `kmsgclose()` of `device/kmsg.c`.
pub(crate) fn close() {
    let (mut ring, level) = lock_irq();
    ring.in_use = false;
    unlock_irq(ring, level);
}

/// Copy the readable run of the ring into `ior`'s buffer and advance the read
/// offset; returns the bytes copied.
///
/// # Safety
///
/// `ior` must own a writable buffer of its count.
unsafe fn copy_out(ring: &mut Ring, ior: *mut IoReq) -> c_int {
    let len = (ring.write + KMSGBUFSIZE - ring.read) % KMSGBUFSIZE;

    // The C narrowed `io_count` to `int` before clamping it to the ring's
    // readable run, and the ring is 16 KiB, so the run fits an `int`.
    let wanted = unsafe { (*ior).count }.max(0) as c_int;
    let amt = wanted.min(len as c_int);
    let count = usize::try_from(amt).unwrap_or(0);

    let data = unsafe { (*ior).data.cast::<u8>() };
    let first = count.min(KMSGBUFSIZE - ring.read);
    let source = ring.buffer.as_ptr();
    // SAFETY: `data` has room for `count` bytes; the run is the readable
    // bytes from the read offset to the ring's end, then on from its start.
    unsafe {
        ptr::copy_nonoverlapping(source.add(ring.read), data, first);
        ptr::copy_nonoverlapping(source, data.add(first), count - first);
    }
    ring.read = (ring.read + count) % KMSGBUFSIZE;
    amt
}

/// `kmsgread()` of `device/kmsg.c`.
///
/// # Safety
///
/// `ior` must be a live read request.
pub(crate) unsafe fn read(
    ior: *mut IoReq,
) -> Result<DeviceSuccess, KmsgError> {
    // The C narrowed `io_count` to `vm_size_t` for the allocation.
    let size = unsafe { (*ior).count } as VmSize;
    let kr = unsafe { ds_routines::device_read_alloc(ior, size) };
    if kr != KERN_SUCCESS {
        return Err(KmsgError::Kern(kr));
    }

    let (mut ring, level) = lock_irq();
    if ring.read == ring.write {
        // SAFETY: the request is live.
        if unsafe { (*ior).mode } & D_NOWAIT != 0 {
            unlock_irq(ring, level);
            return Err(KmsgError::Device(DeviceError::WouldBlock));
        }

        // SAFETY: the request is live, the queue stays at its address, and
        // the lock is held.
        unsafe {
            (*ior).done = Some(kmsg_read_done);
            read_queue().push_back_ptr(NonNull::new_unchecked(ior));
        }
        unlock_irq(ring, level);
        return Ok(DeviceSuccess::IoQueued);
    }

    // SAFETY: `ior` owns its buffer.
    let amt = unsafe { copy_out(&mut ring, ior) };
    // SAFETY: the request is live.
    unsafe { (*ior).residual = (*ior).count - c_long::from(amt) };
    unlock_irq(ring, level);
    Ok(DeviceSuccess::Success)
}

/// `kmsg_read_done()` of `device/kmsg.c`: the queued read's completion.
///
/// # Safety
///
/// `ior` must be the live request `read()` queued, and the call must come
/// through `ior`'s `done` slot, as `iodone()` invokes it without the lock
/// held.
unsafe fn kmsg_read_done(ior: *mut IoReq) -> c_int {
    let (mut ring, level) = lock_irq();
    if ring.read == ring.write {
        // SAFETY: the request is live and requeued at once, as the C did,
        // with the lock held.
        unsafe {
            (*ior).done = Some(kmsg_read_done);
            read_queue().push_back_ptr(NonNull::new_unchecked(ior));
        }
        unlock_irq(ring, level);
        return 0;
    }

    // SAFETY: `ior` owns its buffer.
    let amt = unsafe { copy_out(&mut ring, ior) };
    // SAFETY: the request is live.
    unsafe { (*ior).residual = (*ior).count - c_long::from(amt) };
    unlock_irq(ring, level);

    unsafe { ds_routines::ds_read_done(ior) };
    c_int::from(true)
}

/// `kmsg_putchar()` of `device/kmsg.c`.
pub(crate) fn putchar(c: c_int) {
    // Before the interrupt system is up, the console's early output is
    // single-threaded, as in C, so the level stays where it is.
    let (mut ring, level) = if ioapic::SPL_INIT.load(Ordering::Relaxed) {
        let (ring, level) = lock_irq();
        (ring, Some(level))
    } else {
        (KMSG.lock(), None)
    };

    // The C stored the `int` into a `char` buffer, keeping its low byte.
    let write = ring.write;
    ring.buffer[write] = c as u8;
    ring.write = (write + 1) % KMSGBUFSIZE;
    if ring.write == ring.read {
        ring.read = (ring.read + 1) % KMSGBUFSIZE;
    }

    // SAFETY: the queue holds live reads, and the lock is held.
    while let Some(ior) = unsafe { read_queue() }.pop_front() {
        // SAFETY: the dequeued entry is a live read request, as the C's cast
        // asserted.
        unsafe { ds_routines::iodone(ptr::from_mut(ior)) };
    }

    match level {
        Some(level) => unlock_irq(ring, level),
        None => drop(ring),
    }
}

/// The status reply for `flavor`, or [`None`] for a flavor the device does not
/// serve.
pub(crate) const fn getstat(
    flavor: c_uint,
) -> Option<([c_int; DEV_GET_SIZE_COUNT as usize], u32)> {
    match flavor {
        DEV_GET_SIZE => Some((GET_SIZE_REPLY, DEV_GET_SIZE_COUNT)),
        _ => None,
    }
}
/// `kmsggetstat()` in C.
///
/// # Safety
///
/// For `DEV_GET_SIZE`, the only flavor the C served, `data` must be writable
/// for `DEV_GET_SIZE_COUNT` integers and `count` must be writable; the C wrote
/// both and read neither.
pub(crate) unsafe fn kmsggetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut c_uint,
) -> c_int {
    match getstat(flavor) {
        Some((reply, n)) => {
            unsafe {
                for (i, value) in reply.iter().enumerate() {
                    *data.add(i) = *value;
                }
                *count = n;
            }
            Ok(DeviceSuccess::Success).as_io_return()
        }
        None => Err(DeviceError::InvalidOperation).as_io_return(),
    }
}

/// `kmsgopen()` in C.
///
/// # Safety
///
/// `dev`, `flag` and `ior` are ignored, as the C ignored them.
pub(crate) unsafe fn kmsgopen(
    _dev: DevT,
    _flag: c_int,
    _ior: *mut IoReq,
) -> c_int {
    match open() {
        Ok(success) => Ok(success).as_io_return(),
        Err(error) => Err(error).as_io_return(),
    }
}

/// `kmsgclose()` in C.
///
/// # Safety
///
/// `dev` and `flag` are ignored, as the C ignored them.
pub(crate) unsafe fn kmsgclose(_dev: DevT, _flag: c_int) {
    close();
}

/// `kmsgread()` in C.
///
/// # Safety
///
/// `ior` must be a live read request.
pub(crate) unsafe fn kmsgread(_dev: DevT, ior: *mut IoReq) -> c_int {
    match unsafe { read(ior) } {
        Ok(success) => Ok(success).as_io_return(),
        Err(error) => error.as_io_return(),
    }
}
