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
    DEV_GET_SIZE_RECORD_SIZE, DevT, IoReq, IoReqQueue,
};
use crate::arch::x86_64::platform::MachPlatform;
use crate::device::ds_routines;
use crate::device::r#return::{DeviceError, DeviceSuccess, IoResult};
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_long, c_uint};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use lock::IrqSpinLock;

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

/// `kmsg_lock` of `device/kmsg.c`, holding the ring it guards.  An irq spin
/// lock, since interrupt handlers print.
static KMSG: IrqSpinLock<Ring, MachPlatform> = IrqSpinLock::new(Ring {
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

/// `kmsgopen()` of `device/kmsg.c`.
pub(crate) fn open() -> IoResult {
    let mut ring = KMSG.lock();
    if ring.in_use {
        drop(ring);
        return Err(DeviceError::AlreadyOpen);
    }
    ring.in_use = true;
    drop(ring);
    Ok(DeviceSuccess::Success)
}

/// `kmsgclose()` of `device/kmsg.c`.
pub(crate) fn close() {
    let mut ring = KMSG.lock();
    ring.in_use = false;
    drop(ring);
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
pub(crate) unsafe fn read(ior: *mut IoReq) -> IoResult {
    // The C narrowed `io_count` to `vm_size_t` for the allocation.
    let size = unsafe { (*ior).count } as VmSize;
    unsafe { ds_routines::device_read_alloc(ior, size) }?;

    let mut ring = KMSG.lock();
    if ring.read == ring.write {
        // SAFETY: the request is live.
        if unsafe { (*ior).mode } & D_NOWAIT != 0 {
            drop(ring);
            return Err(DeviceError::WouldBlock);
        }

        // SAFETY: the request is live, the queue stays at its address, and
        // the lock is held.
        unsafe {
            (*ior).done = Some(kmsg_read_done);
            read_queue().push_back_ptr(NonNull::new_unchecked(ior));
        }
        drop(ring);
        return Ok(DeviceSuccess::IoQueued);
    }

    // SAFETY: `ior` owns its buffer.
    let amt = unsafe { copy_out(&mut ring, ior) };
    // SAFETY: the request is live.
    unsafe { (*ior).residual = (*ior).count - c_long::from(amt) };
    drop(ring);
    Ok(DeviceSuccess::Success)
}

/// `kmsg_read_done()` of `device/kmsg.c`: the queued read's completion.
///
/// # Safety
///
/// `ior` must be the live request `read()` queued, and the call must come
/// through `ior`'s `done` slot, as `iodone()` invokes it without the lock
/// held.
unsafe fn kmsg_read_done(ior: *mut IoReq) -> bool {
    let mut ring = KMSG.lock();
    if ring.read == ring.write {
        // SAFETY: the request is live and requeued at once, as the C did,
        // with the lock held.
        unsafe {
            (*ior).done = Some(kmsg_read_done);
            read_queue().push_back_ptr(NonNull::new_unchecked(ior));
        }
        drop(ring);
        return false;
    }

    // SAFETY: `ior` owns its buffer.
    let amt = unsafe { copy_out(&mut ring, ior) };
    // SAFETY: the request is live.
    unsafe { (*ior).residual = (*ior).count - c_long::from(amt) };
    drop(ring);

    unsafe { ds_routines::ds_read_done(ior) };
    true
}

/// `kmsg_putchar()` of `device/kmsg.c`.
pub(crate) fn putchar(c: c_int) {
    let mut ring = KMSG.lock();

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
) -> Result<(), DeviceError> {
    match getstat(flavor) {
        Some((reply, n)) => {
            unsafe {
                for (i, value) in reply.iter().enumerate() {
                    *data.add(i) = *value;
                }
                *count = n;
            }
            Ok(())
        }
        None => Err(DeviceError::InvalidOperation),
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
) -> IoResult {
    open()
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
pub(crate) unsafe fn kmsgread(_dev: DevT, ior: *mut IoReq) -> IoResult {
    unsafe { read(ior) }
}
