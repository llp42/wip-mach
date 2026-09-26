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
use spin::{Mutex, MutexGuard};

/// `KMSGBUFSIZE` of `device/kmsg.c`.
const KMSGBUFSIZE: usize = 16 * 1024;

/// `kmsg_buffer` of `device/kmsg.c`: the ring of message bytes.
static mut KMSG_BUFFER: [u8; KMSGBUFSIZE] = [0; KMSGBUFSIZE];

/// `kmsg_write_offset` of `device/kmsg.c`.
static mut KMSG_WRITE_OFFSET: c_int = 0;

/// `kmsg_read_offset` of `device/kmsg.c`.
static mut KMSG_READ_OFFSET: c_int = 0;

/// `kmsg_read_queue` of `device/kmsg.c`: the blocked reads.
static KMSG_READ_QUEUE: SyncCell<IoReqQueue> =
    SyncCell(UnsafeCell::new(IoReqQueue::new()));

/// The live blocked-read queue head.
///
/// # Safety
///
/// The caller must hold `KMSG_LOCK`, or run single-threaded before
/// `spl_init` at boot, for as long as it uses the queue.
unsafe fn read_queue() -> Pin<&'static mut IoReqQueue> {
    // SAFETY: the static never moves, and the caller has exclusive access to
    // the queue.
    unsafe { Pin::new_unchecked(&mut *KMSG_READ_QUEUE.0.get()) }
}

/// `kmsg_in_use` of `device/kmsg.c`: exclusive access to the device.
static mut KMSG_IN_USE: bool = false;

/// `kmsg_init_done` of `device/kmsg.c`.
static mut KMSG_INIT_DONE: bool = false;

/// `kmsg_lock` of `device/kmsg.c`.
static KMSG_LOCK: Mutex<()> = Mutex::new(());

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
fn lock_irq() -> (MutexGuard<'static, ()>, c_int) {
    // SAFETY: `splhigh()` is the real asm routine <machine/spl.h> declares,
    // and its result is only handed back to `splx()`.
    let level = unsafe { spl::splhigh() };
    (KMSG_LOCK.lock(), level)
}

/// Release the lock and restore `level`, as `simple_unlock_irq()` did.
fn unlock_irq(guard: MutexGuard<'static, ()>, level: c_int) {
    drop(guard);
    // SAFETY: `level` is the value [`lock_irq()`] returned for this lock.
    unsafe { spl::splx(level) };
}

/// `kmsginit()` of `device/kmsg.c`.
fn init() {
    // SAFETY: called before the device can have users, as the C did.
    unsafe {
        KMSG_WRITE_OFFSET = 0;
        KMSG_READ_OFFSET = 0;
        KMSG_IN_USE = false;
    }
}

/// `kmsgopen()` of `device/kmsg.c`.
pub(crate) fn open() -> Result<DeviceSuccess, DeviceError> {
    let (guard, level) = lock_irq();
    // SAFETY: the lock is held.
    if unsafe { KMSG_IN_USE } {
        unlock_irq(guard, level);
        return Err(DeviceError::AlreadyOpen);
    }
    // SAFETY: the lock is held.
    unsafe { KMSG_IN_USE = true };
    unlock_irq(guard, level);
    Ok(DeviceSuccess::Success)
}

/// `kmsgclose()` of `device/kmsg.c`.
pub(crate) fn close() {
    let (guard, level) = lock_irq();
    // SAFETY: the lock is held.
    unsafe { KMSG_IN_USE = false };
    unlock_irq(guard, level);
}

/// Copy the readable run of the ring into `ior`'s buffer and advance the read
/// offset; returns the bytes copied.
///
/// # Safety
///
/// The lock must be held, `ior` must own a writable buffer of its count, and
/// both offsets must be inside the ring.
unsafe fn copy_out(ior: *mut IoReq) -> c_int {
    let (read_offset, write_offset) =
        unsafe { (KMSG_READ_OFFSET, KMSG_WRITE_OFFSET) };
    let mut len = write_offset - read_offset;
    if len < 0 {
        len += KMSGBUFSIZE as c_int;
    }

    // The C narrowed `io_count` to `int` before clamping it to the ring's
    // readable run, and the ring is 16 KiB.
    let wanted = unsafe { (*ior).count }.max(0) as c_int;
    let amt = wanted.min(len);

    let read = usize::try_from(read_offset).unwrap_or(0);
    let count = usize::try_from(amt).unwrap_or(0);
    let data = unsafe { (*ior).data.cast::<u8>() };
    let base = ptr::addr_of_mut!(KMSG_BUFFER).cast::<u8>();
    if read + count <= KMSGBUFSIZE {
        // SAFETY: the first branch's run stays inside the ring, and `data`
        // has room for `count` bytes.
        unsafe { ptr::copy_nonoverlapping(base.add(read), data, count) };
    } else {
        let first = KMSGBUFSIZE - read;
        // SAFETY: the run wraps, so its first part ends at the ring's end and
        // its second starts at the ring's start.
        unsafe {
            ptr::copy_nonoverlapping(base.add(read), data, first);
            ptr::copy_nonoverlapping(base, data.add(first), count - first);
        }
    }

    // SAFETY: the lock is held and `amt` is at most the ring size.
    unsafe {
        KMSG_READ_OFFSET += amt;
        if KMSG_READ_OFFSET >= KMSGBUFSIZE as c_int {
            KMSG_READ_OFFSET -= KMSGBUFSIZE as c_int;
        }
    }
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

    let (guard, level) = lock_irq();
    // SAFETY: the lock is held.
    if unsafe { KMSG_READ_OFFSET } == unsafe { KMSG_WRITE_OFFSET } {
        // SAFETY: the lock is held.
        if unsafe { (*ior).mode } & D_NOWAIT != 0 {
            unlock_irq(guard, level);
            return Err(KmsgError::Device(DeviceError::WouldBlock));
        }

        // SAFETY: the request is live, and the queue stays at its address.
        unsafe {
            (*ior).done = Some(kmsg_read_done);
            read_queue().push_back_ptr(NonNull::new_unchecked(ior));
        }
        unlock_irq(guard, level);
        return Ok(DeviceSuccess::IoQueued);
    }

    // SAFETY: the lock is held and `ior` owns its buffer.
    let amt = unsafe { copy_out(ior) };
    // SAFETY: the lock is held.
    unsafe { (*ior).residual = (*ior).count - c_long::from(amt) };
    unlock_irq(guard, level);
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
    let (guard, level) = lock_irq();
    // SAFETY: the lock is held.
    if unsafe { KMSG_READ_OFFSET } == unsafe { KMSG_WRITE_OFFSET } {
        // SAFETY: the request is live and requeued at once, as the C did.
        unsafe {
            (*ior).done = Some(kmsg_read_done);
            read_queue().push_back_ptr(NonNull::new_unchecked(ior));
        }
        unlock_irq(guard, level);
        return 0;
    }

    // SAFETY: the lock is held and `ior` owns its buffer.
    let amt = unsafe { copy_out(ior) };
    // SAFETY: the lock is held.
    unsafe { (*ior).residual = (*ior).count - c_long::from(amt) };
    unlock_irq(guard, level);

    unsafe { ds_routines::ds_read_done(ior) };
    c_int::from(true)
}

/// `kmsg_putchar()` of `device/kmsg.c`.
pub(crate) fn putchar(c: c_int) {
    // SAFETY: the flag and the ring are this module's; the first writer runs
    // before any reader exists.
    if !unsafe { KMSG_INIT_DONE } {
        init();
        // SAFETY: the flag and the ring are this module's; the first writer
        // runs before any reader exists.
        unsafe { KMSG_INIT_DONE = true };
    }

    // SAFETY: `spl_init` is set once the interrupt system is up; before that
    // the console's early output is single-threaded, as in C.
    let locked = unsafe { ioapic::SPL_INIT } != 0;
    let saved = if locked { Some(lock_irq()) } else { None };

    // SAFETY: the offset is inside the ring, and the lock is held when one
    // exists.
    unsafe {
        let offset = usize::try_from(KMSG_WRITE_OFFSET).unwrap_or(0);
        // The C stored the `int` into a `char` buffer, keeping its low byte.
        ptr::addr_of_mut!(KMSG_BUFFER)
            .cast::<u8>()
            .add(offset)
            .write(c as u8);
        KMSG_WRITE_OFFSET += 1;
        if KMSG_WRITE_OFFSET == KMSGBUFSIZE as c_int {
            KMSG_WRITE_OFFSET = 0;
        }
        if KMSG_WRITE_OFFSET == KMSG_READ_OFFSET {
            KMSG_READ_OFFSET += 1;
            if KMSG_READ_OFFSET == KMSGBUFSIZE as c_int {
                KMSG_READ_OFFSET = 0;
            }
        }
    }

    // SAFETY: the queue holds live reads; nothing else dequeues without the
    // lock, or before `spl_init` at boot.
    while let Some(ior) = unsafe { read_queue() }.pop_front() {
        // SAFETY: the dequeued entry is a live read request, as the C's cast
        // asserted.
        unsafe { ds_routines::iodone(ptr::from_mut(ior)) };
    }

    if let Some((guard, level)) = saved {
        unlock_irq(guard, level);
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
