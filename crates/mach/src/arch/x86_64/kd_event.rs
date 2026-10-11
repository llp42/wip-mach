// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The keyboard event driver.

use crate::arch::x86_64::platform::MachPlatform;
use crate::device::{IoReq, IoReqQueue};
use crate::kern::console::kprint;
use core::ffi::{c_int, c_long, c_uint};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};
use lock::IrqSpinLock;
use lock::irq_spin_lock;
use mach_device::ds_routines::{device_read_alloc, ds_read_done, iodone};
use mach_device::io_req::{
    DEV_GET_SIZE, DEV_GET_SIZE_COUNT, DEV_GET_SIZE_DEVICE_SIZE,
    DEV_GET_SIZE_RECORD_SIZE, DevT, DeviceMode,
};
use mach_device::r#return::{DeviceError, DeviceSuccess, IoResult};
use mach_kd::{Event, EventQueue};

/// Drain up to `ior`'s byte count of queued events into its data buffer, and
/// return the bytes copied.
pub(crate) fn drain(queue: &mut EventQueue, ior: &mut IoReq) -> c_long {
    let mut count: c_long = 0;
    while !queue.is_empty() && count < ior.count {
        let Some(ev) = queue.pop_front() else {
            break;
        };
        let src = ptr::from_ref::<Event>(ev).cast::<u8>();
        // SAFETY: `device_read_alloc()` allocated `io_count` bytes for the
        // request, and the loop condition keeps this copy inside.
        let dst = unsafe { ior.data.add(count as usize).cast::<u8>() };
        // SAFETY: `device_read_alloc()` allocated `io_count` bytes for the
        // request, and the loop condition keeps this copy inside;
        // `src` is the popped event.
        unsafe { ptr::copy_nonoverlapping(src, dst, size_of::<Event>()) };
        count += size_of::<Event>() as c_long;
    }
    count
}

const KDSKBDMODE: c_uint = 0x8004_4b01;
const KDGKBDTYPE: c_uint = 0x4004_4b02;
const KDSETLEDS: c_uint = 0x8004_4b05;
const KB_ASCII: c_int = 2;
const KB_VANILLAKB: c_int = 0;

/// The driver's mutable state: the C file's file-scope globals.
struct State {
    queue: EventQueue,
    read_queue: IoReqQueue,
    initialized: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            queue: EventQueue::new(),
            read_queue: IoReqQueue::new(),
            initialized: false,
        }
    }
}

// SAFETY: the read queue links requests the device layer owns, which any CPU
// may complete.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the queued requests are shared between CPUs, which their type \
              does not say"
)]
unsafe impl Send for State {}

/// The event queue and the blocked reads, under an irq spin lock, since the
/// keyboard interrupt queues events.
static STATE: IrqSpinLock<State, MachPlatform> =
    irq_spin_lock!("kd event", State::new());

/// The read queue head.
///
/// # Safety
///
/// `s` must be the state in `STATE`, which never moves.
const unsafe fn read_queue(s: &mut State) -> Pin<&mut IoReqQueue> {
    // SAFETY: the caller passes the state in a static, so the head never
    // moves.
    unsafe { Pin::new_unchecked(&mut s.read_queue) }
}

/// Prints the first time a full queue drops an event, then never again.
fn printf_once() {
    static PRINTED: AtomicBool = AtomicBool::new(false);
    if !PRINTED.swap(true, Ordering::Relaxed) {
        kprint!("kbd: queue full\n");
    }
}

/// Enqueue `ev` and complete any reads waiting for data.
fn enqueue_event(s: &mut State, ev: &Event) {
    if s.queue.is_full() {
        printf_once();
    } else {
        s.queue.push_back(*ev);
    }
    // SAFETY: `s` is the state in `STATE`.
    while let Some(entry) = unsafe { read_queue(s) }.pop_front() {
        // SAFETY: the state's lock is held; each entry is an `io_req`, still
        // owned by the device layer and valid for `iodone()`.
        unsafe { iodone(ptr::from_mut(entry)) };
    }
}

/// Resets the queue once.
fn kbdinit() {
    let mut s = STATE.lock();
    if !s.initialized {
        s.queue.clear();
        s.initialized = true;
    }
}

/// Opens the keyboard event device, setting up the kd driver and the queue.
///
/// # Safety
///
/// The device layer calls this for the keyboard device.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
pub(crate) unsafe fn kbdopen(
    _dev: DevT,
    _flags: c_int,
    _ior: *mut IoReq,
) -> IoResult {
    crate::arch::x86_64::kd::kdinit();
    kbdinit();
    Ok(DeviceSuccess::Success)
}

/// Closes the keyboard event device.
///
/// # Safety
///
/// The device layer calls this for an open keyboard.
pub(crate) unsafe fn kbdclose(_dev: DevT, _flags: c_int) {
    crate::arch::x86_64::kd::set_kb_mode(KB_ASCII);
    STATE.lock().queue.clear();
}

/// Reports a status flavor of the keyboard event device.
///
/// # Safety
///
/// The device layer calls this with `data` able to hold the value the flavor
/// asks for and a valid `count`.
pub(crate) unsafe fn kbdgetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut u32,
) -> Result<(), DeviceError> {
    if flavor == KDGKBDTYPE {
        unsafe {
            *data = KB_VANILLAKB;
            *count = 1;
        }
        Ok(())
    } else if flavor == DEV_GET_SIZE {
        unsafe {
            *data.add(DEV_GET_SIZE_DEVICE_SIZE) = 0;
            *data.add(DEV_GET_SIZE_RECORD_SIZE) = size_of::<Event>() as c_int;
            *count = DEV_GET_SIZE_COUNT;
        }
        Ok(())
    } else {
        Err(DeviceError::InvalidOperation)
    }
}

/// Applies a status flavor to the keyboard event device.
///
/// # Safety
///
/// The device layer calls this with `data` holding `count` values for the
/// flavor.
pub(crate) unsafe fn kbdsetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: u32,
) -> Result<(), DeviceError> {
    if flavor == KDSKBDMODE {
        // SAFETY: one integer behind `data`, and kd owns the mode.
        crate::arch::x86_64::kd::set_kb_mode(unsafe { *data });
        Ok(())
    } else if flavor == KDSETLEDS {
        if count != 1 {
            return Err(DeviceError::InvalidOperation);
        }
        // SAFETY: `count == 1` promises one readable value; the LED state is
        // its low byte.
        let val = unsafe { *data };
        crate::arch::x86_64::kd::keyboard::set_leds1(val as u8);
        Ok(())
    } else {
        Err(DeviceError::InvalidOperation)
    }
}

/// Reads queued keyboard events, or queues the request until one arrives.
///
/// # Safety
///
/// The device layer calls this with a valid, read-only request whose buffer
/// `device_read_alloc()` may allocate.
pub(crate) unsafe fn kbdread(_dev: DevT, ior: *mut IoReq) -> IoResult {
    let wanted = unsafe { (*ior).count() };
    if wanted % size_of::<Event>() as c_long != 0 {
        return Err(DeviceError::InvalidSize);
    }
    unsafe { device_read_alloc(ior, wanted as usize) }?;
    let mut s = STATE.lock();
    if s.queue.is_empty() {
        if unsafe { (*ior).mode() }.contains(DeviceMode::NOWAIT) {
            return Err(DeviceError::WouldBlock);
        }
        unsafe { (*ior).set_done(kbd_read_done) };
        // SAFETY: the read queue is the locked state's, and the request
        // stays at its address until `iodone()`.
        unsafe {
            read_queue(&mut s).push_back_ptr(NonNull::new_unchecked(ior));
        };
        return Ok(DeviceSuccess::IoQueued);
    }
    let count = drain(&mut s.queue, unsafe { &mut *ior });
    drop(s);
    unsafe { (*ior).set_residual((*ior).count() - count) };
    Ok(DeviceSuccess::Success)
}

/// Completes a queued read once events arrive.
///
/// # Safety
///
/// The device layer must call this as `ior`'s completion callback, with `ior`
/// the same valid, still-queued request [`kbdread()`] queued.
unsafe fn kbd_read_done(ior: *mut IoReq) -> bool {
    let mut s = STATE.lock();
    if s.queue.is_empty() {
        unsafe { (*ior).set_done(kbd_read_done) };
        unsafe {
            read_queue(&mut s).push_back_ptr(NonNull::new_unchecked(ior));
        };
        return false;
    }
    // SAFETY: `ior` is the request the device layer queued.
    let count = drain(&mut s.queue, unsafe { &mut *ior });
    drop(s);
    // SAFETY: `ior` is the request the device layer queued.
    unsafe { (*ior).set_residual((*ior).count() - count) };
    // SAFETY: the request is complete; its data buffer is populated.
    unsafe { ds_read_done(ior) };
    true
}

/// Queues the scancode `sc` as an event; the kd interrupt path calls this.
pub(crate) fn kd_enqsc(sc: u8) {
    enqueue_event(&mut STATE.lock(), &Event::scancode(sc));
}
