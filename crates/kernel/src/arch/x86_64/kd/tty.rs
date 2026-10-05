// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd.c and i386/i386at/kd.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
//   Copyright 1988, 1989 by Intel Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The console tty and the kd device entry points: open/close/read/write,
//! get/set status, mmap and the line-discipline start.

use super::{KbEntry, console, esc, kd, kdinit, keyboard};
use crate::arch::types::VmOffset;
use crate::arch::vm_param::PAGE_SHIFT;
use crate::arch::x86_64::io_req::{DevT, IoReq};
use crate::arch::x86_64::spl;
use crate::device::chario::{
    LINESW, LdiscSwitch, TS_BUSY, TS_CARR_ON, TS_ISOPEN, TS_TTSTOP, TS_WOPEN,
    TTLOWAT, Tty, tty_get_status, tty_portdeath, tty_queue_completion,
    tty_set_status, ttychars, ttyclose,
};
use crate::device::r#return::{DeviceError, IoResult};
use core::ffi::{c_int, c_uint, c_void};

/// The 115200 baud rate code.
const B115200: u8 = 17;

/// The default console flags `kdopen()` sets: `TF_ODDP|TF_EVENP|TF_ECHO`
/// `|TF_CRMOD|TF_XTABS|TF_LITOUT`.
const KD_TTY_FLAGS: c_int = 0x2 | 0x4 | 0x8 | 0x80 | 0x100 | 0x200;

/// The kd get-state status flavor.
const KDGSTATE: c_uint = 0x4004_6b03;
/// The kd get-key-map-entry status flavor.
const KDGKBENT: c_uint = 0xc005_6b01;
/// The kd set-key-map-entry status flavor.
const KDSKBENT: c_uint = 0x8005_6b02;
/// The kd set-bell status flavor.
const KDSETBELL: c_uint = 0x8004_6b04;

/// `kdmmap()` refuses offsets past this.
const MAP_LIMIT: usize = 128 * 1024;
/// `kdmmap()`'s failure value, as `(vm_offset_t)-1`.
const MAP_FAILED: usize = usize::MAX;

/// The console tty.
fn tty() -> &'static mut Tty {
    &mut kd().tty
}

/// The line discipline `tp.t_line` names, or [`None`] when the tty names one
/// this kernel does not have.
fn ldisc(tp: &Tty) -> Option<&'static LdiscSwitch> {
    let line = usize::try_from(tp.t_line).ok()?;
    LINESW.get(line)
}

/// Feed one character to the line discipline.
pub(crate) fn line_rint(c: u8) {
    let tp = tty();
    let Some(rint) = ldisc(tp).and_then(|d| d.l_rint) else {
        return;
    };
    // SAFETY: the discipline is `chario::input()`, and the tty is up once the
    // console is open.
    unsafe { rint(c_uint::from(c), tp) };
}

/// Allocate the character buffers through `ttychars()`.
pub(crate) fn ttychars_init() {
    // SAFETY: called from kdinit() at SPLKD.
    unsafe { ttychars(tty()) };
}

/// Opens the console tty, setting it up on the first open.
///
/// # Safety
///
/// The device layer calls this with a valid request.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
pub(crate) unsafe fn kdopen(
    dev: DevT,
    flag: c_int,
    ior: *mut IoReq,
) -> IoResult {
    let tp = tty();
    // SAFETY: raising to `splhigh` has no precondition.
    let o_pri = unsafe { spl::splhigh() };
    tp.t_lock.lock();
    if tp.t_state & (TS_ISOPEN | TS_WOPEN) == 0 {
        tp.t_lock.unlock();
        // SAFETY: ttychars allocates the character buffers, and must not run
        // under the tty lock.
        unsafe { ttychars(tp) };
        tp.t_lock.lock();
        tp.t_start = Some(kdstart);
        tp.t_stop = Some(kdstop);
        tp.t_ospeed = B115200;
        tp.t_ispeed = B115200;
        tp.t_flags = KD_TTY_FLAGS;
        kdinit();
    }
    tp.t_state |= TS_CARR_ON;
    tp.t_lock.unlock();
    // SAFETY: `o_pri` is the level `splhigh()` returned above.
    unsafe { spl::splx(o_pri) };
    // SAFETY: the request is the caller's.  The C passed the `int flag` to
    // the `dev_mode_t mode` parameter unchanged.
    Ok(crate::device::chario::open(
        tp,
        c_int::from(dev),
        flag as c_uint,
        unsafe { &mut *ior },
    ))
}

/// Closes the console tty.
///
/// # Safety
///
/// The device layer calls this for an open console.
pub(crate) unsafe fn kdclose(_dev: DevT, _flag: c_int) {
    let tp = tty();
    // SAFETY: raising to `splhigh` has no precondition; the tty lock is taken
    // at that level.
    let s = unsafe { spl::splhigh() };
    tp.t_lock.lock();
    // SAFETY: the tty is the driver's own.
    unsafe { ttyclose(tp) };
    tp.t_lock.unlock();
    // SAFETY: `s` is the level `splhigh()` returned above.
    unsafe { spl::splx(s) };
}

/// Reads from the console tty through its line discipline.
///
/// # Safety
///
/// The device layer calls this with a valid request.
pub(crate) unsafe fn kdread(_dev: DevT, uio: *mut IoReq) -> IoResult {
    let tp = tty();
    tp.t_state |= TS_CARR_ON;
    let Some(read) = ldisc(tp).and_then(|d| d.l_read) else {
        return Err(DeviceError::InvalidOperation);
    };
    // SAFETY: the discipline is `chario::read()`, and the tty and the request
    // are the device layer's.
    unsafe { read(tp, uio) }
}

/// Writes to the console tty through its line discipline.
///
/// # Safety
///
/// The device layer calls this with a valid request.
pub(crate) unsafe fn kdwrite(_dev: DevT, uio: *mut IoReq) -> IoResult {
    let tp = tty();
    let Some(write) = ldisc(tp).and_then(|d| d.l_write) else {
        return Err(DeviceError::InvalidOperation);
    };
    // SAFETY: the discipline is `chario::write()`, and the tty and the request
    // are the device layer's.
    unsafe { write(tp, uio) }
}

/// The page frame of the display memory at `off`, for a mapping.
///
/// # Safety
///
/// The device layer calls this for /dev/console mappings.
pub(crate) unsafe fn kdmmap(_dev: DevT, off: usize, _prot: c_int) -> usize {
    if off >= MAP_LIMIT {
        return MAP_FAILED;
    }
    let base = kd().bitmap_start;
    (base.wrapping_add(off)) >> PAGE_SHIFT
}

/// Clears what the dead `port` held on the console tty, returning whether it
/// held anything.
///
/// # Safety
///
/// The device layer calls this with a valid port.
pub(crate) unsafe fn kdportdeath(dev: DevT, port: VmOffset) -> bool {
    let _ = dev;
    // SAFETY: the tty layer owns the request queues.
    unsafe { tty_portdeath(tty(), port as *mut c_void) }
}

/// Reports the kd status flavors, and the tty's for the others.
///
/// # Safety
///
/// The device layer calls this with `data` holding `*count` values.
pub(crate) unsafe fn kdgetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut u32,
) -> Result<(), DeviceError> {
    if flavor == KDGSTATE {
        if unsafe { *count } < 1 {
            return Err(DeviceError::InvalidOperation);
        }
        unsafe {
            *data = kd().state_bits();
            *count = 1;
        }
        Ok(())
    } else if flavor == KDGKBENT {
        let kb = unsafe { &mut *data.cast::<KbEntry>() };
        keyboard::entry_get(kb);
        unsafe { *count = 1 };
        Ok(())
    } else {
        // SAFETY: the tty layer handles its own flavors.
        unsafe { tty_get_status(tty(), flavor, data, count) }
    }
}

/// Applies the kd status flavors, and the tty's for the others.
///
/// # Safety
///
/// The device layer calls this with `data` holding `count` values.
pub(crate) unsafe fn kdsetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: u32,
) -> Result<(), DeviceError> {
    if flavor == KDSKBENT {
        if count < 1 {
            return Err(DeviceError::InvalidOperation);
        }
        let kb = unsafe { &*data.cast::<KbEntry>() };
        keyboard::entry_set(*kb);
        Ok(())
    } else if flavor == KDSETBELL {
        if count < 1 {
            return Err(DeviceError::InvalidOperation);
        }
        // SAFETY: one integer behind `data`.
        let val = unsafe { *data };
        console::set_bell(val, 0).map(|_| ())
    } else {
        // SAFETY: the tty layer handles its own flavors.
        unsafe { tty_set_status(tty(), flavor, data, count) }
    }
}

/// Draws the tty's queued output; the tty layer calls this at `spltty`.
///
/// # Safety
///
/// `tp` must be the driver's own live [`Tty`], and the call must run at
/// `spltty` with the tty lock held, as `t_start` callers guarantee.
unsafe fn kdstart(tp: *mut Tty) {
    // SAFETY: the tty layer passes the driver's own tty.
    let tp = unsafe { &mut *tp };
    if tp.t_state & TS_TTSTOP != 0 {
        return;
    }
    loop {
        tp.t_state &= !TS_BUSY;
        if tp.t_state & TS_TTSTOP != 0 {
            break;
        }
        let Some(ch) = tp.t_outq.get() else {
            break;
        };
        // SAFETY: the clock's soft interrupt level is the driver's.
        let o_pri = unsafe { spl::splsoftclock() };
        esc::putc_esc(ch);
        // SAFETY: `o_pri` came from `splsoftclock()`, which `splx` accepts.
        unsafe { spl::splx(o_pri) };
    }
    let lowat = match TTLOWAT.get(usize::from(tp.t_ospeed)) {
        Some(&w) => w,
        None => 0,
    };
    if tp.t_outq.count() <= lowat {
        // SAFETY: the delayed write queue is the tty's and stays at its
        // address; `kdstart` runs at spltty with the tty lock held.
        unsafe {
            tty_queue_completion(core::ptr::addr_of_mut!(tp.t_delayed_write));
        };
    }
}

/// The console has no output to stop, so this is a no-op.
///
/// # Safety
///
/// None; the C signature is kept so this can serve as `t_stop`, but the
/// body touches nothing.
const unsafe fn kdstop(_tp: *mut Tty, _flags: c_int) {}
