// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The console tty and the kd device entry points: open/close/read/write,
//! get/set status, mmap and the line-discipline start.

use super::{KEYBOARD, console, kd, kdinit};
use crate::arch::vm_param::PAGE_SHIFT;
use crate::device::IoReq;
use crate::device::Tty;
use core::ffi::{c_int, c_uint};
use lock::lock_api::RawMutex as _;
use mach_device::io_req::DevT;
use mach_device::io_req::DeviceMode;
use mach_device::r#return::{DeviceError, IoResult};
use mach_kd::KbEntry;
use mach_tty::chario::{
    self, TTLOWAT, TtyFlags, TtyState, complete_queue, tty_get_status,
    tty_set_status,
};

/// The 115200 baud rate code.
const B115200: u8 = 17;

/// The default console flags `kdopen()` sets: `TF_ODDP|TF_EVENP|TF_ECHO`
/// `|TF_CRMOD|TF_XTABS|TF_LITOUT`.
const KD_TTY_FLAGS: TtyFlags = TtyFlags::ODDP
    .union(TtyFlags::EVENP)
    .union(TtyFlags::LITOUT)
    .union(TtyFlags::ECHO)
    .union(TtyFlags::CRMOD)
    .union(TtyFlags::XTABS);

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

/// Feed one character to the line discipline, under the tty lock.
///
/// The console has only line discipline 0; a tty set to any other takes no
/// input.
pub(crate) fn line_rint(c: u8) {
    let tp = tty();
    if tp.t_line != 0 {
        return;
    }
    tp.t_lock.lock();
    chario::input(tp, c_uint::from(c));
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// Allocate the character buffers through `chars()`; `kdinit()` calls this
/// with no lock held, as the allocation needs.
pub(crate) fn ttychars_init() {
    chario::chars(tty());
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
    // The keyboard comes up before the tty lock is taken: the keyboard
    // interrupt hands characters to the tty under that lock.
    kdinit();
    let tp = tty();
    tp.t_lock.lock();
    if !tp.t_state.intersects(TtyState::ISOPEN | TtyState::WOPEN) {
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        // `chars()` allocates the character buffers, so it must not run
        // under the tty lock.
        chario::chars(tp);
        tp.t_lock.lock();
        tp.t_start = Some(kdstart);
        tp.t_stop = Some(kdstop);
        tp.t_ospeed = B115200;
        tp.t_ispeed = B115200;
        tp.t_flags = KD_TTY_FLAGS;
    }
    tp.t_state |= TtyState::CARR_ON;
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    // SAFETY: the request is the caller's.  The C passed the `int flag` to
    // the `dev_mode_t mode` parameter unchanged.
    Ok(chario::open(
        tp,
        c_int::from(dev),
        DeviceMode::from_bits_retain(flag as c_uint),
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
    tp.t_lock.lock();
    chario::close(tp);
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// Reads from the console tty through its line discipline.
///
/// # Safety
///
/// The device layer calls this with a valid request.
pub(crate) unsafe fn kdread(_dev: DevT, uio: *mut IoReq) -> IoResult {
    let tp = tty();
    tp.t_state |= TtyState::CARR_ON;
    // The console has only line discipline 0.
    if tp.t_line != 0 {
        return Err(DeviceError::InvalidOperation);
    }
    chario::read(tp, unsafe { &mut *uio })
}

/// Writes to the console tty through its line discipline.
///
/// # Safety
///
/// The device layer calls this with a valid request.
pub(crate) unsafe fn kdwrite(_dev: DevT, uio: *mut IoReq) -> IoResult {
    let tp = tty();
    // The console has only line discipline 0.
    if tp.t_line != 0 {
        return Err(DeviceError::InvalidOperation);
    }
    chario::write(tp, unsafe { &mut *uio })
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
        let bits = {
            let _keyboard = KEYBOARD.lock();
            kd().keyboard.modifiers().bits()
        };
        unsafe {
            *data = c_int::from(bits);
            *count = 1;
        }
        Ok(())
    } else if flavor == KDGKBENT {
        let kb = unsafe { &mut *data.cast::<KbEntry>() };
        let cell = {
            let _keyboard = KEYBOARD.lock();
            kd().keyboard
                .keymap()
                .cell(kb.kb_index, usize::from(kb.kb_state))
        };
        kb.kb_value = cell.ok_or(DeviceError::InvalidOperation)?;
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
        let kb = unsafe { *data.cast::<KbEntry>() };
        let _keyboard = KEYBOARD.lock();
        let cell = kd()
            .keyboard
            .keymap_mut()
            .cell_mut(kb.kb_index, usize::from(kb.kb_state))
            .ok_or(DeviceError::InvalidOperation)?;
        *cell = kb.kb_value;
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

/// Draws the tty's queued output; the tty layer calls this with the tty
/// locked.
///
/// # Safety
///
/// `tp` must be the driver's own live [`Tty`], and the call must run with
/// the tty lock held, as `t_start` callers guarantee.
unsafe fn kdstart(tp: *mut Tty) {
    // SAFETY: the tty layer passes the driver's own tty.
    let tp = unsafe { &mut *tp };
    if tp.t_state.intersects(TtyState::TTSTOP) {
        return;
    }
    loop {
        tp.t_state &= !TtyState::BUSY;
        if tp.t_state.intersects(TtyState::TTSTOP) {
            break;
        }
        let Some(ch) = tp.t_outq.get() else {
            break;
        };
        kd().terminal.lock().write(ch);
    }
    let lowat = match TTLOWAT.get(usize::from(tp.t_ospeed)) {
        Some(&w) => w,
        None => 0,
    };
    if tp.t_outq.count() <= lowat {
        // SAFETY: the delayed write queue is the tty's and stays at its
        // address; `kdstart` runs with the tty lock held.
        unsafe {
            complete_queue(core::ptr::addr_of_mut!(tp.t_delayed_write));
        };
    }
}

/// The console has no output to stop, so this is a no-op.
///
/// # Safety
///
/// None; the C signature is kept so this can serve as `t_stop`, but the
/// body touches nothing.
const unsafe fn kdstop(_tp: *mut Tty, _flags: DeviceMode) {}
