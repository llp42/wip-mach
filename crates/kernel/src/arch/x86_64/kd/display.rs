// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd.c and i386/i386at/kd.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
//   Copyright 1988, 1989 by Intel Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The EGA-style kd display backend: the text write and cursor, and the screen
//! block moves.

use super::slam::{copy_backward, copy_forward, fill_words};
use super::{
    BOTTOM_LINE, C_BITMAP_START, C_HIGH, C_LOW, C_START, C_STOP, EGA_IDX_REG,
    EGA_IO_REG, EGA_START, K_SPACE, ONE_LINE, ONE_PAGE, ONE_SPACE, state,
};
use crate::arch::x86_64::pio::Port;
use core::ffi::{c_char, c_int, c_short};

/// The CRT cursor shape scanlines the firmware default is replaced with when
/// it left them zero.
const CURSOR_START_SCANLINE: u8 = 14;
const CURSOR_STOP_SCANLINE: u8 = 15;
/// Bytes of the bitmap the C cleared at initialization.
const BITMAP_CLEAR_BYTES: usize = 200;

pub(crate) fn dput(pos: c_short, ch: u8, attr: u8) {
    // SAFETY: the screen is mapped and SPLKD is held.
    unsafe { text_put(pos, ch as c_char, attr as c_char) };
}

pub(crate) fn dclear(to: c_short, count: c_int, attr: u8) {
    // SAFETY: the screen is mapped and SPLKD is held.
    unsafe { text_clear(to, count, attr as c_char) };
}

pub(crate) fn dmvup(from: c_short, to: c_short, count: c_int) {
    // SAFETY: the screen is mapped and SPLKD is held.
    unsafe { move_up(from, to, count) };
}

pub(crate) fn dmvdown(from: c_short, to: c_short, count: c_int) {
    // SAFETY: the screen is mapped and SPLKD is held.
    unsafe { move_down(from, to, count) };
}

pub(crate) fn setpos(newpos: c_short) {
    let mut newpos = newpos;
    if newpos > ONE_PAGE {
        scrollup();
        newpos = BOTTOM_LINE;
    }
    if newpos < 0 {
        scrolldn();
        newpos = 0;
    }
    // SAFETY: the CRTC is the driver's and SPLKD is held.
    unsafe { set_cursor(newpos) };
}

pub(crate) fn scrollup() {
    let count = (ONE_PAGE - ONE_LINE) / ONE_SPACE;
    dmvup(ONE_LINE, 0, c_int::from(count));
    dclear(
        BOTTOM_LINE,
        c_int::from(ONE_LINE / ONE_SPACE),
        state().kd_attr,
    );
}

pub(crate) fn scrolldn() {
    let to = ONE_PAGE - ONE_SPACE;
    let from = ONE_PAGE - ONE_LINE - ONE_SPACE;
    let count = (ONE_PAGE - ONE_LINE) / ONE_SPACE;
    dmvdown(from, to, c_int::from(count));
    dclear(0, c_int::from(ONE_LINE / ONE_SPACE), state().kd_attr);
}

/// `text_put()` in C.
///
/// # Safety
///
/// `pos` and `pos + 1` must be in-bounds offsets of the mapped screen
/// `vid_start` points at, and the caller must run at `SPLKD` so nothing
/// else writes the screen concurrently.
unsafe fn text_put(pos: c_short, ch: c_char, chattr: c_char) {
    let s = state();
    // SAFETY: `vid_start` is the mapped screen and `pos` is in range.
    unsafe {
        *s.vid_start.add(pos as usize) = ch as u8;
        *s.vid_start.add(pos as usize + 1) = chattr as u8;
    }
}

/// `set_cursor()` in C.
///
/// # Safety
///
/// The caller must run at `SPLKD`, so the CRTC index/data ports are the
/// driver's alone for the two-write index/value sequence.
unsafe fn set_cursor(newpos: c_short) {
    let curpos = newpos / ONE_SPACE;
    let s = state();
    Port::new(s.kd_index_reg as u16).write_u8(C_HIGH);
    Port::new(s.kd_io_reg as u16).write_u8((curpos >> 8) as u8);
    Port::new(s.kd_index_reg as u16).write_u8(C_LOW);
    Port::new(s.kd_io_reg as u16).write_u8((curpos & 0xff) as u8);
    s.kd_curpos = newpos;
}

/// Converts a signed word count to a `usize`, or [`None`] if negative.
///
/// The C this replaces let a negative count run over the full 32-bit
/// range instead of rejecting it; no caller here passes one.
fn word_count(count: c_int) -> Option<usize> {
    usize::try_from(count).ok()
}

/// `move_up()` in C.
///
/// # Safety
///
/// `from` and `to` must both be in-bounds offsets of the mapped screen
/// `vid_start` points at, with `count` words available from each, and the
/// caller must run at `SPLKD`.
unsafe fn move_up(from: c_short, to: c_short, count: c_int) {
    let s = state();
    let Some(count) = word_count(count) else {
        return;
    };
    // SAFETY: both offsets are inside the screen.
    unsafe {
        copy_forward(
            s.vid_start.add(from as usize).cast::<u16>(),
            s.vid_start.add(to as usize).cast::<u16>(),
            count,
        );
    };
}

/// `move_down()` in C.
///
/// # Safety
///
/// `from` and `to` must both be in-bounds offsets of the mapped screen
/// `vid_start` points at, with `count` words available from each, and the
/// caller must run at `SPLKD`.
unsafe fn move_down(from: c_short, to: c_short, count: c_int) {
    let s = state();
    let Some(count) = word_count(count) else {
        return;
    };
    // SAFETY: both offsets are inside the screen.
    unsafe {
        copy_backward(
            s.vid_start.add(from as usize).cast::<u16>(),
            s.vid_start.add(to as usize).cast::<u16>(),
            count,
        );
    };
}

/// `text_clear()` in C.
///
/// # Safety
///
/// `to` must be an in-bounds offset of the mapped screen `vid_start`
/// points at, with `count` words available from it, and the caller must
/// run at `SPLKD`.
unsafe fn text_clear(to: c_short, count: c_int, chattr: c_char) {
    let s = state();
    let value = (u16::from(chattr as u8) << 8) + u16::from(K_SPACE);
    let Some(count) = word_count(count) else {
        return;
    };
    // SAFETY: the offset is inside the screen.
    unsafe {
        fill_words(s.vid_start.add(to as usize).cast::<u16>(), count, value);
    };
}

/// `noop_reset()` in C.
///
/// # Safety
///
/// None: the function does nothing, so there is no precondition to
/// uphold.
const unsafe fn noop_reset() {}

/// Prepare the display for reboot.
pub(crate) const fn reset() {
    // SAFETY: resetting has no preconditions.
    unsafe { noop_reset() };
}

/// `phystokv()` of <`i386/i386/vm_param.h`>.
const fn phystokv(addr: usize) -> usize {
    const BASE: usize = 0xffff_ffff_8000_0000;
    addr.wrapping_add(BASE)
}

/// `get_cursor()` in C.
fn get_cursor() -> c_short {
    let s = state();
    Port::new(s.kd_index_reg as u16).write_u8(C_HIGH);
    let high = Port::new(s.kd_io_reg as u16).read_u8();
    Port::new(s.kd_index_reg as u16).write_u8(C_LOW);
    let low = Port::new(s.kd_io_reg as u16).read_u8();
    let pos = u16::from(low) | (u16::from(high) << 8);
    ONE_SPACE * pos as c_short
}

/// `kd_xga_init()` in C; called once, from `kdinit()`.
pub(crate) fn xga_init() {
    {
        let s = state();
        s.vid_start = phystokv(EGA_START) as *mut u8;
        s.kd_index_reg = EGA_IDX_REG as c_short;
        s.kd_io_reg = EGA_IO_REG as c_short;
        s.kd_lines = 25;
        s.kd_cols = 80;
        let addr = phystokv(C_BITMAP_START) as *mut u8;
        // SAFETY: the bitmap base is mapped by the boot.
        unsafe { core::ptr::write_bytes(addr, 0, BITMAP_CLEAR_BYTES) };
    }

    let s = state();
    Port::new(s.kd_index_reg as u16).write_u8(C_START);
    let mut start = Port::new(s.kd_io_reg as u16).read_u8();
    start &= !0x20;
    Port::new(s.kd_io_reg as u16).write_u8(start);
    Port::new(s.kd_index_reg as u16).write_u8(C_STOP);
    let stop = Port::new(s.kd_io_reg as u16).read_u8();

    if start == 0 && stop == 0 {
        let s = state();
        Port::new(s.kd_index_reg as u16).write_u8(C_START);
        Port::new(s.kd_io_reg as u16).write_u8(CURSOR_START_SCANLINE);
        Port::new(s.kd_index_reg as u16).write_u8(C_STOP);
        Port::new(s.kd_io_reg as u16).write_u8(CURSOR_STOP_SCANLINE);
    }

    setpos(get_cursor());
}
