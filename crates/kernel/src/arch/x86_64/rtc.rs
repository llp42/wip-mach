// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/rtc.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright 1988, 1989 by Intel Corporation, Santa Clara, California.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The CMOS clock.

use crate::arch::x86_64::pio::Port;
use crate::arch::x86_64::spl;
use crate::kern::console::kprint;
use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

/// The first year the two-digit year field can name.
const CENTURY_START: u32 = 1970;

/// The register select port.
const RTC_ADDR: Port = Port::new(0x70);
/// The data port.
const RTC_DATA: Port = Port::new(0x71);

/// Register A: the time base and update rate, `RTC_A`.
const RTC_A: u8 = 0x0a;
/// Register B: the update and mode control, `RTC_B`.
const RTC_B: u8 = 0x0b;
/// Register D: the valid-RAM-and-time byte, `RTC_D`.
const RTC_D: u8 = 0x0d;
/// `RTC_UIP`: an update is in progress, in register A.
const RTC_UIP: u8 = 0x80;
/// `RTC_DIV2`: a 32.768 `KHz` time base, in register A.
const RTC_DIV2: u8 = 0x20;
/// `RTC_RATE6`: an interrupt rate of 976.562 Hz, in register A.
const RTC_RATE6: u8 = 0x06;
/// `RTC_SET`: updates stopped for a time set, in register B.
const RTC_SET: u8 = 0x80;
/// `RTC_HM`: 24-hour mode, in register B.
const RTC_HM: u8 = 0x02;
/// `RTC_VRT`: RAM and time are valid, in register D.
const RTC_VRT: u8 = 0x80;
/// How many registers [`RtcSt::load`] reads.
const RTC_NREG: u8 = 0x0e;
/// How many registers [`RtcSt::save`] writes.
const RTC_NREGP: u8 = 0x0a;

/// The month lengths, with February at 28.
const MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Why the clock cannot supply a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RtcError {
    /// Register D's `RTC_VRT` is clear: the battery lost the time.
    NotValid,
}

/// The fourteen CMOS registers in order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
// The field names keep their `rtc_` prefix.
#[allow(clippy::struct_field_names)]
#[allow(missing_docs)]
struct RtcSt {
    rtc_sec: u8,
    /// `rtc_asec`: the alarm seconds register.
    rtc_asec: u8,
    rtc_min: u8,
    /// `rtc_amin`: the alarm minutes register.
    rtc_amin: u8,
    rtc_hr: u8,
    /// `rtc_ahr`: the alarm hours register.
    rtc_ahr: u8,
    rtc_dow: u8,
    rtc_dom: u8,
    rtc_mon: u8,
    rtc_yr: u8,
    rtc_statusa: u8,
    rtc_statusb: u8,
    rtc_statusc: u8,
    rtc_statusd: u8,
}

const _: () = assert!(size_of::<RtcSt>() == 14);
const _: () = assert!(align_of::<RtcSt>() == 1);
const _: () = assert!(offset_of!(RtcSt, rtc_sec) == 0);
const _: () = assert!(offset_of!(RtcSt, rtc_asec) == 1);
const _: () = assert!(offset_of!(RtcSt, rtc_min) == 2);
const _: () = assert!(offset_of!(RtcSt, rtc_amin) == 3);
const _: () = assert!(offset_of!(RtcSt, rtc_hr) == 4);
const _: () = assert!(offset_of!(RtcSt, rtc_ahr) == 5);
const _: () = assert!(offset_of!(RtcSt, rtc_dow) == 6);
const _: () = assert!(offset_of!(RtcSt, rtc_dom) == 7);
const _: () = assert!(offset_of!(RtcSt, rtc_mon) == 8);
const _: () = assert!(offset_of!(RtcSt, rtc_yr) == 9);
const _: () = assert!(offset_of!(RtcSt, rtc_statusa) == 10);
const _: () = assert!(offset_of!(RtcSt, rtc_statusb) == 11);
const _: () = assert!(offset_of!(RtcSt, rtc_statusc) == 12);
const _: () = assert!(offset_of!(RtcSt, rtc_statusd) == 13);

impl RtcSt {
    /// Reads registers 0 through `RTC_NREG - 1` into the fields.
    fn load(&mut self) {
        let registers = [
            &mut self.rtc_sec,
            &mut self.rtc_asec,
            &mut self.rtc_min,
            &mut self.rtc_amin,
            &mut self.rtc_hr,
            &mut self.rtc_ahr,
            &mut self.rtc_dow,
            &mut self.rtc_dom,
            &mut self.rtc_mon,
            &mut self.rtc_yr,
            &mut self.rtc_statusa,
            &mut self.rtc_statusb,
            &mut self.rtc_statusc,
            &mut self.rtc_statusd,
        ];
        for (register, byte) in (0_u8..RTC_NREG).zip(registers) {
            RTC_ADDR.write_u8(register);
            *byte = RTC_DATA.read_u8();
        }
    }

    /// Writes the time and alarm fields back, leaving the status bytes alone.
    fn save(&self) {
        let registers = [
            &self.rtc_sec,
            &self.rtc_asec,
            &self.rtc_min,
            &self.rtc_amin,
            &self.rtc_hr,
            &self.rtc_ahr,
            &self.rtc_dow,
            &self.rtc_dom,
            &self.rtc_mon,
            &self.rtc_yr,
        ];
        for (register, byte) in (0_u8..RTC_NREGP).zip(registers) {
            RTC_ADDR.write_u8(register);
            RTC_DATA.write_u8(*byte);
        }
    }
}

/// Whether [`rtcinit()`] has run.
static RTC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Programs registers A and B.
fn rtcinit() {
    RTC_ADDR.write_u8(RTC_A);
    RTC_DATA.write_u8(RTC_DIV2 | RTC_RATE6);
    RTC_ADDR.write_u8(RTC_B);
    RTC_DATA.write_u8(RTC_HM);
}

/// Runs [`rtcinit()`] on the first call ever.
fn rtcinit_once() {
    if !RTC_INITIALIZED.swap(true, Ordering::Relaxed) {
        rtcinit();
    }
}

/// Reads the register block.
fn rtcget() -> Result<RtcSt, RtcError> {
    rtcinit_once();
    RTC_ADDR.write_u8(RTC_D);
    if RTC_DATA.read_u8() & RTC_VRT == 0 {
        return Err(RtcError::NotValid);
    }
    RTC_ADDR.write_u8(RTC_A);
    while RTC_DATA.read_u8() & RTC_UIP != 0 {
        RTC_ADDR.write_u8(RTC_A);
    }
    let mut st = RtcSt::default();
    st.load();
    Ok(st)
}

/// Programs the time registers back.
fn rtcput(st: &RtcSt) {
    rtcinit_once();
    RTC_ADDR.write_u8(RTC_B);
    let saved = RTC_DATA.read_u8();
    RTC_ADDR.write_u8(RTC_B);
    RTC_DATA.write_u8(saved | RTC_SET);
    st.save();
    RTC_ADDR.write_u8(RTC_B);
    RTC_DATA.write_u8(saved & !RTC_SET);
}

/// The decimal value of the binary-coded-decimal byte `byte`.
fn hexdectodec(byte: u8) -> u32 {
    u32::from((byte >> 4) & 0x0F) * 10 + u32::from(byte & 0x0F)
}

/// The binary-coded-decimal byte for the two decimal digits of `value`.
const fn dectohexdec(value: u64) -> u8 {
    // In contract `value` is below 100, so the two nibbles are its two digits
    // and the C's `char` conversion loses nothing.
    ((((value / 10) << 4) & 0xF0) | ((value % 10) & 0x0F)) as u8
}

/// The number of days in `year`.
const fn yeartoday(year: u32) -> u32 {
    if !year.is_multiple_of(4) {
        return 365;
    }
    if !year.is_multiple_of(100) {
        return 366;
    }
    if !year.is_multiple_of(400) {
        return 365;
    }
    366
}

/// The month lengths with February at 29 in a bissextile year.
const fn month_lengths(bissextile: bool) -> [u8; 12] {
    let mut months = MONTH;
    if bissextile {
        months[1] = 29;
    }
    months
}

/// Read the wall clock.
pub(crate) fn read_todc() -> Result<u64, RtcError> {
    // SAFETY: raising to `splclock` has no precondition, and the value it
    // returns is only handed back to `splx()`.
    let ospl = unsafe { spl::splclock() };
    let st = match rtcget() {
        Ok(st) => st,
        Err(error) => {
            // SAFETY: `ospl` is the level `splclock()` returned.
            unsafe { spl::splx(ospl) };
            return Err(error);
        }
    };
    // SAFETY: `ospl` is the level `splclock()` returned.
    unsafe { spl::splx(ospl) };

    let sec = hexdectodec(st.rtc_sec);
    let min = hexdectodec(st.rtc_min);
    let hr = hexdectodec(st.rtc_hr);
    let dom = hexdectodec(st.rtc_dom);
    let mon = hexdectodec(st.rtc_mon);
    let mut yr = hexdectodec(st.rtc_yr);
    yr = if yr < CENTURY_START % 100 {
        yr + CENTURY_START - CENTURY_START % 100 + 100
    } else {
        yr + CENTURY_START - CENTURY_START % 100
    };

    if yr >= CENTURY_START + 90 {
        kprint!(
            "FIXME: we are approaching {}, update CENTURY_START\n",
            CENTURY_START,
        );
    }

    kprint!(
        "RTC time is {:04}-{:02}-{:02} {:02}:{:02}:{:02}\n",
        yr,
        mon,
        dom,
        hr,
        min,
        sec,
    );

    let mut days = 0_u64;
    let months = month_lengths(yeartoday(yr) == 366);
    for (length, month) in months.iter().zip(1_u32..) {
        if month >= mon {
            break;
        }
        days += u64::from(*length);
    }
    for year in CENTURY_START..yr {
        days += u64::from(yeartoday(year));
    }

    let mut n = u64::from(sec) + 60 * u64::from(min) + 3600 * u64::from(hr);
    n += u64::from(dom.saturating_sub(1)) * 3600 * 24;
    n += days * 3600 * 24;
    Ok(n)
}

/// Program the wall clock with `seconds` since the Unix epoch.
pub(crate) fn write_todc(seconds: i64) -> Result<(), RtcError> {
    // SAFETY: raising to `splclock` has no precondition, and the value it
    // returns is only handed back to `splx()`.
    let ospl = unsafe { spl::splclock() };
    let mut st = match rtcget() {
        Ok(st) => st,
        Err(error) => {
            // SAFETY: `ospl` is the level `splclock()` returned.
            unsafe { spl::splx(ospl) };
            return Err(error);
        }
    };
    // SAFETY: `ospl` is the level `splclock()` returned.
    unsafe { spl::splx(ospl) };

    // The clock is a post-epoch count, so the sign-extending cast keeps its
    // value.
    let seconds = seconds as u64;

    let mut n = seconds % (3600 * 24);
    st.rtc_sec = dectohexdec(n % 60);
    n /= 60;
    st.rtc_min = dectohexdec(n % 60);
    st.rtc_hr = dectohexdec(n / 60);

    n = seconds / (3600 * 24);
    // 1/1/70 is a Thursday and the field counts from Sunday, so the value is
    // below seven and the cast is exact.
    st.rtc_dow = ((n + 4) % 7) as u8;

    let mut year = u64::from(CENTURY_START);
    let mut year_days = u64::from(yeartoday(CENTURY_START));
    while n >= year_days {
        n -= year_days;
        year += 1;
        // In contract the clock is between 1970 and 2070, so the year stays
        // far inside `u32`.
        year_days = u64::from(yeartoday(year as u32));
    }
    st.rtc_yr = dectohexdec(year % 100);

    let months = month_lengths(year_days == 366);
    let mut month = 0_u64;
    for length in &months {
        let length = u64::from(*length);
        if n < length {
            break;
        }
        n -= length;
        month += 1;
    }
    st.rtc_mon = dectohexdec(month + 1);
    st.rtc_dom = dectohexdec(n + 1);

    // SAFETY: `splclock()` returns the level `splx()` restores; the C re-took
    // it right before `rtcput()`.
    let ospl = unsafe { spl::splclock() };
    rtcput(&st);
    // SAFETY: `ospl` is the level just returned by `splclock()`.
    unsafe { spl::splx(ospl) };

    Ok(())
}
