// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Host time entries and boot-time stamps over the machine clock.

use crate::error::Error;
use crate::platform::Platform;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicI64, Ordering};
use mach_sched::time_value::{TIME_NANOS_MAX, TimeValue, TimeValue64};
use mach_thread::processor;
use mach_thread::sched_prim::{thread_bind, thread_block};

/// The nanoseconds component that asks `host_adjust_time64()` to report the
/// outstanding adjustment without changing it.
pub const MACH_ADJTIME_NSECS_OMIT: i64 = TIME_NANOS_MAX;

/// The boot clock less the real-time clock, in signed nanoseconds: any CPU
/// reads it while the clock-setting path adds to it, so it is one atomic
/// word.
static CLOCK_BOOTTIME_OFFSET: AtomicI64 = AtomicI64::new(0);

/// The boot-time offset as the normalized time value the stamps add.
fn boottime_offset() -> TimeValue64 {
    let nanos = CLOCK_BOOTTIME_OFFSET.load(Ordering::Relaxed);
    TimeValue64 {
        seconds: nanos.div_euclid(TIME_NANOS_MAX),
        nanoseconds: nanos.rem_euclid(TIME_NANOS_MAX),
    }
}

/// Folds the real-time clock's change into the boot clock's offset.
fn clock_boottime_update<P: Platform>(new_time: TimeValue64) {
    let delta = wallclock::<P>().sub(new_time);
    // `sub` leaves the nanoseconds normalized, so the offset grows by the
    // whole delta, as the C's time-value addition did.
    let nanos = delta
        .seconds
        .wrapping_mul(TIME_NANOS_MAX)
        .wrapping_add(delta.nanoseconds);
    CLOCK_BOOTTIME_OFFSET.fetch_add(nanos, Ordering::Relaxed);
}

/// The wall clock the machine clock maintains.
#[must_use]
pub fn wallclock<P: Platform>() -> TimeValue64 {
    TimeValue64::from_nanos(P::clock().wall().as_nanos())
}

/// Replace the wall clock under `splhigh()`.
pub fn set_wallclock<P: Platform>(value: TimeValue64) {
    P::clock().set_wall(clock::WallTime::from_nanos(value.to_nanos()));
}

/// The ticks since boot.
#[must_use]
pub fn elapsed_ticks<P: Platform>() -> usize {
    P::clock().elapsed_ticks().get() as usize
}

/// `record_time_stamp()`: the wall clock in the boot-time frame.
#[must_use]
pub fn record_time_stamp<P: Platform>() -> TimeValue64 {
    wallclock::<P>().add(boottime_offset())
}

/// `read_time_stamp()`: a boot-time-frame `stamp` in real time.
#[must_use]
pub fn read_time_stamp(stamp: TimeValue64) -> TimeValue64 {
    stamp.sub(boottime_offset())
}

/// `host_get_time()`: the 32-bit wall clock.
pub fn get_time<P: Platform>(host: *mut c_void) -> Result<TimeValue, Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }
    Ok(TimeValue::from(wallclock::<P>()))
}

/// `host_get_time64()`.
pub fn get_time64<P: Platform>(
    host: *mut c_void,
) -> Result<TimeValue64, Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }
    Ok(wallclock::<P>())
}

/// `host_get_uptime64()`.
pub fn get_uptime64<P: Platform>(
    host: *mut c_void,
) -> Result<TimeValue64, Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }
    Ok(TimeValue64::from_nanos(P::clock().mono().as_nanos()))
}

/// `host_set_time64()`, which is also the body the 32-bit entry falls
/// through to.
pub fn set_time64<P: Platform>(
    host: *mut c_void,
    new_time: TimeValue64,
) -> Result<(), Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }

    let thread = P::cpu_thread();
    let boot = processor::boot_processor();
    // SAFETY: `thread` is the live current thread and `boot` the live
    // boot processor; `thread_bind()` only stores the pairing under the
    // thread lock.
    unsafe { thread_bind(thread, boot) };

    if P::cpu_processor().as_ptr() != boot {
        // SAFETY: the thread is bound to `boot`, so the block resumes
        // there; the C passed a null continuation.
        unsafe { thread_block::<P>(None) };
    }

    let s = P::splhigh();
    clock_boottime_update::<P>(new_time);
    // `set_wall` stores the domain, programs the RTC and publishes the page.
    set_wallclock::<P>(new_time);
    // SAFETY: `s` is the level `splhigh()` returned.
    unsafe { P::splx(s) };

    // SAFETY: `thread` is the live current thread, and binding it to no
    // processor unbinds it.
    unsafe { thread_bind(thread, ptr::null_mut()) };

    Ok(())
}

/// The body of `host_adjust_time64()`: bind to the master CPU, then read and
/// rewrite the gradual-adjustment state at `splclock()`, answering the
/// outstanding adjustment.
pub fn adjust_time<P: Platform>(
    host: *mut c_void,
    new_adjustment: TimeValue64,
) -> Result<TimeValue64, Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }

    let thread = P::cpu_thread();
    let boot = processor::boot_processor();
    // SAFETY: `thread` is the live current thread and `boot` the live
    // boot processor; `thread_bind()` only stores the pairing under the
    // thread lock.
    unsafe { thread_bind(thread, boot) };

    if P::cpu_processor().as_ptr() != boot {
        // SAFETY: the thread is bound to `boot`, so the block resumes
        // there; the C passed a null continuation.
        unsafe { thread_block::<P>(None) };
    }

    // SAFETY: `splclock()` is the real asm routine, and its return value is
    // only handed back to `splx()`.
    let s = unsafe { P::splclock() };

    // The C read the outstanding adjustment before the write, under the
    // same `splclock()`, so both arms answer it: the query leaves the
    // stored value alone, and the write hands back what it replaced.
    let old_nanos = if new_adjustment.nanoseconds == MACH_ADJTIME_NSECS_OMIT {
        P::clock().adjustment()
    } else {
        let nanos = new_adjustment
            .seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(new_adjustment.nanoseconds);
        P::clock().set_adjustment(nanos)
    };

    // The C split the outstanding microseconds into whole seconds and the
    // remainder, truncating toward zero, so a negative correction keeps
    // both parts negative.
    let micros = old_nanos / 1000;
    let old = TimeValue64 {
        seconds: micros / 1_000_000,
        nanoseconds: (micros % 1_000_000) * 1000,
    };

    // SAFETY: `s` is the level `splclock()` returned.
    unsafe { P::splx(s) };

    // SAFETY: `thread` is the live current thread, and binding it to no
    // processor unbinds it.
    unsafe { thread_bind(thread, ptr::null_mut()) };

    Ok(old)
}
