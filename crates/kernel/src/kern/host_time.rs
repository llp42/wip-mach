// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/mach_clock.h:
//   Copyright (C) 2006, 2007 Free Software Foundation, Inc.
// Derived from kern/mach_clock.c:
//   Copyright (c) 1994-1988 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Host time entries and boot-time stamps over the machine
//! [`CLOCK`](crate::arch::x86_64::clock_platform::CLOCK).

use crate::arch::x86_64::clock_platform::CLOCK;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::spl;
use crate::glue::time_value::{
    MACH_ADJTIME_NSECS_OMIT, TimeValue, TimeValue64,
};
use crate::kern::processor;
use crate::kern::sched_prim::{thread_bind, thread_block};
use crate::kern::types::KernError;
use core::ffi::c_void;
use core::ptr;

/// `clock_boottime_offset` of `kern/mach_clock.c`: the boot clock less the
/// real-time clock.
static mut CLOCK_BOOTTIME_OFFSET: TimeValue64 = TimeValue64 {
    seconds: 0,
    nanoseconds: 0,
};

/// `clock_boottime_update()` in `kern/mach_clock.c`: fold the real-time clock's
/// change into the boot clock's offset.
fn clock_boottime_update(new_time: TimeValue64) {
    let time = wallclock();
    let delta = time.sub(new_time);
    // SAFETY: the caller runs at `splhigh()`, which serializes the clock
    // interrupt that owns the offset.
    let offset = unsafe { CLOCK_BOOTTIME_OFFSET };
    // SAFETY: the caller runs at `splhigh()`, which serializes the clock
    // interrupt that owns the offset.
    unsafe { CLOCK_BOOTTIME_OFFSET = offset.add(delta) };
}

/// The wall clock [`CLOCK`] maintains.
pub(crate) fn wallclock() -> TimeValue64 {
    TimeValue64::from_nanos(CLOCK.wall().as_nanos())
}

/// Replace the wall clock under `splhigh()`.
pub(crate) fn set_wallclock(value: TimeValue64) {
    CLOCK.set_wall(clock::WallTime::from_nanos(value.to_nanos()));
}

/// The ticks since boot.
pub(crate) fn elapsed_ticks() -> usize {
    CLOCK.elapsed_ticks().get() as usize
}

/// `record_time_stamp()`: the caller's `stamp` becomes the boot-time frame
/// reading.
///
/// # Safety
///
/// `stamp` must be valid for a write.
pub(crate) unsafe fn record_time_stamp(stamp: *mut TimeValue64) {
    let value = wallclock();
    // SAFETY: the offset is the maintained global.
    let offset = unsafe { CLOCK_BOOTTIME_OFFSET };
    unsafe { stamp.write(value.add(offset)) };
}

/// `read_time_stamp()`: translate a boot-time-frame `stamp` into the caller's
/// real-time `result`.
///
/// # Safety
///
/// `stamp` must point at a readable [`TimeValue64`] and `result` at writable
/// storage for one.
pub(crate) unsafe fn read_time_stamp(
    stamp: *const TimeValue64,
    result: *mut TimeValue64,
) {
    let value = unsafe { stamp.read() };
    // SAFETY: the offset is the maintained global; the reader takes one
    // value of it.
    let offset = unsafe { CLOCK_BOOTTIME_OFFSET };
    unsafe { result.write(value.sub(offset)) };
}

/// `host_get_time()`: the 32-bit wall clock.
pub(crate) fn get_time(host: *mut c_void) -> Result<TimeValue, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }
    Ok(TimeValue::from(wallclock()))
}

/// `host_get_time64()`.
pub(crate) fn get_time64(host: *mut c_void) -> Result<TimeValue64, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }
    Ok(wallclock())
}

/// `host_get_uptime64()`.
pub(crate) fn get_uptime64(
    host: *mut c_void,
) -> Result<TimeValue64, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }
    Ok(TimeValue64::from_nanos(CLOCK.mono().as_nanos()))
}

/// `host_set_time64()`, which is also the body the 32-bit entry falls
/// through to.
pub(crate) fn set_time64(
    host: *mut c_void,
    new_time: TimeValue64,
) -> Result<(), KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }

    let thread = per_cpu::thread();
    let boot = processor::boot_processor();
    // SAFETY: `thread` is the live current thread and `boot` the live
    // boot processor; `thread_bind()` only stores the pairing under the
    // thread lock.
    unsafe { thread_bind(thread, boot) };

    if per_cpu::processor().as_ptr() != boot {
        // SAFETY: the thread is bound to `boot`, so the block resumes
        // there; the C passed a null continuation.
        unsafe { thread_block(None) };
    }

    // SAFETY: `splhigh()` is the real asm routine, and its value is only
    // handed back to `splx()`.
    let s = unsafe { spl::splhigh() };
    clock_boottime_update(new_time);
    // `set_wall` stores the domain, programs the RTC and publishes the page.
    set_wallclock(new_time);
    // SAFETY: `s` is the level `splhigh()` returned.
    unsafe { spl::splx(s) };

    // SAFETY: `thread` is the live current thread and the null is the C
    // `PROCESSOR_NULL`, the unbind the C performed.
    unsafe { thread_bind(thread, ptr::null_mut()) };

    Ok(())
}

/// The body of `host_adjust_time64()`: bind to the master CPU, then read and
/// rewrite the gradual-adjustment state at `splclock()`, answering the
/// outstanding adjustment.
pub(crate) fn adjust_time(
    host: *mut c_void,
    new_adjustment: TimeValue64,
) -> Result<TimeValue64, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }

    let thread = per_cpu::thread();
    let boot = processor::boot_processor();
    // SAFETY: `thread` is the live current thread and `boot` the live
    // boot processor; `thread_bind()` only stores the pairing under the
    // thread lock.
    unsafe { thread_bind(thread, boot) };

    if per_cpu::processor().as_ptr() != boot {
        // SAFETY: the thread is bound to `boot`, so the block resumes
        // there; the C passed a null continuation.
        unsafe { thread_block(None) };
    }

    // SAFETY: `splclock()` is the real asm routine, and its return value is
    // only handed back to `splx()`.
    let s = unsafe { spl::splclock() };

    // The C read the outstanding adjustment before the write, under the
    // same `splclock()`, so both arms answer it: the query leaves the
    // stored value alone, and the write hands back what it replaced.
    let old_nanos = if new_adjustment.nanoseconds == MACH_ADJTIME_NSECS_OMIT {
        CLOCK.adjustment()
    } else {
        let nanos = new_adjustment
            .seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(new_adjustment.nanoseconds);
        CLOCK.set_adjustment(nanos)
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
    unsafe { spl::splx(s) };

    // SAFETY: `thread` is the live current thread and the null is the C
    // `PROCESSOR_NULL`, the unbind the C performed.
    unsafe { thread_bind(thread, ptr::null_mut()) };

    Ok(old)
}
