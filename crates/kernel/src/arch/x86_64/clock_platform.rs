// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `clock` platform for `x86_64`: the HPET counter, `spl`, the RTC and
//! the mapped time page.

use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::{apic, rtc, spl};
use crate::glue::time_value::{MappedTimeValue, TimeValue64};
use crate::kern::debug::kpanic;
use crate::vm::vm_kern::{self, KERNEL_MAP};
use clock::{
    Calendar, Clock, Critical, HashedWheel, Instant, Ticks, TimeCounter,
    TimePage, WallTime,
};
use core::ffi::c_int;
use core::pin::Pin;
use core::ptr::{self, NonNull, addr_of_mut};
use core::sync::atomic::{AtomicPtr, Ordering, fence};

/// The interrupt mask [`MachPlatform::enter_critical`] took.
pub(crate) struct SplGuard(c_int);

impl Drop for SplGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the level `splhigh()` returned on this CPU.
        unsafe { spl::splx(self.0) };
    }
}

impl Critical for MachPlatform {
    type Guard = SplGuard;

    fn enter_critical(&self) -> SplGuard {
        // SAFETY: `splhigh()` is the real asm routine; its value is only
        // handed back to `splx()` in the guard's `Drop`.
        SplGuard(unsafe { spl::splhigh() })
    }
}

impl TimeCounter for MachPlatform {
    fn counter(&self) -> u32 {
        apic::hpclock_read_counter()
    }

    fn counter_period_nsec(&self) -> u32 {
        apic::hpclock_get_counter_period_nsec()
    }
}

impl Calendar for MachPlatform {
    fn set_rtc(&self, seconds: i64) {
        // SAFETY: `writetodc_seconds` takes the epoch count the RTC wants.
        let _ = unsafe { rtc::writetodc_seconds(seconds) };
    }
}

impl TimePage for MachPlatform {
    fn publish(&self, wall: WallTime, uptime: Instant) {
        publish_mapped_time(wall.as_nanos(), uptime.as_nanos());
    }
}

/// `mtime` of `kern/mach_clock.c`: the page `mapable_time_init()` wired, or
/// null before that.
static MTIME: AtomicPtr<MappedTimeValue> = AtomicPtr::new(ptr::null_mut());

/// Publish both domains to the mapped time page (the `clock` crate's
/// [`TimePage`] hook).
pub(crate) fn publish_mapped_time(wall_nanos: u64, uptime_nanos: u64) {
    update_mapped_time(TimeValue64::from_nanos(wall_nanos));
    update_mapped_uptime(TimeValue64::from_nanos(uptime_nanos));
}

/// `update_mapped_time()` in `kern/mach_clock.c`.
fn update_mapped_time(value: TimeValue64) {
    let mtime = MTIME.load(Ordering::Relaxed);
    if mtime.is_null() {
        return;
    }

    // The C stored the `int64_t` seconds into the page's `int` fields, and
    // the truncation is part of the interface `include/mach/time_value.h`
    // documents.  The volatile stores and SeqCst fences are the C's
    // `volatile` pointer and `__sync_synchronize()`.
    // SAFETY: `mtime` is the page `mapable_time_init()` wired, never
    // unmapped, and its only writer is the master CPU's clock interrupt,
    // where this runs; every field written is a plain scalar of the
    // `mapped_time_value_t` mirror.
    unsafe {
        addr_of_mut!((*mtime).check_seconds)
            .write_volatile(value.seconds as c_int);
        addr_of_mut!((*mtime).check_seconds64).write_volatile(value.seconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).microseconds)
            .write_volatile((value.nanoseconds / 1000) as c_int);
        addr_of_mut!((*mtime).time_value.nanoseconds)
            .write_volatile(value.nanoseconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).seconds).write_volatile(value.seconds as c_int);
        addr_of_mut!((*mtime).time_value.seconds)
            .write_volatile(value.seconds);
    }
}

/// `update_mapped_uptime()` in `kern/mach_clock.c`.
fn update_mapped_uptime(value: TimeValue64) {
    let mtime = MTIME.load(Ordering::Relaxed);
    if mtime.is_null() {
        return;
    }

    // SAFETY: `mtime` is the page `mapable_time_init()` wired, never
    // unmapped, and written only from the master CPU's clock interrupt; the
    // uptime fields are plain scalars of the same mirror.
    unsafe {
        addr_of_mut!((*mtime).check_upseconds64).write_volatile(value.seconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).uptime_value.nanoseconds)
            .write_volatile(value.nanoseconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).uptime_value.seconds)
            .write_volatile(value.seconds);
    }
}

/// `mapable_time_init()` in `kern/mach_clock.c`.
pub(crate) fn mapable_time_init() {
    // SAFETY: `kernel_map` is the live kernel map this boot step runs on.
    let map = unsafe { NonNull::new_unchecked(KERNEL_MAP) };
    let Ok(page) = vm_kern::kmem_alloc_wired(map, crate::vm::types::PAGE_SIZE)
    else {
        kpanic!("mapable_time_init", "mapable_time_init");
    };

    // SAFETY: `page` is the wired page just allocated, so zeroing it and
    // recording it is what the C `memset()` and assignment did.
    unsafe { (page as *mut u8).write_bytes(0, crate::vm::types::PAGE_SIZE) };
    MTIME.store(page as *mut MappedTimeValue, Ordering::Relaxed);
    // Publish whatever the machine clock holds at this boot step. The
    // earlier `set_wall` publish landed on a null `MTIME`.
    publish_mapped_time(CLOCK.wall().as_nanos(), CLOCK.mono().as_nanos());
}

/// The mapped time page: `mtime` of `kern/mach_clock.c`, null until
/// `mapable_time_init()` ran at boot.
pub(crate) fn mapped_time_page() -> *mut MappedTimeValue {
    MTIME.load(Ordering::Relaxed)
}

/// The one machine clock (ADR 0038). Only cpu0 calls [`Clock::tick`].
pub(crate) static CLOCK: Clock<MachPlatform> = Clock::new(MachPlatform);

/// The one machine-wide timer wheel, driven from cpu0's hardclock.
pub(crate) static WHEEL: HashedWheel<&'static Clock<MachPlatform>> =
    HashedWheel::new(&CLOCK, Ticks::ZERO);

/// The pinned wheel callouts and the softclock run on.
pub(crate) const fn wheel()
-> Pin<&'static HashedWheel<&'static Clock<MachPlatform>>> {
    Pin::static_ref(&WHEEL)
}

/// A callout on the machine wheel, with no extra payload: the action
/// recovers its owner from the field address.
pub(crate) type MachCallout =
    clock::Callout<'static, &'static Clock<MachPlatform>, ()>;

/// The deferred pass of the machine wheel (ADR 0042).
pub(crate) fn softclock() {
    while wheel().advance() {}
}

/// Advance the machine clock and arm the deferred wheel pass from cpu0's
/// hardclock (ADR 0038, ADR 0042).
pub(crate) fn tick(basepri: bool) {
    // The sole mutator of tick, mono and wall (ADR 0038).
    CLOCK.tick(clock::TICK);

    if wheel().poll() {
        if basepri {
            // SAFETY: `splsoftclock()` is the routine <i386/spl.h>
            // declares; the C discarded its level because the interrupt
            // return restores it.
            let _ = unsafe { spl::splsoftclock() };
            softclock();
        } else {
            spl::setsoftclock();
        }
    }
}
