// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `clock` platform for `x86_64`: the HPET counter, the RTC and the
//! mapped time page, with the clock's locks on [`MachPlatform`].

use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::vm_platform::VM_STATE;
use crate::arch::x86_64::{apic, rtc, spl};
use crate::kern::debug::kpanic;
use crate::mig::time_value::{MappedTimeValue, TimeValue64};
use clock::{
    Calendar, Clock, HashedWheel, Instant, Locking, Ticks, TimeCounter,
    TimePage, WallTime,
};
use core::ffi::c_int;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering, fence};
use mach_vm::vm_kern;
use volatile::{VolatilePtr, map_field};

impl Locking for MachPlatform {
    type Lock = Self;
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
        // A clock that cannot keep the time keeps the old one.
        let _ = rtc::write_todc(seconds);
    }
}

impl TimePage for MachPlatform {
    fn publish(&self, wall: WallTime, uptime: Instant) {
        publish_mapped_time(wall.as_nanos(), uptime.as_nanos());
    }
}

/// The mapped time page [`mapable_time_init`] wired, or null before that.
static MTIME: AtomicPtr<MappedTimeValue> = AtomicPtr::new(ptr::null_mut());

/// Publish both domains to the mapped time page (the `clock` crate's
/// [`TimePage`] hook).
pub(crate) fn publish_mapped_time(wall_nanos: u64, uptime_nanos: u64) {
    update_mapped_time(TimeValue64::from_nanos(wall_nanos));
    update_mapped_uptime(TimeValue64::from_nanos(uptime_nanos));
}

/// Publishes `value` as the wall time on the mapped time page.
fn update_mapped_time(value: TimeValue64) {
    let Some(mtime) = NonNull::new(MTIME.load(Ordering::Relaxed)) else {
        return;
    };
    // SAFETY: `mtime` is the page `mapable_time_init()` wired, never unmapped,
    // and its only writer is the master CPU's clock interrupt, where this
    // runs; every field written is a plain scalar of the `MappedTimeValue`
    // mirror.
    let page = unsafe { VolatilePtr::new(mtime) };

    // The seconds are stored into the page's `int` fields too, and their
    // truncation is part of the interface.  The volatile stores and `SeqCst`
    // fences order the writes for the user side's double check.
    map_field!(page.check_seconds).write(value.seconds as c_int);
    map_field!(page.check_seconds64).write(value.seconds);
    fence(Ordering::SeqCst);
    map_field!(page.microseconds).write((value.nanoseconds / 1000) as c_int);
    map_field!(page.time_value.nanoseconds).write(value.nanoseconds);
    fence(Ordering::SeqCst);
    map_field!(page.seconds).write(value.seconds as c_int);
    map_field!(page.time_value.seconds).write(value.seconds);
}

/// Publishes `value` as the uptime on the mapped time page.
fn update_mapped_uptime(value: TimeValue64) {
    let Some(mtime) = NonNull::new(MTIME.load(Ordering::Relaxed)) else {
        return;
    };
    // SAFETY: `mtime` is the page `mapable_time_init()` wired, never
    // unmapped, and written only from the master CPU's clock interrupt; the
    // uptime fields are plain scalars of the same mirror.
    let page = unsafe { VolatilePtr::new(mtime) };

    map_field!(page.check_upseconds64).write(value.seconds);
    fence(Ordering::SeqCst);
    map_field!(page.uptime_value.nanoseconds).write(value.nanoseconds);
    fence(Ordering::SeqCst);
    map_field!(page.uptime_value.seconds).write(value.seconds);
}

/// Wires and zeroes the mapped time page, then publishes the clock on it.
pub(crate) fn mapable_time_init() {
    // SAFETY: `kernel_map` is the live kernel map this boot step runs on.
    let map = unsafe { NonNull::new_unchecked(VM_STATE.kernel_map()) };
    let Ok(page) = vm_kern::kmem_alloc_wired(map, mach_vm::types::PAGE_SIZE)
    else {
        kpanic!("mapable_time_init", "mapable_time_init");
    };

    // SAFETY: `page` is the wired page just allocated, so zeroing it and
    // recording it is what the C `memset()` and assignment did.
    unsafe { (page as *mut u8).write_bytes(0, mach_vm::types::PAGE_SIZE) };
    MTIME.store(page as *mut MappedTimeValue, Ordering::Relaxed);
    // Publish whatever the machine clock holds at this boot step. The
    // earlier `set_wall` publish landed on a null `MTIME`.
    publish_mapped_time(CLOCK.wall().as_nanos(), CLOCK.mono().as_nanos());
}

/// The mapped time page, null until [`mapable_time_init`] ran at boot.
pub(crate) fn mapped_time_page() -> *mut MappedTimeValue {
    MTIME.load(Ordering::Relaxed)
}

/// The one machine clock. Only cpu0 calls [`Clock::tick`].
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

/// The deferred pass of the machine wheel.
pub(crate) fn softclock() {
    while wheel().advance() {}
}

/// Advance the machine clock and arm the deferred wheel pass from cpu0's
/// hardclock.
pub(crate) fn tick(basepri: bool) {
    // The sole mutator of tick, mono and wall.
    CLOCK.tick(clock::TICK);

    if wheel().poll() {
        if basepri {
            // SAFETY: lowering to the soft-clock level has no precondition
            // here; the level is discarded because the interrupt return
            // restores it.
            let _ = unsafe { spl::splsoftclock() };
            softclock();
        } else {
            spl::setsoftclock();
        }
    }
}
