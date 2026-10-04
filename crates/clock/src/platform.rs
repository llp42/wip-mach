// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the clock needs from the machine, injected by the kernel.

use crate::types::{Instant, WallTime};

/// The free-running counter the clock interpolates between ticks.
pub trait TimeCounter {
    /// The current counter value.
    fn counter(&self) -> u32;

    /// The nanoseconds one counter unit spans.
    fn counter_period_nsec(&self) -> u32;
}

/// The `lock` platform the clock's and the wheels' irq spin locks run on,
/// so the clock interrupt never spins on a lock its own CPU holds.
pub trait Locking {
    /// The modular backend of `lock`.
    type Lock: lock::Platform;
}

impl<T: Locking + ?Sized> Locking for &T {
    type Lock = T::Lock;
}

/// The real-time clock the wall clock is written back to.
pub trait Calendar {
    /// Programs the RTC with `seconds` since the Unix epoch.
    fn set_rtc(&self, seconds: i64);
}

/// The mapped time page userspace reads.
pub trait TimePage {
    /// Publishes the wall clock and the uptime the readers see.
    fn publish(&self, wall: WallTime, uptime: Instant);
}

/// Everything [`Clock`](crate::Clock) needs from the machine.
pub trait Platform: TimeCounter + Locking + Calendar + TimePage {}

impl<P: TimeCounter + Locking + Calendar + TimePage> Platform for P {}
