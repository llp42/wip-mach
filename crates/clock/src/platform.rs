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

/// Interrupt exclusion for the clock's critical sections.
pub trait Critical {
    /// The token whose drop restores the interrupted state.
    type Guard: Drop;

    /// Disables the interrupts that can reach the clock and returns the
    /// token that restores them.
    fn enter_critical(&self) -> Self::Guard;
}

impl<T: Critical + ?Sized> Critical for &T {
    type Guard = T::Guard;

    fn enter_critical(&self) -> T::Guard {
        (**self).enter_critical()
    }
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
pub trait Platform: TimeCounter + Critical + Calendar + TimePage {}

impl<P: TimeCounter + Critical + Calendar + TimePage> Platform for P {}
