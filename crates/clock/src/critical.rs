// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt-safe lock the clock's mutable state lives in.

use crate::platform::Critical;
use spin::Mutex;

/// A spin lock whose acquire and release nest inside a
/// [`Critical`] guard, so an interrupt that wants the same lock cannot
/// deadlock the holder.
pub struct CriticalLock<T> {
    inner: Mutex<T>,
}

impl<T> CriticalLock<T> {
    /// A lock holding `value`.
    pub(crate) const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    /// Enters the critical section and locks the state.
    ///
    /// The guard order is the caller's: drop the data guard before the
    /// critical guard.
    pub(crate) fn lock<P: Critical>(
        &self,
        platform: &P,
    ) -> (P::Guard, spin::MutexGuard<'_, T>) {
        let critical = platform.enter_critical();
        (critical, self.inner.lock())
    }
}
