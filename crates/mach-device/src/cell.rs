// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `SyncCell`: a singleton cell for the device service's C-shaped mutable
//! state.

use core::cell::UnsafeCell;

/// A singleton cell whose `Sync` promise the caller's lock or interrupt level
/// makes true.
#[repr(transparent)]
pub struct SyncCell<T>(pub(crate) UnsafeCell<T>);

impl<T> SyncCell<T> {
    /// A cell holding `value`.
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The address of the value.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

// SAFETY: the user serializes every access at its documented level.
unsafe impl<T> Sync for SyncCell<T> {}
