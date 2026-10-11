// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `SyncCell`: a singleton cell for the segment table.

use core::cell::UnsafeCell;

/// A singleton cell whose `Sync` promise the caller's locks make true.
#[repr(transparent)]
pub struct SyncCell<T>(pub UnsafeCell<T>);

// SAFETY: the user serializes every access with its documented lock.
unsafe impl<T> Sync for SyncCell<T> {}
