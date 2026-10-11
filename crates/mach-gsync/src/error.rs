// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Why a gsync call failed.

/// A failed `gsync_wait` or `gsync_wake`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The address is not word-aligned, not mapped, or not accessible as
    /// the call needs it.
    InvalidAddress,
    /// The other task's page could not be mapped into the kernel.
    MemoryFailure,
    /// The word did not hold the value the wait expected, or no thread
    /// waited on the address the wake named.
    InvalidArgument,
    /// The wait was interrupted.
    Interrupted,
    /// The wait timed out.
    TimedOut,
}
