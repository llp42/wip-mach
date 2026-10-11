// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Why a host call failed.

/// A failed host call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An argument does not apply to this call.
    InvalidArgument,
    /// The host the call names is not one.
    InvalidHost,
    /// The kernel could not allocate the reply.
    ResourceShortage,
}
