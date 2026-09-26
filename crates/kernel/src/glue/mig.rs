// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! MIG conversions between the Rust error codes and the C result codes.

use crate::kern::types::KernError;
use core::ffi::c_int;

impl From<KernError> for c_int {
    fn from(error: KernError) -> Self {
        Self::from(error.as_u8())
    }
}
