// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The eventcounter traps.
//!
//! Nothing registers an eventcounter, in GNU Mach either: its table was only
//! ever read, so a wait never found a counter and failed, and a dying thread
//! had no wait to leave.  The traps keep that answer.

use crate::kern::error::Error;
use core::ffi::{c_int, c_uint};

/// The `evc_wait` trap entry: no eventcounter `_ev_id` names exists.
pub(crate) extern "C" fn evc_wait(_ev_id: c_uint) -> c_int {
    c_int::from(Error::InvalidArgument)
}

/// The `evc_wait_clear` trap entry: no eventcounter `_ev_id` names exists.
pub(crate) extern "C" fn evc_wait_clear(_ev_id: c_uint) -> c_int {
    c_int::from(Error::InvalidArgument)
}
