// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The callout the scheduler's timeouts run on.

use crate::platform::Platform;

/// A callout on the wheel the scheduler's timeouts run on, with no extra
/// payload: the action recovers its owner from the field address.
pub type Callout<P> = clock::Callout<'static, <P as Platform>::TimeBase, ()>;
