// SPDX-License-Identifier: CMU-Mach
// Derived from include/mach/policy.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The scheduling policies.

use core::ffi::c_int;

/// The default scheduling policy.
pub const POLICY_TIMESHARE: c_int = 1;
/// `POLICY_FIXEDPRI`: fixed-priority scheduling.
pub const POLICY_FIXEDPRI: c_int = 2;
/// `POLICY_LAST`: the highest defined policy.
pub const POLICY_LAST: c_int = 2;

/// Whether `policy` names no policy a processor set could hold.
pub(crate) const fn invalid_policy(policy: c_int) -> bool {
    policy <= 0 || policy > POLICY_LAST
}
