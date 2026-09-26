// SPDX-License-Identifier: CMU-Mach
// Derived from util/atoi.c and util/atoi.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
//   Copyright 1988, 1989 by Intel Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `mach_atoi()`, which `util/atoi.c` used to define; `util/atoi.h` keeps the
//! C declaration and the `MACH_ATOI_DEFAULT` macro.

use core::ffi::c_int;
use core::slice;

/// `MACH_ATOI_DEFAULT` of <util/atoi.h>: the "no number" value the C interface
/// stores.
const MACH_ATOI_DEFAULT: c_int = -1;

/// Parse the leading decimal digits of `bytes`.
#[must_use]
fn parse(bytes: &[u8]) -> (usize, Option<c_int>) {
    let mut number: c_int = 0;
    let mut used = 0;

    while let Some(&byte) = bytes.get(used) {
        if !byte.is_ascii_digit() {
            break;
        }
        number = number
            .wrapping_mul(10)
            .wrapping_add(c_int::from(byte - b'0'));
        used += 1;
    }

    let number = (used != 0).then_some(number);
    (used, number)
}

/// `mach_atoi()` of <util/atoi.h>: parse the leading decimal digits at `s`,
/// store the number or `MACH_ATOI_DEFAULT` at `nump`, and return the number of
/// bytes consumed.
///
/// # Safety
///
/// `s` must be readable up to and including the first non-digit byte -- a
/// NUL-terminated string satisfies this; `nump` must be valid for a write.
pub(crate) unsafe fn mach_atoi(s: *const u8, nump: *mut c_int) -> c_int {
    let mut len = 0;

    while unsafe { *s.add(len) }.is_ascii_digit() {
        len += 1;
    }

    let bytes = unsafe { slice::from_raw_parts(s, len) };

    let (used, number) = parse(bytes);

    unsafe { *nump = number.unwrap_or(MACH_ATOI_DEFAULT) };

    // The C original converted `cp - original` to an `int`; `used` is bounded
    // by the readable byte count, so only a multi-gigabyte digit run could
    // differ.
    used as c_int
}
