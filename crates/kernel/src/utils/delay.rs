// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/loose_ends.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The busy-wait delay.

use core::ffi::c_int;

/// Loop iterations per microsecond; the old cpuspeed value.
const CPU_SPEED: c_int = 4;

/// Busy-waits for about `n` microseconds.
pub(crate) const fn delay(n: c_int) {
    let mut remaining = CPU_SPEED.wrapping_mul(n);
    loop {
        remaining = remaining.wrapping_sub(1);
        if remaining <= 0 {
            break;
        }
        core::hint::black_box(remaining);
    }
}
