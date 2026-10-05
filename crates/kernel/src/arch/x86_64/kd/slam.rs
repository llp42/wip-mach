// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kdasm.S and x86_64/kdasm.S:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The screen-slam block moves: a word fill and the forward and backward word
//! copies.

use core::arch::asm;

/// Fills `count` words at `start` with `value`.
///
/// # Safety
///
/// `start` must be valid for writes of `count` words.
pub(crate) unsafe fn fill_words(start: *mut u16, count: usize, value: u16) {
    unsafe {
        asm!(
            "cld",
            "rep stosw",
            inout("di") start => _,
            inout("cx") count => _,
            in("ax") value,
            options(att_syntax, nostack),
        );
    }
}

/// Copies `count` words forward from `from` to `to`.
///
/// # Safety
///
/// `from` must be valid for reads of `count` words and `to` valid for
/// writes of `count` words.
pub(crate) unsafe fn copy_forward(
    from: *const u16,
    to: *mut u16,
    count: usize,
) {
    unsafe {
        asm!(
            "cld",
            "rep movsw",
            inout("si") from => _,
            inout("di") to => _,
            inout("cx") count => _,
            options(att_syntax, nostack),
        );
    }
}

/// Copies `count` words backward from `from` to `to`, so that a
/// destination above the source overlaps without clobbering it.
///
/// # Safety
///
/// `from` must be valid for reads of `count` words and `to` valid for
/// writes of `count` words.
pub(crate) unsafe fn copy_backward(
    from: *const u16,
    to: *mut u16,
    count: usize,
) {
    unsafe {
        asm!(
            "std",
            "rep movsw",
            "cld",
            inout("si") from => _,
            inout("di") to => _,
            inout("cx") count => _,
            options(att_syntax, nostack),
        );
    }
}
