// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

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
