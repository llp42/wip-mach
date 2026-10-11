// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The pattern checks and fills of verify-mode caches.

use core::ptr::NonNull;

/// The first byte of `buf` that differs from `pattern`, or `None`.
///
/// # Safety
///
/// `buf` must hold `pattern.len()` readable bytes.
pub(crate) unsafe fn verify_bytes(
    buf: *const u8,
    pattern: &[u8],
) -> Option<NonNull<u8>> {
    for (i, byte) in pattern.iter().enumerate() {
        if unsafe { *buf.add(i) } != *byte {
            // SAFETY: the mismatch byte is inside the range.
            return Some(unsafe {
                NonNull::new_unchecked(buf.add(i).cast_mut())
            });
        }
    }

    None
}

/// The first word of the `size` bytes at `buf` that differs from `pattern`, or
/// `None`.
///
/// # Safety
///
/// `buf` must hold `size` readable bytes.
pub(crate) unsafe fn verify(
    buf: *const u8,
    pattern: u64,
    size: usize,
) -> Option<NonNull<u8>> {
    let end = buf.wrapping_add(size);
    let mut ptr = buf.cast::<u64>();

    while ptr.cast::<u8>() < end {
        if unsafe { ptr.read() } != pattern {
            return unsafe {
                verify_bytes(ptr.cast(), &pattern.to_ne_bytes())
            };
        }
        ptr = unsafe { ptr.add(1) };
    }

    None
}

/// Fills the `size` bytes at `buf` with `pattern`.
///
/// # Safety
///
/// `buf` must hold `size` writable bytes.
pub(crate) unsafe fn fill(buf: *mut u8, pattern: u64, size: usize) {
    let end = buf.wrapping_add(size);
    let mut ptr = buf.cast::<u64>();

    while ptr.cast::<u8>() < end {
        unsafe { ptr.write(pattern) };
        ptr = unsafe { ptr.add(1) };
    }
}

/// Checks that the `size` bytes at `buf` hold `old` and refills them with
/// `new`, returning the first word that differs, or `None`.
///
/// # Safety
///
/// `buf` must hold `size` readable and writable bytes.
pub(crate) unsafe fn verify_fill(
    buf: *mut u8,
    old: u64,
    new: u64,
    size: usize,
) -> Option<NonNull<u8>> {
    let end = buf.wrapping_add(size);
    let mut ptr = buf.cast::<u64>();

    while ptr.cast::<u8>() < end {
        if unsafe { ptr.read() } != old {
            return unsafe { verify_bytes(ptr.cast(), &old.to_ne_bytes()) };
        }
        unsafe { ptr.write(new) };
        ptr = unsafe { ptr.add(1) };
    }

    None
}
