// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! A snapshot of a statistical timer, for the deltas of the next read.

use crate::timer::{Timer, delta};
use core::ffi::c_uint;
use core::mem::{offset_of, size_of};

/// A saved timer reading.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TimerSave {
    pub low: c_uint,
    pub high: c_uint,
}

impl TimerSave {
    /// The ticks elapsed since this reading, which is updated to the current
    /// timer value.
    ///
    /// # Safety
    ///
    /// `timer` and `self` must be the live pair of one thread, and the caller
    /// must serialize updates to them, as the thread lock does.
    #[must_use]
    pub unsafe fn delta(&mut self, timer: &Timer) -> c_uint {
        let low = timer.low_bits;
        if self.high == timer.high_bits_check {
            let elapsed = low.wrapping_sub(self.low);
            self.low = low;
            elapsed
        } else {
            delta(timer, self)
        }
    }
}

const _: () = assert!(size_of::<TimerSave>() == 8);

const _: () = assert!(align_of::<TimerSave>() == 4);

const _: () = assert!(offset_of!(TimerSave, low) == 0);

const _: () = assert!(offset_of!(TimerSave, high) == 4);
