// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! A set of CPUs, one bit each.

use core::ffi::c_int;
use core::sync::atomic::{AtomicIsize, Ordering};

/// The set of CPUs a pmap is in use on, one bit each.
#[derive(Debug)]
#[repr(transparent)]
pub struct CpuSet(AtomicIsize);

impl CpuSet {
    pub(crate) const fn new() -> Self {
        Self(AtomicIsize::new(0))
    }

    /// The bit a CPU number selects; the set holds at most 32 CPUs.
    pub(crate) const fn mask(cpu: c_int) -> isize {
        1isize.wrapping_shl(cpu as u32)
    }

    pub(crate) fn bits(&self) -> isize {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn set_bits(&self, bits: isize) {
        self.0.store(bits, Ordering::Relaxed);
    }

    pub(crate) fn set(&self, cpu: c_int) {
        self.0.fetch_or(Self::mask(cpu), Ordering::SeqCst);
    }

    pub(crate) fn clear(&self, cpu: c_int) {
        self.0.fetch_and(!Self::mask(cpu), Ordering::SeqCst);
    }

    pub(crate) fn contains(&self, cpu: c_int) -> bool {
        self.bits() & Self::mask(cpu) != 0
    }
}
