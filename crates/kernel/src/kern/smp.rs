// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The generic SMP controller

use crate::config::MAX_NCPUS;
use core::ffi::c_int;
use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

// `CpuId::BOOT` names block 0 of `per_cpu_array`.
const _: () = assert!(MAX_NCPUS >= 1);

/// The number of CPUs in the machine, always at least one.
static NCPUS: AtomicU8 = AtomicU8::new(1);

/// A CPU number the machine reports, below [`MAX_NCPUS`].
///
/// The C passed CPU numbers as `int`s and left the bound to the caller's
/// word.  This one carries the bound in the type, so the per-CPU accessors
/// that take a [`CpuId`] hold no `# Safety` of their own: every constructor
/// either checks `cpu < MAX_NCPUS` or takes it as a contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CpuId(u32);

impl CpuId {
    /// The CPU the boot code starts on: a constant, since the role is never
    /// reassigned.
    pub const BOOT: Self = Self(0);

    /// The CPU `cpu` names, without checking.
    ///
    /// # Safety
    ///
    /// `cpu` must be below [`MAX_NCPUS`].
    #[must_use]
    pub const unsafe fn new_unchecked(cpu: u32) -> Self {
        Self(cpu)
    }

    /// The CPU the C `int` `cpu` names, without checking.
    ///
    /// # Safety
    ///
    /// `cpu` must be non-negative and below [`MAX_NCPUS`].
    #[must_use]
    pub const unsafe fn from_c_int(cpu: c_int) -> Self {
        // The contract holds `cpu` in `0..MAX_NCPUS`, so the sign change
        // cannot wrap.
        Self(cpu as u32)
    }

    /// Every CPU block the configuration provides, `0..MAX_NCPUS`.
    pub fn all() -> impl Iterator<Item = Self> {
        // `MAX_NCPUS` is at most 64, so the narrowing cannot wrap.
        (0..MAX_NCPUS as u32).map(Self)
    }

    /// Every CPU the machine brought up, `0..NCPUS`.
    pub fn online() -> impl Iterator<Item = Self> {
        Self::all().take(usize::from(ncpus()))
    }

    /// The number the C stores in a `cpu_id` field.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The number as an index into a per-CPU array.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for CpuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Sets the number of CPUs the kernel runs on.
///
/// # Panics
///
/// If `ncpus` is zero: the count is always at least one, and zero is not a
/// number of CPUs.  If `ncpus` exceeds [`MAX_NCPUS`]: the configuration's
/// capacity is the most the per-CPU arrays hold.
pub(crate) fn set_ncpus(ncpus: u8) {
    assert!(ncpus != 0, "set_ncpus: zero CPUs");
    assert!(
        usize::from(ncpus) <= MAX_NCPUS,
        "set_ncpus: {ncpus} CPUs, capacity {MAX_NCPUS}"
    );
    NCPUS.store(ncpus, Ordering::Release);
}

/// The number of CPUs the kernel runs on.
pub(crate) fn ncpus() -> u8 {
    NCPUS.load(Ordering::Acquire)
}
