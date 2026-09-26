// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The atomics, data cell and spin hint every lock is built from:
//! `core`'s normally, loom's under `cfg(loom)` so each protocol can be
//! model-checked.

#[cfg(not(loom))]
pub(crate) use core::sync::atomic::{
    AtomicBool, AtomicU32, AtomicUsize, Ordering, fence,
};
#[cfg(loom)]
pub(crate) use loom::sync::atomic::{
    AtomicBool, AtomicU32, AtomicUsize, Ordering, fence,
};

#[cfg(loom)]
pub(crate) use loom::cell::UnsafeCell;

/// Tells the CPU, or loom's scheduler, that the caller is spinning.
#[inline]
pub(crate) fn spin_loop() {
    #[cfg(not(loom))]
    core::hint::spin_loop();
    #[cfg(loom)]
    loom::hint::spin_loop();
}

/// A `core::cell::UnsafeCell` behind loom's closure API, so loom can
/// track every access to the data a lock protects.
#[cfg(not(loom))]
#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct UnsafeCell<T>(core::cell::UnsafeCell<T>);

#[cfg(not(loom))]
impl<T> UnsafeCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(core::cell::UnsafeCell::new(value))
    }

    pub(crate) fn into_inner(self) -> T {
        self.0.into_inner()
    }

    pub(crate) fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
        f(self.0.get())
    }

    pub(crate) fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
        f(self.0.get())
    }
}

/// Declares a `const fn`, except under loom, whose atomics and cells
/// cannot be built in a constant.
macro_rules! const_fn {
    ($(#[$attr:meta])* $vis:vis const fn $($rest:tt)*) => {
        #[cfg(not(loom))]
        $(#[$attr])* $vis const fn $($rest)*
        #[cfg(loom)]
        $(#[$attr])* $vis fn $($rest)*
    };
}

pub(crate) use const_fn;
