// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The irq-quiet section: a CPU-local region in which no local interrupt
//! handler runs.

#[cfg(debug_assertions)]
use crate::checker;
use crate::platform::Platform;
use core::marker::PhantomData;

/// Enters an irq-quiet section with no guard, for raw locks whose unlock
/// may run in another function.
pub(crate) fn enter_irq_quiet<P: Platform>() {
    P::irq_quiet_enter();
    #[cfg(debug_assertions)]
    checker::section_enter::<P>();
}

/// Leaves an irq-quiet section entered with [`enter_irq_quiet`].
///
/// # Safety
///
/// The running thread entered an irq-quiet section that it has not left.
pub(crate) unsafe fn exit_irq_quiet<P: Platform>() {
    #[cfg(debug_assertions)]
    checker::section_exit::<P>();
    unsafe { P::irq_quiet_exit() };
}

/// An irq-quiet section, left when dropped.
///
/// Neither `Send` nor `Sync`: the section belongs to the thread and CPU
/// that entered it.
#[derive(Debug)]
#[must_use = "the section ends as soon as the guard is dropped"]
pub struct IrqQuiet<P: Platform>(PhantomData<(P, *const ())>);

impl<P: Platform> IrqQuiet<P> {
    /// Enters an irq-quiet section.
    pub fn enter() -> Self {
        enter_irq_quiet::<P>();
        Self(PhantomData)
    }
}

impl<P: Platform> Drop for IrqQuiet<P> {
    fn drop(&mut self) {
        // SAFETY: this guard entered the section, on this thread since it
        // is not `Send`, and has not left it.
        unsafe { exit_irq_quiet::<P>() };
    }
}
