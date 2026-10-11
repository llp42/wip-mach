// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The per-CPU AST reasons: what each CPU has to act on before it
//! returns to user mode.

use core::sync::atomic::{AtomicU32, Ordering};
use mach_page::smp::{CpuId, MAX_NCPUS};

bitflags::bitflags! {
    /// One or more AST reasons: what a CPU has to do before it returns to
    /// user mode.
    ///
    /// Machine-dependent code raises reasons and the AST check acts on them.
    /// The platform adds reasons of its own above the ones named here, so
    /// every bit is kept: complementing a reason set leaves them in place.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AstReason: u32 {
        /// The thread has been asked to halt at a clean point.
        const HALT = 0x1;
        /// The thread is terminating.
        const TERMINATE = 0x2;
        /// The scheduling AST reason.
        const BLOCK = 0x4;
        // The platform's reasons.
        const _ = !0;
    }
}

impl AstReason {
    /// The reasons that mean the thread should halt.
    pub const SHOULD_HALT: Self = Self::HALT.union(Self::TERMINATE);
    /// The reasons the scheduler holds back while the idle loop waits.
    const SCHEDULING: Self =
        Self::HALT.union(Self::TERMINATE).union(Self::BLOCK);
}

/// An [`AstReason`] set machine-dependent code reads from any CPU.
///
/// One slot per CPU holds the reasons pending there.  A poster makes its
/// bits visible with `Acquire`/`AcqRel`, the CPU that takes the AST
/// clears the slot with `swap`, and boot initializes it with `Relaxed`
/// while no other CPU runs.
#[repr(transparent)]
pub struct AtomicAstReason(AtomicU32);

impl AtomicAstReason {
    /// A slot holding `reason`.
    #[must_use]
    pub const fn new(reason: AstReason) -> Self {
        Self(AtomicU32::new(reason.bits()))
    }

    /// Returns the slot's reasons.
    pub fn load(&self, order: Ordering) -> AstReason {
        AstReason::from_bits_retain(self.0.load(order))
    }

    /// Replaces the slot's reasons.
    pub fn store(&self, reason: AstReason, order: Ordering) {
        self.0.store(reason.bits(), order);
    }

    /// Sets the bits of `reason`, returning the previous reasons.
    pub fn fetch_or(&self, reason: AstReason, order: Ordering) -> AstReason {
        AstReason::from_bits_retain(self.0.fetch_or(reason.bits(), order))
    }

    /// Clears the bits of `reason`, returning the previous reasons.
    pub fn fetch_and(&self, reason: AstReason, order: Ordering) -> AstReason {
        AstReason::from_bits_retain(self.0.fetch_and(reason.bits(), order))
    }

    /// Replaces the slot's reasons with `reason`, returning the previous.
    pub fn swap(&self, reason: AstReason, order: Ordering) -> AstReason {
        AstReason::from_bits_retain(self.0.swap(reason.bits(), order))
    }
}

/// The reasons pending on each CPU, one slot per [`CpuId`].  The trap and
/// syscall returns in `arch/x86_64/locore.rs` test the slots directly.
pub static AST_ARRAY: [AtomicAstReason; MAX_NCPUS] =
    [const { AtomicAstReason::new(AstReason::empty()) }; MAX_NCPUS];

/// Returns the reasons pending on `cpu`.
#[must_use]
pub fn needed(cpu: CpuId) -> AstReason {
    AST_ARRAY[cpu.as_usize()].load(Ordering::Acquire)
}

/// Sets `reasons` on `cpu`.
pub fn on(cpu: CpuId, reasons: AstReason) {
    AST_ARRAY[cpu.as_usize()].fetch_or(reasons, Ordering::AcqRel);
}

/// Clears `reasons` on `cpu`.
pub fn off(cpu: CpuId, reasons: AstReason) {
    AST_ARRAY[cpu.as_usize()].fetch_and(!reasons, Ordering::AcqRel);
}

/// Whether CPU `cpu` has an AST other than the scheduling reasons, which the
/// idle loop handles itself.
#[must_use]
pub fn scheduling_pending(cpu: CpuId) -> bool {
    needed(cpu).intersects(!AstReason::SCHEDULING)
}

/// Clears the scheduling reasons of `cpu`, the counterpart of
/// [`scheduling_pending()`] the scheduler calls before idling.
pub fn clear_scheduling(cpu: CpuId) {
    AST_ARRAY[cpu.as_usize()]
        .fetch_and(!AstReason::SCHEDULING, Ordering::AcqRel);
}

/// Zeroes every CPU's slot.  The scheduler runs this during boot, before
/// any CPU can take an AST.
pub fn init() {
    for cpu in CpuId::all() {
        AST_ARRAY[cpu.as_usize()].store(AstReason::empty(), Ordering::Relaxed);
    }
}
