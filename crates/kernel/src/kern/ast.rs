// SPDX-License-Identifier: CMU-Mach
// SPDX-FileCopyrightText: 1991,1990,1989,1988,1987 Carnegie Mellon University
// SPDX-FileCopyrightText: 1993,1994 The University of Utah and the Computer Systems Laboratory (CSL)
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from Mach4 (commit e8a91124a56b72f46c5337679517cb5e4349d766)
//   <https://github.com/openmach/mach4>
// original files: kernel/kern/ast.c and kernel/kern/ast.h

//! The per-CPU AST reasons: what each CPU has to act on before it
//! returns to user mode.

use crate::arch::x86_64::ast::MACHINE_PER_THREAD;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::config::MAX_NCPUS;
use crate::kern::policy::POLICY_FIXEDPRI;
use crate::kern::processor::{ProcessorRef, ProcessorState};
use crate::kern::sched::NRQS;
use crate::kern::sched_prim::thread_block;
use crate::kern::smp::CpuId;
use crate::kern::thread::{TH_SUSP, Thread, ThreadQueue};
use core::ffi::c_int;
use core::sync::atomic::{AtomicU32, Ordering};

/// One or more AST reasons, as a bit set.
///
/// A reason is something the CPU has to do before it returns to user
/// mode; machine-dependent code raises reasons and the AST check acts
/// on them.  The per-thread mask groups the reasons that travel with a
/// thread, and the scheduling mask the ones the scheduler handles on
/// its own.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AstReason(u32);

impl AstReason {
    /// No reason: the empty set.
    pub const EMPTY: Self = Self(0);
    /// The thread has been asked to halt at a clean point.
    pub const HALT: Self = Self(0x1);
    /// The thread is terminating.
    pub const TERMINATE: Self = Self(0x2);
    /// The scheduling AST reason.
    pub const BLOCK: Self = Self(0x4);
    /// The network thread has packets to deliver.
    pub const NETWORK: Self = Self(0x8);

    /// The reasons reset from the thread at a context switch.
    pub(crate) const PER_THREAD: Self =
        Self(Self::HALT.0 | Self::TERMINATE.0 | MACHINE_PER_THREAD.0);

    /// The reasons that mean the thread should halt.
    pub(crate) const SHOULD_HALT: Self =
        Self(Self::HALT.0 | Self::TERMINATE.0);

    /// The reasons the scheduler holds back while the idle loop waits.
    const SCHEDULING: Self =
        Self(Self::HALT.0 | Self::TERMINATE.0 | Self::BLOCK.0);

    /// A reason set from its bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any bit of `other` is set in `self`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether no reason is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for AstReason {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for AstReason {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for AstReason {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitAndAssign for AstReason {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl core::ops::Not for AstReason {
    type Output = Self;

    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// An [`AstReason`] set machine-dependent code reads from any CPU.
///
/// One slot per CPU holds the reasons pending there.  A poster makes its
/// bits visible with `Acquire`/`AcqRel`, the CPU that takes the AST
/// clears the slot with `swap`, and boot initializes it with `Relaxed`
/// while no other CPU runs.
#[repr(transparent)]
pub(crate) struct AtomicAstReason(AtomicU32);

impl AtomicAstReason {
    /// A slot holding `reason`.
    pub(crate) const fn new(reason: AstReason) -> Self {
        Self(AtomicU32::new(reason.0))
    }

    /// Returns the slot's reasons.
    pub(crate) fn load(&self, order: Ordering) -> AstReason {
        AstReason(self.0.load(order))
    }

    /// Replaces the slot's reasons.
    pub(crate) fn store(&self, reason: AstReason, order: Ordering) {
        self.0.store(reason.0, order);
    }

    /// Sets the bits of `reason`, returning the previous reasons.
    pub(crate) fn fetch_or(
        &self,
        reason: AstReason,
        order: Ordering,
    ) -> AstReason {
        AstReason(self.0.fetch_or(reason.0, order))
    }

    /// Clears the bits of `reason`, returning the previous reasons.
    pub(crate) fn fetch_and(
        &self,
        reason: AstReason,
        order: Ordering,
    ) -> AstReason {
        AstReason(self.0.fetch_and(reason.0, order))
    }

    /// Replaces the slot's reasons with `reason`, returning the previous.
    pub(crate) fn swap(
        &self,
        reason: AstReason,
        order: Ordering,
    ) -> AstReason {
        AstReason(self.0.swap(reason.0, order))
    }
}

/// The reasons pending on each CPU, one slot per [`CpuId`].  The trap and
/// syscall returns in `arch/x86_64/locore.rs` test the slots directly.
pub(crate) static AST_ARRAY: [AtomicAstReason; MAX_NCPUS] =
    [const { AtomicAstReason::new(AstReason::EMPTY) }; MAX_NCPUS];

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

/// Replaces the per-thread reasons of `cpu` with `thread`'s pending ones.
///
/// # Safety
///
/// `thread` must be a live thread.
pub unsafe fn context(thread: *mut Thread, cpu: CpuId) {
    // SAFETY: `thread` is live, so `(*thread).ast` is readable.
    unsafe {
        let word = &AST_ARRAY[cpu.as_usize()];
        word.fetch_and(!AstReason::PER_THREAD, Ordering::AcqRel);
        word.fetch_or((*thread).ast, Ordering::AcqRel);
    }
}

/// Zeroes every CPU's slot.  The scheduler runs this during boot, before
/// any CPU can take an AST.
pub(crate) fn init() {
    for cpu in CpuId::all() {
        AST_ARRAY[cpu.as_usize()].store(AstReason::EMPTY, Ordering::Relaxed);
    }
}

/// Acts on the reasons pending on the running CPU.
///
/// # Safety
///
/// Machine-dependent code calls this on return to user mode with interrupts
/// disabled; the CPU must have no AST action in progress.
pub(crate) unsafe fn taken() {
    let self_ = per_cpu::thread();
    let cpu = cpu_id();
    let reasons =
        AST_ARRAY[cpu.as_usize()].swap(AstReason::EMPTY, Ordering::AcqRel);
    // SAFETY: this runs on the CPU's trap stack with interrupts still
    // disabled from the AST entry.
    unsafe { spl::spl0() };

    if reasons.contains(AstReason::NETWORK) {
        // SAFETY: the network code owns the AST; interrupts are enabled
        // here.
        unsafe { crate::device::net_io::ast() };
    }

    if self_ == per_cpu::processor().idle_thread() {
        return;
    }

    unsafe {
        while should_halt(self_) {
            Thread::halt_self(Some(
                crate::arch::x86_64::locore::thread_exception_return,
            ));
        }

        // `halt_self()` may block, so the thread may be back on another CPU.
        if reasons.contains(AstReason::BLOCK)
            || csw_needed(self_, per_cpu::processor())
        {
            thread_block(Some(
                crate::arch::x86_64::locore::thread_exception_return,
            ));
        }
    }
}

/// Checks the running processor for AST conditions at `splsched`.
///
/// The interrupt path enters here directly.
///
/// # Safety
///
/// The caller must be the running thread's CPU, able to take `splsched`, and
/// must not hold the run-queue lock.
pub(crate) unsafe extern "C" fn check() {
    let mycpu = cpu_id();
    let thread = per_cpu::thread();
    let myprocessor = per_cpu::processor();
    let s = unsafe { spl::splsched() };

    unsafe {
        match myprocessor.state() {
            ProcessorState::OffLine
            | ProcessorState::Idle
            | ProcessorState::Dispatching => (),
            ProcessorState::Assign | ProcessorState::Shutdown => {
                on(mycpu, AstReason::BLOCK);
            }
            ProcessorState::Running => {
                on(mycpu, (*thread).ast);
                if needed(mycpu).is_empty() {
                    check_running(mycpu, thread, myprocessor);
                }
            }
        }

        spl::splx(s);
    }
}

/// Whether `thread` has a halt or terminate reason pending.
///
/// # Safety
///
/// `thread` must be a live thread.
unsafe fn should_halt(thread: *mut Thread) -> bool {
    // SAFETY: `thread` is live, so `(*thread).ast` is readable.
    unsafe { (*thread).ast.intersects(AstReason::SHOULD_HALT) }
}

/// The [`ProcessorState::Running`] arm of [`check()`], after the thread's
/// own reasons have been propagated.
///
/// # Safety
///
/// `myprocessor` must be the running CPU's processor, `thread` its current
/// thread, and the caller must hold `splsched` with the run-queue lock free.
unsafe fn check_running(
    mycpu: CpuId,
    thread: *mut Thread,
    myprocessor: ProcessorRef,
) {
    unsafe {
        if (*thread).state() & TH_SUSP != 0 || myprocessor.runq_count() > 0 {
            on(mycpu, AstReason::BLOCK);
            return;
        }

        let pset = myprocessor.processor_set();
        if (*pset).policies & POLICY_FIXEDPRI != 0 {
            if csw_needed(thread, myprocessor) {
                on(mycpu, AstReason::BLOCK);
            } else if (*thread).policy == POLICY_FIXEDPRI {
                myprocessor.set_first_quantum(true);
            }
            return;
        }

        let rq = &raw mut (*pset).runq;
        if myprocessor.first_quantum()
            || (*rq).count.load(Ordering::Relaxed) == 0
        {
            return;
        }

        let low = (*rq).low;
        if (*queue_at(rq, low)).is_empty() {
            (*rq).lock.lock();
            if (*rq).count.load(Ordering::Relaxed) > 0 {
                let mut i = (*rq).low;
                while i < NRQS as c_int {
                    if !(*queue_at(rq, i)).is_empty() {
                        break;
                    }
                    i += 1;
                }
                (*rq).low = i;
            }
            (*rq).lock.unlock();
        }

        if (*rq).low <= (*thread).sched_pri {
            on(mycpu, AstReason::BLOCK);
        }
    }
}

/// A pointer to `runq[low]`, one step of the run-queue hint walk.
///
/// # Safety
///
/// `rq` must be a live run queue and `low` a valid queue index.
unsafe fn queue_at(
    rq: *mut crate::kern::sched::RunQueue,
    low: c_int,
) -> *mut ThreadQueue {
    unsafe {
        (&raw mut (*rq).runq)
            .cast::<ThreadQueue>()
            .add(low as usize)
    }
}

/// Whether a context switch is needed for `thread` on `processor`.
///
/// # Safety
///
/// `thread` must be live.
///
/// # Panics
///
/// If `processor` is not the running CPU's; see
/// [`ProcessorRef::has_runnable()`].
unsafe fn csw_needed(thread: *mut Thread, processor: ProcessorRef) -> bool {
    let suspended = unsafe { (*thread).state() } & TH_SUSP != 0;
    suspended || processor.has_runnable()
}
