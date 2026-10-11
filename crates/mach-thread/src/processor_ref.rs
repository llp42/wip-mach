// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! A handle on one of the static per-CPU processor records.

use crate::platform::Platform;
use crate::processor::Processor;
use crate::processor_set::ProcessorSet;
use crate::smp::CpuId;
use crate::thread::Thread;
use crate::types::{ProcessorSlot, ProcessorState};
use core::ffi::c_int;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::Ordering;

/// A handle on one of the static per-CPU [`Processor`] records, as
/// [`processor_at()`](crate::processor::processor_at) and
/// [`Platform::cpu_processor()`] hand it
/// out.
///
/// The record outlives every handle, so each accessor is safe: it touches one
/// atomic field, never the whole record, whose other fields change under
/// their locks. A handle kept across a block still names the processor it was
/// taken on, which may no longer be the running one.
pub struct ProcessorRef<P: Platform>(*mut Processor<P>);

// The derives would bound `P` itself, which the handle never holds.
impl<P: Platform> Clone for ProcessorRef<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Platform> Copy for ProcessorRef<P> {}

impl<P: Platform> PartialEq for ProcessorRef<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<P: Platform> Eq for ProcessorRef<P> {}

impl<P: Platform> fmt::Debug for ProcessorRef<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProcessorRef").field(&self.0).finish()
    }
}

impl<P: Platform> ProcessorRef<P> {
    /// Wraps `processor` in a handle.
    ///
    /// # Safety
    ///
    /// `processor` must point at one of the static per-CPU processor records.
    #[must_use]
    pub const unsafe fn from_static(processor: *mut Processor<P>) -> Self {
        Self(processor)
    }

    /// Returns the record's address, for the routines that take the lock
    /// guarding its other fields.
    #[must_use]
    pub const fn as_ptr(self) -> *mut Processor<P> {
        self.0
    }

    /// Returns the record, for projection onto one of its atomic fields only.
    const fn record(self) -> *const Processor<P> {
        self.0.cast_const()
    }

    /// Returns the processor's state.
    #[must_use]
    pub fn state(self) -> ProcessorState {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).state.load(Ordering::Acquire) }
    }

    /// Sets the processor's state.
    pub fn set_state(self, state: ProcessorState) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).state.store(state, Ordering::Release) }
    }

    /// Returns the thread a dispatch left for this processor, or null.
    #[must_use]
    pub fn next_thread(self) -> *mut Thread<P> {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).next_thread.load(Ordering::Acquire) }
    }

    /// Sets the thread a dispatch leaves for this processor.
    pub fn set_next_thread(self, thread: *mut Thread<P>) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe {
            (*self.record())
                .next_thread
                .store(thread, Ordering::Release);
        }
    }

    /// Returns the processor's idle thread, or null before it starts.
    #[must_use]
    pub fn idle_thread(self) -> *mut Thread<P> {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).idle_thread.load(Ordering::Relaxed) }
    }

    /// Records `thread` as the processor's idle thread.
    pub fn set_idle_thread(self, thread: *mut Thread<P>) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe {
            (*self.record())
                .idle_thread
                .store(thread, Ordering::Relaxed);
        }
    }

    /// Sets the quantum left to the running thread.
    pub fn set_quantum(self, quantum: c_int) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).quantum.store(quantum, Ordering::Relaxed) }
    }

    /// Sets whether the running thread is still in its first quantum.
    pub fn set_first_quantum(self, first: bool) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe {
            (*self.record())
                .first_quantum
                .store(c_int::from(first), Ordering::Relaxed);
        }
    }

    /// Returns whether the running thread is still in its first quantum.
    #[must_use]
    pub fn first_quantum(self) -> bool {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).first_quantum.load(Ordering::Relaxed) != 0 }
    }

    /// Returns the set the processor belongs to, or null while it is out of
    /// every set.
    #[must_use]
    pub fn processor_set(self) -> *mut ProcessorSet<P> {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).processor_set.load(Ordering::Acquire) }
    }

    /// Returns the number of threads on the processor's own run queue.
    #[must_use]
    pub fn runq_count(self) -> c_int {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).runq.count.load(Ordering::Relaxed) }
    }

    /// Returns whether the processor or its set has a thread to run.
    ///
    /// # Panics
    ///
    /// If this is not the running CPU's processor: the set it names stays
    /// live only for code on that CPU.
    #[must_use]
    pub fn has_runnable(self) -> bool {
        assert!(
            self == P::cpu_processor(),
            "has_runnable: not the running CPU's processor"
        );
        if self.runq_count() > 0 {
            return true;
        }
        let pset = self.processor_set();
        // SAFETY: only this CPU's action thread takes the processor out of
        // its set, never while this code runs, and a set is not freed while
        // a processor remains in it; the set is null only between the
        // shutdown's removal and the CPU's halt.
        !pset.is_null()
            && unsafe { (*pset).runq.count.load(Ordering::Relaxed) } > 0
    }

    /// Returns the CPU the record belongs to.
    #[must_use]
    fn cpu(self) -> CpuId {
        let offset =
            self.0.addr() - P::task_state().processors.as_ptr().addr();
        let index = offset / size_of::<ProcessorSlot<P>>();
        // SAFETY: the handle names an element of the processor records, which
        // holds `MAX_NCPUS` records, so `index` is below `MAX_NCPUS` and the
        // narrowing cannot wrap.
        unsafe { CpuId::new_unchecked(index as u32) }
    }

    /// Interrupts the processor so that it runs
    /// [`check()`](crate::ast::check) and acts on the
    /// dispatch, reschedule or suspension just made for it.
    pub fn ast_check(self) {
        P::remote_ast(self.cpu());
    }
}
