// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2023 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: i386/i386/percpu.c and i386/i386/percpu.h

//! The per-CPU block: one record per CPU, reached through `%gs`, naming
//! the running thread, its stack and its processor.

use crate::arch::types::VmOffset;
use crate::config::MAX_NCPUS;
use crate::kern::processor::{Processor, ProcessorRef, processor_at};
use crate::kern::smp::{CpuId, ncpus};
use crate::kern::thread::Thread;
use core::arch::asm;
use core::mem::offset_of;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

/// A CPU's per-CPU block: the state `%gs` reaches at fixed offsets.
///
/// Each block keeps to its own cache lines, so no two CPUs' blocks ever
/// share one. Every field is atomic: other CPUs and the assembly reach them
/// concurrently.
#[repr(C, align(64))]
pub struct PerCpu {
    /// The block's own address once [`init()`] has run, null before.
    pub self_ptr: AtomicPtr<Self>,
    /// The ID the CPU's local APIC matches physical destinations against,
    /// zero until the CPU's `apic::setup()` records it.
    pub apic_id: AtomicU32,
    /// The CPU's number, below `MAX_NCPUS`; an AP's boot code stores it
    /// before any Rust code runs, and the boot CPU's is zero.
    pub cpu_id: AtomicU32,
    /// The CPU's element of the processor array once [`init()`] has run,
    /// null before.
    pub processor: AtomicPtr<Processor>,
    /// The thread the CPU is running, or null while it runs none; the
    /// context switch rewrites it.
    pub thread: AtomicPtr<Thread>,
    /// The kernel stack the CPU is running on; the context switch saves the
    /// outgoing registers into it.
    pub stack: AtomicUsize,
}

/// The blocks, one per CPU; each CPU's boot code bases its `%gs` on its
/// element, and an AP's also stores its `cpu_id` there.
#[unsafe(export_name = "per_cpu_array")]
static PER_CPU_ARRAY: [PerCpu; MAX_NCPUS] =
    // SAFETY: every field is an atomic, valid when zeroed.
    unsafe { core::mem::zeroed() };

impl PerCpu {
    /// Returns the thread the CPU is running, or null while it runs none.
    #[must_use]
    pub fn thread(&self) -> *mut Thread {
        self.thread.load(Ordering::Relaxed)
    }

    /// Records `thread` as the thread the CPU is running.
    ///
    /// # Safety
    ///
    /// The caller must be the CPU's context switcher about to resume
    /// `thread`, which no other CPU may run, or its shutdown clearing the
    /// field: the context switch and every [`Self::thread()`] caller trust
    /// the value.
    pub unsafe fn set_thread(&self, thread: *mut Thread) {
        self.thread.store(thread, Ordering::Relaxed);
    }

    /// Returns the kernel stack the CPU is running on.
    #[must_use]
    pub fn stack(&self) -> VmOffset {
        self.stack.load(Ordering::Relaxed)
    }

    /// Returns the CPU's local APIC ID, the physical IPI destination.
    #[must_use]
    pub fn apic_id(&self) -> u32 {
        self.apic_id.load(Ordering::Relaxed)
    }

    /// Records the CPU's local APIC ID; the CPU's own APIC setup is the
    /// only writer, before any other CPU sends it an IPI.
    pub(crate) fn set_apic_id(&self, apic_id: u32) {
        self.apic_id.store(apic_id, Ordering::Relaxed);
    }
}

/// Returns the number of the CPU running this code.
#[inline]
#[must_use]
pub fn cpu_id() -> CpuId {
    // WARN: sound only because the kernel is non-preemptible: `pure` lets
    // the compiler merge or hoist this read, and callers index per-CPU
    // state with the result; a thread preempted between the read and its
    // use would resume on another CPU and touch wrong slots.
    let cpu: u32;
    // SAFETY: the boot code bases `%gs` on the running CPU's block before
    // any Rust code runs, so its `cpu_id` is readable. The value is below
    // `MAX_NCPUS`: the boot CPU's is the zero of the static, and each other
    // CPU's boot code stores its `CPU_ID_LUT` entry, an index below
    // `ncpus()`, which `set_ncpus()` bounds by `MAX_NCPUS`.
    unsafe {
        asm!(
            "mov {cpu:e}, gs:[{offset}]",
            cpu = out(reg) cpu,
            offset = const offset_of!(PerCpu, cpu_id),
            options(pure, readonly, nostack, preserves_flags),
        );
        CpuId::new_unchecked(cpu)
    }
}

/// Returns the running CPU's per-CPU block.
///
/// # Panics
///
/// If [`init()`] has not yet run on this CPU.
#[inline]
#[must_use]
pub fn per_cpu() -> &'static PerCpu {
    // WARN: sound only because the kernel is non-preemptible: `pure` lets
    // the compiler merge or hoist this read, and callers index per-CPU
    // state with the result; a thread preempted between the read and its
    // use would resume on another CPU and touch wrong slots.
    let per_cpu: *mut PerCpu;
    // SAFETY: the boot code bases `%gs` on the running CPU's block before
    // any Rust code runs, so its `self_ptr` is readable.
    unsafe {
        asm!(
            "mov {per_cpu}, gs:[{offset}]",
            per_cpu = out(reg) per_cpu,
            offset = const offset_of!(PerCpu, self_ptr),
            options(pure, readonly, nostack, preserves_flags),
        );
    }
    assert!(!per_cpu.is_null(), "per_cpu: before per_cpu::init");
    // SAFETY: a non-null `self_ptr` is the address `init()` stored, that of
    // this CPU's element of the static array.
    unsafe { &*per_cpu }
}

/// Returns the processor record of the running CPU.
///
/// # Panics
///
/// If [`init()`] has not yet run on this CPU.
#[inline]
#[must_use]
pub fn processor() -> ProcessorRef {
    // WARN: sound only because the kernel is non-preemptible: `pure` lets
    // the compiler merge or hoist this read, and callers index per-CPU
    // state with the result; a thread preempted between the read and its
    // use would resume on another CPU and touch wrong slots.
    let processor: *mut Processor;
    // SAFETY: the boot code bases `%gs` on the running CPU's block before
    // any Rust code runs, so its `processor` is readable.
    unsafe {
        asm!(
            "mov {processor}, gs:[{offset}]",
            processor = out(reg) processor,
            offset = const offset_of!(PerCpu, processor),
            options(pure, readonly, nostack, preserves_flags),
        );
    }
    assert!(!processor.is_null(), "processor: before per_cpu::init");
    // SAFETY: a non-null `processor` is the link `init()` stored, to this
    // CPU's element of the static processor array.
    unsafe { ProcessorRef::from_static(processor) }
}

/// Returns the running CPU's thread.
#[inline]
#[must_use]
pub fn thread() -> *mut Thread {
    // WARN: sound only because the kernel is non-preemptible: `pure` lets
    // the compiler merge or hoist this read, and callers index per-CPU
    // state with the result; a thread preempted between the read and its
    // use would resume on another CPU and touch wrong slots.
    let thread: *mut Thread;
    // SAFETY: the boot code bases `%gs` on the running CPU's block before
    // any Rust code runs, and the aligned load is atomic.
    unsafe {
        asm!(
            "mov {thread}, gs:[{offset}]",
            thread = out(reg) thread,
            offset = const offset_of!(PerCpu, thread),
            options(pure, readonly, nostack, preserves_flags),
        );
    }
    thread
}

/// Records `thread` as the running CPU's thread.
///
/// # Safety
///
/// The caller must be the running CPU's context switcher about to resume
/// `thread`, which no other CPU may run: the context switch and every
/// [`thread()`] caller trust the value.
#[inline]
pub unsafe fn set_thread(thread: *mut Thread) {
    unsafe {
        asm!(
            "mov gs:[{offset}], {thread}",
            thread = in(reg) thread,
            offset = const offset_of!(PerCpu, thread),
            options(nostack, preserves_flags),
        );
    }
}

/// Returns the running CPU's kernel stack.
#[inline]
#[must_use]
pub fn stack() -> VmOffset {
    // WARN: sound only because the kernel is non-preemptible: `pure` lets
    // the compiler merge or hoist this read, and callers index per-CPU
    // state with the result; a thread preempted between the read and its
    // use would resume on another CPU and touch wrong slots.
    let stack: VmOffset;
    // SAFETY: the boot code bases `%gs` on the running CPU's block before
    // any Rust code runs, and the aligned load is atomic.
    unsafe {
        asm!(
            "mov {stack}, gs:[{offset}]",
            stack = out(reg) stack,
            offset = const offset_of!(PerCpu, stack),
            options(pure, readonly, nostack, preserves_flags),
        );
    }
    stack
}

/// Records `stack` as the running CPU's kernel stack.
///
/// # Safety
///
/// The caller must be the running CPU's context switcher, about to run on
/// `stack`, a live kernel stack: the next context switch saves the outgoing
/// registers into it.
#[inline]
pub unsafe fn set_stack(stack: VmOffset) {
    unsafe {
        asm!(
            "mov gs:[{offset}], {stack}",
            stack = in(reg) stack,
            offset = const offset_of!(PerCpu, stack),
            options(nostack, preserves_flags),
        );
    }
}

/// Returns CPU `cpu`'s per-CPU block.
///
/// # Panics
///
/// If `cpu` is not below `MAX_NCPUS`, which only a `CpuId` built against its
/// unchecked constructors' contract can be.
#[inline]
#[must_use]
pub fn per_cpu_at(cpu: CpuId) -> &'static PerCpu {
    &PER_CPU_ARRAY[cpu.as_usize()]
}

/// Returns the blocks of the CPUs the machine brought up, `0..NCPUS`.
pub fn iter() -> impl Iterator<Item = &'static PerCpu> {
    PER_CPU_ARRAY.iter().take(usize::from(ncpus()))
}

/// Records one CPU's number, links its processor record, and points its
/// block at itself.
///
/// # Safety
///
/// The boot path of `cpu` must call this once per CPU, before anything
/// reads that CPU's block.
pub(crate) unsafe fn init(cpu: CpuId) {
    let block = &PER_CPU_ARRAY[cpu.as_usize()];
    block.cpu_id.store(cpu.bits(), Ordering::Relaxed);
    block
        .processor
        .store(processor_at(cpu).as_ptr(), Ordering::Relaxed);
    block
        .self_ptr
        .store(ptr::from_ref(block).cast_mut(), Ordering::Relaxed);
}

/// Returns whether [`init()`] has run on this CPU.
#[must_use]
pub(crate) fn is_init() -> bool {
    // WARN: sound only because the kernel is non-preemptible: `pure` lets
    // the compiler merge or hoist this read, and callers index per-CPU
    // state with the result; a thread preempted between the read and its
    // use would resume on another CPU and touch wrong slots.
    let self_ptr: usize;
    // SAFETY: the boot code bases `%gs` on the running CPU's block before
    // any Rust code runs, so `self_ptr` is readable; only `init()` writes
    // it.
    unsafe {
        asm!(
            "mov {self_ptr}, gs:[{offset}]",
            self_ptr = out(reg) self_ptr,
            offset = const offset_of!(PerCpu, self_ptr),
            options(pure, readonly, nostack, preserves_flags),
        );
    }
    self_ptr != 0
}
