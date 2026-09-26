// SPDX-License-Identifier: CMU-Mach
// Derived from kern/sched.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The scheduler records of `kern/sched.h`.

use crate::kern::lock::SimpleLock;
use crate::kern::thread::ThreadQueue;
use core::ffi::c_int;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicI32, Ordering};

/// `NRQS` in <kern/sched.h>: one run queue per priority.
pub const NRQS: usize = 65;

/// `BASEPRI_SYSTEM` in <kern/sched.h>: the priority of kernel threads.
pub const BASEPRI_SYSTEM: c_int = 6;

/// `PRI_SHIFT` in <kern/sched.h>: where a thread's usage is scaled into
/// priorities.
pub(crate) const PRI_SHIFT: u32 = 17;

/// `SCHED_SHIFT` in <kern/sched.h>: the `SCHED_SCALE` scaling of
/// `sched_usage`.
pub(crate) const SCHED_SHIFT: u32 = 7;

/// `SCHED_SCALE` in <kern/sched.h>: the fixed-point unit of `sched_load` and
/// `sched_usage`.
pub(crate) const SCHED_SCALE: c_int = 128;

/// `RUN_QUEUE_NULL` in <kern/sched.h>: not on any run queue.
pub const RUN_QUEUE_NULL: *mut RunQueue = core::ptr::null_mut();

/// `struct run_queue` of <kern/sched.h>: the `NRQS` priority queues and their
/// lock.
#[repr(C)]
pub struct RunQueue {
    /// `runq`: one queue per priority.
    pub runq: [ThreadQueue; NRQS],
    /// `lock`: one lock for all the queues, taken at splsched.
    pub lock: SimpleLock,
    /// `low`: the lowest non-empty queue.
    pub low: c_int,
    /// `count`: the number of runnable threads; written under `lock`, read
    /// without it as a hint.
    pub count: AtomicI32,
}

// The heads are two words, so the offset stays.
const _: () = assert!(size_of::<ThreadQueue>() == 16);
const _: () = assert!(size_of::<RunQueue>() == 1056);
const _: () =
    assert!(offset_of!(RunQueue, lock) == NRQS * size_of::<ThreadQueue>());
const _: () = assert!(
    offset_of!(RunQueue, low)
        == offset_of!(RunQueue, lock) + size_of::<SimpleLock>()
);
const _: () = assert!(
    offset_of!(RunQueue, count)
        == offset_of!(RunQueue, low) + size_of::<c_int>()
);

/// Whether `priority` is outside the `NRQS` run queues; the C `invalid_pri()`
/// of <kern/sched.h>.
pub(crate) fn invalid_pri(priority: c_int) -> bool {
    usize::try_from(priority).map_or(true, |priority| priority >= NRQS)
}

/// Adds `delta` to `field`, which one writer updates at a time: a run-queue
/// `count` under its lock, or a processor's quantum on its own CPU. The
/// single writer lets a plain load and store stand in for a locked
/// read-modify-write.
pub(crate) fn add_single_writer(field: &AtomicI32, delta: c_int) {
    field.store(
        field.load(Ordering::Relaxed).wrapping_add(delta),
        Ordering::Relaxed,
    );
}
