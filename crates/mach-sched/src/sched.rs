// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The scheduler's constants, its tick and its minimum quantum.

use core::ffi::{c_int, c_uint};
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

/// The ticks per second.
pub const CLOCK_HZ: c_int = 100;
const _: () = assert!(CLOCK_HZ as u64 == clock::HZ);

/// The microseconds per tick.
pub const TICK: c_int = 1_000_000 / CLOCK_HZ;

/// One run queue per priority.
pub const NRQS: usize = 65;

/// The priority of kernel threads.
pub const BASEPRI_SYSTEM: c_int = 6;

/// Where a thread's usage is scaled into priorities.
pub const PRI_SHIFT: u32 = 17;

/// The `SCHED_SCALE` scaling of `sched_usage`.
pub const SCHED_SHIFT: u32 = 7;

/// The fixed-point unit of `sched_load` and `sched_usage`.
pub const SCHED_SCALE: c_int = 128;

/// Whether `priority` is outside the `NRQS` run queues.
#[must_use]
pub fn invalid_pri(priority: c_int) -> bool {
    usize::try_from(priority).map_or(true, |priority| priority >= NRQS)
}

/// Adds `delta` to `field`, which one writer updates at a time.
///
/// The writer is a run-queue `count`'s under its lock, or a processor's
/// quantum's on its own CPU. The single writer lets a plain load and store
/// stand in for a locked read-modify-write.
pub fn add_single_writer(field: &AtomicI32, delta: c_int) {
    field.store(
        field.load(Ordering::Relaxed).wrapping_add(delta),
        Ordering::Relaxed,
    );
}

/// The `sched_tick` counter: the seconds the priority scan has run.
static SCHED_TICK: AtomicU32 = AtomicU32::new(0);

/// The shortest quantum, in ticks.
static MIN_QUANTUM_TICKS: AtomicI32 = AtomicI32::new(0);

/// The `sched_tick` counter, as the C read it.
#[must_use]
pub fn sched_tick() -> c_uint {
    SCHED_TICK.load(Ordering::Relaxed)
}

/// Advances `sched_tick` by one, once a second.
pub fn advance_sched_tick() {
    SCHED_TICK.fetch_add(1, Ordering::Relaxed);
}

/// The `min_quantum` value, as the C read it.
#[must_use]
pub fn min_quantum() -> c_int {
    MIN_QUANTUM_TICKS.load(Ordering::Relaxed)
}

/// Sets the quantum and restarts `sched_tick`, at boot.
pub fn init() {
    MIN_QUANTUM_TICKS.store(CLOCK_HZ / 33, Ordering::Relaxed);
    SCHED_TICK.store(0, Ordering::Relaxed);
}
