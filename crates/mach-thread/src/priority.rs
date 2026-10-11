// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The quantum recalculation.

use crate::ast;
use crate::platform::Platform;
use crate::sched_prim::{compute_my_priority, update_priority};
use crate::thread::Thread;
use core::ffi::{c_int, c_uint};
use core::sync::atomic::Ordering;
use mach_sched::policy::POLICY_TIMESHARE;
use mach_sched::sched::{PRI_SHIFT, SCHED_SHIFT, add_single_writer};
use mach_sched::sched::{min_quantum, sched_tick};

/// The `cpu_ticks` index of an idle tick, one of the states the clock
/// interrupt charges.
pub const CPU_STATE_IDLE: c_int = 2;

/// The change that moves a thread between run queues.
const USAGE_THRESHOLD: c_uint = 1 << (PRI_SHIFT + 2 + SCHED_SHIFT);

/// Charges `nticks` to `thread`'s quantum and usage, and requests a reschedule
/// when the quantum runs out.
///
/// # Safety
///
/// `thread` must be the running CPU's live interrupted thread or the thread
/// the clock charged, and the caller must hold no lock the thread
/// or processor-set lock would nest under.
pub unsafe fn thread_quantum_update<P: Platform>(
    thread: *mut Thread<P>,
    nticks: c_int,
    state: c_int,
) {
    let myprocessor = P::cpu_processor().as_ptr();
    // SAFETY: the processor record is live; its set is null only while the
    // assignment code is moving it.
    let pset = unsafe { (*myprocessor).processor_set.load(Ordering::Acquire) };
    if pset.is_null() {
        return;
    }

    // SAFETY: the set is live; both counts are non-negative and
    // `processor_count` is at most `MAX_NCPUS`, so the index is inside
    // `machine_quantum`.  The fallback is the value the array itself starts
    // at, so a corrupt count cannot read foreign state.
    unsafe {
        (*pset).set_quantum = usize::try_from(
            if (*pset).runq.count.load(Ordering::Relaxed)
                > (*pset).processor_count
            {
                (*pset).processor_count
            } else {
                (*pset).runq.count.load(Ordering::Relaxed)
            },
        )
        .ok()
        .and_then(|index| (*pset).machine_quantum.get(index))
        .copied()
        .unwrap_or_else(min_quantum);

        let mut quantum =
            if (*myprocessor).runq.count.load(Ordering::Relaxed) != 0 {
                min_quantum()
            } else {
                (*pset).set_quantum
            };

        if state != CPU_STATE_IDLE {
            let myquantum = &(*myprocessor).quantum;
            add_single_writer(myquantum, nticks.wrapping_neg());

            if quantum != (*myprocessor).last_quantum.load(Ordering::Relaxed)
                && (*pset).processor_count > 1
            {
                (*myprocessor)
                    .last_quantum
                    .store(quantum, Ordering::Relaxed);
                let level = P::splhigh();
                (*pset).quantum_adj_lock.lock();
                let index = (*pset).quantum_adj_index;
                quantum = min_quantum().wrapping_add(
                    index.wrapping_mul(quantum.wrapping_sub(min_quantum()))
                        / (*pset).processor_count.wrapping_sub(1),
                );
                let next = index.wrapping_add(1);
                (*pset).quantum_adj_index = if next >= (*pset).processor_count
                {
                    0
                } else {
                    next
                };
                (*pset).quantum_adj_lock.unlock();
                P::splx(level);
            }

            let level = P::splsched();
            (*thread).lock.lock();
            if (*myprocessor).quantum.load(Ordering::Relaxed) <= 0 {
                if (*thread).sched.sched_stamp != sched_tick() {
                    update_priority(thread);
                } else if (*thread).sched.policy == POLICY_TIMESHARE
                    && (*thread).sched.depress_priority < 0
                {
                    Thread::<P>::timer_delta(thread);
                    (*thread).sched.sched_usage = (*thread)
                        .sched
                        .sched_usage
                        .wrapping_add((*thread).sched.sched_delta);
                    (*thread).sched.sched_delta = 0;
                    compute_my_priority(thread);
                }
                (*thread).lock.unlock();
                P::splx(level);

                (*myprocessor).first_quantum.store(0, Ordering::Relaxed);
                if (*thread).sched.policy == POLICY_TIMESHARE {
                    add_single_writer(myquantum, quantum);
                } else {
                    add_single_writer(myquantum, (*thread).sched.sched_data);
                }
            } else {
                if (*thread).sched.sched_stamp != sched_tick() {
                    update_priority(thread);
                } else if (*thread).sched.policy == POLICY_TIMESHARE
                    && (*thread).sched.depress_priority < 0
                {
                    Thread::<P>::timer_delta(thread);
                    if (*thread).sched.sched_delta >= USAGE_THRESHOLD {
                        (*thread).sched.sched_usage = (*thread)
                            .sched
                            .sched_usage
                            .wrapping_add((*thread).sched.sched_delta);
                        (*thread).sched.sched_delta = 0;
                        compute_my_priority(thread);
                    }
                }
                (*thread).lock.unlock();
                P::splx(level);
            }

            ast::check::<P>();
        }
    }
}
