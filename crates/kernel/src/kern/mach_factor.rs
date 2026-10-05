// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/mach_factor.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
// Derived from kern/mach_factor.h:
//   Copyright (C) 2006, 2007 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The Mach factor computation.

use crate::kern::processor;
use crate::kern::sched::{SCHED_SCALE, SCHED_SHIFT};
use core::ffi::c_long;
use core::ptr;
use core::sync::atomic::AtomicI64 as AtomicLong;
use core::sync::atomic::Ordering;

/// The fixed-point unit of the load averages and the mach factor.
const LOAD_SCALE: c_long = 1000;

/// The decay weights, `LOAD_SCALE`ths.
const FRACT: [c_long; 3] = [800, 966, 983];

/// The three load averages `host_info()` reports.
static AVENRUN: [AtomicLong; 3] = [const { AtomicLong::new(0) }; 3];

/// The three scaled factors `host_info()` reports.
static MACH_FACTOR: [AtomicLong; 3] = [const { AtomicLong::new(0) }; 3];

/// The `avenrun` counters, as `host_info()` reports them.
///
/// The `Relaxed` accesses match the C's plain reads and writes: the counters
/// are recomputed every scheduler tick and nothing synchronizes through
/// them.
pub(crate) fn avenrun() -> [c_long; 3] {
    AVENRUN
        .each_ref()
        .map(|value| value.load(Ordering::Relaxed))
}

/// The `mach_factor` counters, as `host_info()` reports them.
pub(crate) fn mach_factor() -> [c_long; 3] {
    MACH_FACTOR
        .each_ref()
        .map(|value| value.load(Ordering::Relaxed))
}

/// Updates the load averages and the mach factors from each processor set's
/// run queues.
pub(crate) fn compute() {
    let all_psets = processor::ALL_PSETS.lock();
    let mut cursor = all_psets.list().cursor_front();
    while let Some(pset) = cursor.current_ptr() {
        cursor.move_next();
        let pset = pset.as_ptr();
        // SAFETY: `pset` is a live set from the list, and its lock protects
        // every field the C read while holding it.
        unsafe {
            (*pset).lock.lock();

            let ncpus = (*pset).processor_count;
            if ncpus > 0 {
                let mut nthreads = (*pset).runq.count.load(Ordering::Relaxed);
                let mut pcursor = (*pset).processors.cursor_front();
                while let Some(processor) = pcursor.current_ptr() {
                    pcursor.move_next();
                    nthreads = nthreads.wrapping_add(
                        (*processor.as_ptr())
                            .runq
                            .count
                            .load(Ordering::Relaxed),
                    );
                }
                nthreads = nthreads
                    .wrapping_add(ncpus.wrapping_sub((*pset).idle_count));
                if ptr::eq(pset, processor::default_pset()) {
                    nthreads = nthreads.wrapping_sub(1);
                }

                let ncpus_long = c_long::from(ncpus);
                let nthreads_long = c_long::from(nthreads);
                let (factor_now, load_now) = if nthreads > ncpus {
                    (
                        ncpus_long.wrapping_mul(LOAD_SCALE)
                            / (nthreads_long.wrapping_add(1)),
                        (nthreads_long << SCHED_SHIFT) / ncpus_long,
                    )
                } else {
                    (
                        ncpus_long
                            .wrapping_sub(nthreads_long)
                            .wrapping_mul(LOAD_SCALE),
                        c_long::from(SCHED_SCALE),
                    )
                };
                let average_now = nthreads_long.wrapping_mul(LOAD_SCALE);

                (*pset).mach_factor =
                    ((*pset).mach_factor << 2).wrapping_add(factor_now) / 5;
                (*pset).load_average =
                    ((*pset).load_average << 2).wrapping_add(average_now) / 5;

                if ptr::eq(pset, processor::default_pset()) {
                    for (factor, fract) in MACH_FACTOR.iter().zip(FRACT.iter())
                    {
                        let value = factor
                            .load(Ordering::Relaxed)
                            .wrapping_mul(*fract)
                            .wrapping_add(factor_now.wrapping_mul(
                                LOAD_SCALE.wrapping_sub(*fract),
                            ))
                            / LOAD_SCALE;
                        factor.store(value, Ordering::Relaxed);
                    }
                    for (average, fract) in AVENRUN.iter().zip(FRACT.iter()) {
                        let value = average
                            .load(Ordering::Relaxed)
                            .wrapping_mul(*fract)
                            .wrapping_add(average_now.wrapping_mul(
                                LOAD_SCALE.wrapping_sub(*fract),
                            ))
                            / LOAD_SCALE;
                        average.store(value, Ordering::Relaxed);
                    }
                }

                (*pset).sched_load =
                    (*pset).sched_load.wrapping_add(load_now) >> 1;
            }

            (*pset).lock.unlock();
        }
    }
    drop(all_psets);
}
