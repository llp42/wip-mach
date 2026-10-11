// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `RunQueue`: the `NRQS` priority queues a processor or a processor set
//! dispatches from, holding scheduling records.

use crate::sched::{NRQS, add_single_writer};
use crate::sched_info::SchedInfo;
use collections::tail_queue::{self, TailQueue};
use core::ffi::{c_int, c_uint};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicI32, Ordering};
use mach_page::simple_lock::SimpleLock;

tail_queue::adapter!(
    /// The adapter for a record's `links` in a run queue.
    pub SchedLinksAdapter = SchedInfo { links }
);

/// One priority's queue of records.
pub type SchedQueue = TailQueue<'static, SchedLinksAdapter>;

/// The `NRQS` priority queues and their lock.
#[repr(C)]
pub struct RunQueue {
    /// `runq`: one queue per priority.
    pub runq: [SchedQueue; NRQS],
    /// `lock`: one lock for all the queues, taken at splsched.
    pub lock: SimpleLock,
    /// `low`: the lowest non-empty queue.
    pub low: c_int,
    /// `count`: the number of runnable records; written under `lock`, read
    /// without it as a hint.
    pub count: AtomicI32,
}

impl RunQueue {
    /// An empty run queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            runq: [const { SchedQueue::new() }; NRQS],
            lock: SimpleLock::new(),
            low: 0,
            count: AtomicI32::new(0),
        }
    }

    /// Empties the run queue at `runq` in place.
    ///
    /// # Safety
    ///
    /// `runq` must point at writable storage for a run queue no other CPU
    /// can reach yet.
    pub unsafe fn init(runq: *mut Self) {
        // SAFETY: the caller hands over unshared storage.
        unsafe {
            (*runq).lock.init();
            (*runq).low = 0;
            (*runq).count.store(0, Ordering::Relaxed);
            (*runq).runq = [const { SchedQueue::new() }; NRQS];
        }
    }
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Pins the queue at `q`, one priority of a run queue, for one operation.
///
/// # Safety
///
/// `q` must be a queue of a run queue, which never moves, and the caller must
/// hold the run queue's lock for as long as it uses the result.
pub const unsafe fn pin_queue<'a>(
    q: *mut SchedQueue,
) -> Pin<&'a mut SchedQueue> {
    // SAFETY: the queue never moves, and the lock the caller holds keeps
    // anything else from reaching it.
    unsafe { Pin::new_unchecked(&mut *q) }
}

/// The queue a record of priority `sched_pri` belongs in: priorities past
/// the last queue go to the last.
const fn queue_index(sched_pri: c_int) -> usize {
    // The C assigns the signed priority to an `unsigned int`, so a negative
    // value fails the bounds check and is clamped.
    let whichq = sched_pri as c_uint;
    if whichq >= NRQS as c_uint {
        NRQS - 1
    } else {
        whichq as usize
    }
}

/// Puts `si` on `rq` at its priority, returning whether the priority was
/// past the last queue and clamped.
///
/// # Safety
///
/// `rq` must be a live run queue and `si` the record of a locked thread, at
/// splsched; the caller may hold the thread lock but not the run queue's.
pub unsafe fn enqueue(rq: *mut RunQueue, si: *mut SchedInfo) -> bool {
    // SAFETY: the record is live, and the run-queue lock taken below guards
    // the queues.
    unsafe {
        let clamped = (*si).sched_pri as c_uint >= NRQS as c_uint;
        let whichq = queue_index((*si).sched_pri);

        (*rq).lock.lock();
        pin_queue(&raw mut (*rq).runq[whichq])
            .push_back_ptr(NonNull::new_unchecked(si));
        // `low` is a queue index in `0..NRQS`.
        if whichq < (*rq).low as usize
            || (*rq).count.load(Ordering::Relaxed) == 0
        {
            (*rq).low = whichq as c_int;
        }
        add_single_writer(&(*rq).count, 1);
        (*si).runq = rq;
        (*rq).lock.unlock();
        clamped
    }
}

/// Takes `si` off its run queue and returns that queue, or null when it was
/// not on one.
///
/// Every writer of `sched_pri` holds the thread lock and changes it while
/// the record is off every run queue, so its priority names the queue it
/// sits in.
///
/// # Safety
///
/// `si` must be the record of a live thread whose lock the caller holds.
pub unsafe fn remove(si: *mut SchedInfo) -> *mut RunQueue {
    // SAFETY: the record is live, and the run-queue lock guards the queues.
    unsafe {
        let mut rq = (*si).runq;
        if !rq.is_null() {
            (*rq).lock.lock();
            if rq == (*si).runq {
                pin_queue(&raw mut (*rq).runq[queue_index((*si).sched_pri)])
                    .remove_ptr(NonNull::new_unchecked(si));
                add_single_writer(&(*rq).count, -1);
                (*si).runq = ptr::null_mut();
                (*rq).lock.unlock();
            } else {
                // The record left the queue before the lock; the caller's
                // thread lock keeps it from moving again.
                (*rq).lock.unlock();
                rq = ptr::null_mut();
            }
        }
        rq
    }
}

/// Takes the first record of the highest-priority non-empty queue off `rq`,
/// or returns null when `rq` is empty.
///
/// # Panics
///
/// If the run queue counts records that none of its queues holds.
///
/// # Safety
///
/// `rq` must be a live run queue, at splsched, whose lock the caller does not
/// hold.
pub unsafe fn dequeue(rq: *mut RunQueue) -> *mut SchedInfo {
    // SAFETY: the run-queue lock taken here guards the queues and counts.
    unsafe {
        (*rq).lock.lock();
        if (*rq).count.load(Ordering::Relaxed) > 0 {
            let mut i = (*rq).low;
            while i < NRQS as c_int {
                let q = &raw mut (*rq).runq[i as usize];
                if !(*q).is_empty() {
                    let si = pin_queue(q)
                        .cursor_front_mut()
                        .remove_current()
                        .map_or(ptr::null_mut(), ptr::from_mut);
                    (*si).runq = ptr::null_mut();
                    add_single_writer(&(*rq).count, -1);
                    (*rq).low = i;
                    (*rq).lock.unlock();
                    return si;
                }
                i += 1;
            }
            panic!("choose_thread")
        }
        (*rq).lock.unlock();
        ptr::null_mut()
    }
}
