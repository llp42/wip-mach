// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Scheme 6 of Varghese and Lauck, "Hashed and Hierarchical Timing
//! Wheels" (SOSP 1987): a power-of-two hash of unsorted lists, one list
//! per bucket.
//!
//! Each record stores the absolute tick it expires on.  A visit to its
//! bucket runs it on that tick and passes over it on the revolutions
//! before.  Records live inside [`Callout`]s, the wheel's only
//! interface for arming: it links and unlinks them without allocating.
//!
//! A wheel keeps its buckets behind its own irq spin lock, so any CPU
//! may arm or cancel on it, and the clock interrupt may [`poll`] it.
//! [`advance`] runs the expiry actions with the lock released, so an
//! action may re-arm its record.  Where wheels live — one per CPU, per
//! subsystem, or one for the machine — is the caller's choice.
//!
//! [`Callout`]: crate::Callout
//! [`poll`]: HashedWheel::poll
//! [`advance`]: HashedWheel::advance

use crate::platform::Locking;
use crate::types::Ticks;
use collections::list::{self, List};
use core::cell::Cell;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};
use lock::irq_spin_lock;
use lock::{IrqSpinLock, MutexGuard};

/// The number of bucket-index bits; the paper recommends a power of two
/// so the index is a mask.
pub const TABLE_BITS: u32 = 8;

/// The number of buckets, `2^TABLE_BITS`: 2.56 s of ticks at 100 Hz.
pub const TABLE_SIZE: usize = 1 << TABLE_BITS;

/// The bucket-index mask.
const TABLE_MASK: u64 = (TABLE_SIZE as u64) - 1;

/// The bins of [`Stats::intervals`].
#[cfg(debug_assertions)]
pub const INTERVAL_BINS: usize = 16;

/// A source of whole ticks for a [`HashedWheel`].
///
/// The kernel's machine clock implements this; a wheel never advances
/// time itself.
pub trait TickSource {
    /// The current tick count.
    fn now(&self) -> Ticks;
}

impl<T: TickSource + ?Sized> TickSource for &T {
    fn now(&self) -> Ticks {
        (**self).now()
    }
}

/// The expiry action of a [`Record`].
///
/// It must not block: a canceller spins until it returns, and the kernel
/// is non-preemptible, so nothing takes the CPU from the spinner and an
/// action that blocked may never get a CPU back to return on.
///
/// # Safety
///
/// The action runs from [`HashedWheel::advance`], in whatever context its
/// caller runs, with the wheel unlocked; it must accept the context
/// registered with it.  It may start or stop any record on the same
/// wheel, its own included; an `advance` it calls returns `false`.
pub(crate) type ExpiryAction = unsafe fn(*mut ());

/// The action of a record that was never armed; never run.
///
/// # Safety
///
/// `ctx` is ignored, so any value is accepted; the action never runs.
const unsafe fn no_action(_ctx: *mut ()) {}

/// Where a record is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// On no wheel; its owner may reuse or free it.
    Idle,
    /// Linked into the bucket of its expiry tick.
    Armed,
    /// Taken off its bucket by a running `advance`, its action not yet
    /// started; still preventable.
    Due,
    /// Its action has started; on no list, but `advance` reads it once
    /// more when the action returns.
    Running,
    /// Its action has started and has since armed it again: linked like
    /// `Armed`, and still read by `advance` when the action returns.
    RunningArmed,
}

/// One timer record.
///
/// Its owner embeds it; a wheel only links it.  Every field is written
/// under the lock of the wheel the record is on, so the record is
/// reached only through that wheel's methods.
pub(crate) struct Record {
    link: list::Link,
    /// The tick the record expires on.
    expires: Cell<u64>,
    action: Cell<ExpiryAction>,
    /// Atomic only so the record is `Send`; the lock orders it like
    /// the cells.
    ctx: AtomicPtr<()>,
    state: Cell<State>,
    /// A linked record is reached through its address, so neither it
    /// nor anything embedding it may be `Unpin`.
    _pinned: PhantomPinned,
}

// SAFETY: a record's cells are read and written only under the lock of
// the wheel it is on, through that wheel's methods, so references to it
// on several CPUs never race.
unsafe impl Sync for Record {}

impl Record {
    /// A record on no wheel.
    pub(crate) const fn idle() -> Self {
        Self {
            link: list::Link::new(),
            expires: Cell::new(0),
            action: Cell::new(no_action),
            ctx: AtomicPtr::new(core::ptr::null_mut()),
            state: Cell::new(State::Idle),
            _pinned: PhantomPinned,
        }
    }
}

list::adapter!(RecordAdapter = Record { link });

/// One bucket, or the list of records due on the tick being visited.
type Bucket = List<'static, RecordAdapter>;

/// The bucket a tick lands in.
fn bucket_index(tick: u64) -> usize {
    usize::try_from(tick & TABLE_MASK).unwrap_or(0)
}

/// Debug-build counters of a [`HashedWheel`], for sizing it against a real
/// workload.
#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stats {
    /// The records armed now, due ones included.
    pub armed: usize,
    /// The most records armed at once.
    pub peak: usize,
    /// Arms by interval: bin `i` counts intervals of `2^i` to
    /// `2^(i+1) - 1` ticks, and the last bin every longer one.
    pub intervals: [u64; INTERVAL_BINS],
}

#[cfg(debug_assertions)]
impl Stats {
    const fn new() -> Self {
        Self {
            armed: 0,
            peak: 0,
            intervals: [0; INTERVAL_BINS],
        }
    }

    fn armed(&mut self, ticks: u64) {
        self.armed += 1;
        self.peak = self.peak.max(self.armed);
        let bin = usize::try_from(ticks.ilog2()).unwrap_or(usize::MAX);
        self.intervals[bin.min(INTERVAL_BINS - 1)] += 1;
    }

    const fn disarmed(&mut self) {
        self.armed -= 1;
    }
}

/// The state a wheel's lock guards.
struct Inner {
    buckets: [Bucket; TABLE_SIZE],
    /// The records due on the tick the running `advance` visits.
    due: Bucket,
    /// The last tick the wheel visited.
    cursor: u64,
    /// Whether an `advance` is running actions.
    advancing: bool,
    #[cfg(debug_assertions)]
    stats: Stats,
}

impl Inner {
    /// Unlinks `r` if it is on a list, returning whether it was.  A
    /// record whose action is running stays running.
    ///
    /// # Safety
    ///
    /// `r` must point at a live record that is idle or on this wheel.
    // Only debug builds count arms.
    #[cfg_attr(not(debug_assertions), allow(clippy::unused_self))]
    unsafe fn unlink(&mut self, r: NonNull<Record>) -> bool {
        let record = unsafe { r.as_ref() };
        let unlinked = match record.state.get() {
            State::Armed | State::Due => State::Idle,
            State::RunningArmed => State::Running,
            State::Idle | State::Running => return false,
        };
        // Both lists are this wheel's, and removal needs no head.
        unsafe { Bucket::remove_ptr(r) };
        record.state.set(unlinked);
        #[cfg(debug_assertions)]
        self.stats.disarmed();
        true
    }

    /// Moves the records of `tick`'s bucket that expire on `tick` to the
    /// due list, in the order they were armed.
    ///
    /// # Panics
    ///
    /// Halts if a record the cursor rests on cannot be unlinked, which
    /// the list guarantees it can.
    ///
    /// # Safety
    ///
    /// `self` must be inside a pinned wheel.
    unsafe fn collect(&mut self, tick: u64) {
        let Self { buckets, due, .. } = self;
        let bucket = &mut buckets[bucket_index(tick)];
        // SAFETY: the caller's wheel is pinned, and the lists never move
        // out of it.
        let (bucket, mut due) =
            unsafe { (Pin::new_unchecked(bucket), Pin::new_unchecked(due)) };
        let mut cursor = bucket.cursor_front_mut();
        while let Some(record) = cursor.current() {
            if record.expires.get() != tick {
                cursor.move_next();
                continue;
            }
            let record = cursor
                .remove_current()
                .expect("the cursor rests on the record it just read");
            record.state.set(State::Due);
            // Buckets push at the front, so pushing at the front again
            // restores the arming order.
            due.as_mut().push_front(record);
        }
    }

    /// Takes the first due record and marks it running.
    ///
    /// # Safety
    ///
    /// `self` must be inside a pinned wheel.
    unsafe fn pop_due(&mut self) -> Option<NonNull<Record>> {
        // SAFETY: the caller's wheel is pinned, and the list never moves
        // out of it.
        let due = unsafe { Pin::new_unchecked(&mut self.due) };
        let record = due.cursor_front_mut().remove_current()?;
        record.state.set(State::Running);
        #[cfg(debug_assertions)]
        self.stats.disarmed();
        Some(NonNull::from(record))
    }
}

/// The hashed timing wheel.
///
/// A wheel is `!Unpin`: its buckets point back into it, so it mutates
/// through `Pin<&Self>`.  A `static` wheel is pinned with
/// [`Pin::static_ref`].
pub struct HashedWheel<P: TickSource + Locking> {
    platform: P,
    state: IrqSpinLock<Inner, P::Lock>,
}

impl<P: TickSource + Locking> HashedWheel<P> {
    /// A wheel whose cursor starts at tick `now`, reading time through
    /// `platform`.
    ///
    /// `now` should be the source's tick when the wheel is first used;
    /// a wheel that starts behind visits every tick it missed.  Each
    /// call site builds a lock name of its own.
    #[track_caller]
    pub const fn new(platform: P, now: Ticks) -> Self {
        Self {
            platform,
            state: irq_spin_lock!(
                "clock wheel",
                Inner {
                    buckets: [const { List::new() }; TABLE_SIZE],
                    due: List::new(),
                    cursor: now.get(),
                    advancing: false,
                    #[cfg(debug_assertions)]
                    stats: Stats::new(),
                }
            ),
        }
    }

    /// The last tick the wheel visited.
    pub fn cursor(&self) -> Ticks {
        Ticks::new(self.state.lock().cursor)
    }

    /// Whether the source has moved past the wheel's cursor.
    pub fn behind(&self) -> bool {
        let now = self.platform.now().get();
        self.cursor().get() < now
    }

    /// Moves the cursor over the ticks up to the source's on which
    /// nothing expires, returning whether a tick with work is next.
    ///
    /// Cheap enough for the clock interrupt: when it returns `true`, the
    /// caller runs [`advance`](Self::advance) in a deferred context.
    pub fn poll(&self) -> bool {
        let mut inner = self.state.lock();
        let now = self.platform.now().get();
        let mut work = false;
        while inner.cursor < now {
            let next = inner.cursor.wrapping_add(1);
            if inner.buckets[bucket_index(next)]
                .iter()
                .any(|record| record.expires.get() == next)
            {
                work = true;
                break;
            }
            inner.cursor = next;
        }
        drop(inner);
        work
    }

    /// Arms `r` for `interval` ticks from the source's current tick,
    /// running `action` with `ctx` when it expires; re-arms it if it is
    /// armed.
    ///
    /// A zero interval is one tick.  A record armed while its action
    /// runs is linked at once, and is not idle until that action has
    /// returned.
    ///
    /// # Safety
    ///
    /// `r` must point at a live [`Record`] that is idle or on this wheel.
    /// It must stay live, at its address, and reached only through this
    /// wheel until [`is_idle`](Self::is_idle) says it is idle again.
    /// `action` and `ctx` must keep the [`ExpiryAction`] contract.
    pub(crate) unsafe fn start(
        self: Pin<&Self>,
        r: NonNull<Record>,
        interval: Ticks,
        action: ExpiryAction,
        ctx: *mut (),
    ) {
        let mut inner = self.state.lock();
        // Read under the lock, so a caller delayed before it, by an
        // interrupt or by spinning for the lock, cannot arm from a stale
        // tick.
        let now = self.platform.now().get();
        let _ = unsafe { inner.unlink(r) };
        let ticks = interval.get().max(1);
        let expires = now.max(inner.cursor).saturating_add(ticks);
        let record = unsafe { r.as_ref() };
        record.expires.set(expires);
        record.action.set(action);
        record.ctx.store(ctx, Ordering::Relaxed);
        record.state.set(if record.state.get() == State::Running {
            State::RunningArmed
        } else {
            State::Armed
        });
        // SAFETY: the wheel is pinned, and the lists never move out of
        // it.
        let bucket = unsafe {
            Pin::new_unchecked(&mut inner.buckets[bucket_index(expires)])
        };
        // SAFETY: the caller keeps the record live and in place until it
        // leaves the wheel.
        unsafe { bucket.push_front_ptr(r) };
        #[cfg(debug_assertions)]
        inner.stats.armed(ticks);
    }

    /// Disarms `r`, returning whether that prevented a pending expiry.
    ///
    /// An action of `r` that is already running keeps running; `r` is
    /// not idle until it returns.
    ///
    /// # Safety
    ///
    /// `r` must point at a live [`Record`] that is idle or on this wheel.
    #[must_use]
    pub(crate) unsafe fn stop(self: Pin<&Self>, r: NonNull<Record>) -> bool {
        unsafe { self.state.lock().unlink(r) }
    }

    /// Whether `r` is idle: on no list, and no action of it running.
    ///
    /// # Safety
    ///
    /// `r` must point at a live [`Record`] that is idle or on this wheel.
    pub(crate) unsafe fn is_idle(&self, r: NonNull<Record>) -> bool {
        let _inner = self.state.lock();
        unsafe { r.as_ref() }.state.get() == State::Idle
    }

    /// Visits the next tick's bucket and runs the actions of the records
    /// that expire on it, returning whether it visited a tick.
    ///
    /// `false` means the wheel has caught up with its source, or another
    /// `advance` of it is running; loop while it returns `true` to catch
    /// up after missed ticks.  The actions run with the lock released,
    /// in the order their records were armed.
    #[must_use]
    pub fn advance(self: Pin<&Self>) -> bool {
        let mut inner = self.state.lock();
        let now = self.platform.now().get();
        if inner.advancing || inner.cursor >= now {
            return false;
        }
        inner.cursor = inner.cursor.wrapping_add(1);
        inner.advancing = true;
        let tick = inner.cursor;
        // SAFETY: the wheel is pinned.
        unsafe { inner.collect(tick) };

        // One lock per record: it settles the record whose action just
        // returned and takes the next.
        loop {
            // SAFETY: the wheel is pinned.
            let Some(r) = (unsafe { inner.pop_due() }) else {
                inner.advancing = false;
                drop(inner);
                return true;
            };
            // SAFETY: a record stays live until it is idle, and it is not
            // idle until its action has returned and it is settled below.
            let record = unsafe { r.as_ref() };
            let (action, ctx) =
                (record.action.get(), record.ctx.load(Ordering::Relaxed));

            // SAFETY: `start`'s caller registered a pair that keeps the
            // action's contract.
            MutexGuard::unlocked(&mut inner, || unsafe { action(ctx) });

            // Only the action's record may have run it, and `stop` and
            // `start` keep a running record running.
            record
                .state
                .set(if record.state.get() == State::RunningArmed {
                    State::Armed
                } else {
                    State::Idle
                });
        }
    }

    /// The wheel's debug counters.
    #[cfg(debug_assertions)]
    pub fn stats(&self) -> Stats {
        self.state.lock().stats
    }
}
