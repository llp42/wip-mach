// SPDX-License-Identifier: MIT
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
//! A wheel keeps its buckets behind its own lock — the platform's
//! [`Critical`] section, then a spin lock — so any CPU may arm or
//! cancel on it, and the clock interrupt may [`poll`] it.
//! [`advance`] runs the expiry actions with the lock released, so an
//! action may re-arm its record.  Where wheels live — one per CPU, per
//! subsystem, or one for the machine — is the caller's choice.
//!
//! [`Callout`]: crate::Callout
//! [`poll`]: HashedWheel::poll
//! [`advance`]: HashedWheel::advance

use crate::critical::CriticalLock;
use crate::platform::Critical;
use crate::types::Ticks;
use collections::list::{self, List};
use core::cell::Cell;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

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
pub struct HashedWheel<P: TickSource + Critical> {
    platform: P,
    state: CriticalLock<Inner>,
}

impl<P: TickSource + Critical> HashedWheel<P> {
    /// A wheel whose cursor starts at tick `now`, reading time and
    /// entering critical sections through `platform`.
    ///
    /// `now` should be the source's tick when the wheel is first used;
    /// a wheel that starts behind visits every tick it missed.
    pub const fn new(platform: P, now: Ticks) -> Self {
        Self {
            platform,
            state: CriticalLock::new(Inner {
                buckets: [const { List::new() }; TABLE_SIZE],
                due: List::new(),
                cursor: now.get(),
                advancing: false,
                #[cfg(debug_assertions)]
                stats: Stats::new(),
            }),
        }
    }

    /// The last tick the wheel visited.
    pub fn cursor(&self) -> Ticks {
        let (critical, inner) = self.state.lock(&self.platform);
        let cursor = inner.cursor;
        drop(inner);
        drop(critical);
        Ticks::new(cursor)
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
        let (critical, mut inner) = self.state.lock(&self.platform);
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
        drop(critical);
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
        let (critical, mut inner) = self.state.lock(&self.platform);
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
        drop(inner);
        drop(critical);
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
        let (critical, mut inner) = self.state.lock(&self.platform);
        let prevented = unsafe { inner.unlink(r) };
        drop(inner);
        drop(critical);
        prevented
    }

    /// Whether `r` is idle: on no list, and no action of it running.
    ///
    /// # Safety
    ///
    /// `r` must point at a live [`Record`] that is idle or on this wheel.
    pub(crate) unsafe fn is_idle(&self, r: NonNull<Record>) -> bool {
        let (critical, inner) = self.state.lock(&self.platform);
        let idle = unsafe { r.as_ref() }.state.get() == State::Idle;
        drop(inner);
        drop(critical);
        idle
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
        let (mut critical, mut inner) = self.state.lock(&self.platform);
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
                return true;
            };
            // SAFETY: a record stays live until it is idle, and it is not
            // idle until its action has returned and it is settled below.
            let record = unsafe { r.as_ref() };
            let (action, ctx) =
                (record.action.get(), record.ctx.load(Ordering::Relaxed));
            drop(inner);
            drop(critical);

            // SAFETY: `start`'s caller registered a pair that keeps the
            // action's contract.
            unsafe { action(ctx) };

            (critical, inner) = self.state.lock(&self.platform);
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
        let (critical, inner) = self.state.lock(&self.platform);
        let stats = inner.stats;
        drop(inner);
        drop(critical);
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::NoCritical;
    use core::sync::atomic::AtomicU64;

    /// A tick source the tests drive by hand.
    struct Source(AtomicU64);

    impl Source {
        const fn new(ticks: u64) -> Self {
            Self(AtomicU64::new(ticks))
        }

        fn bump(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl TickSource for Source {
        fn now(&self) -> Ticks {
            Ticks::new(self.0.load(Ordering::Relaxed))
        }
    }

    impl Critical for Source {
        type Guard = NoCritical;

        fn enter_critical(&self) -> NoCritical {
            NoCritical
        }
    }

    type TestHashedWheel<'s> = Pin<Box<HashedWheel<&'s Source>>>;

    /// A wheel on `source`, starting at its tick.
    fn hashed_wheel(source: &Source) -> TestHashedWheel<'_> {
        Box::pin(HashedWheel::new(source, source.now()))
    }

    /// A leaked record, stable for the whole test.
    fn leaked() -> NonNull<Record> {
        NonNull::from(Box::leak(Box::new(Record::idle())))
    }

    /// Counts its runs in the `AtomicU64` it is registered with.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `AtomicU64`.
    unsafe fn count(ctx: *mut ()) {
        unsafe { (*ctx.cast::<AtomicU64>()).fetch_add(1, Ordering::Relaxed) };
    }

    /// A leaked counter as an action context.
    fn counter() -> (&'static AtomicU64, *mut ()) {
        let counter: &'static AtomicU64 =
            Box::leak(Box::new(AtomicU64::new(0)));
        (counter, core::ptr::from_ref(counter).cast_mut().cast())
    }

    /// Arms `r` on `wheel` to count into `ctx`.
    fn arm(
        wheel: &TestHashedWheel<'_>,
        r: NonNull<Record>,
        ticks: u64,
        ctx: *mut (),
    ) {
        // SAFETY: the record and counter are leaked.
        unsafe { wheel.as_ref().start(r, Ticks::new(ticks), count, ctx) };
    }

    /// Bumps the source once and advances until caught up.
    fn tick(wheel: &TestHashedWheel<'_>, source: &Source) {
        source.bump();
        while wheel.as_ref().advance() {}
    }

    #[test]
    fn new_starts_at_the_given_tick() {
        let source = Source::new(42);
        let wheel = hashed_wheel(&source);
        assert_eq!(wheel.cursor(), Ticks::new(42));
        assert!(!wheel.behind());
        source.bump();
        assert!(wheel.behind());
    }

    #[test]
    fn the_idle_action_does_nothing() {
        // SAFETY: the idle action ignores its context.
        unsafe { no_action(core::ptr::null_mut()) };
    }

    #[test]
    fn a_zero_interval_fires_on_the_next_tick() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let (fired, ctx) = counter();
        let r = leaked();
        arm(&wheel, r, 0, ctx);
        // SAFETY: the record is leaked.
        assert!(!unsafe { wheel.is_idle(r) });
        tick(&wheel, &source);
        assert_eq!(fired.load(Ordering::Relaxed), 1);
        // SAFETY: the record is leaked.
        assert!(unsafe { wheel.is_idle(r) });
    }

    #[test]
    fn intervals_fire_on_their_exact_tick() {
        for interval in [1u64, 2, 255, 256, 257, 511, 512, 513, 1000] {
            let source = Source::new(0);
            let wheel = hashed_wheel(&source);
            let (fired, ctx) = counter();
            arm(&wheel, leaked(), interval, ctx);
            for _ in 1..interval {
                tick(&wheel, &source);
            }
            assert_eq!(fired.load(Ordering::Relaxed), 0, "early: {interval}");
            tick(&wheel, &source);
            assert_eq!(fired.load(Ordering::Relaxed), 1, "late: {interval}");
        }
    }

    #[test]
    fn stop_prevents_and_reports() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let (fired, ctx) = counter();
        let r = leaked();
        arm(&wheel, r, 2, ctx);
        // SAFETY: the record is leaked.
        assert!(unsafe { wheel.as_ref().stop(r) });
        // SAFETY: the record is leaked and idle.
        assert!(!unsafe { wheel.as_ref().stop(r) });
        for _ in 0..4 {
            tick(&wheel, &source);
        }
        assert_eq!(fired.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn restart_replaces_the_deadline() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let (fired, ctx) = counter();
        let r = leaked();
        arm(&wheel, r, 1000, ctx);
        arm(&wheel, r, 1, ctx);
        tick(&wheel, &source);
        assert_eq!(fired.load(Ordering::Relaxed), 1);
        for _ in 0..1000 {
            tick(&wheel, &source);
        }
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_lagging_wheel_arms_from_the_source_tick() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let (fired, ctx) = counter();
        for _ in 0..5 {
            source.bump();
        }
        arm(&wheel, leaked(), 1, ctx);
        for _ in 0..5 {
            assert!(wheel.as_ref().advance());
        }
        assert_eq!(fired.load(Ordering::Relaxed), 0);
        tick(&wheel, &source);
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn advance_without_a_tick_does_nothing() {
        let source = Source::new(5);
        let wheel = hashed_wheel(&source);
        assert!(!wheel.as_ref().advance());
        assert_eq!(wheel.cursor(), Ticks::new(5));
    }

    #[test]
    fn empty_ticks_still_move_the_cursor() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        for _ in 0..1000 {
            tick(&wheel, &source);
        }
        assert_eq!(wheel.cursor(), Ticks::new(1000));
    }

    /// A log of which records ran, in order.
    struct Log {
        ran: std::sync::Mutex<Vec<usize>>,
    }

    /// One record's entry in a [`Log`].
    struct Entry {
        log: &'static Log,
        id: usize,
    }

    /// Appends its entry's id to the log.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `Entry`.
    unsafe fn log(ctx: *mut ()) {
        let entry = unsafe { &*ctx.cast::<Entry>() };
        entry.log.ran.lock().unwrap().push(entry.id);
    }

    #[test]
    fn records_due_on_one_tick_run_in_arming_order() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let log: &'static Log = Box::leak(Box::new(Log {
            ran: std::sync::Mutex::new(Vec::new()),
        }));
        // Id 3 is due a revolution later, so the visit skips it.
        for (id, ticks) in [(0, 3u64), (1, 3), (2, 3), (3, 259)] {
            let entry = Box::leak(Box::new(Entry { log, id }));
            // SAFETY: the record and entry are leaked.
            unsafe {
                wheel.as_ref().start(
                    leaked(),
                    Ticks::new(ticks),
                    self::log,
                    core::ptr::from_mut(entry).cast(),
                );
            }
        }
        for _ in 0..3 {
            tick(&wheel, &source);
        }
        assert_eq!(*log.ran.lock().unwrap(), [0, 1, 2]);
        for _ in 3..259 {
            tick(&wheel, &source);
        }
        assert_eq!(*log.ran.lock().unwrap(), [0, 1, 2, 3]);
    }

    /// What a re-entrant test action works on.
    struct Probe {
        wheel: *const HashedWheel<&'static Source>,
        own: NonNull<Record>,
        other: NonNull<Record>,
        runs: AtomicU64,
        results: std::sync::Mutex<Vec<bool>>,
    }

    impl Probe {
        fn leaked(wheel: &TestHashedWheel<'static>) -> &'static Self {
            Box::leak(Box::new(Self {
                wheel: core::ptr::from_ref(wheel.as_ref().get_ref()),
                own: leaked(),
                other: leaked(),
                runs: AtomicU64::new(0),
                results: std::sync::Mutex::new(Vec::new()),
            }))
        }

        fn ctx(&'static self) -> *mut () {
            core::ptr::from_ref(self).cast_mut().cast()
        }

        fn hashed_wheel(&self) -> Pin<&HashedWheel<&'static Source>> {
            // SAFETY: the tests leak the boxed, pinned wheel.
            unsafe { Pin::new_unchecked(&*self.wheel) }
        }

        fn record(&self, result: bool) {
            self.results.lock().unwrap().push(result);
        }
    }

    /// The probe's context as a probe.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `Probe`.
    unsafe fn probe<'a>(ctx: *mut ()) -> &'a Probe {
        unsafe { &*ctx.cast::<Probe>() }
    }

    /// Re-arms its own record for one more tick, twice.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `Probe` whose wheel is live.
    unsafe fn rearm(ctx: *mut ()) {
        let probe = unsafe { probe(ctx) };
        if probe.runs.fetch_add(1, Ordering::Relaxed) < 2 {
            // SAFETY: the probe's record is leaked.
            unsafe {
                probe.hashed_wheel().start(
                    probe.own,
                    Ticks::new(1),
                    rearm,
                    ctx,
                );
            };
        }
    }

    /// Stops its own running record and the probe's other one.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `Probe` whose wheel is live.
    unsafe fn stop_both(ctx: *mut ()) {
        let probe = unsafe { probe(ctx) };
        probe.runs.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the probe's records are leaked.
        unsafe {
            probe.record(probe.hashed_wheel().stop(probe.own));
            probe.record(probe.hashed_wheel().stop(probe.other));
            probe.record(probe.hashed_wheel().is_idle(probe.own));
        }
    }

    /// Re-arms its own running record, then stops it again.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `Probe` whose wheel is live.
    unsafe fn rearm_and_stop(ctx: *mut ()) {
        let probe = unsafe { probe(ctx) };
        probe.runs.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the probe's record is leaked.
        unsafe {
            probe.hashed_wheel().start(
                probe.own,
                Ticks::new(1),
                rearm_and_stop,
                ctx,
            );
            probe.record(probe.hashed_wheel().is_idle(probe.own));
            probe.record(probe.hashed_wheel().stop(probe.own));
            probe.record(probe.hashed_wheel().is_idle(probe.own));
        }
    }

    /// Calls `advance` from inside an action.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live `Probe` whose wheel is live.
    unsafe fn nested(ctx: *mut ()) {
        let probe = unsafe { probe(ctx) };
        probe.record(probe.hashed_wheel().advance());
    }

    /// A wheel leaked for the re-entrant tests, and its source.
    fn leaked_hashed_wheel()
    -> (&'static Source, &'static TestHashedWheel<'static>) {
        let source: &'static Source = Box::leak(Box::new(Source::new(0)));
        (source, Box::leak(Box::new(hashed_wheel(source))))
    }

    #[test]
    fn an_action_may_rearm_its_record() {
        let (source, wheel) = leaked_hashed_wheel();
        let probe = Probe::leaked(wheel);
        // SAFETY: the record and probe are leaked.
        unsafe {
            wheel
                .as_ref()
                .start(probe.own, Ticks::new(1), rearm, probe.ctx());
        };
        for _ in 0..5 {
            tick(wheel, source);
        }
        assert_eq!(probe.runs.load(Ordering::Relaxed), 3);
        // SAFETY: the record is leaked.
        assert!(unsafe { wheel.is_idle(probe.own) });
    }

    #[test]
    fn an_action_may_stop_a_due_record_but_not_itself() {
        let (source, wheel) = leaked_hashed_wheel();
        let probe = Probe::leaked(wheel);
        let (fired, ctx) = counter();
        // SAFETY: the records, probe and counter are leaked.
        unsafe {
            wheel.as_ref().start(
                probe.own,
                Ticks::new(1),
                stop_both,
                probe.ctx(),
            );
            wheel.as_ref().start(probe.other, Ticks::new(1), count, ctx);
        }
        tick(wheel, source);
        assert_eq!(probe.runs.load(Ordering::Relaxed), 1);
        assert_eq!(fired.load(Ordering::Relaxed), 0);
        // Its own stop comes too late; the other's is prevented; it is
        // still running.
        assert_eq!(*probe.results.lock().unwrap(), [false, true, false]);
        // SAFETY: the records are leaked.
        unsafe {
            assert!(wheel.is_idle(probe.own));
            assert!(wheel.is_idle(probe.other));
        }
    }

    #[test]
    fn a_rearmed_running_record_is_busy_until_its_action_returns() {
        let (source, wheel) = leaked_hashed_wheel();
        let probe = Probe::leaked(wheel);
        // SAFETY: the record and probe are leaked.
        unsafe {
            wheel.as_ref().start(
                probe.own,
                Ticks::new(1),
                rearm_and_stop,
                probe.ctx(),
            );
        };
        for _ in 0..3 {
            tick(wheel, source);
        }
        assert_eq!(probe.runs.load(Ordering::Relaxed), 1);
        // Re-armed while running, it is not idle; the stop prevents the
        // new expiry but it is still running.
        assert_eq!(*probe.results.lock().unwrap(), [false, true, false]);
        // SAFETY: the record is leaked.
        assert!(unsafe { wheel.is_idle(probe.own) });
        #[cfg(debug_assertions)]
        assert_eq!(wheel.stats().armed, 0);
    }

    #[test]
    fn a_nested_advance_returns_false() {
        let (source, wheel) = leaked_hashed_wheel();
        let probe = Probe::leaked(wheel);
        // SAFETY: the record and probe are leaked.
        unsafe {
            wheel.as_ref().start(
                probe.own,
                Ticks::new(1),
                nested,
                probe.ctx(),
            );
        };
        source.bump();
        source.bump();
        assert!(wheel.as_ref().advance());
        assert_eq!(*probe.results.lock().unwrap(), [false]);
        assert!(wheel.as_ref().advance());
        assert!(!wheel.as_ref().advance());
    }

    #[test]
    fn poll_skips_ticks_without_work() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let (fired, ctx) = counter();
        // Lands in the bucket of tick 4, a revolution early.
        arm(&wheel, leaked(), 260, ctx);
        arm(&wheel, leaked(), 6, ctx);
        assert!(!wheel.poll());
        for _ in 0..10 {
            source.bump();
        }
        assert!(wheel.poll());
        assert_eq!(wheel.cursor(), Ticks::new(5));
        assert!(wheel.as_ref().advance());
        assert_eq!(fired.load(Ordering::Relaxed), 1);
        assert!(!wheel.poll());
        assert_eq!(wheel.cursor(), Ticks::new(10));
    }

    #[test]
    fn wheels_do_not_share_records() {
        let source = Source::new(0);
        let first = hashed_wheel(&source);
        let second = hashed_wheel(&source);
        let (fired, ctx) = counter();
        arm(&first, leaked(), 1, ctx);
        source.bump();
        while second.as_ref().advance() {}
        assert_eq!(fired.load(Ordering::Relaxed), 0);
        while first.as_ref().advance() {}
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }

    /// The tick source of [`STATIC_HASHED_WHEEL`].
    static STATIC_SOURCE: Source = Source::new(0);

    /// A wheel built at compile time.
    static STATIC_HASHED_WHEEL: HashedWheel<&Source> =
        HashedWheel::new(&STATIC_SOURCE, Ticks::ZERO);

    #[test]
    fn a_wheel_can_be_a_static() {
        let wheel = Pin::static_ref(&STATIC_HASHED_WHEEL);
        let (fired, ctx) = counter();
        // SAFETY: the record and counter are leaked.
        unsafe { wheel.start(leaked(), Ticks::new(1), count, ctx) };
        STATIC_SOURCE.bump();
        assert!(wheel.advance());
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn stats_count_arms_and_bin_intervals() {
        let source = Source::new(0);
        let wheel = hashed_wheel(&source);
        let (_, ctx) = counter();
        let records = [leaked(), leaked(), leaked()];
        arm(&wheel, records[0], 1, ctx);
        arm(&wheel, records[1], 300, ctx);
        arm(&wheel, records[2], 1 << 20, ctx);
        // SAFETY: the record is leaked.
        assert!(unsafe { wheel.as_ref().stop(records[1]) });
        tick(&wheel, &source);
        let stats = wheel.stats();
        assert_eq!(stats.armed, 1);
        assert_eq!(stats.peak, 3);
        let mut intervals = [0; INTERVAL_BINS];
        intervals[0] = 1;
        intervals[8] = 1;
        intervals[INTERVAL_BINS - 1] = 1;
        assert_eq!(stats.intervals, intervals);
    }
}
