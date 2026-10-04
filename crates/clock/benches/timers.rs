// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Host benchmarks for the timer wheel and the machine clock.
//!
//! Run with `mise run bench::clock` (the host target must be named,
//! since the workspace builds the bare-metal kernel by default).  Wheel
//! ids read `<workload>/<callouts>`:
//!
//! - `start`, `stop`: arm or cancel every callout; per callout.
//! - `expire`: every callout due on the next tick; one advance.
//! - `empty/advance`, `empty/poll`: one tick of an empty wheel, through
//!   the deferred pass or the interrupt-time peek.
//! - `steady`: one tick with every callout re-arming itself from its
//!   action, intervals from `intervals.txt` (90% under 5 s).
//! - `cancel`: `steady`, but 90% of arms are cancelled 1 to 50 ticks
//!   later (a reply within 500 ms) and re-armed at once.

use clock::{
    Calendar, Callout, Clock, HashedWheel, Instant, Locking, TickSource,
    Ticks, TimeCounter, TimePage, Timer, TimerSave, WallTime,
};
use core::cell::{Cell, RefCell};
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{
    AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering,
};
use core::time::Duration;
use criterion::{
    BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
#[cfg(debug_assertions)]
use lock::HeldLocks;
use lock::{Bucket, Platform, ThreadRef, WaitTable};
use std::hint::black_box;
use std::thread::{self, Thread};
use std::time::Instant as HostInstant;

/// The `lock` platform the benchmarks run on, over std threads; nothing
/// interrupts them, so an irq-quiet section does nothing.
struct BenchLocks;

/// The record a [`ThreadRef`] of [`BenchLocks`] points at; leaked, so a
/// late unpark of a finished thread stays sound.
#[repr(align(8))]
struct BenchThread {
    thread: Thread,
    parked: AtomicBool,
}

std::thread_local! {
    static ME: &'static BenchThread = Box::leak(Box::new(BenchThread {
        thread: thread::current(),
        parked: AtomicBool::new(false),
    }));
}

#[cfg(debug_assertions)]
std::thread_local! {
    static HELD: &'static HeldLocks = Box::leak(Box::new(HeldLocks::new()));
}

/// One bucket, which every lock of the benchmarks shares.
static BUCKETS: [Bucket; 1] = [const { Bucket::new() }; 1];

static TABLE: WaitTable = WaitTable::new(&BUCKETS);

/// Returns the record `thread` names.
const fn record(thread: ThreadRef) -> &'static BenchThread {
    // SAFETY: every `ThreadRef` of `BenchLocks` names a leaked
    // `BenchThread`.
    unsafe { thread.as_ptr().cast::<BenchThread>().as_ref() }
}

// SAFETY: a thread's record is its own and leaked, `park` and `unpark`
// are std's, which keep a token, and every lock shares one wait table.
unsafe impl Platform for BenchLocks {
    fn current() -> ThreadRef {
        ME.with(|me| ThreadRef::new(NonNull::from(*me).cast()))
    }

    fn is_running(thread: ThreadRef) -> bool {
        !record(thread).parked.load(Ordering::SeqCst)
    }

    fn irq_quiet_enter() {}

    unsafe fn irq_quiet_exit() {}

    fn park() {
        ME.with(|me| me.parked.store(true, Ordering::SeqCst));
        thread::park();
        ME.with(|me| me.parked.store(false, Ordering::SeqCst));
    }

    fn unpark(thread: ThreadRef) {
        record(thread).thread.unpark();
    }

    fn wait_table() -> &'static WaitTable {
        &TABLE
    }

    #[cfg(debug_assertions)]
    fn held_locks() -> &'static HeldLocks {
        HELD.with(|held| *held)
    }
}

/// The clock platform the clock benchmarks drive: atomics only.
struct BenchPlatform {
    counter: AtomicU32,
    period_nsec: AtomicU32,
    rtc: AtomicI64,
    published_wall: AtomicU64,
    published_uptime: AtomicU64,
}

impl BenchPlatform {
    const fn new() -> Self {
        Self {
            counter: AtomicU32::new(0),
            period_nsec: AtomicU32::new(1),
            rtc: AtomicI64::new(0),
            published_wall: AtomicU64::new(0),
            published_uptime: AtomicU64::new(0),
        }
    }
}

impl TimeCounter for BenchPlatform {
    fn counter(&self) -> u32 {
        self.counter.load(Ordering::Relaxed)
    }

    fn counter_period_nsec(&self) -> u32 {
        self.period_nsec.load(Ordering::Relaxed)
    }
}

impl Locking for BenchPlatform {
    type Lock = BenchLocks;
}

impl Calendar for BenchPlatform {
    fn set_rtc(&self, seconds: i64) {
        self.rtc.store(seconds, Ordering::Relaxed);
    }
}

impl TimePage for BenchPlatform {
    fn publish(&self, wall: WallTime, uptime: Instant) {
        self.published_wall
            .store(wall.as_nanos(), Ordering::Relaxed);
        self.published_uptime
            .store(uptime.as_nanos(), Ordering::Relaxed);
    }
}

/// A leaked clock, so it outlives every benchmark.
fn clock() -> &'static Clock<BenchPlatform> {
    Box::leak(Box::new(Clock::new(BenchPlatform::new())))
}

/// The wheel's platform: a tick count the benchmarks bump by hand.
struct Source(AtomicU64);

impl Source {
    fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl TickSource for Source {
    fn now(&self) -> Ticks {
        Ticks::new(self.0.load(Ordering::Relaxed))
    }
}

impl Locking for Source {
    type Lock = BenchLocks;
}

/// The wheel under test.
type BenchHashedWheel = HashedWheel<&'static Source>;

/// A leaked wheel on a leaked source at tick zero.
fn leaked_hashed_wheel() -> (&'static Source, Pin<&'static BenchHashedWheel>) {
    let source: &'static Source =
        Box::leak(Box::new(Source(AtomicU64::new(0))));
    let wheel: &'static BenchHashedWheel =
        Box::leak(Box::new(HashedWheel::new(source, Ticks::ZERO)));
    (source, Pin::static_ref(wheel))
}

/// A callout with no data.
type NopCallout = Callout<'static, &'static Source, ()>;

/// The no-op expiry action.
const fn noop(_callout: Pin<&NopCallout>) {}

/// Leaks `n` stopped callouts on `wheel`.
fn callouts(
    wheel: Pin<&'static BenchHashedWheel>,
    n: usize,
) -> Vec<Pin<&'static NopCallout>> {
    (0..n)
        .map(|_| {
            let callout: &'static NopCallout =
                Box::leak(Box::new(Callout::new(wheel, noop, ())));
            Pin::static_ref(callout)
        })
        .collect()
}

/// The callout counts.
const SIZES: [usize; 4] = [64, 256, 1024, 4096];

/// The saved interval table, in ticks.
fn table() -> &'static [u64] {
    let table: Vec<u64> = include_str!("intervals.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.parse().expect("intervals.txt: a tick count"))
        .collect();
    table.leak()
}

/// `Throughput` for a batch of `n` elements.
fn elements(n: usize) -> Throughput {
    Throughput::Elements(u64::try_from(n).unwrap_or(u64::MAX))
}

fn bench_start(c: &mut Criterion) {
    let mut group = c.benchmark_group("start");
    let table = table();
    for n in SIZES {
        let (_, wheel) = leaked_hashed_wheel();
        let callouts = callouts(wheel, n);
        group.throughput(elements(n));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_custom(|iters| {
                let mut timed = Duration::ZERO;
                for _ in 0..iters {
                    let begin = HostInstant::now();
                    for (callout, &ticks) in callouts.iter().zip(table) {
                        callout.start(Ticks::new(black_box(ticks)));
                    }
                    timed += begin.elapsed();
                    for callout in &callouts {
                        let _ = callout.stop();
                    }
                }
                timed
            });
        });
    }
}

fn bench_stop(c: &mut Criterion) {
    let mut group = c.benchmark_group("stop");
    let table = table();
    for n in SIZES {
        let (_, wheel) = leaked_hashed_wheel();
        let callouts = callouts(wheel, n);
        group.throughput(elements(n));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_custom(|iters| {
                let mut timed = Duration::ZERO;
                for _ in 0..iters {
                    for (callout, &ticks) in callouts.iter().zip(table) {
                        callout.start(Ticks::new(ticks));
                    }
                    let begin = HostInstant::now();
                    for callout in &callouts {
                        let _ = black_box(callout.stop());
                    }
                    timed += begin.elapsed();
                }
                timed
            });
        });
    }
}

fn bench_expire(c: &mut Criterion) {
    let mut group = c.benchmark_group("expire");
    for n in SIZES {
        let (source, wheel) = leaked_hashed_wheel();
        let callouts = callouts(wheel, n);
        group.throughput(elements(n));
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_custom(|iters| {
                let mut timed = Duration::ZERO;
                for _ in 0..iters {
                    for callout in &callouts {
                        callout.start(Ticks::new(1));
                    }
                    let begin = HostInstant::now();
                    source.bump();
                    let _ = black_box(wheel.advance());
                    timed += begin.elapsed();
                }
                timed
            });
        });
    }
}

fn bench_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("empty");
    let (source, wheel) = leaked_hashed_wheel();
    group.bench_function("advance", |b| {
        b.iter(|| {
            source.bump();
            black_box(wheel.advance())
        });
    });
    let (source, wheel) = leaked_hashed_wheel();
    group.bench_function("poll", |b| {
        b.iter(|| {
            source.bump();
            black_box(wheel.get_ref().poll())
        });
    });
}

/// The share of arms, in percent, that `cancel` cancels early.
const CANCEL_PERCENT: u64 = 90;

/// The longest a cancelled arm lives, in ticks: 500 ms.
const CANCEL_WITHIN: u64 = 50;

/// The slots of the cancel schedule: a power of two above
/// [`CANCEL_WITHIN`], so a new cancel never lands in the slot being
/// drained.
const CANCEL_SLOTS: usize = 64;

/// The cancels scheduled so far, by tick.
struct Cancels {
    percent: u64,
    /// Bumped on every arm of a timer, so a cancel scheduled for an
    /// earlier arm is recognised as stale.
    arms: Vec<u32>,
    slots: Vec<Vec<(usize, u32)>>,
    rng: u64,
    tick: u64,
}

impl Cancels {
    fn new(n: usize, percent: u64) -> Self {
        Self {
            percent,
            arms: vec![0; n],
            slots: (0..CANCEL_SLOTS).map(|_| Vec::new()).collect(),
            rng: 0x9e37_79b9_7f4a_7c15,
            tick: 0,
        }
    }

    /// The next xorshift64 draw.
    const fn draw(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn slot(tick: u64) -> usize {
        usize::try_from(tick % CANCEL_SLOTS as u64).unwrap_or(0)
    }

    /// Records an arm of timer `id`, scheduling its cancel with the
    /// configured odds.
    fn armed(&mut self, id: usize) {
        self.arms[id] = self.arms[id].wrapping_add(1);
        if self.draw() % 100 < self.percent {
            let at = self.tick + 1 + self.draw() % CANCEL_WITHIN;
            self.slots[Self::slot(at)].push((id, self.arms[id]));
        }
    }
}

/// What every timer of a steady-state run shares.
struct Shared {
    table: &'static [u64],
    next: Cell<usize>,
    cancels: RefCell<Cancels>,
}

// SAFETY: the benchmarks run on one thread, so the cells are never
// shared; `Callout::start` only needs `Sync` for actions run elsewhere.
unsafe impl Sync for Shared {}

impl Shared {
    fn interval(&self) -> u64 {
        let at = self.next.get();
        self.next.set((at + 1) % self.table.len());
        self.table[at]
    }
}

/// A steady-state timer's data.
struct Periodic {
    id: usize,
    shared: &'static Shared,
}

/// A timer that re-arms itself when it expires.
type PeriodicCallout = Callout<'static, &'static Source, Periodic>;

/// Arms `timer` for its next interval.
fn arm(timer: Pin<&PeriodicCallout>) {
    let Periodic { id, shared } = *timer.data();
    timer.start(Ticks::new(shared.interval()));
    shared.cancels.borrow_mut().armed(id);
}

/// One tick of a wheel holding `n` self-re-arming timers, `percent` of
/// whose arms are cancelled early.
fn bench_steady_state(c: &mut Criterion, name: &str, percent: u64) {
    let mut group = c.benchmark_group(name);
    let table = table();
    for n in SIZES {
        let (source, wheel) = leaked_hashed_wheel();
        let shared: &'static Shared = Box::leak(Box::new(Shared {
            table,
            next: Cell::new(0),
            cancels: RefCell::new(Cancels::new(n, percent)),
        }));
        let timers: Vec<Pin<&'static PeriodicCallout>> = (0..n)
            .map(|id| {
                let timer: &'static PeriodicCallout = Box::leak(Box::new(
                    Callout::new(wheel, arm, Periodic { id, shared }),
                ));
                Pin::static_ref(timer)
            })
            .collect();
        for &timer in &timers {
            arm(timer);
        }
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                source.bump();
                let slot = {
                    let mut cancels = shared.cancels.borrow_mut();
                    cancels.tick += 1;
                    Cancels::slot(cancels.tick)
                };
                while wheel.advance() {}
                let due = core::mem::take(
                    &mut shared.cancels.borrow_mut().slots[slot],
                );
                for &(id, arms) in &due {
                    if shared.cancels.borrow().arms[id] != arms {
                        continue;
                    }
                    let _ = timers[id].stop();
                    arm(timers[id]);
                }
                let mut due = due;
                due.clear();
                shared.cancels.borrow_mut().slots[slot] = due;
            });
        });
    }
}

fn bench_steady(c: &mut Criterion) {
    bench_steady_state(c, "steady", 0);
}

fn bench_cancel(c: &mut Criterion) {
    bench_steady_state(c, "cancel", CANCEL_PERCENT);
}

fn bench_reads(c: &mut Criterion) {
    let clock = clock();
    let mut group = c.benchmark_group("reads");
    group.bench_function("mono", |b| b.iter(|| black_box(clock.mono())));
    group.bench_function("wall", |b| b.iter(|| black_box(clock.wall())));
    group.bench_function("elapsed_ticks", |b| {
        b.iter(|| black_box(clock.elapsed_ticks()));
    });
    group.bench_function("tick", |b| {
        b.iter(|| clock.tick(clock::TICK));
    });
}

fn bench_accounting(c: &mut Criterion) {
    let mut group = c.benchmark_group("accounting");
    let mut timer = Timer::zeroed();
    group.bench_function("bump", |b| b.iter(|| timer.bump(10_000)));
    group.bench_function("read", |b| b.iter(|| black_box(timer.read())));
    let mut save = TimerSave::default();
    group.bench_function("delta", |b| {
        b.iter(|| {
            // SAFETY: the benchmark is single-threaded and owns the pair.
            black_box(unsafe { save.delta(&timer) })
        });
    });
}

fn bench_new(c: &mut Criterion) {
    c.bench_function("clock_new", |b| {
        b.iter(|| black_box(Clock::new(BenchPlatform::new())));
    });
}

criterion_group!(
    benches,
    bench_start,
    bench_stop,
    bench_expire,
    bench_empty,
    bench_steady,
    bench_cancel,
    bench_reads,
    bench_accounting,
    bench_new,
);
criterion_main!(benches);
