// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times the sleeping locks, uncontended and contended, beside a spin
//! lock.
//!
//! The locks run on [`Bench`], a platform whose sections cost nothing and
//! whose park and unpark are the host's, so the numbers are the lock
//! protocol's and the wait table's.  Ids read `mutex/<workload>/<lock>`.
//!
//! - `uncontended`: one thread takes and releases the lock.
//! - `contended/<n>`: `n` threads each take the lock and add to its data
//!   once per iteration; one iteration is one hold by every thread.  The
//!   rwlock rows take it for writing, or for reading only.
//!
//! Under `cfg(loom)` the locks are built on loom's atomics, which only
//! work inside a model, so the benchmark is empty.

#[cfg(loom)]
fn main() {}

#[cfg(not(loom))]
criterion::criterion_main!(timed::benches);

#[cfg(not(loom))]
mod timed {
    use core::hint::black_box;
    use core::ptr::NonNull;
    use core::time::Duration;
    use criterion::{Criterion, criterion_group};
    #[cfg(debug_assertions)]
    use lock::HeldLocks;
    use lock::{
        Bucket, Mutex, Platform, RawMutex, RwLock, SpinLock, ThreadRef,
        WaitTable,
    };
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{self, Thread};
    use std::time::Instant;

    const THREADS: [usize; 3] = [2, 3, 4];

    /// A platform whose sections are no-ops and whose threads park on the
    /// host's.
    struct Bench;

    /// The record a [`ThreadRef`] of [`Bench`] points at; leaked, so a
    /// late unpark of a finished thread stays sound.
    #[repr(align(8))]
    struct BenchThread {
        thread: Thread,
        parked: AtomicBool,
    }

    std::thread_local! {
        static THREAD: &'static BenchThread =
            Box::leak(Box::new(BenchThread {
                thread: thread::current(),
                parked: AtomicBool::new(false),
            }));
    }

    static BUCKETS: [Bucket; 64] = [const { Bucket::new() }; 64];

    static TABLE: WaitTable = WaitTable::new(&BUCKETS);

    const fn record(thread: ThreadRef) -> &'static BenchThread {
        // SAFETY: every `ThreadRef` of `Bench` comes from `Bench::current`,
        // the address of a leaked `BenchThread`.
        unsafe { thread.as_ptr().cast::<BenchThread>().as_ref() }
    }

    // SAFETY: each thread's identity is its own leaked record; irq-quiet
    // sections may be no-ops where no interrupt handler takes a lock, as
    // none does on these host threads; `park` and `unpark` are the host's,
    // whose token semantics match the contract.
    unsafe impl Platform for Bench {
        fn current() -> ThreadRef {
            THREAD.with(|thread| ThreadRef::new(NonNull::from(*thread).cast()))
        }

        fn is_running(thread: ThreadRef) -> bool {
            !record(thread).parked.load(Ordering::Relaxed)
        }

        fn irq_quiet_enter() {}

        unsafe fn irq_quiet_exit() {}

        fn park() {
            let me = THREAD.with(|thread| *thread);
            me.parked.store(true, Ordering::Relaxed);
            thread::park();
            me.parked.store(false, Ordering::Relaxed);
        }

        fn unpark(thread: ThreadRef) {
            record(thread).thread.unpark();
        }

        fn wait_table() -> &'static WaitTable {
            &TABLE
        }

        #[cfg(debug_assertions)]
        fn held_locks() -> &'static HeldLocks {
            std::thread_local! {
                static HELD: &'static HeldLocks =
                    Box::leak(Box::new(HeldLocks::new()));
            }
            HELD.with(|held| *held)
        }
    }

    fn uncontended(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("mutex/uncontended");
        let raw = RawMutex::<Bench>::new();
        let _ = group.bench_function("raw_mutex", |bencher| {
            bencher.iter(|| {
                black_box(&raw).lock();
                // SAFETY: locked on the line above, on this thread.
                unsafe { black_box(&raw).unlock() };
            });
        });
        let mutex = Mutex::<u64, Bench>::new(0);
        let _ = group.bench_function("mutex", |bencher| {
            bencher.iter(|| *black_box(&mutex).lock() += 1);
        });
        let rwlock = RwLock::<u64, Bench>::new(0);
        let _ = group.bench_function("rwlock_write", |bencher| {
            bencher.iter(|| *black_box(&rwlock).write() += 1);
        });
        let _ = group.bench_function("rwlock_read", |bencher| {
            bencher.iter(|| *black_box(&rwlock).read());
        });
        let spin = SpinLock::<u64, Bench>::new(0);
        let _ = group.bench_function("spin_lock", |bencher| {
            bencher.iter(|| *black_box(&spin).lock() += 1);
        });
        group.finish();
    }

    /// Returns how long `threads` threads took to each run `hold`
    /// `iters` times, timed from a common start.
    fn race(threads: usize, iters: u64, hold: impl Fn() + Sync) -> Duration {
        let start = Barrier::new(threads + 1);
        thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    scope.spawn(|| {
                        let _ = start.wait();
                        for _ in 0..iters {
                            hold();
                        }
                    })
                })
                .collect();
            let _ = start.wait();
            let began = Instant::now();
            for worker in workers {
                worker.join().expect("a benchmark thread panicked");
            }
            began.elapsed()
        })
    }

    fn contended(criterion: &mut Criterion) {
        for threads in THREADS {
            let mut group = criterion
                .benchmark_group(format!("mutex/contended/{threads}"));
            let mutex = Mutex::<u64, Bench>::new(0);
            let _ = group.bench_function("mutex", |bencher| {
                bencher.iter_custom(|iters| {
                    race(threads, iters, || *black_box(&mutex).lock() += 1)
                });
            });
            let rwlock = RwLock::<u64, Bench>::new(0);
            let _ = group.bench_function("rwlock_write", |bencher| {
                bencher.iter_custom(|iters| {
                    race(threads, iters, || *black_box(&rwlock).write() += 1)
                });
            });
            let _ = group.bench_function("rwlock_read", |bencher| {
                bencher.iter_custom(|iters| {
                    race(threads, iters, || {
                        let _ = *black_box(&rwlock).read();
                    })
                });
            });
            let spin = SpinLock::<u64, Bench>::new(0);
            let _ = group.bench_function("spin_lock", |bencher| {
                bencher.iter_custom(|iters| {
                    race(threads, iters, || *black_box(&spin).lock() += 1)
                });
            });
            group.finish();
        }
    }

    criterion_group! {
        name = benches;
        config = Criterion::default()
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(2))
            .sample_size(20);
        targets = uncontended, contended
    }
}
