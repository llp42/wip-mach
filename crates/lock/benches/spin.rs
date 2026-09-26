// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times the spin locks, uncontended and contended.
//!
//! The locks run on [`Bench`], a platform whose sections cost nothing, so
//! the numbers are the lock protocol's alone.  Ids read
//! `spin/<workload>/<lock>`.
//!
//! - `uncontended`: one thread takes and releases the lock.
//! - `contended/<n>`: `n` threads each take the lock and add to its data
//!   once per iteration; one iteration is one hold by every thread.
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
        Bucket, IrqSpinLock, Platform, RawSpinLock, SpinLock, ThreadRef,
        WaitTable,
    };
    use std::sync::Barrier;
    use std::thread;
    use std::time::Instant;

    const THREADS: [usize; 3] = [2, 3, 4];

    /// A platform whose sections are no-ops; spin locks never park.
    struct Bench;

    /// Not zero-sized, so every thread's record has its own address.
    #[repr(align(8))]
    struct BenchThread {
        _identity: u8,
    }

    std::thread_local! {
        static THREAD: BenchThread = const { BenchThread { _identity: 0 } };
    }

    static BUCKETS: [Bucket; 1] = [const { Bucket::new() }; 1];

    static TABLE: WaitTable = WaitTable::new(&BUCKETS);

    // SAFETY: each thread's identity is its own thread-local record;
    // irq-quiet sections may be no-ops where no interrupt handler takes a
    // lock, as none does on these host threads; and `park` and `unpark` are
    // unreachable from a spin lock.
    unsafe impl Platform for Bench {
        fn current() -> ThreadRef {
            THREAD.with(|thread| ThreadRef::new(NonNull::from(thread).cast()))
        }

        fn is_running(_thread: ThreadRef) -> bool {
            true
        }

        fn irq_quiet_enter() {}

        unsafe fn irq_quiet_exit() {}

        fn park() {
            unreachable!("a spin lock parked");
        }

        fn unpark(_thread: ThreadRef) {
            unreachable!("a spin lock unparked");
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
        let mut group = criterion.benchmark_group("spin/uncontended");
        let raw = RawSpinLock::<Bench>::new();
        let _ = group.bench_function("raw_spin_lock", |bencher| {
            bencher.iter(|| {
                black_box(&raw).lock();
                // SAFETY: locked on the line above, on this thread.
                unsafe { black_box(&raw).unlock() };
            });
        });
        let spin = SpinLock::<u64, Bench>::new(0);
        let _ = group.bench_function("spin_lock", |bencher| {
            bencher.iter(|| *black_box(&spin).lock() += 1);
        });
        let irq_spin = IrqSpinLock::<u64, Bench>::new(0);
        let _ = group.bench_function("irq_spin_lock", |bencher| {
            bencher.iter(|| *black_box(&irq_spin).lock() += 1);
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
            let mut group =
                criterion.benchmark_group(format!("spin/contended/{threads}"));
            let spin = SpinLock::<u64, Bench>::new(0);
            let _ = group.bench_function("spin_lock", |bencher| {
                bencher.iter_custom(|iters| {
                    race(threads, iters, || *black_box(&spin).lock() += 1)
                });
            });
            let irq_spin = IrqSpinLock::<u64, Bench>::new(0);
            let _ = group.bench_function("irq_spin_lock", |bencher| {
                bencher.iter_custom(|iters| {
                    race(threads, iters, || *black_box(&irq_spin).lock() += 1)
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
