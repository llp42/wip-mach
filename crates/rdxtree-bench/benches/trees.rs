// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times `kmem::RadixTree` against the `kern/rdxtree` it replaced.
//!
//! Both trees see the same key sequences and the same value pointers,
//! built before timing starts; the whole workload runs inside one timed
//! call and returns a checksum so the optimizer cannot drop the work.
//! Ids read `<tree>/<workload>/<entries>`, with `old` the BSD-2-Clause
//! `kern/rdxtree` and `new` the MIT `kmem::RadixTree`.
//!
//! - `insert_alloc`: fill under the lowest free name.
//! - `insert_named`: fill under shuffled explicit names.
//! - `lookup`: one lookup per name present.
//! - `remove`: remove every name.
//! - `walk`: walk every entry in key order.
//! - `churn`: remove a name and insert it again, once per name.
//! - `replace`: rewrite every present value in key order.
//! - `clear`: fill, then drop every entry in one call.
//! - `ipc`: batches of 64 allocs, lookups of the oldest third, removals
//!   of the newest sixth, then a walk and a clear.
//! - `insert_sparse`: fill under full-domain explicit names.
//! - `lookup_sparse`: one lookup per name present, sparse keys.
//! - `lookup_sparse_miss`: one lookup per absent name, sparse keys.

use core::ffi::c_void;
use core::hint::black_box;
use core::ptr::NonNull;
use core::time::Duration;
use criterion::measurement::WallTime;
use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, criterion_group,
    criterion_main,
};
use rdxtree_bench::{NewTree, OldTree, Tree, mix};

const SIZES: [usize; 4] = [64, 1024, 32768, 131072];
const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// A xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// `n` distinct u32 names in a fixed shuffled order.
fn names(n: usize) -> Vec<u32> {
    let mut rng = Rng(SEED);
    let mut keys: Vec<u32> = (0..n as u32).collect();
    for i in (1..n).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        keys.swap(i, j);
    }
    keys
}

/// `n` sparse u32 names starting at `start`, spanning the full domain.
///
/// The multiplier is odd, so the map is a u32 bijection: no duplicates
/// inside one call, and two disjoint ranges stay disjoint.
fn names_sparse(start: usize, n: usize) -> Vec<u32> {
    (start..start + n)
        .map(|i| (i as u32).wrapping_mul(0x9E37_79B9))
        .collect()
}

/// `n` stable value addresses, alive for the whole run.
fn values(n: usize) -> (Vec<u64>, Vec<NonNull<c_void>>) {
    let backing: Vec<u64> = vec![0; n];
    let ptrs = backing
        .iter()
        .map(|slot| NonNull::from(slot).cast::<c_void>())
        .collect();
    (backing, ptrs)
}

fn insert_alloc<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        T::new,
        |mut tree| {
            let mut sum = 0_u64;
            for &ptr in ptrs {
                sum = mix(sum, u64::from(tree.insert_alloc(ptr)));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn insert_named<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        T::new,
        |mut tree| {
            let mut sum = 0_u64;
            for (&key, &ptr) in keys.iter().zip(ptrs) {
                sum = mix(sum, u64::from(tree.insert_named(key, ptr)));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn fill<T: Tree>(keys: &[u32], ptrs: &[NonNull<c_void>]) -> T {
    let mut tree = T::new();
    for (&key, &ptr) in keys.iter().zip(ptrs) {
        assert!(tree.insert_named(key, ptr));
    }
    tree
}

fn lookup<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |tree| {
            let mut sum = 0_u64;
            for &key in keys {
                sum = mix(sum, tree.lookup(key));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn remove<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |mut tree| {
            let mut sum = 0_u64;
            for &key in keys {
                sum = mix(sum, tree.remove(key));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn walk<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |tree| black_box(tree.walk()),
        BatchSize::PerIteration,
    );
}

fn churn<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |mut tree| {
            let mut sum = 0_u64;
            for (&key, &ptr) in keys.iter().zip(ptrs) {
                sum = mix(sum, tree.remove(key));
                sum = mix(sum, u64::from(tree.insert_named(key, ptr)));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn replace<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |mut tree| {
            let mut sum = 0_u64;
            for (&key, &ptr) in keys.iter().zip(ptrs) {
                sum = mix(sum, tree.replace(key, ptr));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn clear<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |mut tree| {
            tree.clear();
            black_box(tree.walk())
        },
        BatchSize::PerIteration,
    );
}

fn ipc<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        T::new,
        |mut tree| {
            let mut sum = 0_u64;
            let mut live: Vec<(u32, NonNull<c_void>)> = Vec::new();
            let mut next = 0;
            while next < ptrs.len() {
                let batch = core::cmp::min(64, ptrs.len() - next);
                for &ptr in &ptrs[next..next + batch] {
                    let name = tree.insert_alloc(ptr);
                    sum = mix(sum, u64::from(name));
                    live.push((name, ptr));
                }
                next += batch;
                let third = live.len() / 3;
                for &(name, _) in &live[..third] {
                    sum = mix(sum, tree.lookup(name));
                }
                let sixth = live.len() / 6;
                for _ in 0..sixth {
                    if let Some((name, _)) = live.pop() {
                        sum = mix(sum, tree.remove(name));
                    }
                }
            }
            sum = mix(sum, tree.walk());
            tree.clear();
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn lookup_sparse_miss<T: Tree>(
    b: &mut criterion::Bencher<'_, WallTime>,
    keys: &[u32],
    miss: &[u32],
    ptrs: &[NonNull<c_void>],
) {
    b.iter_batched(
        || fill::<T>(keys, ptrs),
        |tree| {
            let mut sum = 0_u64;
            for &key in miss {
                sum = mix(sum, tree.lookup(key));
            }
            black_box(sum)
        },
        BatchSize::PerIteration,
    );
}

fn bench<T: Tree>(group: &mut BenchmarkGroup<'_, WallTime>, tree: &str) {
    for &n in &SIZES {
        let keys = names(n);
        let sparse = names_sparse(0, n);
        let sparse_miss = names_sparse(n, n);
        let (_backing, ptrs) = values(n);
        group.bench_function(
            BenchmarkId::new(tree, format!("insert_alloc/{n}")),
            |b| insert_alloc::<T>(b, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("insert_named/{n}")),
            |b| insert_named::<T>(b, &keys, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("lookup/{n}")),
            |b| lookup::<T>(b, &keys, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("remove/{n}")),
            |b| remove::<T>(b, &keys, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("walk/{n}")),
            |b| walk::<T>(b, &keys, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("churn/{n}")),
            |b| churn::<T>(b, &keys, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("replace/{n}")),
            |b| replace::<T>(b, &keys, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("clear/{n}")),
            |b| clear::<T>(b, &keys, &ptrs),
        );
        group
            .bench_function(BenchmarkId::new(tree, format!("ipc/{n}")), |b| {
                ipc::<T>(b, &ptrs)
            });
        group.bench_function(
            BenchmarkId::new(tree, format!("insert_sparse/{n}")),
            |b| insert_named::<T>(b, &sparse, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("lookup_sparse/{n}")),
            |b| lookup::<T>(b, &sparse, &ptrs),
        );
        group.bench_function(
            BenchmarkId::new(tree, format!("lookup_sparse_miss/{n}")),
            |b| lookup_sparse_miss::<T>(b, &sparse, &sparse_miss, &ptrs),
        );
    }
}

fn trees(c: &mut Criterion) {
    let mut group = c.benchmark_group("radix");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));
    bench::<OldTree>(&mut group, "old");
    bench::<NewTree>(&mut group, "new");
    group.finish();
}

criterion_group!(benches, trees);
criterion_main!(benches);
