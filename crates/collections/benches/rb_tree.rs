// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times the red-black tree on the workloads that tell a tree apart.
//!
//! Every workload runs whole inside one timed call, over nodes allocated
//! before timing starts, and returns a checksum of what it saw so the
//! optimizer cannot drop the work.  Keys come from a generator that keeps
//! running across calls, so no call replays another and a branch
//! predictor cannot learn a sequence.  Ids read `rb_tree/<workload>/<nodes>`.
//!
//! - `insert`: insert every node under a fresh random key.
//! - `insert_asc`: insert every node under an ascending key.
//! - `insert_hint`: insert every node under an ascending key, each right
//!   after the one before, by cursor: no search.
//! - `dups`: insert every node under one of 16 keys.
//! - `floor`: one `upper_bound` lookup per node, at a random key.
//! - `ceil`: one `lower_bound` lookup per node, at a random key.
//! - `find`: one `lower_bound` lookup per node, at a key in the tree.
//! - `walk`: walk the tree in order.
//! - `walk_rev`: walk it back to front.
//! - `churn`: remove a random node by address, give it a fresh key and
//!   insert it again, once per node.
//! - `move_near`: remove a random node, give it the key of a random
//!   other node and insert it again, by search.
//! - `move_near_hint`: the same, inserting by cursor right after that node.
//! - `drain`: insert every node, then remove them all from the front.

use collections::rb_tree::{self, Link, RbTree};
use core::hint::black_box;
use core::iter;
use core::ops::Bound;
use core::ptr::NonNull;
use core::time::Duration;
use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main,
};

const SIZES: [usize; 3] = [0x10, 0x400, 0x1_0000];
const DUP_KEYS: u64 = 16;
const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// A node on a tree.
struct Node {
    key: u64,
    link: Link,
}

rb_tree::adapter!(Adapter = Node { link } key(u64) = |node| node.key);

type Tree = RbTree<'static, Adapter>;

const fn mix(hash: u64, key: u64) -> u64 {
    hash.wrapping_mul(31).wrapping_add(key)
}

/// A xorshift generator.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0.wrapping_shl(13);
        self.0 ^= self.0.wrapping_shr(7);
        self.0 ^= self.0.wrapping_shl(17);
        self.0
    }

    /// Returns a fresh key, below 2^63.
    const fn key(&mut self) -> u64 {
        self.next().wrapping_shr(1)
    }

    /// Returns an index below `bound`.
    fn below(&mut self, bound: usize) -> usize {
        let wide = u128::from(self.next())
            .wrapping_mul(u128::try_from(bound).unwrap_or(0));
        usize::try_from(wide.wrapping_shr(64)).unwrap_or(0)
    }
}

/// A tree over nodes that stay where they are, and the generator that
/// draws their keys.
struct Fixture {
    nodes: Vec<Node>,
    tree: Tree,
    rng: Rng,
}

impl Fixture {
    /// Returns a fixture whose tree already holds every node.
    fn new(n: usize) -> Self {
        let mut fixture = Self {
            nodes: iter::repeat_with(|| Node {
                key: 0,
                link: Link::new(),
            })
            .take(n)
            .collect(),
            tree: Tree::new(),
            rng: Rng(SEED ^ u64::try_from(n).unwrap_or(0)),
        };
        for i in 0..n {
            let key = fixture.rng.key();
            fixture.put(i, key);
        }
        fixture
    }

    /// Gives node `i` the key `key` and inserts it.
    fn put(&mut self, i: usize, key: u64) {
        let Some(node) = self.nodes.get_mut(i) else {
            return;
        };
        node.key = key;
        // SAFETY: the node lives as long as the fixture, never moves (the
        // vector is never grown), and is on no tree: it is new, or the
        // caller emptied the tree, or removed it.
        unsafe { self.tree.insert_ptr(NonNull::from(node)) };
    }

    /// Gives node `i` the key `key` and inserts it right after `after`, or
    /// as the first node when there is no `after`.  Returns the node.
    fn put_after(
        &mut self,
        i: usize,
        key: u64,
        after: Option<NonNull<Node>>,
    ) -> Option<NonNull<Node>> {
        let node = NonNull::from(self.nodes.get_mut(i)?);
        // SAFETY: the node is live, unmoved and on no tree; `after` is on
        // this tree, and `key` lies between its key and the next one's.
        unsafe {
            (*node.as_ptr()).key = key;
            match after {
                None => self.tree.cursor_front_mut().insert_before_ptr(node),
                Some(prev) => {
                    self.tree.cursor_mut_from_ptr(prev).insert_after_ptr(node);
                }
            }
        }
        Some(node)
    }

    fn ends(&self, hash: u64) -> u64 {
        let front = self.tree.front().map_or(0, |node| node.key);
        let back = self.tree.back().map_or(0, |node| node.key);
        mix(mix(hash, front), back)
    }
}

fn insert(fixture: &mut Fixture) -> u64 {
    fixture.tree.clear();
    for i in 0..fixture.nodes.len() {
        let key = fixture.rng.key();
        fixture.put(i, key);
    }
    fixture.ends(0)
}

fn insert_asc(fixture: &mut Fixture) -> u64 {
    fixture.tree.clear();
    for i in 0..fixture.nodes.len() {
        let ascending = u64::try_from(i)
            .unwrap_or(0)
            .wrapping_mul(2)
            .wrapping_add(1);
        fixture.put(i, ascending);
    }
    fixture.ends(0)
}

fn insert_hint(fixture: &mut Fixture) -> u64 {
    fixture.tree.clear();
    let mut last = None;
    for i in 0..fixture.nodes.len() {
        let ascending = u64::try_from(i)
            .unwrap_or(0)
            .wrapping_mul(2)
            .wrapping_add(1);
        last = fixture.put_after(i, ascending, last);
    }
    fixture.ends(0)
}

fn dups(fixture: &mut Fixture) -> u64 {
    fixture.tree.clear();
    for i in 0..fixture.nodes.len() {
        let key = fixture.rng.next().checked_rem(DUP_KEYS).unwrap_or(0);
        fixture.put(i, key);
    }
    fixture.ends(0)
}

fn floor(fixture: &mut Fixture) -> u64 {
    let mut hash = 0;
    for _ in 0..fixture.nodes.len() {
        let key = fixture.rng.key();
        let found = fixture.tree.upper_bound(Bound::Included(&key));
        hash = mix(hash, found.current().map_or(0, |node| node.key));
    }
    hash
}

fn ceil(fixture: &mut Fixture) -> u64 {
    let mut hash = 0;
    for _ in 0..fixture.nodes.len() {
        let key = fixture.rng.key();
        let found = fixture.tree.lower_bound(Bound::Included(&key));
        hash = mix(hash, found.current().map_or(0, |node| node.key));
    }
    hash
}

fn find(fixture: &mut Fixture) -> u64 {
    let mut hash = 0;
    for _ in 0..fixture.nodes.len() {
        let at = fixture.rng.below(fixture.nodes.len());
        let key = fixture.nodes.get(at).map_or(0, |node| node.key);
        let found = fixture.tree.lower_bound(Bound::Included(&key));
        let hit = found.current().filter(|node| node.key == key);
        hash = mix(hash, hit.map_or(0, |node| node.key));
    }
    hash
}

fn walk(fixture: &mut Fixture) -> u64 {
    fixture
        .tree
        .iter()
        .fold(0, |hash, node| mix(hash, node.key))
}

fn walk_rev(fixture: &mut Fixture) -> u64 {
    fixture
        .tree
        .iter()
        .rev()
        .fold(0, |hash, node| mix(hash, node.key))
}

fn churn(fixture: &mut Fixture) -> u64 {
    for _ in 0..fixture.nodes.len() {
        let at = fixture.rng.below(fixture.nodes.len());
        let key = fixture.rng.key();
        let Some(node) = fixture.nodes.get_mut(at) else {
            continue;
        };
        // SAFETY: the node is on the tree, which the fixture owns.
        unsafe { fixture.tree.remove_ptr(NonNull::from(&mut *node)) };
        fixture.put(at, key);
    }
    fixture.ends(0)
}

/// Moves every node once: a random node leaves, and joins again with the key
/// of a random other node, placed by search or by cursor right after it.
fn move_near(fixture: &mut Fixture, hinted: bool) -> u64 {
    let count = fixture.nodes.len();
    for _ in 0..count {
        let moved = fixture.rng.below(count);
        let other = fixture.rng.below(count.saturating_sub(1));
        let anchor = if other >= moved {
            other.saturating_add(1)
        } else {
            other
        };
        let Some(anchor_key) = fixture.nodes.get(anchor).map(|node| node.key)
        else {
            continue;
        };
        let Some(node) = fixture.nodes.get_mut(moved) else {
            continue;
        };
        // SAFETY: the node is on the tree, which the fixture owns.
        unsafe { fixture.tree.remove_ptr(NonNull::from(&mut *node)) };
        let key = anchor_key;
        if hinted {
            let after = fixture.nodes.get_mut(anchor).map(NonNull::from);
            let _placed = fixture.put_after(moved, key, after);
        } else {
            fixture.put(moved, key);
        }
    }
    fixture.ends(0)
}

fn move_near_search(fixture: &mut Fixture) -> u64 {
    move_near(fixture, false)
}

fn move_near_hint(fixture: &mut Fixture) -> u64 {
    move_near(fixture, true)
}

fn drain(fixture: &mut Fixture) -> u64 {
    fixture.tree.clear();
    for i in 0..fixture.nodes.len() {
        let key = fixture.rng.key();
        fixture.put(i, key);
    }
    let mut hash = 0;
    let mut cursor = fixture.tree.cursor_front_mut();
    while let Some(node) = cursor.remove_current() {
        hash = mix(hash, node.key);
    }
    hash
}

/// Times `run` at every size in the group `name`, each over a fixture
/// whose tree starts full.
fn bench(criterion: &mut Criterion, name: &str, run: fn(&mut Fixture) -> u64) {
    let mut group = criterion.benchmark_group(name);
    for n in SIZES {
        let mut fixture = Fixture::new(n);
        let _: &mut BenchmarkGroup<'_, WallTime> = group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &n,
            |bencher, _| bencher.iter(|| run(black_box(&mut fixture))),
        );
    }
    group.finish();
}

fn rb_tree(criterion: &mut Criterion) {
    bench(criterion, "rb_tree/insert", insert);
    bench(criterion, "rb_tree/insert_asc", insert_asc);
    bench(criterion, "rb_tree/insert_hint", insert_hint);
    bench(criterion, "rb_tree/dups", dups);
    bench(criterion, "rb_tree/floor", floor);
    bench(criterion, "rb_tree/ceil", ceil);
    bench(criterion, "rb_tree/find", find);
    bench(criterion, "rb_tree/walk", walk);
    bench(criterion, "rb_tree/walk_rev", walk_rev);
    bench(criterion, "rb_tree/churn", churn);
    bench(criterion, "rb_tree/move_near", move_near_search);
    bench(criterion, "rb_tree/move_near_hint", move_near_hint);
    bench(criterion, "rb_tree/drain", drain);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);
    targets = rb_tree
}
criterion_main!(benches);
