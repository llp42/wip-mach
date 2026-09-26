// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times each shape on the workloads that tell the shapes apart.
//!
//! Every workload runs whole inside one timed call, over nodes allocated
//! before timing starts, and returns a checksum of the order it saw so
//! the optimizer cannot drop the walk.  Ids read
//! `<shape>/<workload>/<nodes>`.
//!
//! - `lifo`: push every node at the front, then pop them all.
//! - `fifo`: push every node at the back, then pop them all from the
//!   front.
//! - `walk`: push every node, then walk the structure eight times.
//! - `walk_rev`: the same, back to front.
//! - `churn`: push every node, then 256 times remove a node by address
//!   and push it back at the front.
//! - `concat`: deal the nodes round-robin over 16 queues, then append
//!   them all onto the first.

use collections::list::{self, List};
use collections::simple_queue::{self, SimpleQueue};
use collections::singly_list::{self, SinglyList};
use collections::tail_queue::{self, TailQueue};
use core::hint::black_box;
use core::pin::{Pin, pin};
use core::ptr::NonNull;
use core::time::Duration;
use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main,
};

const CHURN_OPS: usize = 256;
const CHURN_STRIDE: usize = 7919;
const CONCAT_WAYS: usize = 16;
const WALK_ROUNDS: usize = 8;
const SIZES: [usize; 3] = [1 << 4, 1 << 10, 1 << 16];

const fn mix(hash: u64, key: u64) -> u64 {
    hash.wrapping_mul(31).wrapping_add(key)
}

const fn churn_index(i: usize, n: usize) -> usize {
    match i.wrapping_mul(CHURN_STRIDE).checked_rem(n) {
        Some(index) => index,
        None => 0,
    }
}

/// A node on a singly linked list.
struct SlNode {
    key: u64,
    link: singly_list::Link,
}

/// A node on a list.
struct LNode {
    key: u64,
    link: list::Link,
}

/// A node on a simple queue.
struct SqNode {
    key: u64,
    link: simple_queue::Link,
}

/// A node on a tail queue.
struct TqNode {
    key: u64,
    link: tail_queue::Link,
}

singly_list::adapter!(SlAdapter = SlNode { link });
list::adapter!(LAdapter = LNode { link });
simple_queue::adapter!(SqAdapter = SqNode { link });
tail_queue::adapter!(TqAdapter = TqNode { link });

const fn sl_node(key: u64) -> SlNode {
    SlNode {
        key,
        link: singly_list::Link::new(),
    }
}

const fn l_node(key: u64) -> LNode {
    LNode {
        key,
        link: list::Link::new(),
    }
}

const fn sq_node(key: u64) -> SqNode {
    SqNode {
        key,
        link: simple_queue::Link::new(),
    }
}

const fn tq_node(key: u64) -> TqNode {
    TqNode {
        key,
        link: tail_queue::Link::new(),
    }
}

/// Returns the `i`th head of a pinned array of heads.
fn lane<Q, const N: usize>(heads: Pin<&mut [Q; N]>, i: usize) -> Pin<&mut Q> {
    // SAFETY: an element of a pinned array is pinned too, and nothing
    // moves it out.
    unsafe { heads.map_unchecked_mut(|all| all.get_unchecked_mut(i)) }
}

/// Returns the first head and the `w`th of a pinned array of heads.
fn first_and<Q, const N: usize>(
    heads: Pin<&mut [Q; N]>,
    w: usize,
) -> (Pin<&mut Q>, Pin<&mut Q>) {
    // SAFETY: elements of a pinned array are pinned too, nothing moves
    // them out, and for `w > 0` the two borrows are disjoint.
    unsafe {
        let (first, rest) = heads.get_unchecked_mut().split_at_mut(w);
        (
            Pin::new_unchecked(first.get_unchecked_mut(0)),
            Pin::new_unchecked(rest.get_unchecked_mut(0)),
        )
    }
}

fn singly_list_lifo(nodes: &mut [SlNode]) -> u64 {
    let mut list = SinglyList::<SlAdapter>::new();
    for node in nodes {
        list.push_front(node);
    }
    let mut hash = 0;
    while let Some(node) = list.pop_front() {
        hash = mix(hash, node.key);
    }
    hash
}

fn singly_list_walk(nodes: &mut [SlNode]) -> u64 {
    let mut list = SinglyList::<SlAdapter>::new();
    for node in nodes {
        list.push_front(node);
    }
    let mut hash = 0;
    for _ in 0..WALK_ROUNDS {
        hash = list.iter().fold(hash, |acc, node| mix(acc, node.key));
    }
    hash
}

fn singly_list_churn(nodes: &mut [SlNode]) -> u64 {
    let n = nodes.len();
    let base = nodes.as_mut_ptr();
    let mut list = SinglyList::<SlAdapter>::new();
    for i in 0..n {
        // SAFETY: the index is in bounds; the nodes outlive the list,
        // nothing else reaches them, and they are on no list.
        unsafe { list.push_front_ptr(NonNull::new_unchecked(base.add(i))) };
    }
    for i in 0..CHURN_OPS {
        // SAFETY: the index is in bounds.
        let node =
            unsafe { NonNull::new_unchecked(base.add(churn_index(i, n))) };
        if list.remove_ptr(node.as_ptr()).is_ok() {
            // SAFETY: the node has just left the list and nothing else
            // reaches it.
            unsafe { list.push_front_ptr(node) };
        }
    }
    list.iter().fold(0, |acc, node| mix(acc, node.key))
}

fn list_lifo(nodes: &mut [LNode]) -> u64 {
    let mut list = pin!(List::<LAdapter>::new());
    for node in nodes {
        list.as_mut().push_front(node);
    }
    let mut hash = 0;
    while let Some(node) = list.as_mut().cursor_front_mut().remove_current() {
        hash = mix(hash, node.key);
    }
    hash
}

fn list_walk(nodes: &mut [LNode]) -> u64 {
    let mut list = pin!(List::<LAdapter>::new());
    for node in nodes {
        list.as_mut().push_front(node);
    }
    let mut hash = 0;
    for _ in 0..WALK_ROUNDS {
        hash = list.iter().fold(hash, |acc, node| mix(acc, node.key));
    }
    hash
}

fn list_churn(nodes: &mut [LNode]) -> u64 {
    let n = nodes.len();
    let base = nodes.as_mut_ptr();
    let mut list = pin!(List::<LAdapter>::new());
    for i in 0..n {
        // SAFETY: the index is in bounds; the nodes outlive the list,
        // nothing else reaches them, and they are on no list.
        unsafe {
            list.as_mut()
                .push_front_ptr(NonNull::new_unchecked(base.add(i)));
        }
    }
    for i in 0..CHURN_OPS {
        // SAFETY: the index is in bounds, the node is on this list, which
        // nothing else reaches, and it rejoins the list once it has left.
        unsafe {
            let node = NonNull::new_unchecked(base.add(churn_index(i, n)));
            List::<LAdapter>::remove_ptr(node);
            list.as_mut().push_front_ptr(node);
        }
    }
    list.iter().fold(0, |acc, node| mix(acc, node.key))
}

fn simple_queue_lifo(nodes: &mut [SqNode]) -> u64 {
    let mut queue = pin!(SimpleQueue::<SqAdapter>::new());
    for node in nodes {
        queue.as_mut().push_front(node);
    }
    let mut hash = 0;
    while let Some(node) = queue.as_mut().pop_front() {
        hash = mix(hash, node.key);
    }
    hash
}

fn simple_queue_fifo(nodes: &mut [SqNode]) -> u64 {
    let mut queue = pin!(SimpleQueue::<SqAdapter>::new());
    for node in nodes {
        queue.as_mut().push_back(node);
    }
    let mut hash = 0;
    while let Some(node) = queue.as_mut().pop_front() {
        hash = mix(hash, node.key);
    }
    hash
}

fn simple_queue_walk(nodes: &mut [SqNode]) -> u64 {
    let mut queue = pin!(SimpleQueue::<SqAdapter>::new());
    for node in nodes {
        queue.as_mut().push_back(node);
    }
    let mut hash = 0;
    for _ in 0..WALK_ROUNDS {
        hash = queue.iter().fold(hash, |acc, node| mix(acc, node.key));
    }
    hash
}

fn simple_queue_churn(nodes: &mut [SqNode]) -> u64 {
    let n = nodes.len();
    let base = nodes.as_mut_ptr();
    let mut queue = pin!(SimpleQueue::<SqAdapter>::new());
    for i in 0..n {
        // SAFETY: the index is in bounds; the nodes outlive the queue,
        // nothing else reaches them, and they are on no queue.
        unsafe {
            queue
                .as_mut()
                .push_back_ptr(NonNull::new_unchecked(base.add(i)));
        }
    }
    for i in 0..CHURN_OPS {
        // SAFETY: the index is in bounds.
        let node =
            unsafe { NonNull::new_unchecked(base.add(churn_index(i, n))) };
        if queue.as_mut().remove_ptr(node.as_ptr()).is_ok() {
            // SAFETY: the node has just left the queue and nothing else
            // reaches it.
            unsafe { queue.as_mut().push_front_ptr(node) };
        }
    }
    queue.iter().fold(0, |acc, node| mix(acc, node.key))
}

fn simple_queue_concat(nodes: &mut [SqNode]) -> u64 {
    let mut heads =
        pin!([const { SimpleQueue::<SqAdapter>::new() }; CONCAT_WAYS]);
    for (i, node) in nodes.iter_mut().enumerate() {
        lane(heads.as_mut(), i.wrapping_rem(CONCAT_WAYS)).push_back(node);
    }
    for w in 1..CONCAT_WAYS {
        let (first, other) = first_and(heads.as_mut(), w);
        first.append(other);
    }
    lane(heads.as_mut(), 0)
        .iter()
        .fold(0, |acc, node| mix(acc, node.key))
}

fn tail_queue_fifo(nodes: &mut [TqNode]) -> u64 {
    let mut queue = pin!(TailQueue::<TqAdapter>::new());
    for node in nodes {
        queue.as_mut().push_back(node);
    }
    let mut hash = 0;
    while let Some(node) = queue.as_mut().cursor_front_mut().remove_current() {
        hash = mix(hash, node.key);
    }
    hash
}

fn tail_queue_walk(nodes: &mut [TqNode]) -> u64 {
    let mut queue = pin!(TailQueue::<TqAdapter>::new());
    for node in nodes {
        queue.as_mut().push_back(node);
    }
    let mut hash = 0;
    for _ in 0..WALK_ROUNDS {
        hash = queue.iter().fold(hash, |acc, node| mix(acc, node.key));
    }
    hash
}

fn tail_queue_walk_rev(nodes: &mut [TqNode]) -> u64 {
    let mut queue = pin!(TailQueue::<TqAdapter>::new());
    for node in nodes {
        queue.as_mut().push_back(node);
    }
    let mut hash = 0;
    for _ in 0..WALK_ROUNDS {
        hash = queue
            .iter()
            .rev()
            .fold(hash, |acc, node| mix(acc, node.key));
    }
    hash
}

fn tail_queue_churn(nodes: &mut [TqNode]) -> u64 {
    let n = nodes.len();
    let base = nodes.as_mut_ptr();
    let mut queue = pin!(TailQueue::<TqAdapter>::new());
    for i in 0..n {
        // SAFETY: the index is in bounds; the nodes outlive the queue,
        // nothing else reaches them, and they are on no queue.
        unsafe {
            queue
                .as_mut()
                .push_back_ptr(NonNull::new_unchecked(base.add(i)));
        }
    }
    for i in 0..CHURN_OPS {
        // SAFETY: the index is in bounds, the node is on this queue, and
        // it rejoins the queue once it has left.
        unsafe {
            let node = NonNull::new_unchecked(base.add(churn_index(i, n)));
            queue.as_mut().remove_ptr(node);
            queue.as_mut().push_front_ptr(node);
        }
    }
    queue.iter().fold(0, |acc, node| mix(acc, node.key))
}

fn tail_queue_concat(nodes: &mut [TqNode]) -> u64 {
    let mut heads =
        pin!([const { TailQueue::<TqAdapter>::new() }; CONCAT_WAYS]);
    for (i, node) in nodes.iter_mut().enumerate() {
        lane(heads.as_mut(), i.wrapping_rem(CONCAT_WAYS)).push_back(node);
    }
    for w in 1..CONCAT_WAYS {
        let (first, other) = first_and(heads.as_mut(), w);
        first.append(other);
    }
    lane(heads.as_mut(), 0)
        .iter()
        .fold(0, |acc, node| mix(acc, node.key))
}

/// Times `run` at every size in the group `name`, each call over fresh
/// nodes made by `make`.
fn bench<T>(
    criterion: &mut Criterion,
    name: &str,
    run: fn(&mut [T]) -> u64,
    make: fn(u64) -> T,
) {
    let mut group = criterion.benchmark_group(name);
    for n in SIZES {
        let mut nodes: Vec<T> = (0..).take(n).map(make).collect();
        let _: &mut BenchmarkGroup<'_, WallTime> = group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &n,
            |bencher, _| bencher.iter(|| run(black_box(&mut nodes))),
        );
    }
    group.finish();
}

fn singly_list(criterion: &mut Criterion) {
    bench(criterion, "singly_list/lifo", singly_list_lifo, sl_node);
    bench(criterion, "singly_list/walk", singly_list_walk, sl_node);
    bench(criterion, "singly_list/churn", singly_list_churn, sl_node);
}

fn list(criterion: &mut Criterion) {
    bench(criterion, "list/lifo", list_lifo, l_node);
    bench(criterion, "list/walk", list_walk, l_node);
    bench(criterion, "list/churn", list_churn, l_node);
}

fn simple_queue(criterion: &mut Criterion) {
    bench(criterion, "simple_queue/lifo", simple_queue_lifo, sq_node);
    bench(criterion, "simple_queue/fifo", simple_queue_fifo, sq_node);
    bench(criterion, "simple_queue/walk", simple_queue_walk, sq_node);
    bench(criterion, "simple_queue/churn", simple_queue_churn, sq_node);
    bench(
        criterion,
        "simple_queue/concat",
        simple_queue_concat,
        sq_node,
    );
}

fn tail_queue(criterion: &mut Criterion) {
    bench(criterion, "tail_queue/fifo", tail_queue_fifo, tq_node);
    bench(criterion, "tail_queue/walk", tail_queue_walk, tq_node);
    bench(
        criterion,
        "tail_queue/walk_rev",
        tail_queue_walk_rev,
        tq_node,
    );
    bench(criterion, "tail_queue/churn", tail_queue_churn, tq_node);
    bench(criterion, "tail_queue/concat", tail_queue_concat, tq_node);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);
    targets = singly_list, list, simple_queue, tail_queue
}
criterion_main!(benches);
