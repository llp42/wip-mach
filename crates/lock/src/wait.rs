// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The wait table: hashed queues, keyed by lock address, where parked
//! threads wait.
//!
//! A sleeping lock parks a thread under a key, the address of the lock
//! word, and wakes it by the same key.  Keys hash to a [`Bucket`]: a
//! ticket lock, always taken inside an irq-quiet section so that an
//! unpark may come from an interrupt handler, over a queue of waiters in
//! arrival order.  Unrelated keys may share a bucket; every walk skips
//! the waiters of other keys.  An unpark picks a key's waiters in arrival
//! order.
//!
//! A waiter lives on its parked thread's stack.  Its unparker takes it
//! off the queue, sets its woken flag and unparks its thread, all under
//! the bucket lock; setting the flag is the unparker's last touch of the
//! waiter.  So a waiter is on its queue exactly while its flag is clear,
//! as seen under the bucket lock.  A woken thread takes the bucket lock
//! once more before its park returns: its unparker is then done with the
//! thread as well, which may exit and have its record freed at once.

#[cfg(debug_assertions)]
use crate::checker;
use crate::platform::{Platform, ThreadRef};
use collections::tail_queue::{self, TailQueue};
use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::pin::{Pin, pin};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The high half of a bucket's ticket word holds the next ticket to hand
/// out and the low half the ticket now served.
const NEXT_SHIFT: u32 = 16;
const ONE_TICKET: u32 = 1 << NEXT_SHIFT;
const SERVING: u32 = ONE_TICKET - 1;

/// Returns whether both halves of the ticket word are equal, so that no
/// ticket is outstanding and none is being served.
const fn is_free(word: u32) -> bool {
    word >> NEXT_SHIFT == word & SERVING
}

/// Hands out the next ticket and spins, only reading, until it is served.
fn take(word: &AtomicU32) {
    let taken = word.fetch_add(ONE_TICKET, Ordering::Acquire);
    let ticket = taken >> NEXT_SHIFT;
    let mut serving = taken & SERVING;
    debug_assert!(
        ticket.wrapping_sub(serving) & SERVING != SERVING,
        "a wait-table bucket is held or waited for by 65535 threads: the \
         next would see it free",
    );
    while serving != ticket {
        core::hint::spin_loop();
        serving = word.load(Ordering::Acquire) & SERVING;
    }
}

/// Serves the next ticket, releasing the bucket.
///
/// # Safety
///
/// The caller holds the bucket lock.
unsafe fn serve_next(word: &AtomicU32) {
    // The holder is the only writer of the now-serving half, so a relaxed
    // read sees the ticket it was served, and advancing the half by hand
    // keeps a wrap from carrying into the next ticket.
    let seen = word.load(Ordering::Relaxed);
    debug_assert!(!is_free(seen), "a bucket is unlocked while free");
    let serving = seen & SERVING;
    if serving == SERVING {
        let _ = word.fetch_sub(SERVING, Ordering::Release);
    } else {
        let _ = word.fetch_add(1, Ordering::Release);
    }
}

/// Enters an irq-quiet section with no guard, for a raw lock whose unlock
/// may run in another function.
fn enter_irq_quiet<P: Platform>() {
    P::irq_quiet_enter();
    #[cfg(debug_assertions)]
    checker::section_enter::<P>();
}

/// Leaves an irq-quiet section entered with [`enter_irq_quiet`].
///
/// # Safety
///
/// The running thread entered an irq-quiet section that it has not left.
unsafe fn exit_irq_quiet<P: Platform>() {
    #[cfg(debug_assertions)]
    checker::section_exit::<P>();
    unsafe { P::irq_quiet_exit() };
}

/// What a waiter tells its unparker about itself, such as whether it
/// waits to read or to write.
pub(crate) type Token = usize;

/// A parked thread's entry in its bucket's queue; on the thread's stack.
struct Waiter {
    /// Guarded by the bucket lock.
    link: tail_queue::Link,
    key: usize,
    token: Token,
    thread: ThreadRef,
    /// A flag on the parked thread's stack, apart from the node, so the
    /// thread polls it without touching a node its unparker holds.
    woken: NonNull<AtomicBool>,
}

tail_queue::adapter!(WaiterAdapter = Waiter { link });

/// Waiters leave from the middle when an unpark picks some of a key's
/// waiters and not others, and by address when a parked thread unwinds.
type Queue = TailQueue<'static, WaiterAdapter>;

/// One wait-table bucket: the queue of every thread parked under a key
/// that hashes here, and the lock that guards it.
///
/// The lock is taken inside an irq-quiet section, so an unpark may come
/// from anywhere, including an interrupt handler.  A bucket holds
/// waiters only while its wait table is borrowed for `'static`, so it
/// never moves while it holds them.
pub struct Bucket {
    lock: AtomicU32,
    queue: UnsafeCell<Queue>,
}

// SAFETY: the queue is reached only under the bucket lock.
unsafe impl Sync for Bucket {}

impl Bucket {
    /// Returns an empty bucket.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lock: AtomicU32::new(0),
            queue: UnsafeCell::new(TailQueue::new()),
        }
    }

    /// Takes the bucket lock, inside an irq-quiet section.
    fn lock<P: Platform>(&'static self) -> Locked<P> {
        enter_irq_quiet::<P>();
        take(&self.lock);
        Locked {
            bucket: self,
            platform: PhantomData,
            not_send: PhantomData,
        }
    }
}

impl Default for Bucket {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bucket").finish_non_exhaustive()
    }
}

/// A held bucket lock; releases it and leaves its section when dropped.
struct Locked<P: Platform> {
    bucket: &'static Bucket,
    platform: PhantomData<fn() -> P>,
    not_send: PhantomData<*const ()>,
}

impl<P: Platform> Locked<P> {
    #[allow(
        clippy::needless_pass_by_ref_mut,
        reason = "the exclusive borrow keeps `f` from reaching the queue \
                  a second time"
    )]
    fn with_queue<R>(&mut self, f: impl FnOnce(Pin<&mut Queue>) -> R) -> R {
        debug_assert!(
            !is_free(self.bucket.lock.load(Ordering::Relaxed)),
            "wait-table queue reached with its bucket lock free",
        );
        // SAFETY: the bucket lock is held, so this is the only access to
        // the queue, and the bucket is borrowed for `'static`, so it never
        // moves again.
        f(unsafe { Pin::new_unchecked(&mut *self.bucket.queue.get()) })
    }
}

impl<P: Platform> Drop for Locked<P> {
    fn drop(&mut self) {
        // SAFETY: this guard took the bucket lock and entered the section
        // on this thread, since it is not `Send`.
        unsafe {
            serve_next(&self.bucket.lock);
            exit_irq_quiet::<P>();
        }
    }
}

/// Multiplies a key into a hash: the golden ratio, as a fraction of the
/// word, spreads nearby addresses over far-apart buckets.
#[cfg(target_pointer_width = "64")]
const GOLDEN: usize = 0x9E37_79B9_7F4A_7C15;
#[cfg(target_pointer_width = "32")]
const GOLDEN: usize = 0x9E37_79B9;

/// The hashed queues every sleeping lock of a platform waits in.
pub struct WaitTable {
    buckets: &'static [Bucket],
}

impl WaitTable {
    /// Returns a wait table over `buckets`.
    ///
    /// # Panics
    ///
    /// Panics if `buckets` is empty.
    #[must_use]
    pub const fn new(buckets: &'static [Bucket]) -> Self {
        assert!(!buckets.is_empty(), "a wait table needs a bucket");
        Self { buckets }
    }

    const fn bucket(&'static self, key: usize) -> &'static Bucket {
        let hash = key.wrapping_mul(GOLDEN) >> (usize::BITS / 2);
        &self.buckets[hash % self.buckets.len()]
    }
}

impl fmt::Debug for WaitTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitTable")
            .field("buckets", &self.buckets)
            .finish_non_exhaustive()
    }
}

/// What an unpark did, as its callback and caller see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnparkResult {
    /// How many threads it woke.
    pub(crate) unparked: usize,
    /// Whether threads stay parked under the key.
    pub(crate) have_more: bool,
    /// The first thread it picked, the longest waiting.
    pub(crate) first: Option<ThreadRef>,
}

/// Parks the running thread under `key` until an unpark of `key` picks
/// it; may sleep, so it must not be called inside a section.
///
/// `validate` runs under the bucket lock, before the thread is queued:
/// a lock's unlocker takes the same bucket lock to wake it, so what
/// `validate` reads cannot change unseen until the thread is queued.  If
/// it returns false, the thread is not queued and `park` returns false at
/// once.  Returns true once an unpark has woken the thread.
///
/// # Panics
///
/// Panics if the order checker or [`Platform::park`] does, as the test
/// platform does inside a section; where panics unwind, the thread first
/// leaves the queue.
pub(crate) fn park<P: Platform>(
    key: usize,
    token: Token,
    validate: &mut dyn FnMut() -> bool,
) -> bool {
    let woken = AtomicBool::new(false);
    let mut waiter = Waiter {
        link: tail_queue::Link::new(),
        key,
        token,
        thread: P::current(),
        woken: NonNull::from(&woken),
    };
    let node = NonNull::from(&mut waiter);
    let bucket = P::wait_table().bucket(key);
    let mut locked = bucket.lock::<P>();
    let queued = validate();
    if queued {
        // SAFETY: the waiter stays on this frame, untouched by name, until
        // this function returns, which it does only once the waiter left
        // the queue: after its flag is set, or through `Unqueue` when
        // unwinding.
        locked.with_queue(|queue| unsafe { queue.push_back_ptr(node) });
    }
    drop(locked);
    queued && sleep::<P>(bucket, node, &woken)
}

/// Sleeps until `woken` is set, once the waiter at `node` is queued in
/// `bucket`; returns true.
///
/// # Panics
///
/// As [`park`], whose waiter first leaves its queue.
fn sleep<P: Platform>(
    bucket: &'static Bucket,
    node: NonNull<Waiter>,
    woken: &AtomicBool,
) -> bool {
    #[cfg(panic = "unwind")]
    let unqueue = Unqueue::<P> {
        bucket,
        node,
        woken,
        platform: PhantomData,
    };
    #[cfg(not(panic = "unwind"))]
    let _ = node;
    #[cfg(debug_assertions)]
    checker::may_sleep::<P>();
    while !woken.load(Ordering::Acquire) {
        P::park();
    }
    #[cfg(panic = "unwind")]
    core::mem::forget(unqueue);
    // The flag can be seen set while the unparker, still holding the
    // bucket lock, has yet to unpark this thread.
    drop(bucket.lock::<P>());
    true
}

/// Takes an unwinding thread's waiter off its queue if no unparker has,
/// before its frame goes; forgotten once the thread is woken.
#[cfg(panic = "unwind")]
struct Unqueue<'a, P: Platform> {
    bucket: &'static Bucket,
    node: NonNull<Waiter>,
    woken: &'a AtomicBool,
    platform: PhantomData<fn() -> P>,
}

#[cfg(panic = "unwind")]
impl<P: Platform> Drop for Unqueue<'_, P> {
    fn drop(&mut self) {
        let mut locked = self.bucket.lock::<P>();
        // An unparker may have taken the waiter since the thread last
        // looked; under the bucket lock, the flag says for sure.
        if !self.woken.load(Ordering::Relaxed) {
            locked.with_queue(|queue| {
                debug_assert!(
                    queue.iter().any(|queued| core::ptr::eq(
                        queued,
                        self.node.as_ptr()
                    )),
                    "unwinding waiter with a clear flag is not on its queue",
                );
                // SAFETY: under the bucket lock, a clear flag means the
                // waiter is still on this bucket's queue.
                unsafe { queue.remove_ptr(self.node) };
            });
        }
    }
}

/// Picks the waiters of `key` that `pick` takes, wakes them, and returns
/// what it did.
///
/// Walks the key's waiters in arrival order, offering each to `pick` in
/// turn until it declines one or none is left.  `grant` then runs under the
/// bucket lock, before any picked thread wakes, so it can hand the lock
/// over in its word while no waiter can queue or leave.  Neither callback
/// may sleep or take a lock that is not a spin lock.  May be called from
/// anywhere, including an irq-quiet section.
pub(crate) fn unpark<P: Platform>(
    key: usize,
    pick: &mut dyn FnMut(Token) -> bool,
    grant: &mut dyn FnMut(UnparkResult),
) -> UnparkResult {
    let mut locked = P::wait_table().bucket(key).lock::<P>();
    locked.with_queue(|mut queue| {
        let mut picked = pin!(Queue::new());
        let mut result = UnparkResult {
            unparked: 0,
            have_more: false,
            first: None,
        };
        while let Some(top) = first_of(&queue, key)
            // SAFETY: a waiter stays live while it is on the queue.
            .filter(|top| pick(unsafe { top.as_ref() }.token))
        {
            // SAFETY: `top` is a waiter on this queue, which the bucket
            // lock guards, and joins `picked` to be woken below.
            let waiter = unsafe {
                queue.as_mut().remove_ptr(top);
                picked.as_mut().push_back_ptr(top);
                top.as_ref()
            };
            result.first = result.first.or(Some(waiter.thread));
            result.unparked += 1;
        }
        result.have_more = first_of(&queue, key).is_some();
        grant(result);
        while let Some(waiter) =
            picked.as_mut().cursor_front_mut().remove_current()
        {
            let thread = waiter.thread;
            // SAFETY: the waiter's thread polls this flag until it is set
            // and only then frees it; nothing touches the waiter after.
            let woken = unsafe { waiter.woken.as_ref() };
            debug_assert!(
                !woken.load(Ordering::Relaxed),
                "a queued waiter was woken already: its thread may have \
                 freed it",
            );
            woken.store(true, Ordering::Release);
            P::unpark(thread);
        }
        result
    })
}

/// Returns the longest waiting waiter of `key` in `queue`, by the pointer
/// it was queued with: the unpark that takes it off writes through that
/// pointer, which one made from a `&Waiter` would not allow.
fn first_of(queue: &Queue, key: usize) -> Option<NonNull<Waiter>> {
    let mut cursor = queue.cursor_front();
    loop {
        if cursor.current()?.key == key {
            return cursor.current_ptr();
        }
        cursor.move_next();
    }
}

/// Wakes the longest waiting thread parked under `key`, if any; as
/// [`unpark`].
pub(crate) fn unpark_one<P: Platform>(
    key: usize,
    grant: &mut dyn FnMut(UnparkResult),
) -> UnparkResult {
    let mut picked = false;
    unpark::<P>(key, &mut |_| !core::mem::replace(&mut picked, true), grant)
}
