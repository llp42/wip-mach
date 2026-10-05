// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/gsync.c and kern/gsync.h:
//   Copyright (C) 2016 Free Software Foundation, Inc.
//   Contributed by Agustina Arzille <avarzille@riseup.net>, 2016.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The global address-based synchronization, which `kern/gsync.c` used to
//! define for `kern/gsync.h`.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::user_access;
use crate::kern::error::Error;
use crate::kern::ipc_sched::{
    thread_will_wait, thread_will_wait_with_timeout,
};
use crate::kern::kmutex::KMutex;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, THREAD_INTERRUPTED, clear_wait, thread_block,
};
use crate::kern::task::{Task, current_task};
use crate::kern::thread::Thread;
use crate::vm::types::{PAGE_SIZE, VmInherit, VmObject, VmProt};
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS;
use crate::vm::vm_map::{EnterRequest, VmMap, trunc_page};
use collections::tail_queue::{self, TailQueue};
use core::cmp::Ordering;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull, addr_of_mut};

/// The `GSYNC_*` bits of <kern/gsync.h>.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Flags(c_int);

impl Flags {
    /// `GSYNC_SHARED`: the address is shared, so the object keys it.
    pub const SHARED: Self = Self(0x01);
    /// `GSYNC_QUAD`: check or write two words.
    pub const QUAD: Self = Self(0x02);
    /// `GSYNC_TIMED`: the wait has a timeout.
    pub const TIMED: Self = Self(0x04);
    /// `GSYNC_BROADCAST`: wake every matching waiter.
    pub const BROADCAST: Self = Self(0x08);
    /// `GSYNC_MUTATE`: write the value before waking.
    pub const MUTATE: Self = Self(0x10);

    /// The `int` the C half passes.
    #[must_use]
    pub const fn from_bits(bits: c_int) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// `GSYNC_NBUCKETS` in kern/gsync.c.
const GSYNC_NBUCKETS: usize = 512;

/// An entry in the global hash table: `struct gsync_hbucket` of kern/gsync.c.
struct Bucket {
    entries: GsyncQueue,
    lock: KMutex,
}

impl Bucket {
    const fn new() -> Self {
        Self {
            entries: GsyncQueue::new(),
            lock: KMutex::new(),
        }
    }
}

/// `gsync_buckets` of kern/gsync.c: the hash table of waiting threads.
static mut GSYNC_BUCKETS: [Bucket; GSYNC_NBUCKETS] =
    [const { Bucket::new() }; GSYNC_NBUCKETS];

/// The bucket at `index`, which every caller derives from the key's hash.
fn bucket(index: usize) -> *mut Bucket {
    // SAFETY: the index is `hash(key) % GSYNC_NBUCKETS`, and the table is a
    // live static that never moves.
    unsafe { addr_of_mut!(GSYNC_BUCKETS).cast::<Bucket>().add(index) }
}

/// `union gsync_key` of kern/gsync.c: what identifies the address a thread
/// waits on.  The C union never compares a task-local key equal to a shared
/// one, so the Rust form keeps the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// A task-local address: the C `local.map`/`local.addr` pair.
    Local { map: usize, addr: VmOffset },
    /// A shared address: the C `shared.obj`/`shared.off` pair.
    Shared { object: usize, offset: VmOffset },
}

/// `MIX2_LL()` in kern/gsync.c.
const fn mix(x: u32, y: u32) -> u32 {
    x.rotate_left(5) ^ y
}

/// `gsync_key_hash()` in kern/gsync.c: mix the key's two words through the
/// C's rotation.
fn hash(key: Key) -> usize {
    let (u, v) = match key {
        Key::Local { map, addr } => (map as u64, addr as u64),
        Key::Shared { object, offset } => (object as u64, offset as u64),
    };
    let mut ret = size_of::<*const c_void>() as u32;
    for word in <[u64; 2]>::from((u, v)) {
        ret = mix(ret, word as u32);
        ret = mix(ret, (word >> 32) as u32);
    }
    ret as usize
}

/// A thread blocked on an address: `struct gsync_waiter` of kern/gsync.c.
pub(crate) struct GsyncWaiter {
    link: tail_queue::Link,
    /// Whether the waiter is on its bucket's list; guarded by the bucket
    /// lock. A waker clears it as it unlinks the waiter, which is how a wait
    /// that ended some other way tells whether it must unlink itself.
    queued: bool,
    key: Key,
    waiter: *mut Thread,
}

tail_queue::adapter!(
    /// The adapter for a waiter's `link` in its bucket's `entries`.
    pub(crate) GsyncWaiterAdapter = GsyncWaiter { link }
);

/// A bucket's waiters, sorted by key: a new waiter goes before the first one
/// with a greater key, and any waiter leaves from the middle.
type GsyncQueue = TailQueue<'static, GsyncWaiterAdapter>;

/// The queue of `bucketp`, pinned for one operation.
///
/// Every operation pins afresh, because `requeue_run()` may name the same
/// bucket twice.
///
/// # Safety
///
/// `bucketp` must be a bucket of `GSYNC_BUCKETS`, which never moves, and the
/// caller must hold its lock for as long as it uses the result.
unsafe fn queue_of<'a>(bucketp: *mut Bucket) -> Pin<&'a mut GsyncQueue> {
    // SAFETY: the bucket never moves, and the lock the caller holds keeps
    // anything else from reaching the queue.
    unsafe { Pin::new_unchecked(&mut *addr_of_mut!((*bucketp).entries)) }
}

/// `struct vm_args` of kern/gsync.c: the object and offset a probe found.
struct VmArgs {
    object: *mut VmObject,
    offset: VmOffset,
}

/// `probe_address()` in kern/gsync.c: look `addr` up in `map` and hand back
/// the locked object and its offset.
fn probe(
    map: *mut VmMap,
    addr: VmOffset,
    flags: Flags,
    args: &mut VmArgs,
) -> Result<(), Error> {
    let mut prot = VmProt::READ;
    if flags.contains(Flags::MUTATE) {
        prot |= VmProt::WRITE;
    }

    let Some(mut map) = NonNull::new(map) else {
        return Err(Error::InvalidAddress);
    };
    // SAFETY: the caller's task holds the live map, and the lookup takes its
    // read lock and returns the object locked, as the C's `keep_map_locked`
    // argument asked.
    match VmMap::lookup(&mut map, addr, prot, true) {
        Ok(found) => {
            args.object = found.object;
            args.offset = found.offset;
            if found.protection.contains(prot) {
                return Ok(());
            }
            // SAFETY: the lookup left the map read-locked and the object
            // locked; the C released both on this path.
            unsafe {
                (*map.as_ptr()).lock.done();
                (*found.object).lock.unlock();
            }
            Err(Error::InvalidAddress)
        }
        Err(_) => Err(Error::InvalidAddress),
    }
}

/// `gsync_prepare_key()` in kern/gsync.c: probe the address, build the key
/// from it, and return the bucket the key hashes to.
fn prepare_key(
    task: &Task,
    addr: VmOffset,
    flags: Flags,
    args: &mut VmArgs,
) -> Result<(Key, usize), Error> {
    probe(task.map.cast::<VmMap>(), addr, flags, args)?;
    let key = if flags.contains(Flags::SHARED) {
        Key::Shared {
            object: args.object as usize,
            offset: args.offset,
        }
    } else {
        Key::Local {
            map: task.map as usize,
            addr,
        }
    };
    Ok((key, hash(key) % GSYNC_NBUCKETS))
}

/// `temp_mapping()` in kern/gsync.c: map `addr`'s page into the kernel, or
/// zero when the mapping fails.
fn temp_mapping(args: &VmArgs, addr: VmOffset, prot: VmProt) -> VmOffset {
    let mut paddr = VM_MIN_KERNEL_ADDRESS;
    let offset = args
        .offset
        .wrapping_sub(addr.wrapping_sub(trunc_page(addr)));
    let request = EnterRequest {
        address: &mut paddr,
        size: PAGE_SIZE,
        mask: 0,
        anywhere: true,
        object: args.object,
        offset,
        needs_copy: false,
        cur_protection: prot,
        max_protection: VmProt::ALL,
        inheritance: VmInherit::COPY,
    };
    // SAFETY: `kernel_map` is the live kernel map, and the caller's probe
    // returned `args.object` locked and referenced.  The C zeroed the address
    // on failure.
    match unsafe { (*KERNEL_MAP.cast::<VmMap>()).enter(request) } {
        Ok(()) => paddr,
        Err(_) => 0,
    }
}

/// `gsync_find_key()` in kern/gsync.c: the first entry not less than `key`,
/// or `None` for the head when there is none.  The flag is true when an entry
/// compared equal.
fn find_key(
    entries: &GsyncQueue,
    key: Key,
) -> (Option<NonNull<GsyncWaiter>>, bool) {
    let mut cursor = entries.cursor_front();
    while let Some(waiter) = cursor.current() {
        match waiter.key.cmp(&key) {
            Ordering::Less => (),
            Ordering::Equal => return (cursor.current_ptr(), true),
            Ordering::Greater => return (cursor.current_ptr(), false),
        }
        cursor.move_next();
    }
    (None, false)
}

/// `dequeue_waiter()` in kern/gsync.c: unlink `waiter` and wake its thread;
/// clearing `queued` does what the C's explicit re-initialization of the link
/// did.
///
/// # Safety
///
/// `waiter` must be linked into `bucketp`'s list, and the caller must hold
/// that bucket locked.
unsafe fn dequeue_waiter(bucketp: *mut Bucket, waiter: NonNull<GsyncWaiter>) {
    unsafe {
        queue_of(bucketp).remove_ptr(waiter);
        (*waiter.as_ptr()).queued = false;
        // SAFETY: the waiter's thread was marked waiting before it blocked,
        // and `clear_wait()` takes the thread lock itself.
        clear_wait((*waiter.as_ptr()).waiter, THREAD_AWAKENED, 0);
    }
}

/// Compare the word(s) the wait tests and release the map lock, releasing
/// the bucket lock too on failure.
///
/// # Safety
///
/// `task_map` must hold the read lock the probe took, `bucketp` the bucket
/// lock, and `args` the locked object the probe returned; `remote` must say
/// whether the waited task is another one.
#[expect(clippy::too_many_arguments)]
unsafe fn wait_compare(
    task_map: *mut VmMap,
    bucketp: *mut Bucket,
    args: &VmArgs,
    remote: bool,
    addr: VmOffset,
    lo: c_uint,
    hi: c_uint,
    flags: Flags,
) -> Result<(), Error> {
    let mut equal;
    if remote {
        let paddr = temp_mapping(args, addr, VmProt::READ);
        if paddr == 0 {
            // SAFETY: the bucket lock and the map's read lock.
            unsafe {
                (*bucketp).lock.unlock();
                (*task_map).lock.done();
            }
            // SAFETY: the reference the caller added, and the failed
            // mapping took none.
            unsafe { crate::vm::vm_object::deallocate(args.object) };
            return Err(Error::MemoryFailure);
        }

        let offset = addr & (PAGE_SIZE - 1);
        let mapped = paddr.wrapping_add(offset);
        // SAFETY: the temporary mapping covers this page, and the C read the
        // first `int`, plus the second under `GSYNC_QUAD`.
        equal = unsafe { (mapped as *const c_uint).read() == lo };
        if flags.contains(Flags::QUAD) {
            equal = equal
                && unsafe { (mapped as *const c_uint).add(1).read() == hi };
        }

        // SAFETY: the mapping is the one just entered; its removal drops the
        // object reference the C's comment named.
        let _ = unsafe {
            (*KERNEL_MAP.cast::<VmMap>()).remove(paddr, paddr + PAGE_SIZE)
        };
    } else {
        let mut value: c_uint = 0;
        // SAFETY: `addr` is the task-local address the probe just validated,
        // and `value` is a local of the size the C copied.
        if unsafe {
            user_access::copyin(
                addr as *const c_void,
                (&raw mut value).cast::<c_void>(),
                size_of::<c_uint>(),
            )
        }
        .is_err()
        {
            // SAFETY: the two locks the lookup and the bucket took.
            unsafe {
                (*task_map).lock.done();
                (*bucketp).lock.unlock();
            }
            return Err(Error::InvalidAddress);
        }

        equal = value == lo;
        if flags.contains(Flags::QUAD) {
            let mut second: c_uint = 0;
            if unsafe {
                user_access::copyin(
                    addr.wrapping_add(size_of::<c_uint>()) as *const c_void,
                    (&raw mut second).cast::<c_void>(),
                    size_of::<c_uint>(),
                )
            }
            .is_err()
            {
                // SAFETY: the same two locks.
                unsafe {
                    (*task_map).lock.done();
                    (*bucketp).lock.unlock();
                }
                return Err(Error::InvalidAddress);
            }
            equal = equal && second == hi;
        }
    }

    // SAFETY: the map's read lock from the lookup.
    unsafe { (*task_map).lock.done() };

    if !equal {
        // SAFETY: the bucket lock taken above.
        unsafe { (*bucketp).lock.unlock() };
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// `gsync_wait()` in kern/gsync.c.
pub(crate) fn wait(
    task: NonNull<Task>,
    addr: VmOffset,
    lo: c_uint,
    hi: c_uint,
    msec: c_uint,
    flags: Flags,
) -> Result<(), Error> {
    if !addr.is_multiple_of(size_of::<c_int>()) {
        return Err(Error::InvalidAddress);
    }

    // SAFETY: the caller promises a live task, and `current_task()` reads the
    // running thread's.
    let remote = task.as_ptr() != unsafe { current_task() };
    let mut args = VmArgs {
        object: ptr::null_mut(),
        offset: 0,
    };
    // SAFETY: the caller promises the live task.
    let (key, bucket_index) =
        prepare_key(unsafe { &*task.as_ptr() }, addr, flags, &mut args)?;

    if remote {
        // The object is returned locked, but the bucket's sleeping lock is
        // taken next, so the C held a reference across it.
        // SAFETY: the lookup returned `args.object` locked.
        unsafe { (*args.object).ref_count += 1 };
    }
    // SAFETY: the lookup returned `args.object` locked.
    unsafe { (*args.object).lock.unlock() };

    // SAFETY: the caller promises the live task.
    let task_map = unsafe { &*task.as_ptr() }.map.cast::<VmMap>();
    let bucketp = bucket(bucket_index);
    // SAFETY: the bucket is live and its mutex serializes every access; the
    // C's `FALSE` is an uninterruptible lock, which cannot fail.
    let _ = unsafe { (*bucketp).lock.lock(false) };

    // SAFETY: `task_map` holds the read lock, `bucketp` the bucket lock, and
    // `args` the object the probe returned and unlocked.
    unsafe {
        wait_compare(task_map, bucketp, &args, remote, addr, lo, hi, flags)?;
    }

    let mut waiter = GsyncWaiter {
        link: tail_queue::Link::new(),
        queued: false,
        key,
        waiter: ptr::null_mut(),
    };
    let waiter_ptr: *mut GsyncWaiter = &raw mut waiter;
    // SAFETY: the bucket lock guards the list.
    let position = find_key(unsafe { &(*bucketp).entries }, key).0;
    // SAFETY: `waiter` is a live local that stays at its address until it is
    // woken, and the bucket lock guards the list it joins.
    unsafe {
        let node = NonNull::new_unchecked(waiter_ptr);
        match position {
            Some(next) => queue_of(bucketp)
                .cursor_mut_from_ptr(next)
                .insert_before_ptr(node),
            None => queue_of(bucketp).push_back_ptr(node),
        }
        (*waiter_ptr).queued = true;
    }

    let thread = per_cpu::thread();
    // SAFETY: `waiter` is a live local; the waker reads the field through the
    // linked node.
    unsafe { (*waiter_ptr).waiter = thread };
    if flags.contains(Flags::TIMED) {
        // SAFETY: the thread is this live, unblocked thread.
        unsafe { thread_will_wait_with_timeout(thread, msec) };
    } else {
        // SAFETY: the thread is this live, unblocked thread.
        unsafe { thread_will_wait(thread) };
    }

    // SAFETY: the bucket lock taken above.
    unsafe { (*bucketp).lock.unlock() };
    // SAFETY: the thread is marked waiting, so the block yields until the
    // wakeup or timeout the wait armed.
    unsafe { thread_block(None) };

    // SAFETY: the waker wrote `wait_result` under the thread lock before
    // waking us.
    let wait_result = unsafe { (*thread).wait_result };
    if wait_result == THREAD_AWAKENED {
        return Ok(());
    }

    // The waker unlinked the node; when the wait ended some other way it is
    // still on the bucket list.
    // SAFETY: the bucket is live and its mutex serializes.
    let _ = unsafe { (*bucketp).lock.lock(false) };
    // SAFETY: the bucket lock guards the flag.
    if unsafe { (*waiter_ptr).queued } {
        // SAFETY: the bucket lock guards the list; the waiter is still
        // linked.
        unsafe {
            queue_of(bucketp).remove_ptr(NonNull::new_unchecked(waiter_ptr));
            (*waiter_ptr).queued = false;
        }
    }
    // SAFETY: the bucket lock taken above.
    unsafe { (*bucketp).lock.unlock() };

    Err(if wait_result == THREAD_INTERRUPTED {
        Error::Interrupted
    } else {
        Error::TimedOut
    })
}

/// `gsync_wake()` in kern/gsync.c.
pub(crate) fn wake(
    task: NonNull<Task>,
    addr: VmOffset,
    val: c_uint,
    flags: Flags,
) -> Result<(), Error> {
    if !addr.is_multiple_of(size_of::<c_int>()) {
        return Err(Error::InvalidAddress);
    }

    let mut args = VmArgs {
        object: ptr::null_mut(),
        offset: 0,
    };
    // SAFETY: the caller promises the live task.
    let (key, bucket_index) =
        prepare_key(unsafe { &*task.as_ptr() }, addr, flags, &mut args)?;

    // SAFETY: the running thread's task, which cannot change here.
    let remote = unsafe { current_task() } != task.as_ptr();
    if remote && flags.contains(Flags::MUTATE) {
        // See `gsync_wait()` on why the reference is taken.
        // SAFETY: the lookup returned `args.object` locked.
        unsafe { (*args.object).ref_count += 1 };
    }
    // SAFETY: the lookup returned `args.object` locked.
    unsafe { (*args.object).lock.unlock() };

    // SAFETY: the caller promises the live task.
    let task_map = unsafe { &*task.as_ptr() }.map.cast::<VmMap>();
    let bucketp = bucket(bucket_index);
    // SAFETY: the bucket is live and its mutex serializes every access.
    let _ = unsafe { (*bucketp).lock.lock(false) };

    if flags.contains(Flags::MUTATE) {
        if remote {
            let paddr =
                temp_mapping(&args, addr, VmProt::READ | VmProt::WRITE);
            if paddr == 0 {
                // SAFETY: the bucket lock and the map's read lock.
                unsafe {
                    (*bucketp).lock.unlock();
                    (*task_map).lock.done();
                }
                // SAFETY: the reference this call added.
                unsafe { crate::vm::vm_object::deallocate(args.object) };
                return Err(Error::MemoryFailure);
            }

            let mapped = paddr.wrapping_add(addr & (PAGE_SIZE - 1));
            // SAFETY: the temporary mapping covers this page.
            unsafe { (mapped as *mut c_uint).write(val) };

            // The C removed from the mapped, unaligned address; its own
            // rounding covers the page.
            // SAFETY: the temporary mapping is live.
            let _ = unsafe {
                (*KERNEL_MAP.cast::<VmMap>())
                    .remove(mapped, mapped + size_of::<c_int>())
            };
        } else {
            // SAFETY: the address is the task-local one the probe validated,
            // and `val` is a local of the size the C copied.
            let copied = unsafe {
                user_access::copyout(
                    (&raw const val).cast::<c_void>(),
                    addr as *mut c_void,
                    size_of::<c_uint>(),
                )
            };
            if copied.is_err() {
                // SAFETY: the bucket lock and the map's read lock.
                unsafe {
                    (*bucketp).lock.unlock();
                    (*task_map).lock.done();
                }
                return Err(Error::InvalidAddress);
            }
        }
    }

    // SAFETY: the map's read lock from the lookup.
    unsafe { (*task_map).lock.done() };

    let (first, exact) = {
        // SAFETY: the bucket lock guards the list.
        let entries = unsafe { &(*bucketp).entries };
        find_key(entries, key)
    };
    let result = match (first, exact) {
        (Some(first), true) => {
            let mut current = Some(first);
            while let Some(waiter) = current {
                // The successor is read before the unlink; a cursor would
                // otherwise advance past it inside `dequeue_waiter()`.
                let next = {
                    // SAFETY: the bucket lock guards the list, and the
                    // waiter is linked into it.
                    let mut cursor = unsafe {
                        queue_of(bucketp).cursor_mut_from_ptr(waiter)
                    };
                    cursor.move_next();
                    cursor.current_ptr()
                };
                // SAFETY: the waiter is linked into the guarded list.
                unsafe { dequeue_waiter(bucketp, waiter) };
                if !flags.contains(Flags::BROADCAST) {
                    break;
                }
                let Some(next) = next else { break };
                // SAFETY: the next waiter lives inside this list; its key is
                // a plain scalar.
                if unsafe { (*next.as_ptr()).key } != key {
                    break;
                }
                current = Some(next);
            }
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    };

    // SAFETY: the bucket lock taken above.
    unsafe { (*bucketp).lock.unlock() };
    result
}

/// The splice loop of `gsync_requeue()` in kern/gsync.c: move the run of
/// waiters that shares `src_key`, from `input` on in `bp1`, to just after
/// `output` in `bp2`, re-keyed to `dst_key`, waking the first when
/// `wake_one`.  `output` of `None` anchors the run at the front, as the C's
/// head anchor did.
///
/// # Safety
///
/// Both buckets must be live and locked, `input` linked in `bp1`, the run
/// must stay at its addresses while linked, and `nw`/`flags` must be the
/// requeue's move and wake requests.
#[expect(clippy::too_many_arguments)]
unsafe fn requeue_run(
    bp1: *mut Bucket,
    bp2: *mut Bucket,
    input: NonNull<GsyncWaiter>,
    output: Option<NonNull<GsyncWaiter>>,
    src_key: Key,
    dst_key: Key,
    nw: c_uint,
    wake_one: bool,
    flags: Flags,
) {
    let mut anchor = output;
    // `bp1` and `bp2` may be the same list, so each operation below pins its
    // own short borrow of a bucket's queue.
    let mut current = input;
    let mut moved: c_uint = 0;
    loop {
        // SAFETY: the waiter is live and guarded by the bucket locks.
        unsafe { (*current.as_ptr()).key = dst_key };
        // The successor is read before the unlink.
        // SAFETY: the waiter is linked into the `bp1` list.
        let next = {
            let mut cursor =
                unsafe { queue_of(bp1).cursor_mut_from_ptr(current) };
            cursor.move_next();
            cursor.current_ptr()
        };
        // SAFETY: the contract keeps the run linked and live, and both
        // buckets are locked.
        unsafe {
            queue_of(bp1).remove_ptr(current);
            match anchor {
                Some(anchor) => queue_of(bp2)
                    .cursor_mut_from_ptr(anchor)
                    .insert_after_ptr(current),
                None => queue_of(bp2).push_front_ptr(current),
            }
        }
        anchor = Some(current);
        moved += 1;

        let next_matches = next.is_some_and(|next| {
            // SAFETY: the next waiter lives inside this list; its key is a
            // plain scalar.
            unsafe { (*next.as_ptr()).key == src_key }
        });
        let proceed = if flags.contains(Flags::BROADCAST) {
            next_matches
        } else {
            moved < nw && next_matches
        };
        if !proceed {
            break;
        }
        let Some(next) = next else { break };
        current = next;
    }

    if wake_one {
        // SAFETY: `input` moved to `bp2`; it is the first waiter the C
        // woke.
        unsafe { dequeue_waiter(bp2, input) };
    }
}

/// `gsync_requeue()` in kern/gsync.c.
pub(crate) fn requeue(
    task: NonNull<Task>,
    src: VmOffset,
    dst: VmOffset,
    wake_one: bool,
    flags: Flags,
) -> Result<(), Error> {
    if !src.is_multiple_of(size_of::<c_int>())
        || !dst.is_multiple_of(size_of::<c_int>())
    {
        return Err(Error::InvalidAddress);
    }

    // SAFETY: the caller promises the live task.
    let task_map = unsafe { &*task.as_ptr() }.map.cast::<VmMap>();
    let mut args = VmArgs {
        object: ptr::null_mut(),
        offset: 0,
    };
    // SAFETY: the caller promises the live task.
    let (src_key, src_index) =
        prepare_key(unsafe { &*task.as_ptr() }, src, flags, &mut args)?;
    // SAFETY: the map and object locks the lookup returned.
    unsafe {
        (*task_map).lock.done();
        (*args.object).lock.unlock();
    }

    // SAFETY: the map and object locks the lookup returned; for the second
    // probe; `requeue` maps nothing, so the object lock is released
    // before the buckets are.
    let (dst_key, dst_index) =
        prepare_key(unsafe { &*task.as_ptr() }, dst, flags, &mut args)?;
    // SAFETY: the map and object locks the second lookup returned;
    // `requeue` maps nothing, so the object lock is released
    // before the buckets are.
    unsafe {
        (*task_map).lock.done();
        (*args.object).lock.unlock();
    }

    let nw = 1 + c_uint::from(wake_one);
    let bp1 = bucket(src_index);
    let bp2 = bucket(dst_index);
    // Acquire the locks in address order, as the C did, to prevent deadlocks.
    // SAFETY: both buckets are live; every access below is under their locks.
    if bp1 == bp2 {
        // SAFETY: both buckets are live and this branch locks one.
        let _ = unsafe { (*bp1).lock.lock(false) };
    } else if (bp1 as usize) < (bp2 as usize) {
        // SAFETY: both buckets are live; the lock order is by address.
        let _ = unsafe { (*bp1).lock.lock(false) };
        // SAFETY: both buckets are live; the lock order is by address.
        let _ = unsafe { (*bp2).lock.lock(false) };
    } else {
        // SAFETY: both buckets are live; the lock order is by address.
        let _ = unsafe { (*bp2).lock.lock(false) };
        // SAFETY: both buckets are live; the lock order is by address.
        let _ = unsafe { (*bp1).lock.lock(false) };
    }

    let (input, exact) = {
        // SAFETY: the bucket locks guard both lists.
        let entries = unsafe { &(*bp1).entries };
        find_key(entries, src_key)
    };
    let result = match (input, exact) {
        (Some(input), true) => {
            // We need a waiter that points one past the waiters in the
            // source queue.
            let output = {
                // SAFETY: the bucket locks guard both lists.
                let entries = unsafe { &(*bp2).entries };
                find_key(entries, dst_key).0
            };
            // SAFETY: both buckets are locked, and `find_key` proved `input`
            // is linked in `bp1`.
            unsafe {
                requeue_run(
                    bp1, bp2, input, output, src_key, dst_key, nw, wake_one,
                    flags,
                );
            }
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    };

    // SAFETY: the bucket locks taken above.
    unsafe {
        (*bp1).lock.unlock();
        if bp1 != bp2 {
            (*bp2).lock.unlock();
        }
    }
    result
}

/// `gsync_setup()` in kern/gsync.c.
pub(crate) fn setup() {
    for i in 0..GSYNC_NBUCKETS {
        // SAFETY: `kern/startup.c` calls this once during the boot, before
        // any other CPU or thread can reach the table.
        unsafe {
            (*bucket(i)).entries = GsyncQueue::new();
        };
    }
}
