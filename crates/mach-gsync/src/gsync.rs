// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! [`Gsync`]: the table of threads waiting on an address, whose methods are
//! the `gsync_wait`, `gsync_wake` and `gsync_requeue` calls.

use crate::bucket::Bucket;
use crate::error::Error;
use crate::platform::Platform;
use crate::probe::Probe;
use crate::types::{Flags, Key};
use crate::waiter::{Waiter, WaiterQueue, find_key};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::pin::pin;
use core::ptr::NonNull;
use lock::RawMutex;
use lock::lock_api::RawMutex as _;
use mach_vm::param::VmOffset;
use mach_vm::platform::{THREAD_AWAKENED, THREAD_INTERRUPTED};
use mach_vm::types::{PAGE_SIZE, VmProt};
use mach_vm::vm_map::VmMap;

/// The number of buckets in the waiter hash table.
const GSYNC_NBUCKETS: usize = 512;

/// The hash table of waiting threads, which the platform keeps in one
/// static; the gsync calls are its methods.
pub struct Gsync<P: Platform> {
    buckets: [Bucket<P>; GSYNC_NBUCKETS],
    /// Held by a requeue across both of its buckets, one locked at a time,
    /// and by a waiter that gives up while it finds its bucket: no waiter is
    /// then seen between two buckets, and its key holds still.  It is
    /// taken before a bucket, never beside one.
    requeue: RawMutex<P::Lock>,
}

// SAFETY: each bucket's lock serializes every access to its waiters.
unsafe impl<P: Platform> Sync for Gsync<P> {}

impl<P: Platform> Default for Gsync<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Mixes `y` into `x` for the key hash.
const fn mix(x: u32, y: u32) -> u32 {
    x.rotate_left(5) ^ y
}

/// Mixes the key's two words into a hash, as the C did over its key union.
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

/// Compare the word(s) the wait tests and release the map lock, releasing
/// the bucket lock too on failure.
///
/// # Safety
///
/// `map` must hold the read lock the lookup took, `bucket` the bucket lock,
/// and `probe` the object the lookup returned; `remote` must say whether the
/// waited task is another one.
#[expect(clippy::too_many_arguments)]
unsafe fn wait_compare<P: Platform>(
    map: *mut VmMap<P>,
    bucket: *const Bucket<P>,
    probe: &Probe,
    remote: bool,
    addr: VmOffset,
    lo: c_uint,
    hi: c_uint,
    flags: Flags,
) -> Result<(), Error> {
    let mut equal;
    if remote {
        let paddr = probe.map_page::<P>(addr, VmProt::READ);
        if paddr == 0 {
            // SAFETY: the bucket lock and the map's read lock.
            unsafe {
                (*bucket).lock.unlock();
                (*map).lock.unlock();
            }
            // SAFETY: the reference the caller added, and the failed
            // mapping took none.
            unsafe { mach_vm::vm_object::deallocate::<P>(probe.object) };
            return Err(Error::MemoryFailure);
        }

        let offset = addr & (PAGE_SIZE - 1);
        let mapped = paddr.wrapping_add(offset);
        // SAFETY: the temporary mapping covers this page, and the check reads
        // the first `int`, plus the second with `Flags::QUAD`.
        equal = unsafe { (mapped as *const c_uint).read() == lo };
        if flags.contains(Flags::QUAD) {
            equal = equal
                && unsafe { (mapped as *const c_uint).add(1).read() == hi };
        }

        // SAFETY: the mapping is the one just entered; its removal drops the
        // object reference the C's comment named.
        let _ = unsafe {
            (*P::state().kernel_map()).remove(paddr, paddr + PAGE_SIZE)
        };
    } else {
        let mut value: c_uint = 0;
        // SAFETY: `addr` is the task-local address the lookup just
        // validated.
        if unsafe { P::copyin_into(addr as *const c_void, &mut value) }
            .is_err()
        {
            // SAFETY: the two locks the lookup and the bucket took.
            unsafe {
                (*map).lock.unlock();
                (*bucket).lock.unlock();
            }
            return Err(Error::InvalidAddress);
        }

        equal = value == lo;
        if flags.contains(Flags::QUAD) {
            let mut second: c_uint = 0;
            if unsafe {
                P::copyin_into(
                    addr.wrapping_add(size_of::<c_uint>()) as *const c_void,
                    &mut second,
                )
            }
            .is_err()
            {
                // SAFETY: the same two locks.
                unsafe {
                    (*map).lock.unlock();
                    (*bucket).lock.unlock();
                }
                return Err(Error::InvalidAddress);
            }
            equal = equal && second == hi;
        }
    }

    // SAFETY: the map's read lock from the lookup.
    unsafe { (*map).lock.unlock() };

    if !equal {
        // SAFETY: the bucket lock taken above.
        unsafe { (*bucket).lock.unlock() };
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

impl<P: Platform> Gsync<P> {
    /// The table with no waiter.
    #[must_use]
    #[allow(
        clippy::large_stack_arrays,
        reason = "one static is built from it, once, at boot; each bucket \
                  carries its lock's name, which is what made it large"
    )]
    pub const fn new() -> Self {
        Self {
            buckets: [const { Bucket::new() }; GSYNC_NBUCKETS],
            requeue: RawMutex::named("gsync requeue"),
        }
    }

    /// The bucket `key` hashes to.
    fn bucket(&self, key: Key) -> *const Bucket<P> {
        let index = hash(key) % GSYNC_NBUCKETS;
        // SAFETY: the index is below the table's length, and the table does
        // not move while a call borrows it.
        unsafe { self.buckets.as_ptr().add(index) }
    }

    /// Waits on `addr` in `map` while it holds `lo` (and `hi` with
    /// [`Flags::QUAD`]), for up to `msec` milliseconds with
    /// [`Flags::TIMED`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAddress`] when `addr` is not word-aligned or not
    /// readable in `map`, [`Error::MemoryFailure`] when another task's page
    /// cannot be mapped, [`Error::InvalidArgument`] when the word differs,
    /// and [`Error::Interrupted`] or [`Error::TimedOut`] when the wait ends
    /// without a wakeup.
    ///
    /// # Safety
    ///
    /// Thread context, holding no lock; `map` must be null or the live map
    /// of a task the caller holds.
    pub unsafe fn wait(
        &self,
        map: *mut VmMap<P>,
        addr: VmOffset,
        lo: c_uint,
        hi: c_uint,
        msec: c_uint,
        flags: Flags,
    ) -> Result<(), Error> {
        if !addr.is_multiple_of(size_of::<c_int>()) {
            return Err(Error::InvalidAddress);
        }

        let remote = map != P::current_map();
        let probe = Probe::lookup(map, addr, flags)?;
        let key = probe.key(map, addr, flags);

        if remote {
            // The object is returned locked, but the bucket's sleeping lock
            // is taken next, so the C held a reference across it.
            // SAFETY: the lookup returned the object locked.
            unsafe { (*probe.object).ref_count += 1 };
        }
        // SAFETY: the lookup returned the object locked.
        unsafe { (*probe.object).lock.unlock() };

        let bucket = self.bucket(key);
        // SAFETY: the bucket lives as long as `self`; the C took it
        // uninterruptibly, as the mutex always waits.
        unsafe { (*bucket).lock.lock() };

        // SAFETY: `map` holds the read lock, `bucket` the bucket lock, and
        // `probe` the object the lookup returned and unlocked.
        unsafe {
            wait_compare(map, bucket, &probe, remote, addr, lo, hi, flags)?;
        }

        let mut waiter = Waiter::new(key);
        let waiter_ptr: *mut Waiter = &raw mut waiter;
        // SAFETY: the bucket lock guards the list.
        let position = unsafe { find_key(&Bucket::waiters(bucket), key) }.0;
        // SAFETY: `waiter` is a live local that stays at its address until it
        // is woken, and the bucket lock guards the list it joins.
        unsafe {
            let node = NonNull::new_unchecked(waiter_ptr);
            match position {
                Some(next) => Bucket::waiters(bucket)
                    .cursor_mut_from_ptr(next)
                    .insert_before_ptr(node),
                None => Bucket::waiters(bucket).push_back_ptr(node),
            }
            (*waiter_ptr).queued = true;
        }

        // SAFETY: `waiter` is a live local; the waker reads the field through
        // the linked node.
        unsafe { (*waiter_ptr).thread = P::current_thread().as_ptr() };
        // SAFETY: thread context, and the thread is not yet waiting.
        unsafe { P::will_wait(flags.contains(Flags::TIMED).then_some(msec)) };

        // SAFETY: the bucket lock taken above.
        unsafe { (*bucket).lock.unlock() };
        // SAFETY: the thread is marked waiting, so the block yields until the
        // wakeup or timeout the wait armed.
        unsafe { P::thread_block(None) };

        // SAFETY: thread context; the waker wrote the result under the
        // thread lock before waking us.
        let wait_result = unsafe { P::wait_result() };
        if wait_result == THREAD_AWAKENED {
            return Ok(());
        }

        // The waker unlinked the node; when the wait ended some other way it
        // is still on a bucket list, which a requeue may have changed.
        self.requeue.lock();
        // SAFETY: the requeue lock keeps the key still.
        let bucket = self.bucket(unsafe { (*waiter_ptr).key });
        // SAFETY: the bucket lives as long as `self`.
        unsafe { (*bucket).lock.lock() };
        // SAFETY: the bucket lock guards the flag.
        if unsafe { (*waiter_ptr).queued } {
            // SAFETY: the bucket lock guards the list; the waiter is still
            // linked.
            unsafe {
                Bucket::waiters(bucket)
                    .remove_ptr(NonNull::new_unchecked(waiter_ptr));
                (*waiter_ptr).queued = false;
            }
        }
        // SAFETY: the bucket lock taken above.
        unsafe { (*bucket).lock.unlock() };
        // SAFETY: the requeue lock taken above.
        unsafe { self.requeue.unlock() };

        Err(if wait_result == THREAD_INTERRUPTED {
            Error::Interrupted
        } else {
            Error::TimedOut
        })
    }

    /// Wakes one waiter on `addr` in `map`, or every one with
    /// [`Flags::BROADCAST`], writing `val` first with [`Flags::MUTATE`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAddress`] when `addr` is not word-aligned or not
    /// accessible in `map`, [`Error::MemoryFailure`] when another task's page
    /// cannot be mapped, and [`Error::InvalidArgument`] when no thread waits
    /// on the address.
    ///
    /// # Safety
    ///
    /// Thread context, holding no lock; `map` must be null or the live map
    /// of a task the caller holds.
    pub unsafe fn wake(
        &self,
        map: *mut VmMap<P>,
        addr: VmOffset,
        val: c_uint,
        flags: Flags,
    ) -> Result<(), Error> {
        if !addr.is_multiple_of(size_of::<c_int>()) {
            return Err(Error::InvalidAddress);
        }

        let probe = Probe::lookup(map, addr, flags)?;
        let key = probe.key(map, addr, flags);

        let remote = P::current_map() != map;
        if remote && flags.contains(Flags::MUTATE) {
            // See `wait()` on why the reference is taken.
            // SAFETY: the lookup returned the object locked.
            unsafe { (*probe.object).ref_count += 1 };
        }
        // SAFETY: the lookup returned the object locked.
        unsafe { (*probe.object).lock.unlock() };

        let bucket = self.bucket(key);
        // SAFETY: the bucket lives as long as `self`.
        unsafe { (*bucket).lock.lock() };

        if flags.contains(Flags::MUTATE) {
            if remote {
                let paddr =
                    probe.map_page::<P>(addr, VmProt::READ | VmProt::WRITE);
                if paddr == 0 {
                    // SAFETY: the bucket lock and the map's read lock.
                    unsafe {
                        (*bucket).lock.unlock();
                        (*map).lock.unlock();
                    }
                    // SAFETY: the reference this call added.
                    unsafe {
                        mach_vm::vm_object::deallocate::<P>(probe.object);
                    }
                    return Err(Error::MemoryFailure);
                }

                let mapped = paddr.wrapping_add(addr & (PAGE_SIZE - 1));
                // SAFETY: the temporary mapping covers this page.
                unsafe { (mapped as *mut c_uint).write(val) };

                // The C removed from the mapped, unaligned address; its own
                // rounding covers the page.
                // SAFETY: the temporary mapping is live.
                let _ = unsafe {
                    (*P::state().kernel_map())
                        .remove(mapped, mapped + size_of::<c_int>())
                };
            } else {
                // SAFETY: the address is the task-local one the lookup
                // validated, and `val` is a local of the size the C copied.
                let copied = unsafe {
                    P::copyout(
                        (&raw const val).cast::<c_void>(),
                        addr as *mut c_void,
                        size_of::<c_uint>(),
                    )
                };
                if copied.is_err() {
                    // SAFETY: the bucket lock and the map's read lock.
                    unsafe {
                        (*bucket).lock.unlock();
                        (*map).lock.unlock();
                    }
                    return Err(Error::InvalidAddress);
                }
            }
        }

        // SAFETY: the map's read lock from the lookup.
        unsafe { (*map).lock.unlock() };

        // SAFETY: the bucket lock guards the list.
        let (first, exact) =
            unsafe { find_key(&Bucket::waiters(bucket), key) };
        let result = match (first, exact) {
            (Some(first), true) => {
                let mut current = Some(first);
                while let Some(waiter) = current {
                    // The successor is read before the unlink; a cursor would
                    // otherwise advance past it inside `Bucket::wake()`.
                    let next = {
                        // SAFETY: the bucket lock guards the list, and the
                        // waiter is linked into it.
                        let mut cursor = unsafe {
                            Bucket::waiters(bucket).cursor_mut_from_ptr(waiter)
                        };
                        cursor.move_next();
                        cursor.current_ptr()
                    };
                    // SAFETY: the waiter is linked into the guarded list.
                    unsafe { (*bucket).wake(waiter) };
                    if !flags.contains(Flags::BROADCAST) {
                        break;
                    }
                    let Some(next) = next else { break };
                    // SAFETY: the next waiter lives inside this list; its key
                    // is a plain scalar.
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
        unsafe { (*bucket).lock.unlock() };
        result
    }

    /// Moves the threads waiting on `src` in `map` to wait on `dst`: the
    /// first one, or every one with [`Flags::BROADCAST`], and with
    /// `wake_one` one more, which it wakes at once.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAddress`] when an address is not word-aligned or not
    /// accessible in `map`, and [`Error::InvalidArgument`] when no thread
    /// waits on `src`.
    ///
    /// # Safety
    ///
    /// Thread context, holding no lock; `map` must be the live map of a task
    /// the caller holds.
    pub unsafe fn requeue(
        &self,
        map: *mut VmMap<P>,
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

        let key_of = |addr| {
            let probe = Probe::lookup(map, addr, flags)?;
            let key = probe.key(map, addr, flags);
            // SAFETY: the lookup returned the object locked and the map
            // read-locked.
            unsafe {
                (*probe.object).lock.unlock();
                (*map).lock.unlock();
            }
            Ok(key)
        };
        let src_key = key_of(src)?;
        let dst_key = key_of(dst)?;

        self.requeue.lock();

        let mut moved = pin!(WaiterQueue::new());
        let src_bucket = self.bucket(src_key);
        // SAFETY: the bucket lives as long as `self`.
        unsafe { (*src_bucket).lock.lock() };
        // SAFETY: the bucket lock guards the list.
        let (first, exact) =
            unsafe { find_key(&Bucket::waiters(src_bucket), src_key) };
        let mut left = if flags.contains(Flags::BROADCAST) {
            usize::MAX
        } else {
            1 + usize::from(wake_one)
        };
        let mut current = if exact { first } else { None };
        while let Some(waiter) = current
            && left > 0
        {
            // SAFETY: the bucket lock guards the list, which links `waiter`;
            // its key is a plain scalar.
            if unsafe { (*waiter.as_ptr()).key } != src_key {
                break;
            }
            // The successor is read before the unlink.
            let next = {
                // SAFETY: as above.
                let mut cursor = unsafe {
                    Bucket::waiters(src_bucket).cursor_mut_from_ptr(waiter)
                };
                cursor.move_next();
                cursor.current_ptr()
            };
            // SAFETY: the waiter is linked into the guarded list, and joins
            // the local one, which nothing else reaches; it stays queued.
            unsafe {
                Bucket::waiters(src_bucket).remove_ptr(waiter);
                moved.as_mut().push_back_ptr(waiter);
            }
            left -= 1;
            current = next;
        }
        // SAFETY: the bucket lock taken above.
        unsafe { (*src_bucket).lock.unlock() };

        if !exact {
            // SAFETY: the requeue lock taken above.
            unsafe { self.requeue.unlock() };
            return Err(Error::InvalidArgument);
        }

        let dst_bucket = self.bucket(dst_key);
        // SAFETY: the bucket lives as long as `self`.
        unsafe { (*dst_bucket).lock.lock() };
        // The moved waiters go after those already waiting on `dst`.
        // SAFETY: the bucket lock guards the list.
        let mut position =
            unsafe { find_key(&Bucket::waiters(dst_bucket), dst_key) }.0;
        while let Some(waiter) = position {
            // SAFETY: as above; the key is a plain scalar.
            if unsafe { (*waiter.as_ptr()).key } != dst_key {
                break;
            }
            // SAFETY: as above.
            let mut cursor = unsafe {
                Bucket::waiters(dst_bucket).cursor_mut_from_ptr(waiter)
            };
            cursor.move_next();
            position = cursor.current_ptr();
        }
        let mut woken = !wake_one;
        while let Some(waiter) = moved.cursor_front().current_ptr() {
            // SAFETY: the waiter is on the local list, which it leaves for
            // the guarded one; the requeue lock keeps any waiter that gives
            // up from reading its key.
            unsafe {
                moved.as_mut().remove_ptr(waiter);
                (*waiter.as_ptr()).key = dst_key;
                match position {
                    Some(next) => Bucket::waiters(dst_bucket)
                        .cursor_mut_from_ptr(next)
                        .insert_before_ptr(waiter),
                    None => Bucket::waiters(dst_bucket).push_back_ptr(waiter),
                }
                if !woken {
                    (*dst_bucket).wake(waiter);
                    woken = true;
                }
            }
        }
        // SAFETY: the bucket lock taken above.
        unsafe { (*dst_bucket).lock.unlock() };
        // SAFETY: the requeue lock taken above.
        unsafe { self.requeue.unlock() };
        Ok(())
    }
}
