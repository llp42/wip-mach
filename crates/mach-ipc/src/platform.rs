// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel services IPC calls beyond VM's, supplied as a zero-sized type.
//!
//! [`Platform`] extends [`mach_vm::Platform`]: locks, user copy, the console,
//! `kalloc`, the running thread's waits and the kernel's maps come from VM's
//! seam, and this trait adds what only IPC asks of the kernel.

use crate::ipc_kmsg::Kmsg;
use crate::ipc_thread::{SavedReceive, ThreadIpc, ThreadRef};
use crate::{IpcPort, IpcSpace};
use core::ffi::c_uint;
use core::ptr::NonNull;

/// A message the running task's statistics count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageEvent {
    /// A message the task queued.
    Sent,
    /// A message the task received.
    Received,
}

/// A slab cache IPC's records come from; the platform keeps one of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcCache {
    /// Ports.
    Port,
    /// Port sets.
    PortSet,
    /// Capability spaces.
    Space,
    /// Space entries.
    Entry,
    /// Message-accepted requests.
    Marequest,
}

impl IpcCache {
    /// The number of caches.
    pub const COUNT: usize = 5;
}

/// The kernel services IPC calls beyond VM's.
///
/// # Safety
///
/// IPC's correctness rests on each function keeping the contract its
/// documentation states, as the kernel's own callers rely on it.
pub unsafe trait Platform: mach_vm::Platform {
    // Threads.

    /// The continuation a blocked receive resumes through.  The kernel
    /// recognises a thread blocked in a receive by this function's address,
    /// so it is the kernel's, and it resumes through
    /// [`receive_continue`](crate::mach_msg::receive_continue).
    const RECEIVE_CONTINUE: unsafe extern "C" fn();

    /// The continuation a blocked send-and-receive resumes through, by
    /// [`msg_continue`](crate::mach_msg::msg_continue).
    const MSG_CONTINUE: unsafe extern "C" fn();

    /// Returns the running thread.
    ///
    /// # Panics
    ///
    /// If the CPU runs no thread.
    fn current_thread() -> ThreadRef;

    /// Returns `thread`'s IPC state, which the platform stores in the
    /// thread.
    ///
    /// # Safety
    ///
    /// `thread` must be a live thread.
    unsafe fn thread_ipc(thread: ThreadRef) -> NonNull<ThreadIpc>;

    /// Returns the receive state `thread` saves before it blocks, which the
    /// platform stores in the thread.
    ///
    /// # Safety
    ///
    /// `thread` must be a live thread.
    unsafe fn saved_receive(thread: ThreadRef) -> NonNull<SavedReceive>;

    /// Makes `thread`, waiting in a message transfer, runnable with a
    /// successful wait result.
    ///
    /// # Safety
    ///
    /// `thread` must be a live thread; IPC locks may be held.
    unsafe fn thread_go(thread: ThreadRef);

    /// Declares that the running thread is about to wait in a message
    /// transfer, for at most `timeout` milliseconds when there is one; the
    /// thread then blocks with [`mach_vm::Platform::thread_block`].
    ///
    /// # Safety
    ///
    /// Thread context.
    unsafe fn will_wait(timeout: Option<c_uint>);

    // Tasks.

    /// Returns the running task's IPC space.
    ///
    /// # Panics
    ///
    /// If the CPU runs no thread.
    fn current_space() -> IpcSpace;

    /// Counts `event` in the running task's statistics.
    ///
    /// # Panics
    ///
    /// If the CPU runs no thread.
    fn count_message(event: MessageEvent);

    // Kernel objects.

    /// Hands `request`, sent to a kernel port, to the kernel object's server,
    /// which consumes it and returns the reply to send, if there is one.
    ///
    /// # Safety
    ///
    /// `request` must be a live message whose destination is a port of the
    /// kernel's space, owned by this call; nothing may be locked.
    unsafe fn kobject_server(request: Kmsg) -> Option<Kmsg>;

    /// Releases what the kernel object of a destroyed port still holds.
    ///
    /// # Safety
    ///
    /// `port` must be a live but inactive port that nothing holds a lock on.
    unsafe fn kobject_destroy(port: IpcPort);

    // Allocation.

    /// The allocator of the name tables.
    type Heap: kmem::Alloc + Default;

    /// Sets up `cache` for records of `size` bytes, reported as `name`.
    ///
    /// # Safety
    ///
    /// Once per cache, before its first allocation.
    unsafe fn ipc_cache_init(
        cache: IpcCache,
        name: &'static [u8],
        size: usize,
    );

    /// Allocates a record from `cache`, or `None` when memory is short.
    ///
    /// # Safety
    ///
    /// [`Self::ipc_cache_init`] must have set `cache` up.
    unsafe fn ipc_cache_alloc(cache: IpcCache) -> Option<NonNull<u8>>;

    /// Returns a record to `cache`.
    ///
    /// # Safety
    ///
    /// `record` must have come from `cache` and not be used again.
    unsafe fn ipc_cache_free(cache: IpcCache, record: NonNull<u8>);
}
