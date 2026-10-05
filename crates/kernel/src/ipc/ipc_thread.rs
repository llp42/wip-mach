// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_thread.c and ipc/ipc_thread.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! IPC operations on threads, which `ipc/ipc_thread.c` used to define.

use crate::kern::thread::Thread;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// What a thread blocked in a message transfer was left with, the
/// `ith_state` of the C.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcWait {
    /// Woken with the outcome: a sender has room in the queue, or a
    /// receiver has its message in `data.kmsg`.  Zero, the state a fresh
    /// thread starts in.
    Done = 0,
    /// Blocked in a send, waiting for room in the queue.
    Sending,
    /// Blocked in a receive, waiting for a message.
    Receiving,
    /// The receiver's buffer was too small; the message's size is in
    /// `data.msize`.
    TooLarge,
    /// The port the receiver waited on died.
    PortDied,
    /// The port the receiver waited on moved into a port set.
    PortChanged,
}

/// `ipc_thread_t`: a reference to a thread, opaque to this module.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRef(NonNull<c_void>);

/// `struct ipc_thread_queue`: a LIFO stack of threads.
#[repr(C)]
#[allow(missing_docs)]
pub struct IpcThreadQueue {
    base: Option<ThreadRef>,
}

const _: () = assert!(size_of::<IpcThreadQueue>() == size_of::<*mut c_void>());
const _: () =
    assert!(size_of::<IpcThreadQueue>() == size_of::<Option<ThreadRef>>());

impl ThreadRef {
    /// View a raw thread the caller promises is valid.
    ///
    /// # Safety
    ///
    /// `thread` must point at a valid `struct thread`.
    pub(crate) const unsafe fn new(thread: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(thread) })
    }

    /// The raw thread pointer, for the C adapters and the exception path.
    pub(crate) const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The successor in the thread's IPC queue.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn next(self) -> Option<Self> {
        let thread = self.as_ptr().cast::<Thread>();
        NonNull::new(unsafe { (*thread).ith_next }.cast()).map(ThreadRef)
    }

    /// The predecessor in the thread's IPC queue.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn prev(self) -> Option<Self> {
        let thread = self.as_ptr().cast::<Thread>();
        NonNull::new(unsafe { (*thread).ith_prev }.cast()).map(ThreadRef)
    }

    /// Store the thread's IPC-queue successor.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn set_next(self, next: Option<Self>) {
        let thread = self.as_ptr().cast::<Thread>();
        unsafe {
            (*thread).ith_next =
                next.map_or(ptr::null_mut(), |t| t.as_ptr().cast());
        }
    }

    /// Store the thread's IPC-queue predecessor.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn set_prev(self, prev: Option<Self>) {
        let thread = self.as_ptr().cast::<Thread>();
        unsafe {
            (*thread).ith_prev =
                prev.map_or(ptr::null_mut(), |t| t.as_ptr().cast());
        }
    }

    /// Make the thread unlinked: both links point at itself.
    ///
    /// # Safety
    ///
    /// The thread must be valid, and it must not be linked in any queue.
    unsafe fn links_init(self) {
        unsafe {
            self.set_next(Some(self));
            self.set_prev(Some(self));
        }
    }
}

impl Default for IpcThreadQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcThreadQueue {
    /// An empty queue; `ipc_thread_queue_init()` uses this.
    #[must_use]
    pub const fn new() -> Self {
        Self { base: None }
    }

    /// `ipc_thread_queue_init()` in C.
    pub const fn init(&mut self) {
        *self = Self::new();
    }

    /// `ipc_thread_queue_first()` in C.
    #[must_use]
    pub const fn first(&self) -> Option<ThreadRef> {
        self.base
    }

    /// `ipc_thread_enqueue()` in C.
    ///
    /// # Safety
    ///
    /// The thread must be valid and not linked in any queue, and the caller
    /// must hold the lock protecting this queue.
    ///
    /// # Panics
    ///
    /// Panics when the queue's first thread has no predecessor, which cannot
    /// happen while the queue is well formed.
    pub unsafe fn enqueue(&mut self, thread: ThreadRef) {
        let Some(first) = self.base else {
            self.base = Some(thread);
            return;
        };

        unsafe {
            let last = first
                .prev()
                .expect("ipc_thread: linked thread without a predecessor");

            thread.set_next(Some(first));
            thread.set_prev(Some(last));
            first.set_prev(Some(thread));
            last.set_next(Some(thread));
        }

        self.base = Some(thread);
    }

    /// `ipc_thread_dequeue()` in C.
    ///
    /// # Safety
    ///
    /// The queued threads must be valid and linked, and the caller must hold
    /// the lock protecting this queue.
    pub unsafe fn dequeue(&mut self) -> Option<ThreadRef> {
        let first = self.first()?;
        unsafe { self.rmqueue_first(first) };
        Some(first)
    }

    /// `ipc_thread_rmqueue()` in C.
    ///
    /// # Safety
    ///
    /// `thread` must be linked in this queue, and the caller must hold the
    /// lock protecting it.
    ///
    /// # Panics
    ///
    /// Panics when the linked thread has no successor or predecessor, which
    /// cannot happen while the queue is well formed.
    pub unsafe fn rmqueue(&mut self, thread: ThreadRef) {
        unsafe {
            let next = thread
                .next()
                .expect("ipc_thread: linked thread without a successor");

            if next == thread {
                self.base = None;
                return;
            }

            let prev = thread
                .prev()
                .expect("ipc_thread: linked thread without a predecessor");

            if self.base == Some(thread) {
                self.base = Some(next);
            }

            next.set_prev(Some(prev));
            prev.set_next(Some(next));
            thread.links_init();
        }
    }

    /// `ipc_thread_rmqueue_first()` in C; the caller's macro used to assume
    /// `thread` was the first.
    ///
    /// # Safety
    ///
    /// `thread` must be the first thread of this queue, and the caller must
    /// hold the lock protecting it.
    ///
    /// # Panics
    ///
    /// Panics when the linked thread has no successor or predecessor, which
    /// cannot happen while the queue is well formed.
    pub unsafe fn rmqueue_first(&mut self, thread: ThreadRef) {
        unsafe {
            let next = thread
                .next()
                .expect("ipc_thread: linked thread without a successor");

            if next == thread {
                self.base = None;
                return;
            }

            let prev = thread
                .prev()
                .expect("ipc_thread: linked thread without a predecessor");

            self.base = Some(next);
            next.set_prev(Some(prev));
            prev.set_next(Some(next));
            thread.links_init();
        }
    }
}

/// `ipc_thread_enqueue()` in C.
///
/// # Safety
///
/// `queue` must be valid, `thread` valid and unlinked, and the caller must
/// hold the lock protecting the queue.
pub(crate) unsafe fn ipc_thread_enqueue(
    queue: *mut IpcThreadQueue,
    thread: *mut c_void,
) {
    unsafe { (*queue).enqueue(ThreadRef::new(thread)) };
}

/// `ipc_thread_dequeue()` in C.
///
/// # Safety
///
/// `queue` must be valid and its threads linked, and the caller must hold the
/// lock protecting it.
pub(crate) unsafe fn ipc_thread_dequeue(
    queue: *mut IpcThreadQueue,
) -> *mut c_void {
    let thread = unsafe { (*queue).dequeue() };
    thread.map_or(ptr::null_mut(), ThreadRef::as_ptr)
}

/// `ipc_thread_rmqueue()` in C.
///
/// # Safety
///
/// `queue` must be valid, `thread` linked in it, and the caller must hold the
/// lock protecting it.
pub(crate) unsafe fn ipc_thread_rmqueue(
    queue: *mut IpcThreadQueue,
    thread: *mut c_void,
) {
    unsafe { (*queue).rmqueue(ThreadRef::new(thread)) };
}

/// `ipc_thread_links_init()` in C.
///
/// # Safety
///
/// `thread` must be valid and not linked in any queue.
pub(crate) unsafe fn ipc_thread_links_init(thread: *mut c_void) {
    unsafe { ThreadRef::new(thread).links_init() };
}

/// `ipc_thread_queue_init()` in C.
///
/// # Safety
///
/// `queue` must be valid.
pub(crate) unsafe fn ipc_thread_queue_init(queue: *mut IpcThreadQueue) {
    unsafe { (*queue).init() };
}

/// `ipc_thread_queue_first()` in C.
///
/// # Safety
///
/// `queue` must be valid.
pub(crate) unsafe fn ipc_thread_queue_first(
    queue: *mut IpcThreadQueue,
) -> *mut c_void {
    let thread = unsafe { (*queue).first() };
    thread.map_or(ptr::null_mut(), ThreadRef::as_ptr)
}

/// `ipc_thread_rmqueue_first()` in C, where it was
/// `ipc_thread_rmqueue_first_macro()`.
///
/// # Safety
///
/// `queue` must be valid, `thread` its first thread, and the caller must hold
/// the lock protecting it.
pub(crate) unsafe fn ipc_thread_rmqueue_first(
    queue: *mut IpcThreadQueue,
    thread: *mut c_void,
) {
    unsafe { (*queue).rmqueue_first(ThreadRef::new(thread)) };
}
