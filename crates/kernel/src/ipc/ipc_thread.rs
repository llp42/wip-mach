// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_thread.c and ipc/ipc_thread.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! IPC operations on threads, which `ipc/ipc_thread.c` used to define.

use crate::kern::thread::Thread;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull};

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

/// The `ith_next`/`ith_prev` pair inside `struct thread`, as one record.
#[repr(C)]
#[allow(missing_docs)]
struct ThreadLinks {
    next: Option<ThreadRef>,
    prev: Option<ThreadRef>,
}

const _: () = assert!(size_of::<IpcThreadQueue>() == size_of::<*mut c_void>());
const _: () =
    assert!(size_of::<IpcThreadQueue>() == size_of::<Option<ThreadRef>>());
const _: () =
    assert!(size_of::<ThreadLinks>() == 2 * size_of::<*mut c_void>());
const _: () = assert!(
    offset_of!(Thread, ith_prev)
        == offset_of!(Thread, ith_next) + size_of::<*mut Thread>()
);

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

    /// The thread's IPC links.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn links(self) -> NonNull<ThreadLinks> {
        unsafe {
            let thread = self.as_ptr().cast::<Thread>();
            let links = core::ptr::addr_of_mut!((*thread).ith_next);
            NonNull::new_unchecked(links.cast::<ThreadLinks>())
        }
    }

    /// Make the thread unlinked: both links point at itself.
    ///
    /// # Safety
    ///
    /// The thread must be valid, and it must not be linked in any queue.
    unsafe fn links_init(self) {
        unsafe {
            let links = self.links();
            (*links.as_ptr()).next = Some(self);
            (*links.as_ptr()).prev = Some(self);
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
            let first_links = first.links();
            let last = (*first_links.as_ptr())
                .prev
                .expect("ipc_thread: linked thread without a predecessor");
            let links = thread.links();

            (*links.as_ptr()).next = Some(first);
            (*links.as_ptr()).prev = Some(last);
            (*first_links.as_ptr()).prev = Some(thread);
            let last_links = last.links();
            (*last_links.as_ptr()).next = Some(thread);
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
            let links = thread.links();
            let next = (*links.as_ptr())
                .next
                .expect("ipc_thread: linked thread without a successor");

            if next == thread {
                self.base = None;
                return;
            }

            let prev = (*links.as_ptr())
                .prev
                .expect("ipc_thread: linked thread without a predecessor");

            if self.base == Some(thread) {
                self.base = Some(next);
            }

            let next_links = next.links();
            (*next_links.as_ptr()).prev = Some(prev);
            let prev_links = prev.links();
            (*prev_links.as_ptr()).next = Some(next);
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
            let links = thread.links();
            let next = (*links.as_ptr())
                .next
                .expect("ipc_thread: linked thread without a successor");

            if next == thread {
                self.base = None;
                return;
            }

            let prev = (*links.as_ptr())
                .prev
                .expect("ipc_thread: linked thread without a predecessor");

            self.base = Some(next);
            let next_links = next.links();
            (*next_links.as_ptr()).prev = Some(prev);
            let prev_links = prev.links();
            (*prev_links.as_ptr()).next = Some(next);
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
