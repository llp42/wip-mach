// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! IPC operations on threads.

use crate::ipc_kmsg::IpcKmsgQueue;
use crate::platform::Platform;
use crate::types::MsgOption;
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// What a thread blocked in a message transfer was left with.
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

/// The receive size or the received message, whichever a blocked receive
/// left in its thread.
#[repr(C)]
pub union ThreadData {
    /// The largest message the receive takes, or the size of one that did
    /// not fit.
    pub msize: c_uint,
    /// The message handed to the receiver.
    pub kmsg: *mut c_void,
}

const _: () = assert!(size_of::<ThreadData>() == 8);

/// A thread's IPC state: its links in an IPC thread queue, what its blocked
/// message transfer was left with, and the messages it is destroying.
///
/// The kernel's thread embeds one; an all-zero value is a thread outside any
/// transfer.
pub struct ThreadIpc {
    /// `ith_next`: the next thread in the IPC thread queue.
    pub next: *mut c_void,
    /// `ith_prev`: the previous thread in the IPC thread queue.
    pub prev: *mut c_void,
    /// `ith_state`: what a blocked message transfer was left with.
    pub state: IpcWait,
    /// The received message or its maximum size.
    pub data: ThreadData,
    /// `ith_seqno`: the sequence number of the received message.
    pub seqno: c_uint,
    /// `ith_messages`: messages being destroyed.
    pub messages: IpcKmsgQueue,
}

/// What a receive saves in its thread before it blocks, for the continuation
/// that resumes it once the thread's stack is gone.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SavedReceive {
    /// The user message buffer.
    pub msg: *mut c_void,
    /// The receive's option bits.
    pub option: MsgOption,
    /// The size of the user buffer.
    pub rcv_size: c_uint,
    /// The timeout, in milliseconds.
    pub timeout: c_uint,
    /// The notification port name.
    pub notify: c_uint,
    /// The object being received from.
    pub object: *mut c_void,
    /// The message queue being received from.
    pub mqueue: *mut c_void,
}

const _: () = assert!(size_of::<SavedReceive>() == 40);

/// A reference to a thread, opaque to this module.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRef(NonNull<c_void>);

/// A LIFO stack of threads.
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
    pub const unsafe fn new(thread: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(thread) })
    }

    /// The raw thread pointer, for the C adapters and the exception path.
    #[must_use]
    pub const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The successor in the thread's IPC queue.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn next<P: Platform>(self) -> Option<Self> {
        let ipc = unsafe { P::thread_ipc(self) }.as_ptr();
        NonNull::new(unsafe { (*ipc).next }).map(ThreadRef)
    }

    /// The predecessor in the thread's IPC queue.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn prev<P: Platform>(self) -> Option<Self> {
        let ipc = unsafe { P::thread_ipc(self) }.as_ptr();
        NonNull::new(unsafe { (*ipc).prev }).map(ThreadRef)
    }

    /// Store the thread's IPC-queue successor.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn set_next<P: Platform>(self, next: Option<Self>) {
        unsafe {
            (*P::thread_ipc(self).as_ptr()).next =
                next.map_or(ptr::null_mut(), Self::as_ptr);
        }
    }

    /// Store the thread's IPC-queue predecessor.
    ///
    /// # Safety
    ///
    /// The thread must be valid.
    unsafe fn set_prev<P: Platform>(self, prev: Option<Self>) {
        unsafe {
            (*P::thread_ipc(self).as_ptr()).prev =
                prev.map_or(ptr::null_mut(), Self::as_ptr);
        }
    }

    /// Make the thread unlinked: both links point at itself.
    ///
    /// # Safety
    ///
    /// The thread must be valid, and it must not be linked in any queue.
    unsafe fn links_init<P: Platform>(self) {
        unsafe {
            self.set_next::<P>(Some(self));
            self.set_prev::<P>(Some(self));
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

    /// Empties the queue.
    pub const fn init(&mut self) {
        *self = Self::new();
    }

    /// The thread on top of the queue, when there is one.
    #[must_use]
    pub const fn first(&self) -> Option<ThreadRef> {
        self.base
    }

    /// Pushes `thread` on the queue.
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
    pub unsafe fn enqueue<P: Platform>(&mut self, thread: ThreadRef) {
        let Some(first) = self.base else {
            self.base = Some(thread);
            return;
        };

        unsafe {
            let last = first
                .prev::<P>()
                .expect("ipc_thread: linked thread without a predecessor");

            thread.set_next::<P>(Some(first));
            thread.set_prev::<P>(Some(last));
            first.set_prev::<P>(Some(thread));
            last.set_next::<P>(Some(thread));
        }

        self.base = Some(thread);
    }

    /// Pops the thread on top of the queue.
    ///
    /// # Safety
    ///
    /// The queued threads must be valid and linked, and the caller must hold
    /// the lock protecting this queue.
    pub unsafe fn dequeue<P: Platform>(&mut self) -> Option<ThreadRef> {
        let first = self.first()?;
        unsafe { self.rmqueue_first::<P>(first) };
        Some(first)
    }

    /// Removes `thread` from the queue.
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
    pub unsafe fn rmqueue<P: Platform>(&mut self, thread: ThreadRef) {
        unsafe {
            let next = thread
                .next::<P>()
                .expect("ipc_thread: linked thread without a successor");

            if next == thread {
                self.base = None;
                return;
            }

            let prev = thread
                .prev::<P>()
                .expect("ipc_thread: linked thread without a predecessor");

            if self.base == Some(thread) {
                self.base = Some(next);
            }

            next.set_prev::<P>(Some(prev));
            prev.set_next::<P>(Some(next));
            thread.links_init::<P>();
        }
    }

    /// Removes `thread`, which must be the one on top of the queue.
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
    pub unsafe fn rmqueue_first<P: Platform>(&mut self, thread: ThreadRef) {
        unsafe {
            let next = thread
                .next::<P>()
                .expect("ipc_thread: linked thread without a successor");

            if next == thread {
                self.base = None;
                return;
            }

            let prev = thread
                .prev::<P>()
                .expect("ipc_thread: linked thread without a predecessor");

            self.base = Some(next);
            next.set_prev::<P>(Some(prev));
            prev.set_next::<P>(Some(next));
            thread.links_init::<P>();
        }
    }
}

/// [`IpcThreadQueue::enqueue`] over raw pointers.
///
/// # Safety
///
/// `queue` must be valid, `thread` valid and unlinked, and the caller must
/// hold the lock protecting the queue.
pub(crate) unsafe fn ipc_thread_enqueue<P: Platform>(
    queue: *mut IpcThreadQueue,
    thread: *mut c_void,
) {
    unsafe { (*queue).enqueue::<P>(ThreadRef::new(thread)) };
}

/// [`IpcThreadQueue::dequeue`] over a raw pointer.
///
/// # Safety
///
/// `queue` must be valid and its threads linked, and the caller must hold the
/// lock protecting it.
pub(crate) unsafe fn ipc_thread_dequeue<P: Platform>(
    queue: *mut IpcThreadQueue,
) -> *mut c_void {
    let thread = unsafe { (*queue).dequeue::<P>() };
    thread.map_or(ptr::null_mut(), ThreadRef::as_ptr)
}

/// [`IpcThreadQueue::rmqueue`] over raw pointers.
///
/// # Safety
///
/// `queue` must be valid, `thread` linked in it, and the caller must hold the
/// lock protecting it.
pub(crate) unsafe fn ipc_thread_rmqueue<P: Platform>(
    queue: *mut IpcThreadQueue,
    thread: *mut c_void,
) {
    unsafe { (*queue).rmqueue::<P>(ThreadRef::new(thread)) };
}

/// Initializes `thread`'s queue links as unlinked.
///
/// # Safety
///
/// `thread` must be valid and not linked in any queue.
pub unsafe fn ipc_thread_links_init<P: Platform>(thread: *mut c_void) {
    unsafe { ThreadRef::new(thread).links_init::<P>() };
}

/// [`IpcThreadQueue::init`] over a raw pointer.
///
/// # Safety
///
/// `queue` must be valid.
pub(crate) unsafe fn ipc_thread_queue_init(queue: *mut IpcThreadQueue) {
    unsafe { (*queue).init() };
}

/// [`IpcThreadQueue::first`] over a raw pointer.
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

/// [`IpcThreadQueue::rmqueue_first`] over raw pointers.
///
/// # Safety
///
/// `queue` must be valid, `thread` its first thread, and the caller must hold
/// the lock protecting it.
pub(crate) unsafe fn ipc_thread_rmqueue_first<P: Platform>(
    queue: *mut IpcThreadQueue,
    thread: *mut c_void,
) {
    unsafe { (*queue).rmqueue_first::<P>(ThreadRef::new(thread)) };
}
