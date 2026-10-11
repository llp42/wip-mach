// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! [`Waiter`]: a thread blocked on an address, and the sorted list of them
//! a bucket keeps.

use crate::types::Key;
use collections::tail_queue::{self, TailQueue};
use core::cmp::Ordering;
use core::ffi::c_void;
use core::ptr::NonNull;

/// A thread blocked on an address.
pub struct Waiter {
    pub link: tail_queue::Link,
    /// Whether the waiter is on its bucket's list; guarded by the bucket
    /// lock. A waker clears it as it unlinks the waiter, which is how a wait
    /// that ended some other way tells whether it must unlink itself.
    pub queued: bool,
    pub key: Key,
    /// The waiting thread, as the platform names it.
    pub thread: *mut c_void,
}

tail_queue::adapter!(
    /// The adapter for a waiter's `link` in its bucket's list.
    pub WaiterAdapter = Waiter { link }
);

/// A bucket's waiters, sorted by key: a new waiter goes before the first one
/// with a greater key, and any waiter leaves from the middle.
pub type WaiterQueue = TailQueue<'static, WaiterAdapter>;

impl Waiter {
    /// A waiter on `key` for the running thread, outside any list.
    pub const fn new(key: Key) -> Self {
        Self {
            link: tail_queue::Link::new(),
            queued: false,
            key,
            thread: core::ptr::null_mut(),
        }
    }
}

/// The first waiter in `waiters` whose key is not less than `key`, or `None`
/// for the end when there is none.  The flag is true when that waiter's key
/// is `key`.
pub fn find_key(
    waiters: &WaiterQueue,
    key: Key,
) -> (Option<NonNull<Waiter>>, bool) {
    let mut cursor = waiters.cursor_front();
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
