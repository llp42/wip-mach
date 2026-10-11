// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The threads waiting for the reaper.

use crate::platform::Platform;
use crate::thread::ThreadQueue;
use core::pin::Pin;

/// The threads waiting for the reaper.
pub(crate) struct ReaperQueue<P: Platform>(ThreadQueue<P>);

// SAFETY: the queue links thread records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked threads are shared between CPUs, which their type \
              does not say"
)]
unsafe impl<P: Platform> Send for ReaperQueue<P> {}

impl<P: Platform> ReaperQueue<P> {
    /// An empty queue.
    pub(crate) const fn new() -> Self {
        Self(ThreadQueue::new())
    }

    /// The queue, pinned.
    pub(crate) const fn pinned(&mut self) -> Pin<&mut ThreadQueue<P>> {
        // SAFETY: the one `ReaperQueue` is in the platform's task state, a
        // static, which never moves.
        unsafe { Pin::new_unchecked(&mut self.0) }
    }
}
