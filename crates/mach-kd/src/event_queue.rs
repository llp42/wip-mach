// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The ring each of the kbd and mouse devices queues its events in.

use crate::event::Event;

/// The slots of a queue.
const SLOTS: usize = 100;

/// A ring of events: `firstfree` is where the next one goes and `firstout`
/// where the next one leaves.
pub struct EventQueue {
    events: [Event; SLOTS],
    firstfree: usize,
    firstout: usize,
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EventQueue {
    /// An empty queue, the image the drivers' statics start from.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: [Event::zeroed(); SLOTS],
            firstfree: 0,
            firstout: 0,
        }
    }

    const fn next(index: usize) -> usize {
        (index + 1) % SLOTS
    }

    #[must_use]
    /// Whether the queue holds no events.
    pub const fn is_empty(&self) -> bool {
        self.firstfree == self.firstout
    }

    /// Whether the queue holds its most, `SLOTS - 1` events: one slot stays
    /// free so that a full queue and an empty one cannot look alike.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        Self::next(self.firstfree) == self.firstout
    }

    /// Drop every queued event, leaving the queue empty.
    pub const fn clear(&mut self) {
        self.firstfree = 0;
        self.firstout = 0;
    }

    /// Copy `ev` into the free slot and advance the write index; the caller
    /// has checked `is_full()`.
    ///
    /// # Panics
    ///
    /// If the write index has left the ring, which `next` never lets it do.
    pub const fn push_back(&mut self, ev: Event) {
        #[expect(
            clippy::indexing_slicing,
            reason = "`next` keeps the write index below SLOTS"
        )]
        let slot = &mut self.events[self.firstfree];
        *slot = ev;
        self.firstfree = Self::next(self.firstfree);
    }

    /// Advance the read index and return the slot it left, or `None` when the
    /// queue is empty.
    pub fn pop_front(&mut self) -> Option<&mut Event> {
        if self.is_empty() {
            return None;
        }
        let out = self.firstout;
        self.firstout = Self::next(out);
        self.events.get_mut(out)
    }
}
