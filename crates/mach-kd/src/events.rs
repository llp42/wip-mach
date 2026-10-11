// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The events one input byte stands for.

use crate::event::Event;

/// The events one input byte stands for, in the order they happened: at
/// most a movement and the three buttons.
#[derive(Clone, Copy, Debug)]
pub struct Events {
    events: [Event; 4],
    len: usize,
}

impl Events {
    pub(super) const fn new() -> Self {
        Self {
            events: [Event::zeroed(); 4],
            len: 0,
        }
    }

    pub(super) fn push(&mut self, event: Event) {
        if let Some(slot) = self.events.get_mut(self.len) {
            *slot = event;
            self.len += 1;
        }
    }

    /// The events, oldest first.
    #[must_use]
    pub fn as_slice(&self) -> &[Event] {
        self.events.get(..self.len).unwrap_or_default()
    }
}

/// Two lists hold the same events whatever their unused slots hold.
impl PartialEq for Events {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Events {}
