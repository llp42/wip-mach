// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The cache of free kernel stacks.

use crate::platform::Platform;
use crate::thread::{set_stack_next, stack_next};
use mach_vm::param::VmOffset;

/// The cached stacks, linked through each stack's last word, and their count.
pub(crate) struct StackFreeList {
    /// The first stack, or zero when the list is empty.
    pub(crate) head: VmOffset,
    pub(crate) count: u32,
}

impl StackFreeList {
    /// An empty list.
    pub(crate) const fn new() -> Self {
        Self { head: 0, count: 0 }
    }

    /// Remove the first stack, or return zero when the list is empty.
    ///
    /// # Safety
    ///
    /// Every entry on the list must be a live cache object.
    pub(crate) const unsafe fn pop<P: Platform>(&mut self) -> VmOffset {
        let stack = self.head;
        if stack != 0 {
            self.head = unsafe { stack_next::<P>(stack) };
            self.count -= 1;
        }
        stack
    }

    /// Return `stack` to the list.
    ///
    /// # Safety
    ///
    /// `stack` must be a live cache object on no list.
    pub(crate) const unsafe fn push<P: Platform>(&mut self, stack: VmOffset) {
        unsafe { set_stack_next::<P>(stack, self.head) };
        self.head = stack;
        self.count += 1;
    }
}
