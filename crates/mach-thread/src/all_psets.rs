// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The list of every processor set.

use crate::platform::Platform;
use crate::processor_set::PsetList;
use core::pin::Pin;

/// The chain of every processor set, and its length.
pub struct AllPsets<P: Platform> {
    list: PsetList<P>,
    /// How many sets the list holds.
    pub count: u32,
}

// SAFETY: the list links processor-set records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked sets are shared between CPUs, which their type \
              does not say"
)]
unsafe impl<P: Platform> Send for AllPsets<P> {}

impl<P: Platform> AllPsets<P> {
    /// No sets.
    pub(crate) const fn new() -> Self {
        Self {
            list: PsetList::new(),
            count: 0,
        }
    }

    /// The list.
    pub const fn list(&self) -> &PsetList<P> {
        &self.list
    }

    /// The list, pinned.
    pub(crate) const fn list_pinned(&mut self) -> Pin<&mut PsetList<P>> {
        // SAFETY: the one `AllPsets` is in the platform's task state, a
        // static, which never moves, and the list is private to this module,
        // so nothing else moves it out.
        unsafe { Pin::new_unchecked(&mut self.list) }
    }
}
