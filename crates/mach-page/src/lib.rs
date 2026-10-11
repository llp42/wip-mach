// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The physical pages: the page descriptor, the physical segments the boot
//! loader reported, the boot heap carved from them, and the buddy allocator
//! and per-CPU pools that hand pages out once the page table exists.
//!
//! The crate has no `Platform`.  An allocating caller passes its CPU and
//! whether it may dip into the reserve, serializes allocation with a lock of
//! its own, and reads back whether a segment fell to its low threshold, so
//! the pageout it starts stays above.  The descriptor is generic over its
//! owner, VM's object, which the allocator never reads.

#![no_std]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "the descriptor's bitfields and the C's counter widths: a mask \
              or the segment table's size bounds each cast"
)]

mod cell;
pub mod memmap;
pub mod page;
pub mod param;
mod seg;
pub mod simple_lock;
pub mod smp;
pub mod table;
pub mod types;

pub use page::Page;
