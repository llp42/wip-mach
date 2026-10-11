// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The object-caching slab allocator: caches of objects of one size, carved
//! from page-aligned slabs, and the general-purpose caches behind `kalloc`.
//!
//! Everything the slab asks of the rest of the kernel arrives through
//! [`Platform`]: its pages, the physical address behind a kernel address,
//! and the console.  The caches that name the platform sit in a
//! [`SlabState`] the kernel declares.

#![no_std]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    reason = "the caches mirror the C's counter widths and pointer \
              arithmetic; each site's width and alignment are known"
)]

pub mod cache;
pub mod kalloc;
pub mod pages;
pub mod platform;
pub mod slab;
pub mod state;
pub mod types;
pub mod verify;

pub use cache::KmemCache;
pub use kalloc::{
    collect, kalloc, kalloc_init, kalloc_ready, kfree, nr_caches,
    slab_collect, slab_init,
};
pub use platform::Platform;
pub use state::SlabState;
