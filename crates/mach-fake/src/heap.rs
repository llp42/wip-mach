// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`HostHeap`]: the global allocator as a `kmem` allocator.

use core::alloc::Layout;
use core::ptr::NonNull;
use kmem::{Alloc, AllocError};
use std::alloc;

/// The name tables' allocator in the tests: the global allocator.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostHeap;

// SAFETY: blocks come from the global allocator with the layout asked, and
// go back to it with the same layout.
unsafe impl Alloc for HostHeap {
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        if layout.size() == 0 {
            return Err(AllocError);
        }
        // SAFETY: the size is not zero.
        NonNull::new(unsafe { alloc::alloc(layout) }).ok_or(AllocError)
    }

    unsafe fn free(&self, block: NonNull<u8>, layout: Layout) {
        // SAFETY: the block came from `alloc` with this layout.
        unsafe { alloc::dealloc(block.as_ptr(), layout) };
    }
}
