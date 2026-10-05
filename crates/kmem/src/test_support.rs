// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A mock allocator that fails on demand and checks every free.

use crate::alloc::{Alloc, AllocError};
use core::alloc::Layout;
use core::cell::Cell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{alloc, dealloc};
use std::sync::Mutex;
use std::vec::Vec;

/// A heap that counts calls, fails from the Nth one on, and panics on a
/// free whose layout differs from the allocation's, or on drop with live
/// blocks.
pub(crate) struct Heap {
    live: Mutex<Vec<(usize, Layout)>>,
    calls: AtomicUsize,
    fail_from: AtomicUsize,
}

impl Heap {
    pub(crate) fn new() -> Self {
        Self::failing_from(usize::MAX)
    }

    /// Fails the `n`th call (from zero) and every one after it.
    pub(crate) fn failing_from(n: usize) -> Self {
        Self {
            live: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            fail_from: AtomicUsize::new(n),
        }
    }

    /// Fails the `n`th call from now (from zero) and every one after it.
    pub(crate) fn fail_from_now(&self, n: usize) {
        self.fail_from.store(self.calls() + n, Ordering::Relaxed);
    }

    /// Lets every later call succeed.
    pub(crate) fn stop_failing(&self) {
        self.fail_from.store(usize::MAX, Ordering::Relaxed);
    }

    pub(crate) fn live(&self) -> usize {
        self.live.lock().unwrap().len()
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    /// Stops the drop check for blocks a test leaked on purpose.
    pub(crate) fn forget_live(&self) {
        self.live.lock().unwrap().clear();
    }
}

impl Drop for Heap {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(self.live.lock().unwrap().is_empty(), "leaked blocks");
        }
    }
}

// SAFETY: blocks come from the global allocator with the layout asked, and
// are freed with the same layout.  A block is filled with 0xAA so a caller
// that assumes zeroed memory is caught.
unsafe impl Alloc for Heap {
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        assert_ne!(layout.size(), 0, "a zero size reached the allocator");
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        if call >= self.fail_from.load(Ordering::Relaxed) {
            return Err(AllocError);
        }
        // SAFETY: the size is not zero.
        let block = NonNull::new(unsafe { alloc(layout) }).expect("host heap");
        // Miri flags any read of uninitialized bytes itself, which the fill
        // would hide.
        #[cfg(not(miri))]
        // SAFETY: the block is `layout.size()` writable bytes.
        unsafe {
            block.as_ptr().write_bytes(0xAA, layout.size());
        }
        self.live.lock().unwrap().push((block.addr().get(), layout));
        Ok(block)
    }

    unsafe fn free(&self, block: NonNull<u8>, layout: Layout) {
        let mut live = self.live.lock().unwrap();
        let at = live
            .iter()
            .position(|&(addr, _)| addr == block.addr().get())
            .expect("free of a block that is not live");
        assert_eq!(live.swap_remove(at).1, layout, "free with another layout");
        // SAFETY: the block came from `alloc` with this layout.
        unsafe { dealloc(block.as_ptr(), layout) };
    }
}

/// A value that counts its drops.
#[derive(Debug)]
pub(crate) struct Tracked<'a>(&'a Cell<usize>);

impl<'a> Tracked<'a> {
    pub(crate) fn new(drops: &'a Cell<usize>) -> Self {
        Self(drops)
    }
}

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boxed::KBox;

    #[test]
    #[should_panic(expected = "leaked blocks")]
    fn a_leak_is_caught() {
        let heap = Heap::new();
        let _ = KBox::leak(KBox::try_new(1_u8, &heap).unwrap());
    }

    #[test]
    #[should_panic(expected = "free with another layout")]
    fn a_free_with_another_layout_is_caught() {
        let heap = Heap::new();
        let block = heap.alloc(Layout::new::<u64>()).unwrap();
        // SAFETY: deliberately wrong, to see the mock refuse it.
        unsafe { heap.free(block, Layout::new::<u32>()) };
    }

    #[test]
    #[should_panic(expected = "not live")]
    fn a_free_of_a_stranger_is_caught() {
        let heap = Heap::new();
        // SAFETY: deliberately wrong, to see the mock refuse it.
        unsafe { heap.free(NonNull::dangling(), Layout::new::<u8>()) };
    }

    #[test]
    #[should_panic(expected = "zero size")]
    fn a_zero_size_is_caught() {
        let heap = Heap::new();
        let _ = heap.alloc(Layout::new::<()>());
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn a_panic_with_a_live_block_is_not_a_leak_report() {
        let heap = Heap::new();
        let block = heap.alloc(Layout::new::<u8>()).unwrap();
        let _ = block;
        panic!("boom");
    }
}
