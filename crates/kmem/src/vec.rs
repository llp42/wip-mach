// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`KVec`], a growable run of values on the heap.

use crate::alloc::{Alloc, AllocError, array_layout, reallocate, release};
use crate::slice::KBoxSlice;
use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop, MaybeUninit};
use core::ops::{Bound, Deref, DerefMut, RangeBounds};
use core::ptr::{self, NonNull};
use core::slice;

/// A growable run of `T` on the heap.
///
/// Growth allocates a new block, copies and frees the old one, and fails
/// with [`AllocError`] instead of panicking; a failed growth leaves the
/// vector as it was.
pub struct KVec<T, A: Alloc> {
    ptr: NonNull<T>,
    cap: usize,
    len: usize,
    alloc: A,
    owns: PhantomData<T>,
}

// SAFETY: a `KVec` owns its values and its allocator outright.
unsafe impl<T: Send, A: Alloc + Send> Send for KVec<T, A> {}
// SAFETY: shared access to a `KVec` is shared access to its values.
unsafe impl<T: Sync, A: Alloc + Sync> Sync for KVec<T, A> {}

impl<T, A: Alloc> KVec<T, A> {
    /// Holds the capacity a first push allocates: the standard library's, so a
    /// byte vector starts at 8 and a large element at 1.
    const MIN_CAP: usize = if size_of::<T>() == 1 {
        8
    } else if size_of::<T>() <= 1024 {
        4
    } else {
        1
    };

    /// The capacity of a vector that owns no block: unbounded for a
    /// zero-sized `T`, which never grows, and zero otherwise.  Branch-free,
    /// so no instantiation carries an arm it can never take.
    const EMPTY_CAP: usize =
        usize::MAX - size_of::<T>().saturating_mul(usize::MAX);

    /// Returns an empty vector; it allocates nothing.
    #[must_use]
    pub const fn new(alloc: A) -> Self {
        Self {
            ptr: NonNull::dangling(),
            cap: Self::EMPTY_CAP,
            len: 0,
            alloc,
            owns: PhantomData,
        }
    }

    /// An empty vector with room for exactly `cap` values.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_with_capacity(
        cap: usize,
        alloc: A,
    ) -> Result<Self, AllocError> {
        let mut vec = Self::new(alloc);
        vec.try_reserve_exact(cap).map(|()| vec)
    }

    /// Returns how many values fit without growing; a zero-sized `T` never
    /// grows.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.cap
    }

    /// Makes room for `additional` more values, growing by doubling.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_reserve(
        &mut self,
        additional: usize,
    ) -> Result<(), AllocError> {
        self.needed(additional).and_then(|needed| {
            if needed <= self.capacity() {
                return Ok(());
            }
            let doubled = self.cap.saturating_mul(2);
            self.set_capacity(needed.max(doubled).max(Self::MIN_CAP))
        })
    }

    /// Makes room for `additional` more values, and no more.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> Result<(), AllocError> {
        self.needed(additional).and_then(|needed| {
            if needed <= self.capacity() {
                return Ok(());
            }
            self.set_capacity(needed)
        })
    }

    /// Appends `value`; a failure drops it.
    ///
    /// Call [`Self::try_reserve`] first and then
    /// [`Self::push_within_capacity`] to keep the value across a failure.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    pub fn try_push(&mut self, value: T) -> Result<(), AllocError> {
        self.try_reserve(1).map(|()| {
            // SAFETY: the reserve left room for one more.
            unsafe { self.push_unchecked(value) };
        })
    }

    /// Appends `value` if it fits without growing, or hands it back.
    ///
    /// # Errors
    ///
    /// `Err(value)` when the vector is full.
    pub const fn push_within_capacity(&mut self, value: T) -> Result<(), T> {
        if self.len == self.capacity() {
            return Err(value);
        }
        // SAFETY: the vector is not full.
        unsafe { self.push_unchecked(value) };
        Ok(())
    }

    /// Appends a copy of every value in `src`.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short; nothing is appended.
    pub fn extend_from_slice(&mut self, src: &[T]) -> Result<(), AllocError>
    where
        T: Copy,
    {
        self.try_reserve(src.len()).map(|()| {
            // SAFETY: the reserve left room for `src.len()` more, and `src`
            // cannot alias the spare capacity it borrows past `len`.
            unsafe {
                ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    self.ptr.as_ptr().add(self.len),
                    src.len(),
                );
            }
            self.len += src.len();
        })
    }

    /// Drops every value; the capacity stays.
    pub fn clear(&mut self) {
        let len = mem::replace(&mut self.len, 0);
        // SAFETY: `len` values were live and are no longer counted.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.ptr.as_ptr(),
                len,
            ));
        }
    }

    /// Removes and returns the value at `index`, shifting the rest down;
    /// `None` when `index` is out of range.
    pub const fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        // SAFETY: `index < len`, so the read is a live value, and the tail
        // moves over the hole it leaves.
        unsafe {
            let at = self.ptr.as_ptr().add(index);
            let value = at.read();
            ptr::copy(at.add(1), at, self.len - index - 1);
            self.len -= 1;
            Some(value)
        }
    }

    /// Removes the values in `range` and yields them; `None` when the range
    /// is reversed or ends past the length.
    ///
    /// The values not yet yielded are dropped with the iterator, and the
    /// tail closes the gap then.
    pub fn drain<R: RangeBounds<usize>>(
        &mut self,
        range: R,
    ) -> Option<Drain<'_, T, A>> {
        let len = self.len;
        resolve(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            len,
        )
        .map(|(start, end)| {
            // The values past `start` are the drain's now; a leaked drain
            // loses them but never double-drops.
            self.len = start;
            Drain {
                vec: self,
                next: start,
                end,
                tail_len: len - end,
            }
        })
    }

    /// Returns the room past the last value, for filling in place.
    ///
    /// Write it, then count the values with [`Self::set_len`].
    pub const fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        // SAFETY: `cap - len` slots past the values belong to the block.
        unsafe {
            slice::from_raw_parts_mut(
                self.ptr.as_ptr().add(self.len).cast(),
                self.capacity() - self.len,
            )
        }
    }

    /// Sets the length.
    ///
    /// # Safety
    ///
    /// `new_len` must not exceed the capacity, and the first `new_len`
    /// slots must hold valid values.
    pub const unsafe fn set_len(&mut self, new_len: usize) {
        self.len = new_len;
    }

    /// Shrinks to the length and returns a fixed-length slice.
    ///
    /// # Errors
    ///
    /// The vector itself, unchanged, when the shrink cannot allocate.
    pub fn into_boxed_slice(mut self) -> Result<KBoxSlice<T, A>, Self> {
        if self.len != self.cap && self.set_capacity(self.len).is_err() {
            return Err(self);
        }
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is not dropped, so `alloc` moves out once, and the
        // block is exactly `len` values.
        Ok(unsafe {
            KBoxSlice::from_raw_parts(
                this.ptr,
                this.len,
                ptr::read(&raw const this.alloc),
            )
        })
    }

    fn needed(&self, additional: usize) -> Result<usize, AllocError> {
        self.len.checked_add(additional).ok_or(AllocError)
    }

    /// # Safety
    ///
    /// The vector must have room for one more value.
    const unsafe fn push_unchecked(&mut self, value: T) {
        // SAFETY: the caller left room for the slot at `len`.
        unsafe { self.ptr.as_ptr().add(self.len).write(value) };
        self.len += 1;
    }

    /// Moves the values into a block of exactly `new_cap` slots.
    fn set_capacity(&mut self, new_cap: usize) -> Result<(), AllocError> {
        array_layout(Layout::new::<T>(), new_cap)
            .and_then(|new_layout| {
                // SAFETY: the old block came from `alloc` with the layout of
                // `cap`, and `len` values fit in both blocks.
                unsafe {
                    reallocate(
                        &self.alloc,
                        self.ptr.cast(),
                        self.old_layout(),
                        new_layout,
                        self.len * size_of::<T>(),
                    )
                }
            })
            .map(|block| {
                self.ptr = block.cast();
                self.cap = new_cap;
            })
    }

    /// Returns the layout of the current block, which growth already
    /// validated.
    const fn old_layout(&self) -> Layout {
        // SAFETY: `set_capacity` built this layout, or `cap` is zero.
        unsafe {
            Layout::from_size_align_unchecked(
                size_of::<T>().unchecked_mul(self.cap),
                align_of::<T>(),
            )
        }
    }
}

impl<T, A: Alloc> Deref for KVec<T, A> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: `len` values of `T` are live at `ptr`.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T, A: Alloc> DerefMut for KVec<T, A> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as `deref`, and `&mut self` is unique.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T, A: Alloc> Drop for KVec<T, A> {
    fn drop(&mut self) {
        self.clear();
        // SAFETY: the block came from `alloc` with the array layout of
        // `cap`, or `cap` is zero and nothing was allocated.
        unsafe { release(&self.alloc, self.ptr.cast(), self.old_layout()) };
    }
}

impl<T: fmt::Debug, A: Alloc> fmt::Debug for KVec<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

/// Returns the `start..end` a range of a vector of `len` values names, or
/// `None` when it is reversed or ends past `len`.
fn resolve(
    start: Bound<usize>,
    end: Bound<usize>,
    len: usize,
) -> Option<(usize, usize)> {
    let start = match start {
        Bound::Included(n) => Some(n),
        Bound::Excluded(n) => n.checked_add(1),
        Bound::Unbounded => Some(0),
    }?;
    let end = match end {
        Bound::Included(n) => n.checked_add(1),
        Bound::Excluded(n) => Some(n),
        Bound::Unbounded => Some(len),
    }?;
    (start <= end && end <= len).then_some((start, end))
}

/// The values [`KVec::drain`] removes, yielded front to back.
pub struct Drain<'a, T, A: Alloc> {
    vec: &'a mut KVec<T, A>,
    next: usize,
    end: usize,
    tail_len: usize,
}

impl<T, A: Alloc> Iterator for Drain<'_, T, A> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next == self.end {
            return None;
        }
        // SAFETY: slots `next..end` hold live values the drain owns.
        let value = unsafe { self.vec.ptr.as_ptr().add(self.next).read() };
        self.next += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end - self.next;
        (left, Some(left))
    }
}

impl<T, A: Alloc> Drop for Drain<'_, T, A> {
    fn drop(&mut self) {
        // SAFETY: slots `next..end` hold the values not yet yielded, and
        // the tail past `end` moves down to the vector's length.
        unsafe {
            let base = self.vec.ptr.as_ptr();
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                base.add(self.next),
                self.end - self.next,
            ));
            let start = self.vec.len;
            ptr::copy(base.add(self.end), base.add(start), self.tail_len);
            self.vec.len = start + self.tail_len;
        }
    }
}

impl<T, A: Alloc> fmt::Debug for Drain<'_, T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drain")
            .field("left", &(self.end - self.next))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Heap, Tracked};
    use core::cell::Cell;
    use std::vec::Vec;

    fn filled<'h>(heap: &'h Heap, items: &[u32]) -> KVec<u32, &'h Heap> {
        let mut v = KVec::new(heap);
        v.extend_from_slice(items).unwrap();
        v
    }

    #[test]
    fn a_new_vector_allocates_nothing() {
        let heap = Heap::new();
        let v = KVec::<u32, _>::new(&heap);
        assert_eq!((v.len(), v.capacity()), (0, 0));
        drop(v);
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn push_grows_by_doubling_from_the_minimum() {
        let heap = Heap::new();
        let mut v = KVec::new(&heap);
        let mut caps = Vec::new();
        for i in 0_u32..9 {
            v.try_push(i).unwrap();
            if caps.last() != Some(&v.capacity()) {
                caps.push(v.capacity());
            }
        }
        assert_eq!(caps, [4, 8, 16]);
        assert_eq!(&*v, &[0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn the_minimum_capacity_follows_the_element_size() {
        let heap = Heap::new();
        let mut bytes = KVec::new(&heap);
        bytes.try_push(0_u8).unwrap();
        bytes.try_reserve_exact(0).unwrap();
        assert_eq!(bytes.capacity(), 8);
        let mut big = KVec::new(&heap);
        big.try_push([0_u8; 2000]).unwrap();
        assert_eq!(big.capacity(), 1);
        big.try_reserve(0).unwrap();
        big.try_reserve_exact(0).unwrap();
        big.try_reserve_exact(1).unwrap();
        assert_eq!(big.capacity(), 2);
    }

    #[test]
    fn a_failed_push_drops_the_value_and_keeps_the_vector() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        let mut v = KVec::new(&heap);
        v.try_push(Tracked::new(&drops)).unwrap();
        let broken = Heap::failing_from(0);
        let mut w = KVec::new(&broken);
        assert_eq!(w.try_push(Tracked::new(&drops)), Err(AllocError));
        assert_eq!(drops.get(), 1);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn reserve_then_push_within_capacity_keeps_the_value() {
        let heap = Heap::new();
        let mut v = KVec::new(&heap);
        v.try_reserve_exact(1).unwrap();
        assert_eq!(v.push_within_capacity(1_u32), Ok(()));
        assert_eq!(v.push_within_capacity(2), Err(2));
        assert_eq!(&*v, &[1]);
    }

    #[test]
    fn reserve_exact_asks_for_no_more() {
        let heap = Heap::new();
        let mut v = KVec::<u32, _>::try_with_capacity(3, &heap).unwrap();
        assert_eq!(v.capacity(), 3);
        v.try_reserve_exact(2).unwrap();
        assert_eq!(v.capacity(), 3);
        v.extend_from_slice(&[1, 2, 3]).unwrap();
        v.try_reserve_exact(2).unwrap();
        assert_eq!(v.capacity(), 5);
    }

    #[test]
    fn reserve_is_a_noop_when_room_remains() {
        let heap = Heap::new();
        let mut v = KVec::<u32, _>::try_with_capacity(4, &heap).unwrap();
        v.try_reserve(4).unwrap();
        assert_eq!(heap.calls(), 1);
    }

    #[test]
    fn a_failed_growth_leaves_the_vector_as_it_was() {
        let heap = Heap::failing_from(1);
        let mut v = KVec::new(&heap);
        v.extend_from_slice(&[1_u8, 2, 3]).unwrap();
        assert_eq!(v.try_reserve(100), Err(AllocError));
        assert_eq!(v.try_reserve_exact(100), Err(AllocError));
        assert_eq!(&*v, &[1, 2, 3]);
        assert_eq!(v.capacity(), 8);
    }

    #[test]
    fn a_failed_extend_appends_nothing() {
        let heap = Heap::failing_from(1);
        let mut v = filled(&heap, &[1]);
        assert!(v.extend_from_slice(&[0; 100]).is_err());
        assert_eq!(&*v, &[1]);
    }

    #[test]
    fn a_size_overflow_is_an_error_not_a_panic() {
        let heap = Heap::new();
        let mut v = KVec::<u32, _>::new(&heap);
        v.try_push(1).unwrap();
        assert_eq!(v.try_reserve(usize::MAX), Err(AllocError));
        assert_eq!(v.try_reserve_exact(usize::MAX), Err(AllocError));
        assert_eq!(v.try_reserve_exact(usize::MAX / 2), Err(AllocError));
        assert!(KVec::<u32, _>::try_with_capacity(usize::MAX, &heap).is_err());
    }

    #[test]
    fn clear_drops_the_values_and_keeps_the_room() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        let mut v = KVec::new(&heap);
        for _ in 0..3 {
            v.try_push(Tracked::new(&drops)).unwrap();
        }
        let cap = v.capacity();
        v.clear();
        assert_eq!((drops.get(), v.len(), v.capacity()), (3, 0, cap));
    }

    #[test]
    fn dropping_drops_the_values_and_frees_the_block() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        let mut v = KVec::new(&heap);
        v.try_push(Tracked::new(&drops)).unwrap();
        drop(v);
        assert_eq!((drops.get(), heap.live()), (1, 0));
    }

    #[test]
    fn remove_shifts_the_tail_down() {
        let heap = Heap::new();
        let mut v = filled(&heap, &[1, 2, 3, 4]);
        assert_eq!(v.remove(1), Some(2));
        assert_eq!(v.remove(0), Some(1));
        assert_eq!(&*v, &[3, 4]);
        assert_eq!(v.remove(2), None);
        assert_eq!(v.remove(3), None);
    }

    #[test]
    fn drain_yields_a_range_and_closes_the_gap() {
        let heap = Heap::new();
        let mut v = filled(&heap, &[1, 2, 3, 4, 5]);
        let got: Vec<u32> = v.drain(1..3).unwrap().collect();
        assert_eq!(got, [2, 3]);
        assert_eq!(&*v, &[1, 4, 5]);
    }

    #[test]
    fn drain_accepts_every_bound() {
        let heap = Heap::new();
        let mut v = filled(&heap, &[1, 2, 3, 4, 5]);
        assert_eq!(v.drain(..=1).unwrap().count(), 2);
        assert_eq!(&*v, &[3, 4, 5]);
        assert_eq!(
            v.drain((Bound::Excluded(0), Bound::Unbounded))
                .unwrap()
                .count(),
            2,
        );
        assert_eq!(&*v, &[3]);
        assert_eq!(v.drain(..).unwrap().count(), 1);
        assert!(v.is_empty());
    }

    #[test]
    fn drain_rejects_a_bad_range() {
        let heap = Heap::new();
        let mut v = filled(&heap, &[1, 2, 3]);
        assert!(v.drain((Bound::Included(2), Bound::Excluded(1))).is_none());
        assert!(v.drain(..4).is_none());
        assert!(v.drain(4..).is_none());
        assert_eq!(v.drain(1..).unwrap().count(), 2);
        v.clear();
        v.extend_from_slice(&[1, 2, 3]).unwrap();
        assert!(v.drain(..=usize::MAX).is_none());
        assert!(
            v.drain((Bound::Excluded(usize::MAX), Bound::Unbounded))
                .is_none()
        );
        assert_eq!(&*v, &[1, 2, 3]);
    }

    #[test]
    fn a_dropped_drain_drops_what_it_did_not_yield() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        let mut v = KVec::new(&heap);
        for _ in 0..5 {
            v.try_push(Tracked::new(&drops)).unwrap();
        }
        let mut d = v.drain(1..4).unwrap();
        assert_eq!(d.size_hint(), (3, Some(3)));
        drop(d.next());
        assert_eq!(drops.get(), 1);
        assert_eq!(std::format!("{d:?}"), "Drain { left: 2 }");
        drop(d);
        assert_eq!((drops.get(), v.len()), (3, 2));
        assert_eq!(v.drain(..).unwrap().count(), 2);
        assert_eq!(drops.get(), 5);
    }

    #[test]
    fn spare_capacity_is_filled_in_place() {
        let heap = Heap::new();
        let mut v = KVec::<u8, _>::try_with_capacity(4, &heap).unwrap();
        v.extend_from_slice(&[1]).unwrap();
        let spare = v.spare_capacity_mut();
        assert_eq!(spare.len(), 3);
        for (slot, byte) in spare.iter_mut().zip([7_u8, 8]) {
            let _ = slot.write(byte);
        }
        // SAFETY: three slots are written and the capacity is four.
        unsafe { v.set_len(3) };
        assert_eq!(&*v, &[1, 7, 8]);
    }

    #[test]
    fn into_boxed_slice_shrinks_to_fit() {
        let heap = Heap::new();
        let v = filled(&heap, &[1, 2, 3]);
        assert_eq!(v.capacity(), 4);
        let s = v.into_boxed_slice().unwrap();
        assert_eq!(&*s, &[1, 2, 3]);
        assert_eq!(heap.live(), 1);
    }

    #[test]
    fn into_boxed_slice_of_a_full_vector_copies_nothing() {
        let heap = Heap::new();
        let mut v = KVec::<u32, _>::try_with_capacity(2, &heap).unwrap();
        v.extend_from_slice(&[1, 2]).unwrap();
        let s = v.into_boxed_slice().unwrap();
        assert_eq!((&*s, heap.calls()), (&[1, 2][..], 1));
    }

    #[test]
    fn into_boxed_slice_of_an_empty_vector_frees_the_block() {
        let heap = Heap::new();
        let mut v = filled(&heap, &[1]);
        v.clear();
        let s = v.into_boxed_slice().unwrap();
        assert!(s.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn a_failed_shrink_hands_the_vector_back() {
        let heap = Heap::failing_from(1);
        let v = filled(&heap, &[1, 2, 3]);
        let v = v.into_boxed_slice().unwrap_err();
        assert_eq!((&*v, v.capacity()), (&[1, 2, 3][..], 4));
    }

    #[test]
    fn a_zero_sized_element_never_allocates() {
        let heap = Heap::new();
        let mut v = KVec::<(), _>::new(&heap);
        assert_eq!(v.capacity(), usize::MAX);
        assert_eq!(v.spare_capacity_mut().len(), usize::MAX);
        // SAFETY: a zero-sized value needs no write, and the capacity is
        // unbounded.
        unsafe { v.set_len(2) };
        assert_eq!(v.spare_capacity_mut().len(), usize::MAX - 2);
        assert_eq!(v.len(), 2);
        drop(v);
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn mutates_in_place_through_the_slice() {
        let heap = Heap::new();
        let mut v = filled(&heap, &[1, 2]);
        v[1] = 5;
        assert_eq!(&*v, &[1, 5]);
        assert_eq!(std::format!("{v:?}"), "[1, 5]");
    }

    #[test]
    fn crosses_threads_when_its_parts_do() {
        fn send<T: Send>(_: &T) {}
        fn sync<T: Sync>(_: &T) {}
        let heap = Heap::new();
        let v = KVec::<u8, _>::new(&heap);
        send(&v);
        sync(&v);
    }
}
