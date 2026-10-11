// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The emulation vector of a task: installing entries, sharing the table
//! with a child, and copying it out.
//!
//! Each routine takes the task's lock and the slot in the task that points
//! at its table, so it names no task.

use crate::dispatch::{EmlDispatch, count_to_size, vector};
use crate::error::Error;
use crate::types::EmulationVector;
use core::ffi::c_int;
use core::mem::size_of;
use core::ptr;
use core::ptr::NonNull;
use mach_page::simple_lock::SimpleLock;
use mach_vm::Platform;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::vm_kern::{kmem_alloc, kmem_free};
use mach_vm::vm_map::{VmMapCopy, round_page};

/// Points a new task's `slot` at `parent`, a parent's table or null, taking a
/// reference to it.
///
/// # Safety
///
/// `slot` must be the new task's writable slot, and a non-null `parent` a
/// live table.
pub unsafe fn share(slot: *mut *mut EmlDispatch, parent: *mut EmlDispatch) {
    let eml = parent;

    if !eml.is_null() {
        unsafe {
            (*eml).lock.lock();
            (*eml).ref_count = (*eml).ref_count.wrapping_add(1);
            (*eml).lock.unlock();
        }
    }

    unsafe { *slot = eml };
}

/// Drops a dying task's reference to its table `eml`, a table or null,
/// freeing it with the last one.
///
/// # Safety
///
/// A non-null `eml` must be the table of the task being deallocated.
pub unsafe fn release<P: Platform>(eml: *mut EmlDispatch) {
    if eml.is_null() {
        return;
    }

    let count = unsafe {
        (*eml).lock.lock();
        let count = (*eml).ref_count.wrapping_sub(1);
        (*eml).ref_count = count;
        (*eml).lock.unlock();
        count
    };

    if count == 0 {
        // SAFETY: the count just reached zero, so nothing else holds the
        // table; its size follows from the count it kept.
        unsafe {
            P::kfree(
                NonNull::new_unchecked(eml.cast::<u8>()),
                count_to_size((*eml).disp_count as usize),
            );
        };
    }
}

/// The range that covers both `[cur_start, cur_end)` and
/// `[vector_start, vector_end)`, as the C's two `if`s picked.
const fn merge_range(
    cur_start: c_int,
    cur_end: c_int,
    vector_start: c_int,
    vector_end: c_int,
) -> (c_int, c_int) {
    let start = if vector_start < cur_start {
        vector_start
    } else {
        cur_start
    };
    let end = if vector_end < cur_end {
        cur_end
    } else {
        vector_end
    };
    (start, end)
}

/// Installs `emulation_vector_count` entries of `emulation_vector` from
/// `vector_start` in the task's emulation vector, growing it as needed.
///
/// # Errors
///
/// Returns [`Error::ResourceShortage`] when the larger table cannot be
/// allocated.
///
/// # Safety
///
/// `lock` and `slot` must be a live task's lock and slot, and
/// `emulation_vector` must point at `emulation_vector_count` readable
/// entries.
pub unsafe fn set_vector_internal<P: Platform>(
    lock: &SimpleLock,
    slot: *mut *mut EmlDispatch,
    vector_start: c_int,
    emulation_vector: *mut VmOffset,
    emulation_vector_count: u32,
) -> Result<(), Error> {
    // The C added the unsigned count to the `int` start and kept the
    // low word.
    let vector_end =
        vector_start.wrapping_add(emulation_vector_count as c_int);
    let mut cur_eml;
    // The vector to discard once the table is installed.
    let mut old_eml: *mut EmlDispatch = ptr::null_mut();
    // The table allocated outside the task lock.
    let mut new_eml: *mut EmlDispatch = ptr::null_mut();
    let mut new_start: c_int = 0;
    let mut new_end: c_int = 0;

    loop {
        unsafe {
            lock.lock();
            cur_eml = *slot;

            if cur_eml.is_null() {
                if !new_eml.is_null() {
                    *slot = new_eml;
                    cur_eml = new_eml;
                    break;
                }

                new_start = vector_start;
                new_end = vector_end;
            } else {
                let cur_start = (*cur_eml).disp_min;
                let cur_end = (*cur_eml).disp_count.wrapping_add(cur_start);

                (*cur_eml).lock.lock();
                if (*cur_eml).ref_count == 1
                    && cur_start <= vector_start
                    && cur_end >= vector_end
                {
                    // The existing vector can hold the new entries; any
                    // newly allocated one is discarded.
                    (*cur_eml).lock.unlock();
                    old_eml = new_eml;
                    break;
                }

                if !new_eml.is_null()
                    && new_start <= cur_start
                    && new_end >= cur_end
                {
                    // The new vector holds the old entries; copy them over
                    // and drop the old table's reference.
                    ptr::copy_nonoverlapping(
                        vector(cur_eml),
                        vector(new_eml).add((cur_start - new_start) as usize),
                        (*cur_eml).disp_count as usize,
                    );
                    (*cur_eml).ref_count =
                        (*cur_eml).ref_count.wrapping_sub(1);
                    if (*cur_eml).ref_count == 0 {
                        old_eml = cur_eml;
                    }
                    (*cur_eml).lock.unlock();

                    *slot = new_eml;
                    cur_eml = new_eml;
                    break;
                }
                (*cur_eml).lock.unlock();

                (new_start, new_end) =
                    merge_range(cur_start, cur_end, vector_start, vector_end);
            }

            lock.unlock();

            if !new_eml.is_null() {
                P::kfree(
                    NonNull::new_unchecked(new_eml.cast::<u8>()),
                    count_to_size((*new_eml).disp_count as usize),
                );
            }
        }

        let new_size = count_to_size(new_end.wrapping_sub(new_start) as usize);
        // The C `kalloc()` returned zero here and then memset a null pointer;
        // an out-of-memory boot returns the error instead.
        let Some(buffer) = P::kalloc(new_size) else {
            return Err(Error::ResourceShortage);
        };

        // SAFETY: the buffer is a fresh allocation of `new_size` bytes; the
        // table's lock starts unlocked and the fields are filled in before
        // the next task-lock round can see it.
        unsafe {
            ptr::write_bytes(buffer.as_ptr(), 0, new_size);
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "every `kalloc` buffer is aligned to 8 bytes, the \
                          table's alignment"
            )]
            let table = buffer.as_ptr().cast::<EmlDispatch>();
            (*table).lock.init();
            (*table).ref_count = 1;
            (*table).disp_min = new_start;
            (*table).disp_count = new_end.wrapping_sub(new_start);
            new_eml = table;
        }
    }

    // SAFETY: the task lock is held and the table was chosen above; the
    // caller promises the readable entries.
    unsafe {
        if emulation_vector_count != 0 {
            ptr::copy_nonoverlapping(
                emulation_vector,
                vector(cur_eml)
                    .add((vector_start - (*cur_eml).disp_min) as usize),
                emulation_vector_count as usize,
            );
        }
        lock.unlock();

        if !old_eml.is_null() {
            P::kfree(
                NonNull::new_unchecked(old_eml.cast::<u8>()),
                count_to_size((*old_eml).disp_count as usize),
            );
        }
    }

    Ok(())
}

/// Copies a task's emulation vector into an out-of-line map copy.
///
/// # Errors
///
/// Returns [`Error::ResourceShortage`] when the staging buffer cannot be
/// allocated, and [`Error::Vm`] when the copy cannot be made.
///
/// # Safety
///
/// `lock` and `slot` must be a live task's lock and slot.
pub unsafe fn get_vector<P: Platform>(
    lock: &SimpleLock,
    slot: *mut *mut EmlDispatch,
) -> Result<EmulationVector, Error> {
    let map = P::state().ipc_kernel_map();
    let mut addr: VmOffset = 0;
    let mut size: VmSize = 0;
    let mut vector_size;
    let mut eml;

    loop {
        unsafe {
            lock.lock();
            eml = *slot;
            if eml.is_null() {
                lock.unlock();
                if addr != 0 {
                    let _ = kmem_free(&mut *map, addr, size);
                }
                return Ok(EmulationVector {
                    start: 0,
                    vector: ptr::null_mut(),
                    count: 0,
                });
            }

            vector_size = ((*eml).disp_count as usize)
                .wrapping_mul(size_of::<VmOffset>());
        }

        let size_needed = round_page(vector_size);
        if size_needed <= size {
            break;
        }

        // SAFETY: the task lock is not held; the caller promised the live
        // task and the map is the live kernel map.
        unsafe {
            lock.unlock();
            if size != 0 {
                let _ = kmem_free(&mut *map, addr, size);
            }
            size = size_needed;
            match kmem_alloc(NonNull::new_unchecked(map), size) {
                Ok(allocated) => addr = allocated,
                Err(_) => return Err(Error::ResourceShortage),
            }
        }
    }

    // SAFETY: the task lock is held, the table is live, and `addr` holds
    // `size` bytes, at least `vector_size` of them.
    unsafe {
        let start = (*eml).disp_min;
        let count = (*eml).disp_count as u32;
        if vector_size != 0 {
            ptr::copy_nonoverlapping(
                vector(eml),
                addr as *mut VmOffset,
                vector_size / size_of::<VmOffset>(),
            );
        }
        lock.unlock();

        let size_used = round_page(vector_size);
        if size_used != size {
            let _ = kmem_free(&mut *map, addr + size_used, size - size_used);
        }

        let size_left = size_used - vector_size;
        if size_left > 0 {
            ptr::write_bytes((addr + vector_size) as *mut u8, 0, size_left);
        }

        // The C ignored the copyin result and returned an uninitialized
        // pointer on failure; the kernel map's wired pages cannot fail it,
        // and the error is returned instead of a garbage vector.
        let memory = if vector_size == 0 {
            ptr::null_mut()
        } else {
            match (&mut *map).copyin(addr, vector_size, true) {
                Ok(copy) => copy.as_ptr(),
                Err(error) => return Err(Error::Vm(error)),
            }
        };

        Ok(EmulationVector {
            start,
            vector: memory.cast(),
            count,
        })
    }
}

/// Maps the out-of-line vector into the kernel map, installs it, and frees the
/// mapping.
///
/// # Errors
///
/// Returns [`Error::Vm`] when the vector cannot be mapped, and the error of
/// installing it.
///
/// # Safety
///
/// `lock` and `slot` must be a live task's lock and slot, and
/// `emulation_vector` a live map copy or null.
pub unsafe fn set_vector<P: Platform>(
    lock: &SimpleLock,
    slot: *mut *mut EmlDispatch,
    vector_start: c_int,
    emulation_vector: *mut VmOffset,
    emulation_vector_count: u32,
) -> Result<(), Error> {
    let map = P::state().ipc_kernel_map();

    let addr = match NonNull::new(emulation_vector.cast::<VmMapCopy<P>>()) {
        Some(copy) => unsafe { (&mut *map).copyout(copy) }?,
        None => 0,
    };

    // SAFETY: `addr` is where the copyout placed the caller's vector, which
    // has `emulation_vector_count` entries.
    let installed = unsafe {
        set_vector_internal::<P>(
            lock,
            slot,
            vector_start,
            addr as *mut VmOffset,
            emulation_vector_count,
        )
    };

    // SAFETY: the region came from the copyout above and is still mapped.
    unsafe {
        let _ = kmem_free(
            &mut *map,
            addr,
            (emulation_vector_count as usize)
                .wrapping_mul(size_of::<VmOffset>()),
        );
    }

    installed
}
