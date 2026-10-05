// SPDX-License-Identifier: CMU-Mach
// Derived from kern/syscall_emulation.c and kern/syscall_emulation.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The user-space system call emulation module.

use crate::arch::types::{VmOffset, VmSize};
use crate::ipc::ipc_init;
use crate::kern::error::Error;
use crate::kern::lock::SimpleLock;
use crate::kern::slab::{kalloc, kfree};
use crate::kern::task::Task;
use crate::vm::vm_kern::{kmem_alloc, kmem_free};
use crate::vm::vm_map::{VmMapCopy, round_page};
use core::ffi::c_int;
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// The `emulation_vector_t` of a task, as `task_get_emulation_vector()`
/// returns one.
pub(crate) struct EmulationVector {
    /// `*vector_start`.
    pub(crate) start: c_int,
    /// The emulation vector, a map copy the server returns out of line.
    pub(crate) vector: *mut VmOffset,
    /// `*emulation_vector_count`.
    pub(crate) count: u32,
}

/// One task's dispatch table, whose vector follows the header in one
/// allocation.
///
/// The `x86_64` system-call entry reads `disp_min`, `disp_count` and
/// `disp_vector` at the C header's offsets, so the field order here is the
/// ABI.
#[repr(C)]
pub struct EmlDispatch {
    /// `lock`: protects `ref_count` only.
    lock: SimpleLock,
    ref_count: c_int,
    /// `disp_count`: the number of entries in the vector.
    disp_count: c_int,
    /// `disp_min`: the index of the vector's lowest entry.
    disp_min: c_int,
    /// `disp_vector`: the dispatch entries, allocated with the header.  The
    /// C writes `[1]` so its `sizeof` carries one entry; the count here
    /// spells that entry in `count_to_size()` instead.
    disp_vector: [VmOffset; 0],
}

const _: () = {
    assert!(size_of::<EmlDispatch>() == 16);
    assert!(core::mem::offset_of!(EmlDispatch, lock) == 0);
    assert!(core::mem::offset_of!(EmlDispatch, ref_count) == 4);
    assert!(core::mem::offset_of!(EmlDispatch, disp_count) == 8);
    assert!(core::mem::offset_of!(EmlDispatch, disp_min) == 12);
    assert!(core::mem::offset_of!(EmlDispatch, disp_vector) == 16);
};

/// The allocation size of a dispatch table holding `count` entries.
const fn count_to_size(count: usize) -> usize {
    size_of::<EmlDispatch>() + size_of::<VmOffset>() * count
}

/// The vector that follows the table's header.
///
/// # Safety
///
/// `eml` must point at a live dispatch table.
unsafe fn vector(eml: *mut EmlDispatch) -> *mut VmOffset {
    // SAFETY: every dispatch table allocates its vector in the same
    // allocation, right after the header.
    unsafe { ptr::addr_of_mut!((*eml).disp_vector).cast::<VmOffset>() }
}

/// Gives `task` a reference to `parent`'s emulation vector.
///
/// # Safety
///
/// `task` must be a live task, and a non-null `parent` a live task.
pub(crate) unsafe fn task_reference(
    task: *mut Task,
    parent: Option<NonNull<Task>>,
) {
    let eml = unsafe {
        parent
            .map_or(ptr::null_mut(), |parent| (*parent.as_ptr()).eml_dispatch)
    };

    if !eml.is_null() {
        unsafe {
            (*eml).lock.lock();
            (*eml).ref_count = (*eml).ref_count.wrapping_add(1);
            (*eml).lock.unlock();
        }
    }

    unsafe { (*task).eml_dispatch = eml };
}

/// Drops one reference to a task's emulation vector, freeing it with the last
/// one.
///
/// # Safety
///
/// `task` must be a live task whose emulation vector belongs to the task
/// this call is deallocating.
pub(crate) unsafe fn task_deallocate(task: *mut Task) {
    let eml = unsafe { (*task).eml_dispatch };
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
            kfree(
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
/// `vector_start` in `task`'s emulation vector, growing it as needed.
///
/// # Errors
///
/// Returns [`Error::NoEmulationTask`] when `task` is null, and
/// [`Error::ResourceShortage`] when the larger table cannot be allocated.
///
/// # Safety
///
/// `task` must be null or a live task, and `emulation_vector` must point at
/// `emulation_vector_count` readable entries.
pub(crate) unsafe fn set_vector_internal(
    task: *mut Task,
    vector_start: c_int,
    emulation_vector: *mut VmOffset,
    emulation_vector_count: u32,
) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::NoEmulationTask);
    }

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
            (*task).lock.lock();
            cur_eml = (*task).eml_dispatch;

            if cur_eml.is_null() {
                if !new_eml.is_null() {
                    (*task).eml_dispatch = new_eml;
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

                    (*task).eml_dispatch = new_eml;
                    cur_eml = new_eml;
                    break;
                }
                (*cur_eml).lock.unlock();

                (new_start, new_end) =
                    merge_range(cur_start, cur_end, vector_start, vector_end);
            }

            (*task).lock.unlock();

            if !new_eml.is_null() {
                kfree(
                    NonNull::new_unchecked(new_eml.cast::<u8>()),
                    count_to_size((*new_eml).disp_count as usize),
                );
            }
        }

        let new_size = count_to_size(new_end.wrapping_sub(new_start) as usize);
        // The C kalloc() returned zero here and then memset a null pointer;
        // an out-of-memory boot returns the error instead.
        let Some(buffer) = kalloc(new_size) else {
            return Err(Error::ResourceShortage);
        };

        // SAFETY: the buffer is a fresh allocation of `new_size` bytes; the
        // table's lock starts unlocked and the fields are filled in before
        // the next task-lock round can see it.
        unsafe {
            ptr::write_bytes(buffer.as_ptr(), 0, new_size);
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
        (*task).lock.unlock();

        if !old_eml.is_null() {
            kfree(
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
/// Returns [`Error::NoEmulationTask`] when `task` is null,
/// [`Error::ResourceShortage`] when the staging buffer cannot be allocated,
/// and [`Error::Vm`] when the copy cannot be made.
///
/// # Safety
///
/// `task` must be null or a live task.
pub(crate) unsafe fn get_vector(
    task: *mut Task,
) -> Result<EmulationVector, Error> {
    if task.is_null() {
        return Err(Error::NoEmulationTask);
    }

    let map = ipc_init::ipc_kernel_map();
    let mut addr: VmOffset = 0;
    let mut size: VmSize = 0;
    let mut vector_size;
    let mut eml;

    loop {
        unsafe {
            (*task).lock.lock();
            eml = (*task).eml_dispatch;
            if eml.is_null() {
                (*task).lock.unlock();
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
            (*task).lock.unlock();
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
        (*task).lock.unlock();

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
/// Returns [`Error::NoEmulationTask`] when `task` is null, [`Error::Vm`]
/// when the vector cannot be mapped, and the error of installing it.
///
/// # Safety
///
/// `task` must be null or a live task, and `emulation_vector` a live map copy
/// or null.
pub(crate) unsafe fn set_vector(
    task: *mut Task,
    vector_start: c_int,
    emulation_vector: *mut VmOffset,
    emulation_vector_count: u32,
) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::NoEmulationTask);
    }

    let map = ipc_init::ipc_kernel_map();

    let addr = match NonNull::new(emulation_vector.cast::<VmMapCopy>()) {
        Some(copy) => unsafe { (&mut *map).copyout(copy) }?,
        None => 0,
    };

    // SAFETY: `addr` is where the copyout placed the caller's vector, which
    // has `emulation_vector_count` entries.
    let installed = unsafe {
        set_vector_internal(
            task,
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
