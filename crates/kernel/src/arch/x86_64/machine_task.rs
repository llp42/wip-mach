// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/machine_task.c, i386/i386/task.h and
// i386/i386/io_perm.h:
//   Copyright (c) 2002, 2007 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The machine task module, which `i386/i386/machine_task.c` used to define,
//! and the `struct machine_task` mirror of `i386/i386/task.h`.

use crate::arch::types::VmSize;
use crate::kern::lock::SimpleLock;
use crate::kern::slab::CacheInitFlags;
use crate::kern::slab::KmemCache;
use core::ffi::c_int;
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};

/// `struct machine_task` of <i386/task.h>: the machine-specific part of a
/// task, the lock and range of its I/O-permission bitmap.
#[repr(C)]
pub struct MachineTask {
    /// `iopb_lock`: protects `iopb_size` and `iopb`.
    pub iopb_lock: SimpleLock,
    /// `iopb_size`: the highest I/O port number enabled.
    pub iopb_size: c_int,
    /// `iopb`: the permission bitmap, or null.
    pub iopb: *mut u8,
}

const _: () = {
    assert!(size_of::<MachineTask>() == 16);
    assert!(align_of::<MachineTask>() == 8);
    assert!(offset_of!(MachineTask, iopb_lock) == 0);
    assert!(offset_of!(MachineTask, iopb_size) == 4);
    assert!(offset_of!(MachineTask, iopb) == 8);
};

/// `IOPB_MAX` of <`i386/io_perm.h>`: the highest I/O port a task's permission
/// bitmap can name.
const IOPB_MAX: VmSize = 0xffff;

/// `IOPB_BYTES` of <`i386/io_perm.h>`: one bit per port, rounded up to whole
/// bytes.
pub(crate) const IOPB_BYTES: VmSize = (IOPB_MAX + 1).div_ceil(8);

/// `machine_task_iopb_cache` of `i386/i386/machine_task.c`: the cache the
/// permission bitmaps come from.
pub(crate) static mut IOPB_CACHE: KmemCache = KmemCache::zeroed();

/// The cache, by raw pointer so that concurrent calls stay sound under Rust's
/// aliasing rules; the cache's own lock serializes them.
fn iopb_cache() -> *mut KmemCache {
    &raw mut IOPB_CACHE
}

impl MachineTask {
    /// `machine_task_init()` in C.
    pub(crate) fn init(&mut self) {
        self.iopb_size = 0;
        self.iopb = ptr::null_mut();
        self.iopb_lock.init();
    }

    /// `machine_task_terminate()` in C: free the bitmap of a task that is
    /// going away.
    pub(crate) fn terminate(&self) {
        let Some(iopb) = NonNull::new(self.iopb) else {
            return;
        };
        // SAFETY: `iopb` came from this cache, and this is the task's last
        // reference, so nothing else can free it or use it now.
        unsafe { (*iopb_cache()).free(iopb) };
    }

    /// `machine_task_collect()` in C: free the bitmap a task no longer
    /// enables any port through.
    pub(crate) fn collect(&mut self) {
        self.iopb_lock.lock();
        if self.iopb_size == 0
            && let Some(iopb) = NonNull::new(self.iopb)
        {
            // SAFETY: `iopb` came from this cache, and the lock this call
            // holds bars another user of the task's bitmap.
            unsafe { (*iopb_cache()).free(iopb) };
            self.iopb = ptr::null_mut();
        }
        self.iopb_lock.unlock();
    }
}

/// `machine_task_module_init()` of <i386/task.h>: build the iopb cache.
///
/// # Safety
///
/// Called once at startup, before any task exists and so before anything
/// can allocate from the cache.
pub(crate) unsafe fn module_init() {
    let cache = &raw mut IOPB_CACHE;
    unsafe {
        (*cache).init(
            c"i386_task_iopb".to_bytes(),
            IOPB_BYTES,
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}
