// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine-specific part of a task: its I/O-permission bitmap.

use crate::arch::types::VmSize;
use crate::kern::slab::CacheInitFlags;
use crate::kern::slab::KmemCache;
use core::ffi::c_int;
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use mach_vm::simple_lock::SimpleLock;

/// The machine-specific part of a task, the lock and range of its
/// I/O-permission bitmap.
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

/// The highest I/O port a task's permission bitmap can name.
const IOPB_MAX: VmSize = 0xffff;

/// One bit per port, rounded up to whole bytes.
pub(crate) const IOPB_BYTES: VmSize = (IOPB_MAX + 1).div_ceil(8);

/// The cache the permission bitmaps come from.
pub(crate) static IOPB_CACHE: KmemCache = KmemCache::zeroed();

impl MachineTask {
    /// Starts the task with no bitmap.
    pub(crate) fn init(&mut self) {
        self.iopb_size = 0;
        self.iopb = ptr::null_mut();
        self.iopb_lock.init();
    }

    /// Frees the bitmap of a task that is going away.
    pub(crate) fn terminate(&self) {
        let Some(iopb) = NonNull::new(self.iopb) else {
            return;
        };
        // SAFETY: `iopb` came from this cache, and this is the task's last
        // reference, so nothing else can free it or use it now.
        unsafe { IOPB_CACHE.free(iopb) };
    }

    /// Frees the bitmap a task no longer enables any port through.
    pub(crate) fn collect(&mut self) {
        self.iopb_lock.lock();
        if self.iopb_size == 0
            && let Some(iopb) = NonNull::new(self.iopb)
        {
            // SAFETY: `iopb` came from this cache, and the lock this call
            // holds bars another user of the task's bitmap.
            unsafe { IOPB_CACHE.free(iopb) };
            self.iopb = ptr::null_mut();
        }
        self.iopb_lock.unlock();
    }
}

/// Builds the iopb cache.
///
/// # Safety
///
/// Called once at startup, before any task exists and so before anything
/// can allocate from the cache.
pub(crate) unsafe fn module_init() {
    IOPB_CACHE.init(
        c"i386_task_iopb".to_bytes(),
        IOPB_BYTES,
        0,
        None,
        CacheInitFlags::empty(),
    );
}
