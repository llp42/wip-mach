// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `EmlDispatch`: a task's dispatch table, shared with its children.

use core::ffi::c_int;
use core::mem::size_of;
use core::ptr;
use mach_page::param::VmOffset;
use mach_page::simple_lock::SimpleLock;

/// One task's dispatch table, whose vector follows the header in one
/// allocation.
///
/// The `x86_64` system-call entry reads `disp_min`, `disp_count` and
/// `disp_vector` at the C header's offsets, so the field order here is the
/// ABI.
#[repr(C)]
pub struct EmlDispatch {
    /// `lock`: protects `ref_count` only.
    pub(crate) lock: SimpleLock,
    pub(crate) ref_count: c_int,
    /// `disp_count`: the number of entries in the vector.
    pub(crate) disp_count: c_int,
    /// `disp_min`: the index of the vector's lowest entry.
    pub(crate) disp_min: c_int,
    /// `disp_vector`: the dispatch entries, allocated with the header.  The
    /// C writes `[1]` so its `sizeof` carries one entry; the count here
    /// spells that entry in `count_to_size()` instead.
    pub(crate) disp_vector: [VmOffset; 0],
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
pub(crate) const fn count_to_size(count: usize) -> usize {
    size_of::<EmlDispatch>() + size_of::<VmOffset>() * count
}

/// The vector that follows the table's header.
///
/// # Safety
///
/// `eml` must point at a live dispatch table.
pub(crate) unsafe fn vector(eml: *mut EmlDispatch) -> *mut VmOffset {
    // SAFETY: every dispatch table allocates its vector in the same
    // allocation, right after the header.
    unsafe { ptr::addr_of_mut!((*eml).disp_vector).cast::<VmOffset>() }
}
