// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The emulation vector as `task_get_emulation_vector()` returns it.

use core::ffi::c_int;
use mach_page::param::VmOffset;

/// The `emulation_vector_t` of a task, as `task_get_emulation_vector()`
/// returns one.
pub struct EmulationVector {
    /// `*vector_start`.
    pub start: c_int,
    /// The emulation vector, a map copy the server returns out of line.
    pub vector: *mut VmOffset,
    /// `*emulation_vector_count`.
    pub count: u32,
}
