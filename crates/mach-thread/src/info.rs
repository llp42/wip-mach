// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The information `task_info`, `thread_info` and `processor_set_info`
//! report, read from the crate's records; the kernel's MIG seam copies each
//! record out.

pub mod pset;
pub mod task;
pub mod thread;
