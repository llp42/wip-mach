// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/task.c and kern/task.h:
//   Copyright (c) 1993-1988 Carnegie Mellon University.
// Derived from include/mach/gnumach.defs:
//   Copyright (C) 2012 Free Software Foundation
// Derived from include/mach/mach.defs:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and
//   the Computer Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `task_deallocate` export of `kern/task.c`: the destructor the
//! generated server code names.  The rest of the file lives in
//! [`crate::kern::task`].

use crate::kern::task;
use core::ffi::c_void;

/// `task_deallocate()` of kern/task.c.
///
/// # Safety
///
/// `task` must be null or a live task the caller holds a reference to, and
/// the caller must hold no locks: the cleanup may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_deallocate(task: *mut c_void) {
    unsafe { task::deallocate(task.cast()) };
}
