// SPDX-License-Identifier: CMU-Mach
// Derived from kern/thread.c and kern/thread.h:
//   Copyright (c) 1994-1987 Carnegie Mellon University.
//   Copyright (c) 1993-1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `thread_deallocate` export of `kern/thread.c`: the destructor the
//! generated server code names.  The rest of the file lives in
//! [`crate::kern::thread`].

use crate::kern::thread::Thread;

/// `thread_deallocate()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or a live thread the caller holds a reference to,
/// and the caller must hold no locks: the teardown may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_deallocate(thread: *mut Thread) {
    unsafe { Thread::deallocate(thread) };
}
