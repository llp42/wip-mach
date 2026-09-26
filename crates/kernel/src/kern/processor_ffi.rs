// SPDX-License-Identifier: CMU-Mach
// Derived from kern/processor.c and kern/processor.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `pset_deallocate` export of `kern/processor.c`: the destructor the
//! generated server code names.  The rest of the file lives in
//! [`crate::kern::processor`].

use crate::kern::processor::ProcessorSet;
use core::ptr::NonNull;

/// `pset_deallocate()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set` that the
/// caller holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pset_deallocate(pset: *mut ProcessorSet) {
    let Some(pset) = NonNull::new(pset) else {
        return;
    };

    unsafe { (*pset.as_ptr()).deallocate() };
}
