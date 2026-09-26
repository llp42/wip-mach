// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_map.c and vm/vm_map.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `vm_map_deallocate` export of `vm/vm_map.c`: the destructor the
//! <`mach/mach_types.defs`> generated code names.  The rest of the file lives
//! in [`crate::vm::vm_map`].

use crate::vm::vm_map::VmMap;
use core::ptr::NonNull;

/// `vm_map_deallocate()` in C.
///
/// # Safety
///
/// A non-null `map` must point at a valid map, and the caller must hold a
/// reference to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_map_deallocate(map: *mut VmMap) {
    if let Some(map) = NonNull::new(map) {
        VmMap::deallocate(map);
    }
}
