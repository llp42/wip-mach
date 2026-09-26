// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386at/model_dep.c:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1986 Avadis Tevanian, Jr., Michael Wayne Young.
// Derived from i386/i386at/model_dep.h:
//   Copyright (c) 2013 Free Software Foundation.
// Derived from i386/i386/model_dep.h:
//   Copyright (C) 2008 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `c_boot_entry()` export `boothdr.S` calls, which
//! `i386/i386at/model_dep.c` used to define and `i386/i386/model_dep.h`
//! declares.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::model_dep;

/// `c_boot_entry()` of <`i386/i386/model_dep.h`>, the C entry `boothdr.S` calls.
#[unsafe(no_mangle)]
pub extern "C" fn c_boot_entry(bi: VmOffset) {
    model_dep::c_boot_entry(bi);
}
