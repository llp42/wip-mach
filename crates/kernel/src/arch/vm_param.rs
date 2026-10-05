// SPDX-License-Identifier: CMU-Mach
// Derived from i386/include/mach/i386/vm_param.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
// And from include/mach/vm_param.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// Derived from i386/i386/vm_param.h and x86_64/x86_64/vm_param.h:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Page geometry of the 64-bit kernel interface.

use crate::arch::types::{VmOffset, VmSize};

/// The number of bits to shift for pages.
pub const PAGE_SHIFT: u32 = 12;

/// `PAGE_SIZE`: one page, `1 << PAGE_SHIFT`.
pub const PAGE_SIZE: VmSize = 1 << PAGE_SHIFT;

/// `PAGE_MASK`: the in-page offset bits, `PAGE_SIZE - 1`.
pub const PAGE_MASK: VmSize = PAGE_SIZE - 1;

/// The size and alignment of one kernel stack: one page.
pub const KERNEL_STACK_SIZE: VmSize = PAGE_SIZE;

/// The top of a user map, half the address space.
pub const VM_MAX_USER_ADDRESS: VmOffset = 0x8000_0000_0000;
