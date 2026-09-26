// SPDX-License-Identifier: CMU-Mach
// Derived from i386/include/mach/i386/vm_param.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
// And from include/mach/vm_param.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// Derived from i386/i386/vm_param.h and x86_64/x86_64/vm_param.h:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Page geometry, from `i386/include/mach/i386/vm_param.h`, the header the
//! 64-bit kernel installs as `<machine/vm_param.h>`.

use crate::arch::types::{VmOffset, VmSize};

/// `PAGE_SHIFT` of <`machine/vm_param.h>`: `I386_PGSHIFT`, the number of bits to
/// shift for pages.
pub const PAGE_SHIFT: u32 = 12;

/// `PAGE_SIZE`: one page, `1 << PAGE_SHIFT` in the C.
pub const PAGE_SIZE: VmSize = 1 << PAGE_SHIFT;

/// `PAGE_MASK`: the in-page offset bits, `PAGE_SIZE - 1` in the C.
pub const PAGE_MASK: VmSize = PAGE_SIZE - 1;

/// `KERNEL_STACK_SIZE` of <`machine/vm_param.h>`: the size and alignment of one
/// kernel stack, `1*I386_PGBYTES` in the C.
pub const KERNEL_STACK_SIZE: VmSize = PAGE_SIZE;

/// `VM_MAX_USER_ADDRESS` of <`machine/vm_param.h>`: the top of a user map, half
/// the address space.
pub const VM_MAX_USER_ADDRESS: VmOffset = 0x8000_0000_0000;
