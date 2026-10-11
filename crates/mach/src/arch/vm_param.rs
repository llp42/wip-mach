// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

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

/// The lowest kernel virtual address: the kernel map begins here, and the
/// direct map of physical memory sits at this offset.
pub const VM_MIN_KERNEL_ADDRESS: VmOffset = 0xffff_ffff_8000_0000;

/// The top of a user map, half the address space.
pub const VM_MAX_USER_ADDRESS: VmOffset = 0x8000_0000_0000;
