// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `/dev/mem`: the physical memory device's map entry.
//!
//! The device hands out physical pages for the memory that is not main
//! RAM, so that the BIOS areas, the VGA window and the like can be
//! mapped; main RAM is refused, and the caller allocates instead.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::PAGE_SHIFT;
use core::ffi::c_int;
use mach_device::io_req::DevT;
use mach_page::memmap;

/// The page frame of the physical address `off`, or `VmOffset::MAX` for memory
/// the kernel manages.
///
/// # Safety
///
/// Called from the `/dev/mem` device switch.
pub(crate) unsafe fn memmmap(
    _dev: DevT,
    off: VmOffset,
    _prot: c_int,
) -> VmOffset {
    if memmap::addr_available(off) {
        return VmOffset::MAX;
    }
    off >> PAGE_SHIFT
}
