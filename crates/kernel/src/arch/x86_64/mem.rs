// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/mem.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `/dev/mem`: `memmmap()` of `i386/i386at/mem.c`.
//!
//! The device hands out physical pages for the memory that is not main
//! RAM, so that the BIOS areas, the VGA window and the like can be
//! mapped; main RAM is refused, and the caller allocates instead.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::PAGE_SHIFT;
use crate::arch::x86_64::biosmem;
use crate::arch::x86_64::io_req::DevT;
use core::ffi::c_int;

/// `memmmap()` in C.
///
/// # Safety
///
/// Called from the `/dev/mem` device switch in `conf.c`.
pub(crate) unsafe fn memmmap(
    _dev: DevT,
    off: VmOffset,
    _prot: c_int,
) -> VmOffset {
    if biosmem::addr_available(off) {
        return VmOffset::MAX;
    }
    off >> PAGE_SHIFT
}
