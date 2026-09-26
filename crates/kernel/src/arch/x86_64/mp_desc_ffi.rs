// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/mp_desc.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// Derived from i386/i386/mp_desc.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The C entry `cpuboot.S` calls: `cpu_ap_main()`, which
//! `i386/i386/mp_desc.h` declares.

use crate::arch::x86_64::mp_desc;

/// `cpu_ap_main()` of <`i386/mp_desc.h`>, the entry `cpuboot.S` calls.
#[unsafe(no_mangle)]
pub extern "C" fn cpu_ap_main() -> ! {
    mp_desc::cpu_ap_main()
}
