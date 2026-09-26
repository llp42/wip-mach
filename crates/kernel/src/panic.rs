// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A Rust panic, reported through the kernel's panic path.

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let (file, line) = info
        .location()
        .map_or(("<unknown>", 0), |loc| (loc.file(), loc.line()));

    crate::kern::debug::panic_fmt(
        file,
        line,
        "mach_rs",
        format_args!("{}", info.message()),
    )
}
