// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `version[]` string `c_boot_entry()` prints.

use core::ffi::c_char;

const VERSION: &str = concat!("WIP Mach ", env!("CARGO_PKG_VERSION"));
const VERSION_BYTES: &[u8] = VERSION.as_bytes();
const VERSION_LEN: usize = VERSION_BYTES.len() + 1;

/// The NUL-terminated `version[]` `c_boot_entry()` reads through
/// `glue::version`; the version comes from `Cargo.toml`.
#[unsafe(no_mangle)]
pub static version: [c_char; VERSION_LEN] = {
    let mut out = [0; VERSION_LEN];
    let mut i = 0;
    while i < VERSION_BYTES.len() {
        out[i] = VERSION_BYTES[i] as c_char;
        i += 1;
    }
    out
};
