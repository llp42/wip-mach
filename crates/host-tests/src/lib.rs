// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Host-side `cargo test` for the kernel modules whose imports stay inside
//! `core` and `alloc`.
//!
//! The shim modules under this crate mirror the kernel's module tree and
//! include the kernel source files verbatim, so the files' `crate::` paths
//! resolve here.  Tests written next to the code under `#[cfg(test)]` and the
//! tests in [`tests`] then run against the same sources the kernel image
//! links.

#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]

extern crate alloc;

pub mod arch;
pub mod device;
pub mod glue;
pub mod kern;
pub mod utils;
pub mod vm;

#[cfg(test)]
mod tests;
