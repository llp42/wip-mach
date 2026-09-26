// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! wip-mach: the Rust kernel, built into the `kernel` image.

#![no_std]
#![no_main]
#![no_builtins]
#![deny(unsafe_op_in_unsafe_fn)]
// The kernel is x86_64-only, and these routines mirror the C's integer and
// pointer conversions one for one: the widths and alignments are known at
// each site, and the truncations, sign changes and wraps are deliberate.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss
)]
// `#[inline(always)]` marks the functions the C headers declared `inline`;
// dropping the attribute changes the ported code generation.
#![allow(clippy::inline_always)]

extern crate alloc;

pub mod arch;
pub mod config;
pub mod device;
pub mod ffi;
pub mod glue;
pub mod ipc;
pub mod kern;
pub mod utils;
pub mod version;
pub mod vm;

mod panic;
