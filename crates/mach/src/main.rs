// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! wip-mach: the Rust kernel, built into the `mach` image.

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

pub mod arch;
pub mod config;
pub mod device;
pub mod kern;
pub mod mig;
pub mod utils;
pub mod vm;

mod panic;
