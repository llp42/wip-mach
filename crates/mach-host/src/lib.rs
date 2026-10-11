// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Mach's host: the object a host port names, with the processors and
//! processor sets the host calls list, host time, the machine slots and
//! record, the per-CPU tick accounting, the reboot call, and the
//! information the host and processor calls report.
//!
//! Everything this crate asks of the rest of the kernel arrives through
//! [`Platform`](platform::Platform), a zero-sized type parameter the kernel
//! implements.  It extends [`mach_thread::platform::Platform`] and
//! [`clock::Platform`]: tasks, threads, processors, ports and `kalloc` come
//! from the seams below, and the crate's own adds the machine clock, the
//! clock interrupt level and halting every CPU.

#![no_std]
// These routines mirror the C's integer and pointer conversions one for
// one: the widths and alignments are known at each site, and the
// truncations, sign changes and wraps are deliberate.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss
)]
#![expect(
    clippy::missing_errors_doc,
    reason = "the error cases of the translated routines are not written up yet"
)]

pub mod error;
pub mod host;
pub mod info;
pub mod machine;
pub mod platform;
pub mod port;
pub mod processor_info;
pub mod time;
pub mod types;
