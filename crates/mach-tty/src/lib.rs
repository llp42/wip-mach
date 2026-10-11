// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! GNU Mach's tty layer: the tty record a serial or console driver owns,
//! its line discipline, the character buffers it queues input and output
//! in, its status and modem calls, and the pseudo-DMA speed tables.
//!
//! A driver hands it the I/O request the device server built, and the
//! layer completes the request through the device server's done paths.
//! It is generic over [`mach_device::platform::Platform`] and adds no trait
//! of its own: its lock, its timeouts on the platform's timer wheel and
//! its buffers come from the seams below.

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

pub mod chario;
pub mod cirbuf;
