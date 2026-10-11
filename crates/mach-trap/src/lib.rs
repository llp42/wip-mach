// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The bodies of Mach's traps, and the exception up-call.
//!
//! Traps come in from user mode: the ones that stand in for RPCs, acting on
//! the object a port name denotes, and `thread_set_self_state`.  Exceptions
//! go out: the up-call raises a thread's exception to its exception ports
//! and hands the message straight to a waiting server.  The kernel keeps the
//! trap table and each trap's entry, which turns a body's `Result` into its
//! `kern_return_t`, and the two `mach_msg` continuations, which IPC's
//! platform names.
//!
//! Everything this crate asks of the rest of the kernel arrives through
//! [`Platform`](platform::Platform), which extends
//! [`mach_device::platform::Platform`] with the return to user mode from a
//! receive.

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
pub mod exception;
pub mod name;
pub mod platform;
pub mod rpc;
pub mod self_state;
pub mod types;
