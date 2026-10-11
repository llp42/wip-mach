// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The system-call emulation of a task: the dispatch table a task embeds a
//! pointer to, which redirects system calls to user-space handlers, and the
//! calls that install, share and copy it.
//!
//! The routines are generic over [`mach_vm::Platform`], whose allocator
//! and kernel maps hold the tables and the out-of-line vectors; the task
//! crosses as its lock and the slot that points at its table.

#![no_std]
#![expect(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "the vector's bounds are the C's `int`s, which userspace sets \
              and the routines convert as the C did"
)]

pub mod dispatch;
pub mod error;
pub mod types;
pub mod vector;

pub use dispatch::EmlDispatch;
pub use error::Error;
pub use types::EmulationVector;
