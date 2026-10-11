// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The scheduler's records and the computations on them: the scheduling
//! record a thread embeds, the run queues that hold such records, the
//! priority decay and computation, the scheduling policies, the per-CPU AST
//! reasons, the statistical CPU timers and the time values they read as.
//!
//! The crate names no thread, processor or processor set: the code that
//! blocks, wakes and dispatches threads sits above it, and recovers each
//! thread from the record it embeds.

#![no_std]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "the priorities, queue indexes and usage counts mirror the C's \
              `int` and `unsigned` conversions one for one"
)]

pub mod ast;
mod cell;
pub mod policy;
pub mod run_queue;
pub mod sched;
pub mod sched_info;
pub mod time_value;
pub mod timer;
pub mod timer_save;

pub use run_queue::RunQueue;
pub use sched_info::SchedInfo;
