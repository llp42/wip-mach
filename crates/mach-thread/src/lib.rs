// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Mach tasks, the threads they contain and the scheduler that runs them,
//! with processors, processor sets, the ports that name them and each
//! task's syscall emulation.
//!
//! Everything this crate asks of the rest of the kernel arrives through
//! [`Platform`](platform::Platform), a zero-sized type parameter the kernel
//! implements.  It extends [`mach_ipc::Platform`], so locks, user copy,
//! `kalloc`, the address spaces and the port spaces come from VM's and
//! IPC's seams; the crate's own adds the machine: context switch, kernel
//! stacks, per-CPU data, interrupt levels, the machine parts of a task and
//! a thread, CPU control and the timer wheel.  The kernel keeps the one
//! [`TaskState`](state::TaskState) in a static.

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

pub mod all_psets;
pub mod ast;
pub mod atomic_processor_state;
pub mod cell;
pub mod cstr;
pub mod error;
pub mod info;
pub mod ipc_processor;
pub mod ipc_sched;
pub mod ipc_tt;
pub mod mach_factor;
pub mod platform;
pub mod priority;
pub mod processor;
pub mod processor_action;
pub mod processor_ref;
pub mod processor_set;
pub mod reaper_queue;
pub mod sched;
pub mod sched_prim;
pub mod stack_free_list;
pub mod state;
pub mod syscall_subr;
pub mod task;
pub mod thread;
pub mod thread_swap;
pub mod types;

pub use mach_page::smp;
