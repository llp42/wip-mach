// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The task record: a task's address space and port space, its accounting,
//! its ports, its emulation vector and the machine's part, with the head
//! of its thread list and the processor set it is assigned to.
//!
//! The record is generic over the thread list `L` and the processor set
//! `S`, which the thread crate above names; the operations on tasks, which
//! all reach their threads or their set, live there too.

#![no_std]

pub mod platform;
pub mod task;
pub mod types;

pub use platform::Platform;
pub use task::Task;
