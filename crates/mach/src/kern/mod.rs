// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Kernel facilities; mirrors `kern/`.

pub mod console;
pub mod debug;
pub mod error;
pub mod eventcount;
pub mod ipc_kobject;
pub mod ipc_mig;
pub mod kheap;
pub mod printf;
pub mod slab;
pub mod startup;
pub mod syscall_sw;
