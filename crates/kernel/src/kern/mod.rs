// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Kernel facilities; mirrors `kern/`.

pub mod ast;
pub mod boot_script;
pub mod bootstrap;
pub mod console;
pub mod debug;
pub mod error;
pub mod eventcount;
pub mod exception;
pub mod gsync;
pub mod host;
pub mod host_time;
pub mod ipc_host;
pub mod ipc_kobject;
pub mod ipc_mig;
pub mod ipc_sched;
pub mod ipc_tt;
pub mod kheap;
pub mod kmutex;
pub mod lock;
pub mod mach_factor;
pub mod machine;
pub mod policy;
pub mod printf;
pub mod priority;
pub mod processor;
pub mod sched;
pub mod sched_prim;
pub mod slab;
pub mod smp;
pub mod startup;
pub mod syscall_emulation;
pub mod syscall_subr;
pub mod syscall_sw;
pub mod task;
pub mod thread;
pub mod thread_swap;
pub mod timer;
