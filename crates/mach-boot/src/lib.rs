// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Mach's bootstrap: the first user tasks, made from the modules the boot
//! loader left.
//!
//! A lone module whose command line names only the program is loaded
//! directly; otherwise the module lines spell a boot script, which creates
//! tasks, hands them ports and runs their programs.  Each program is an
//! ELF image loaded into its task, with its argument and environment
//! vectors on the first thread's user stack.
//!
//! The kernel hands [`bootstrap::create`] its inputs as data, a
//! [`BootInfo`](types::BootInfo).  Everything else the crate asks of the
//! kernel arrives through [`Platform`](platform::Platform), which extends
//! [`mach_thread::platform::Platform`] with the machine: the type of a boot
//! module, the top of user space, the first user registers and a console
//! line read.

#![no_std]

mod boot_script;
pub mod bootstrap;
pub mod platform;
mod text;
pub mod types;
