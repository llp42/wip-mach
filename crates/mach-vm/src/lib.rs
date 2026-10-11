// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Machine-independent Mach virtual memory above the pmap: maps and their
//! copies, VM objects, resident pages, faults, the pageout daemon and the
//! memory-object protocol.
//!
//! Everything VM asks of the rest of the kernel arrives through
//! [`Platform`], a zero-sized type parameter the kernel implements: the
//! pmap, waits and wakeups, the running thread, the kernel's ports and the
//! pager messages, the slab caches, user copy and the console.  The state
//! whose types name the platform sits in a [`VmState`] the platform
//! stores.

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

pub mod cell;
pub mod cstr;
pub mod error;
pub mod memory_object;
pub mod memory_object_proxy;
pub mod param;
pub mod platform;
pub mod state;
pub mod types;
pub mod vm_debug;
pub mod vm_external;
pub mod vm_fault;
pub mod vm_init;
pub mod vm_kern;
pub mod vm_map;
pub mod vm_object;
pub mod vm_page;
pub mod vm_pageout;
pub mod vm_resident;
pub mod vm_user;

pub use mach_page::simple_lock;
pub use platform::Platform;
pub use state::VmState;
