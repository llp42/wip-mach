// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Mach's machine-independent device dispatch: the device server that
//! answers the device interface, the lookup that turns a name into an open
//! device and its port, the pager that maps a device's memory, and the I/O
//! request the drivers complete.
//!
//! Everything this crate asks of the rest of the kernel arrives through
//! [`Platform`](platform::Platform), a zero-sized type parameter the kernel
//! implements.  It extends [`mach_thread::platform::Platform`], so tasks,
//! threads, IPC, VM, user copy and the console come from the seams below;
//! the crate's own adds its state, its slab caches and the one call that
//! sends a [`Message`](types::Message).  The kernel keeps the one
//! [`DeviceState`](state::DeviceState) in a static, built over the
//! machine's device table.

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
pub mod dev_lookup;
pub mod dev_name;
pub mod dev_pager;
pub mod ds_routines;
pub mod io_req;
pub mod platform;
pub mod r#return;
pub mod state;
pub mod subrs;
pub mod types;
