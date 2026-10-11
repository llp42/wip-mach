// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The Rust home of the C `device/` tree, the machine-independent device
//! layer.

pub mod cons;
pub mod device_init;
pub mod intr;
pub mod kmsg;

use crate::arch::x86_64::platform::MachPlatform;

/// A device driver's I/O request.
pub type IoReq = mach_device::io_req::IoReq<MachPlatform>;
/// A queue of requests.
pub type IoReqQueue = mach_device::io_req::IoReqQueue<MachPlatform>;
/// One driver's entry points.
pub type DevOps = mach_device::ds_routines::DevOps<MachPlatform>;
/// The operation vector and unit one indirect device name stands for.
pub type DevIndirect = mach_device::dev_name::DevIndirect<MachPlatform>;
/// A tty line.
pub type Tty = mach_tty::chario::Tty<MachPlatform>;
