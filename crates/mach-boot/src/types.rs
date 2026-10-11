// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The plain data the kernel hands the bootstrap.

use crate::platform::Platform;
use core::ffi::{CStr, c_void};
use kmem::KVec;

/// The heap the bootstrap allocates from: IPC's.
pub type Heap<P> = <P as mach_ipc::Platform>::Heap;

/// What the kernel hands the bootstrap: the boot modules, the kernel
/// command line, and the ports the first tasks receive.
pub struct BootInfo<P: Platform> {
    /// The modules the boot loader left, in its order.
    pub modules: KVec<P::Module, Heap<P>>,
    /// The kernel command line.
    pub cmdline: &'static CStr,
    /// A live port naming the host.
    pub host_port: *mut c_void,
    /// A live port naming the host with privilege.
    pub host_priv_port: *mut c_void,
    /// The live master device port.
    pub device_port: *mut c_void,
}
