// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! VM as this kernel builds it: the `mach_vm` types over [`MachPlatform`].

use crate::arch::x86_64::platform::MachPlatform;
use mach_vm::vm_map;

/// A VM map of this kernel.
pub type VmMap = vm_map::VmMap<MachPlatform>;

/// A VM map entry of this kernel.
pub type VmMapEntry = vm_map::VmMapEntry<MachPlatform>;

/// A VM map copy of this kernel.
pub type VmMapCopy = vm_map::VmMapCopy<MachPlatform>;
