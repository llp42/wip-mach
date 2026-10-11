// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Machine scalar types of the 64-bit kernel interface.

use core::sync::atomic::AtomicUsize;

/// `vm_offset_t`: a type-neutral pointer, the width of an address.
pub type VmOffset = usize;

/// `vm_size_t`: the difference between two `vm_offset_t`s, likewise the width
/// of an address.
pub type VmSize = usize;

/// A [`VmOffset`] shared between CPUs without a lock.
pub type AtomicVmOffset = AtomicUsize;
