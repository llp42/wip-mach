// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Machine scalar types, from `i386/include/mach/i386/vm_types.h`, the header
//! the 64-bit kernel installs as `<machine/vm_types.h>`.

use core::sync::atomic::AtomicUsize;

/// `vm_offset_t`: a type-neutral pointer, `uintptr_t` in the C.
pub type VmOffset = usize;

/// `vm_size_t`: the difference between two `vm_offset_t`s, likewise a
/// `uintptr_t` in the C.
pub type VmSize = usize;

/// A [`VmSize`] shared between CPUs without a lock.
pub type AtomicVmSize = AtomicUsize;

/// `rpc_phys_addr_t`: a physical address on the user/kernel interface, always
/// 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct RpcPhysAddr(u64);

impl RpcPhysAddr {
    /// The zero address.
    pub const ZERO: Self = Self(0);

    /// The value the C stores.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// A physical address from the C side.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// A `vm_offset_t` address as the interface carries it.  The widening
    /// cannot lose a bit.
    #[must_use]
    pub const fn from_vm_offset(address: VmOffset) -> Self {
        Self(address as u64)
    }
}

const _: () = assert!(size_of::<RpcPhysAddr>() == 8);
