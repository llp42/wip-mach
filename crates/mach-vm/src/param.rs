// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine values VM is built for, which the physical pages define, and
//! the physical address the user/kernel interface carries.

pub use mach_page::param::{
    AtomicVmOffset, MAX_NCPUS, PAGE_MASK, PAGE_SHIFT, PAGE_SIZE,
    VM_MIN_KERNEL_ADDRESS, VmOffset, VmSize,
};

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
