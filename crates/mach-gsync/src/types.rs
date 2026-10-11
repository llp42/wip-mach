// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The data-only types of the gsync calls: their flags and the key a wait
//! is filed under.

use core::ffi::c_int;
use mach_vm::param::VmOffset;

bitflags::bitflags! {
    /// The flag bits of the gsync calls.  The C ignored bits it did not
    /// know, so a caller's word converts with `from_bits_retain`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Flags: c_int {
        /// The address is shared, so the memory object keys it.
        const SHARED = 0x01;
        /// Check or write two words.
        const QUAD = 0x02;
        /// The wait has a timeout.
        const TIMED = 0x04;
        /// Wake every matching waiter.
        const BROADCAST = 0x08;
        /// Write the value before waking.
        const MUTATE = 0x10;
    }
}

/// What identifies the address a thread waits on.  A task-local key never
/// compares equal to a shared one, so the key keeps its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Key {
    /// A task-local address: the C `local.map`/`local.addr` pair.
    Local { map: usize, addr: VmOffset },
    /// A shared address: the C `shared.obj`/`shared.off` pair.
    Shared { object: usize, offset: VmOffset },
}
