// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The task record's flag byte.

bitflags::bitflags! {
    /// The single-bit fields `struct task` packs into one byte.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TaskFlags: u8 {
        /// The task is alive.
        const ACTIVE = 1 << 0;
        /// The task may be assigned to another processor set.
        const MAY_ASSIGN = 1 << 1;
        /// The task is essential for the system.
        const ESSENTIAL = 1 << 2;
    }
}
