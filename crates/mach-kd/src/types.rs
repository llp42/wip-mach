// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The console's plain data: the event's time and movement, the key-map
//! flavor record, what the decoders hand the driver, and the modifier and
//! rendition flags.

use crate::chars::Chars;
use crate::events::Events;
use crate::keymap::CELL;
use core::ffi::{c_int, c_long};
use zerocopy::{Immutable, IntoBytes};

/// The `rpc_time_value` an event reserves for its time, which nothing sets.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct TimeValue {
    pub seconds: c_long,
    pub microseconds: c_int,
    /// The C compiler's tail padding, kept zero so no stale kernel byte
    /// reaches a task.
    pub(crate) padding: c_int,
}

/// A mouse movement.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MouseMotion {
    /// The movement right, in mouse units.
    pub mm_delta_x: i16,
    /// The movement up, in mouse units.
    pub mm_delta_y: i16,
}

/// The `kbentry` payload of the `KDGKBENT` and `KDSKBENT` flavors: one cell,
/// named by its modifier state and scan code.
#[repr(C)]
#[derive(Clone, Copy)]
#[expect(missing_docs, reason = "the ABI's `kbentry` layout")]
pub struct KbEntry {
    pub kb_state: u8,
    pub kb_index: u8,
    pub kb_value: [u8; CELL],
}

/// What a scan code from the keyboard interrupt asks of the driver.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// Nothing: a prefix, a modifier, a release, or the Scroll Lock toggle.
    Nothing,
    /// The bytes the key types, for the console tty; possibly none.
    Chars(Chars),
    /// Event mode is on: the scan code goes to the kbd device as it came.
    Scancode(u8),
    /// The mouse keys are on: the events the key stands for, for the mouse
    /// device.
    Mouse(Events),
    /// Ctrl-Alt-Del, with rebooting armed.
    Reboot,
}

/// What a polled scan code yields.
pub struct Polled {
    /// The events the key stands for while the mouse keys are on.
    pub mouse: Events,
    /// The character the key types, folded to seven bits.
    pub ch: Option<u8>,
}

bitflags::bitflags! {
    /// The modifiers keys are decoded with: the `KDGSTATE` value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Modifiers: u8 {
        /// Num Lock is on.
        const NUM_LOCKED = 0x02;
        /// An Alt key is down.
        const ALTED = 0x08;
        /// A Shift key is down.
        const SHIFTED = 0x10;
        /// A Ctrl key, or Caps Lock, is down.
        const CTRLED = 0x20;
    }
}

bitflags::bitflags! {
    /// The rendition flags a select-graphic-rendition sequence sets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Rendition: u8 {
        const REVERSE = 0x01;
        const UNDERLINE = 0x02;
        const BLINK = 0x04;
        const BOLD = 0x08;
        const DIM = 0x10;
        const INVISIBLE = 0x20;
    }
}
