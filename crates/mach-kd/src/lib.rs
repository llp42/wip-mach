// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The machine-independent half of the kd console.
//!
//! It holds the terminal that turns bytes and escape sequences into screen
//! edits, the PC keyboard's scan-code decoder and key map, the mouse packet
//! decoders, and the event records the kbd and mouse devices queue.
//!
//! Nothing here touches the hardware or the rest of the kernel.  The
//! kernel's driver reads the controller and the serial lines and hands the
//! bytes over; the decoders return what the bytes mean, and the driver acts
//! on it.  The terminal alone drives the machine, through the [`Screen`]
//! the driver gives it, since one control sequence can ask for any number
//! of scrolls.

#![no_std]

mod chars;
mod event;
mod event_queue;
mod events;
mod keyboard;
mod keymap;
mod mouse;
mod pen;
mod protocol;
mod screen;
mod terminal;
mod types;

pub use chars::Chars;
pub use event::{Event, MOUSE_LEFT, MOUSE_MIDDLE, MOUSE_RIGHT};
pub use event_queue::EventQueue;
pub use events::Events;
pub use keyboard::Keyboard;
pub use keymap::Keymap;
pub use mouse::Mouse;
pub use protocol::Protocol;
pub use screen::{CELLS, COLUMNS, Screen};
pub use terminal::Terminal;
pub use types::{Input, KbEntry, Modifiers, MouseMotion, Polled};
