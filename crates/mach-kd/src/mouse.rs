// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The mouse packet decoder, for the serial Mouse Systems, Microsoft and
//! Logitech protocols and for PS/2.
//!
//! The decoder sees only packet bytes; the PS/2 command replies are the
//! driver's to collect while it talks to the mouse.

use crate::event::{Event, MOUSE_LEFT, MOUSE_MIDDLE, MOUSE_RIGHT};
use crate::events::Events;
use crate::protocol::Protocol;
use crate::types::MouseMotion;

/// The bytes of the largest packet.
const MAX_PACKET: usize = 5;

/// A packet in assembly, and the button state the packets change.
pub struct Mouse {
    protocol: Option<Protocol>,
    buf: [u8; MAX_PACKET],
    len: usize,
    /// The last button bits, in the protocol's own order; a set bit is a
    /// released button, except under PS/2.
    buttons: u8,
    /// The first byte of the trackman's last packet, buttons only.
    last_gitech: u8,
    /// A fourth trackman byte, carrying the middle button, is due.
    fourth_gitech: bool,
    /// The middle button bit the fourth trackman byte last set.
    middle_gitech: u8,
}

impl Default for Mouse {
    fn default() -> Self {
        Self::new()
    }
}

impl Mouse {
    /// A decoder that ignores every byte until [`Self::open`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            protocol: None,
            buf: [0; MAX_PACKET],
            len: 0,
            buttons: 0,
            last_gitech: 0x40,
            fourth_gitech: false,
            middle_gitech: 0,
        }
    }

    /// The protocol [`Self::open`] chose.
    #[must_use]
    pub const fn protocol(&self) -> Option<Protocol> {
        self.protocol
    }

    /// Starts decoding `protocol` from the first byte of a packet, with no
    /// button held; [`None`] ignores every byte.
    pub const fn open(&mut self, protocol: Option<Protocol>) {
        self.protocol = protocol;
        self.len = 0;
        self.buttons = match protocol {
            Some(Protocol::Ps2) => 0,
            _ => 0x7,
        };
    }

    /// Takes one byte from the mouse, returning the events a packet it
    /// completes stands for.
    ///
    /// # Panics
    ///
    /// If a packet outgrows the buffer, which no protocol's length lets it
    /// do.
    pub fn byte(&mut self, ch: u8) -> Events {
        let mut events = Events::new();
        let Some(protocol) = self.protocol else {
            return events;
        };
        if self.len == 0 {
            let first = match protocol {
                Protocol::Microsoft7 => ch & 0x40 == 0x40,
                Protocol::Microsoft => ch & 0xc0 == 0xc0,
                Protocol::MouseSystems => ch & 0xf8 == 0x80,
                Protocol::LogitechTrackman if self.fourth_gitech => {
                    self.fourth_gitech = false;
                    self.middle_gitech = if ch & 0xf0 != 0 { 0x4 } else { 0 };
                    self.microsoft(self.buf, &mut events);
                    return events;
                }
                Protocol::LogitechTrackman => ch & 0xc0 == 0x40,
                Protocol::Ps2 => true,
            };
            if !first {
                return events;
            }
        }
        #[expect(
            clippy::indexing_slicing,
            reason = "a packet is decoded once it is as long as its protocol's, \
                      which MAX_PACKET bounds"
        )]
        let slot = &mut self.buf[self.len];
        *slot = ch;
        self.len += 1;
        if self.len < protocol.packet_len() {
            return events;
        }
        self.len = 0;
        let buf = self.buf;
        match protocol {
            Protocol::Microsoft7 | Protocol::Microsoft => {
                self.microsoft(buf, &mut events);
            }
            Protocol::MouseSystems => self.mouse_systems(buf, &mut events),
            Protocol::LogitechTrackman => {
                let [first, dx, dy, ..] = buf;
                if dx != 0 || dy != 0 || first != self.last_gitech {
                    self.microsoft(buf, &mut events);
                    self.last_gitech = first & 0xf0;
                } else {
                    self.fourth_gitech = true;
                }
            }
            Protocol::Ps2 => self.ps2(buf, &mut events),
        }
        events
    }

    /// Decodes a Mouse Systems packet: two signed movements to add, and
    /// button bits clear while pressed.
    fn mouse_systems(&mut self, buf: [u8; MAX_PACKET], events: &mut Events) {
        let [first, dx1, dy1, dx2, dy2] = buf;
        let buttons = first & 0x7;
        let sum = |a: u8, b: u8| {
            i16::from(i8::from_ne_bytes([a]))
                .wrapping_add(i16::from(i8::from_ne_bytes([b])))
        };
        let moved = MouseMotion {
            mm_delta_x: sum(dx1, dx2),
            mm_delta_y: sum(dy1, dy2),
        };
        if moved.mm_delta_x != 0 || moved.mm_delta_y != 0 {
            events.push(Event::motion(moved));
        }
        let changes = buttons ^ self.buttons;
        if changes != 0 {
            self.buttons = buttons;
            for (bit, which) in
                [(1, MOUSE_RIGHT), (2, MOUSE_MIDDLE), (4, MOUSE_LEFT)]
            {
                if changes & bit != 0 {
                    events.push(Event::button(which, buttons & bit != 0));
                }
            }
        }
    }

    /// Decodes a Microsoft packet: the movement's high bits ride in the
    /// first byte, and button bits are set while pressed.
    fn microsoft(&mut self, buf: [u8; MAX_PACKET], events: &mut Events) {
        let [first, second, third, ..] = buf;
        let buttons = !(((first & 0x30) >> 4) | self.middle_gitech) & 0x07;
        let mut dx = i16::from(first & 0x03) << 6 | i16::from(second & 0x3f);
        let mut dy = i16::from(first & 0x0c) << 4 | i16::from(third & 0x3f);
        if dx & 0x80 != 0 {
            dx -= 0x100;
        }
        if dy & 0x80 != 0 {
            dy -= 0x100;
        }
        if dx != 0 || dy != 0 {
            events.push(Event::motion(MouseMotion {
                mm_delta_x: dx,
                mm_delta_y: -dy,
            }));
        }
        let changes = buttons ^ self.buttons;
        if changes != 0 {
            self.buttons = buttons;
            for (bit, which) in
                [(1, MOUSE_RIGHT), (2, MOUSE_LEFT), (4, MOUSE_MIDDLE)]
            {
                if changes & bit != 0 {
                    events.push(Event::button(which, buttons & bit != 0));
                }
            }
        }
    }

    /// Decodes a PS/2 packet: the movement's sign bits ride in the first
    /// byte, and button bits are set while pressed.
    fn ps2(&mut self, buf: [u8; MAX_PACKET], events: &mut Events) {
        let [first, dx, dy, ..] = buf;
        let buttons = first & 0x7;
        let signed = |delta: u8, negative: bool| {
            if negative {
                i16::from(delta) - 0x100
            } else {
                i16::from(delta)
            }
        };
        let moved = MouseMotion {
            mm_delta_x: signed(dx, first & 0x10 != 0),
            mm_delta_y: signed(dy, first & 0x20 != 0),
        };
        if moved.mm_delta_x != 0 || moved.mm_delta_y != 0 {
            events.push(Event::motion(moved));
        }
        let changes = buttons ^ self.buttons;
        if changes != 0 {
            self.buttons = buttons;
            for (bit, which) in
                [(1, MOUSE_LEFT), (2, MOUSE_RIGHT), (4, MOUSE_MIDDLE)]
            {
                if changes & bit != 0 {
                    events.push(Event::button(which, buttons & bit == 0));
                }
            }
        }
    }
}
