// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The PC keyboard's scan-code decoder: the modifier state, the key map
//! lookup, the Ctrl-Alt-Del and Scroll Lock sequences, and the keys that
//! stand in for a mouse while Scroll Lock has them on.
//!
//! The decoder sees only the scan codes; the controller's acknowledge and
//! resend bytes are the driver's to handle before it hands a byte over.

use crate::chars::Chars;
use crate::event::{Event, MOUSE_LEFT, MOUSE_MIDDLE, MOUSE_RIGHT};
use crate::events::Events;
use crate::keymap::{ALT, CTRL, Keymap, NORMAL, SCAN, SHIFT, SHIFT_ALT, US};
use crate::types::Modifiers;
use crate::types::{Input, MouseMotion, Polled};

/// The prefix of the extended keys.
const EXTEND: u8 = 0xe0;
/// The scan-code bit of a key release.
const UP: u8 = 0x80;

const ESC: u8 = 0x1b;
const CR: u8 = 0x0d;
const LF: u8 = 0x0a;

const CTRL_KEY: u8 = 0x1d;
const LEFT_SHIFT_KEY: u8 = 0x2a;
const RIGHT_SHIFT_KEY: u8 = 0x36;
const ALT_KEY: u8 = 0x38;
/// Caps Lock, which this map treats as a second Ctrl.
const CAPS_LOCK_KEY: u8 = 0x3a;
const F1_KEY: u8 = 0x3b;
const F3_KEY: u8 = 0x3d;
const NUM_LOCK_KEY: u8 = 0x45;
const SCROLL_LOCK_KEY: u8 = 0x46;
const HOME_KEY: u8 = 0x47;
const UP_KEY: u8 = 0x48;
const PAGE_UP_KEY: u8 = 0x49;
const LEFT_KEY: u8 = 0x4b;
const RIGHT_KEY: u8 = 0x4d;
const END_KEY: u8 = 0x4f;
const DOWN_KEY: u8 = 0x50;
const PAGE_DOWN_KEY: u8 = 0x51;
const DELETE_KEY: u8 = 0x53;

/// The movement of one mouse key, in mouse units.
const MOUSE_STEP: i16 = 6;

/// The decoding state and the key map it reads.
pub struct Keyboard {
    keymap: Keymap,
    /// Scan codes go to the kbd device instead of being decoded.
    events: bool,
    /// The modifier bits keys are decoded with: the `KDGSTATE` value.
    modifiers: Modifiers,
    /// The previous byte was the extended-key prefix.
    extended: bool,
    /// The modifier bits Ctrl-Alt-Del is tracked with, which every key
    /// updates, whatever the mode.
    magic_modifiers: Modifiers,
    mouse_keys: bool,
    /// The mouse button a function key holds down, from 1, or 0.
    mouse_button: u8,
}

impl Default for Keyboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyboard {
    /// A keyboard in ASCII mode with no modifier held, on the US map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keymap: US,
            events: false,
            modifiers: Modifiers::empty(),
            extended: false,
            magic_modifiers: Modifiers::empty(),
            mouse_keys: false,
            mouse_button: 0,
        }
    }

    /// The key map, which the `KDGKBENT` flavor reads.
    #[must_use]
    pub const fn keymap(&self) -> &Keymap {
        &self.keymap
    }

    /// The key map, which the `KDSKBENT` flavor writes.
    pub const fn keymap_mut(&mut self) -> &mut Keymap {
        &mut self.keymap
    }

    /// Sends scan codes to the kbd device when `on`, or decodes them.
    pub const fn set_event_mode(&mut self, on: bool) {
        self.events = on;
    }

    /// The modifier bits: the `KDGSTATE` value.
    #[must_use]
    pub const fn modifiers(&self) -> Modifiers {
        self.modifiers
    }

    /// Releases every modifier.
    pub const fn reset_modifiers(&mut self) {
        self.modifiers = Modifiers::empty();
    }

    /// Decodes the scan code `sc` the keyboard interrupt read.  Ctrl-Alt-Del
    /// yields [`Input::Reboot`] only when `reboot_armed`; otherwise it types
    /// what the key types.
    pub fn interrupt(&mut self, sc: u8, reboot_armed: bool) -> Input {
        if sc == EXTEND && !self.events {
            self.extended = true;
            return Input::Nothing;
        }
        if self.mouse_keys {
            let mouse = self.mouse_key(sc);
            if !mouse.as_slice().is_empty() {
                return Input::Mouse(mouse);
            }
        }
        if sc == SCROLL_LOCK_KEY {
            self.mouse_keys = !self.mouse_keys;
            self.mouse_button = 0;
            return Input::Nothing;
        }

        let up = sc & UP != 0;
        let key = sc & !UP;
        self.magic_modifiers = self.modifier(self.magic_modifiers, key, up);
        if self
            .magic_modifiers
            .contains(Modifiers::CTRLED.union(Modifiers::ALTED))
            && key == DELETE_KEY
            && reboot_armed
        {
            return Input::Reboot;
        }
        if self.events {
            return Input::Scancode(sc);
        }

        let Some(cell) = self.keymap.cell(key, self.column()) else {
            return Input::Nothing;
        };
        let [first, second, _] = cell;
        if first == SCAN {
            self.modifiers = self.modifier(self.modifiers, second, up);
            return Input::Nothing;
        }
        if up {
            return Input::Nothing;
        }
        let bytes = if !self.extended
            && self.modifiers.contains(Modifiers::NUM_LOCKED)
            && (HOME_KEY..=DELETE_KEY).contains(&key)
            && let Some(shifted) = self.keymap.cell(key, SHIFT)
        {
            shifted
        } else {
            cell
        };
        self.extended = false;
        Input::Chars(Chars::from_cell(bytes))
    }

    /// Prepares to decode the scan codes a polled read takes from the
    /// controller.
    pub const fn start_poll(&mut self) {
        self.extended = false;
    }

    /// Decodes the scan code `sc` a polled read took from the controller.
    ///
    /// The polled read types only the first byte of a cell, and turns the
    /// cursor keys into the control characters of a line editor.
    pub fn poll(&mut self, sc: u8) -> Polled {
        let mut polled = Polled {
            mouse: Events::new(),
            ch: None,
        };
        if sc == EXTEND {
            self.extended = true;
            return polled;
        }
        let up = sc & UP != 0;
        let key = sc & !UP;
        if self.mouse_keys {
            polled.mouse = self.mouse_key(key);
        }
        let Some([first, second, third]) =
            self.keymap.cell(key, self.column())
        else {
            return polled;
        };
        if first == SCAN {
            self.modifiers = self.modifier(self.modifiers, second, up);
        } else if !up && first == ESC && second == b'[' {
            polled.ch = Some(match third {
                b'H' => 0x01, // home
                b'A' => 0x10, // up
                b'D' => 0x02, // left
                b'C' => 0x06, // right
                b'B' => 0x0e, // down
                b'Y' => 0x05, // end
                b'9' => 0x04, // delete
                _ => ESC,
            });
        } else if !up {
            let ch = if first == CR { LF } else { first };
            polled.ch = Some(ch & 0x7f);
        }
        polled
    }

    /// The modifier bits `bits` after `key` went up or down.  A Shift, Ctrl
    /// or Alt key also ends an extended-key sequence.
    const fn modifier(
        &mut self,
        bits: Modifiers,
        key: u8,
        up: bool,
    ) -> Modifiers {
        let flag = match key {
            ALT_KEY => Modifiers::ALTED,
            CAPS_LOCK_KEY | CTRL_KEY => Modifiers::CTRLED,
            LEFT_SHIFT_KEY | RIGHT_SHIFT_KEY => Modifiers::SHIFTED,
            NUM_LOCK_KEY if !up => {
                return bits.symmetric_difference(Modifiers::NUM_LOCKED);
            }
            _ => return bits,
        };
        self.extended = false;
        if up {
            bits.difference(flag)
        } else {
            bits.union(flag)
        }
    }

    /// The key-map cell the modifiers select.  An extended key always takes
    /// the unmodified cell.
    const fn column(&self) -> usize {
        let bits = self.modifiers;
        if self.extended {
            NORMAL
        } else if bits.contains(Modifiers::SHIFTED.union(Modifiers::ALTED)) {
            SHIFT_ALT
        } else if bits.contains(Modifiers::CTRLED) {
            CTRL
        } else if bits.contains(Modifiers::SHIFTED) {
            SHIFT
        } else if bits.contains(Modifiers::ALTED) {
            ALT
        } else {
            NORMAL
        }
    }

    /// The mouse events the key `sc` stands for: F1 to F3 click the left,
    /// middle and right buttons, and the arrow and keypad corner keys move.
    /// A click on a second button first releases the one held.
    fn mouse_key(&mut self, sc: u8) -> Events {
        let mut events = Events::new();
        let (dx, dy) = match sc {
            F1_KEY..=F3_KEY => {
                let button = sc - F1_KEY + 1;
                let which = |b: u8| match b {
                    1 => MOUSE_LEFT,
                    2 => MOUSE_MIDDLE,
                    _ => MOUSE_RIGHT,
                };
                let held = self.mouse_button;
                if held != 0 && held != button {
                    events.push(Event::button(which(held), true));
                }
                if held == button {
                    events.push(Event::button(which(button), true));
                    self.mouse_button = 0;
                } else {
                    events.push(Event::button(which(button), false));
                    self.mouse_button = button;
                }
                return events;
            }
            RIGHT_KEY => (MOUSE_STEP, 0),
            LEFT_KEY => (-MOUSE_STEP, 0),
            UP_KEY => (0, MOUSE_STEP),
            DOWN_KEY => (0, -MOUSE_STEP),
            HOME_KEY => (-2 * MOUSE_STEP, 2 * MOUSE_STEP),
            PAGE_UP_KEY => (2 * MOUSE_STEP, 2 * MOUSE_STEP),
            END_KEY => (-2 * MOUSE_STEP, -2 * MOUSE_STEP),
            PAGE_DOWN_KEY => (2 * MOUSE_STEP, -2 * MOUSE_STEP),
            _ => return events,
        };
        events.push(Event::motion(MouseMotion {
            mm_delta_x: dx,
            mm_delta_y: dy,
        }));
        events
    }
}
