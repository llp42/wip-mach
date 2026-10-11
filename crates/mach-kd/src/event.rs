// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The `kd_event` record the kbd and mouse devices hand their readers.

use crate::types::{MouseMotion, TimeValue};
use core::ffi::c_int;
use core::mem::{offset_of, size_of};
use zerocopy::{Immutable, IntoBytes};

/// The `MOUSE_LEFT` event type: the left button went up or down.
pub const MOUSE_LEFT: u16 = 1;
/// The `MOUSE_MIDDLE` event type.
pub const MOUSE_MIDDLE: u16 = 2;
/// The `MOUSE_RIGHT` event type.
pub const MOUSE_RIGHT: u16 = 3;
/// The `MOUSE_MOTION` event type.
const MOUSE_MOTION: u16 = 4;
/// The `KEYBD_EVENT` event type.
const KEYBD_EVENT: u16 = 5;

/// One keyboard or mouse event, with its type and an unused time.
///
/// The payload holds what the type selects, in the bytes the ABI's union
/// gives it: a button's `int` state, a scan code in the first byte, or a
/// movement's two `short` deltas; the bytes it leaves are zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct Event {
    type_: u16,
    /// The C compiler's alignment hole, kept zero so no stale kernel byte
    /// reaches a reader.
    hole: [u8; 6],
    unused_time: TimeValue,
    value: [u8; 4],
    /// The C compiler's tail padding, kept zero likewise.
    tail: [u8; 4],
}

const _: () = {
    assert!(size_of::<Event>() == 32);
    assert!(offset_of!(Event, unused_time) == 8);
    assert!(offset_of!(Event, value) == 24);
};

impl Event {
    /// An all-zero event, the image BSS holds before anything is queued.
    pub(crate) const fn zeroed() -> Self {
        Self {
            hole: [0; 6],
            type_: 0,
            unused_time: TimeValue {
                seconds: 0,
                microseconds: 0,
                padding: 0,
            },
            value: [0; 4],
            tail: [0; 4],
        }
    }

    /// A motion event carrying `moved`.
    #[must_use]
    pub const fn motion(moved: MouseMotion) -> Self {
        let [x0, x1] = moved.mm_delta_x.to_ne_bytes();
        let [y0, y1] = moved.mm_delta_y.to_ne_bytes();
        Self {
            hole: [0; 6],
            type_: MOUSE_MOTION,
            unused_time: TimeValue {
                seconds: 0,
                microseconds: 0,
                padding: 0,
            },
            value: [x0, x1, y0, y1],
            tail: [0; 4],
        }
    }

    /// A button event of type `which`, one of [`MOUSE_LEFT`],
    /// [`MOUSE_MIDDLE`] and [`MOUSE_RIGHT`]; the button went down unless `up`.
    #[must_use]
    pub const fn button(which: u16, up: bool) -> Self {
        Self {
            hole: [0; 6],
            type_: which,
            unused_time: TimeValue {
                seconds: 0,
                microseconds: 0,
                padding: 0,
            },
            value: (up as c_int).to_ne_bytes(),
            tail: [0; 4],
        }
    }

    /// A keyboard event carrying the scan code `sc`.
    #[must_use]
    pub const fn scancode(sc: u8) -> Self {
        Self {
            hole: [0; 6],
            type_: KEYBD_EVENT,
            unused_time: TimeValue {
                seconds: 0,
                microseconds: 0,
                padding: 0,
            },
            value: [sc, 0, 0, 0],
            tail: [0; 4],
        }
    }
}
