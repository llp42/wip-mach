// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd_queue.c and i386/i386at/kd_queue.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The keyboard/mouse event ring buffer, which `i386/i386at/kd_queue.c` used
//! to define.

use crate::glue::time_value::RpcTimeValue;
use core::ffi::c_int;
use core::mem::{offset_of, size_of};

/// `KDQSIZE` in <`i386at/kd_queue.h`>.
const KDQSIZE: usize = 100;

/// `kev_type` of <device/input.h>: an event type.
pub type KevType = u16;

/// `Scancode` of <device/input.h>: a keyboard scan code.
pub type Scancode = u8;

/// `struct mouse_motion` of <device/input.h>.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
#[allow(missing_docs)]
pub struct MouseMotion {
    pub mm_delta_x: i16,
    pub mm_delta_y: i16,
}

/// The `value` union of `kd_event` in <device/input.h>.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
#[allow(missing_docs)]
union KdValue {
    up: c_int,
    sc: u8,
    mmotion: MouseMotion,
}

/// `kd_event` of <device/input.h>, field for field.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
#[allow(missing_docs)]
pub struct KdEvent {
    type_: u16,
    unused_time: RpcTimeValue,
    value: KdValue,
}

/// `kd_event_queue` of <`i386at/kd_queue.h`>.
#[repr(C)]
#[allow(missing_docs)]
pub struct KdEventQueue {
    events: [KdEvent; KDQSIZE],
    firstfree: c_int,
    firstout: c_int,
}

const _: () = {
    assert!(size_of::<KdEvent>() == 32);
    assert!(size_of::<KdEventQueue>() == 3208);
};
const _: () = assert!(
    offset_of!(KdEventQueue, firstfree) == KDQSIZE * size_of::<KdEvent>()
);
const _: () = assert!(
    offset_of!(KdEventQueue, firstout)
        == offset_of!(KdEventQueue, firstfree) + size_of::<c_int>()
);

impl Default for KdEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl KdEvent {
    /// An all-zero event, the image BSS holds before anything is queued; only
    /// `KdEventQueue::new()` needs it.
    const fn zeroed() -> Self {
        Self {
            type_: 0,
            unused_time: RpcTimeValue {
                seconds: 0,
                microseconds: 0,
            },
            value: KdValue { up: 0 },
        }
    }

    /// A `MOUSE_MOTION` event carrying `moved`.
    #[must_use]
    pub const fn motion(moved: MouseMotion) -> Self {
        Self {
            type_: 4,
            unused_time: RpcTimeValue {
                seconds: 0,
                microseconds: 0,
            },
            value: KdValue { mmotion: moved },
        }
    }

    /// A button event of type `which`, pressed when `up` is false: what
    /// `mouse_button()` builds.
    #[must_use]
    pub const fn button(which: KevType, up: bool) -> Self {
        Self {
            type_: which,
            unused_time: RpcTimeValue {
                seconds: 0,
                microseconds: 0,
            },
            value: KdValue { up: up as c_int },
        }
    }

    /// A `KEYBD_EVENT` carrying scancode `sc`: what `kd_enqsc()` builds.
    #[must_use]
    pub const fn scancode(sc: Scancode) -> Self {
        Self {
            type_: 5,
            unused_time: RpcTimeValue {
                seconds: 0,
                microseconds: 0,
            },
            value: KdValue { sc },
        }
    }
}

impl KdEventQueue {
    /// An empty queue, the image the drivers' statics start from.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: [KdEvent::zeroed(); KDQSIZE],
            firstfree: 0,
            firstout: 0,
        }
    }

    const fn next(index: c_int) -> c_int {
        (index + 1) % KDQSIZE as c_int
    }

    #[must_use]
    /// Whether the queue holds no events.
    pub const fn is_empty(&self) -> bool {
        self.firstfree == self.firstout
    }

    /// Whether the queue holds its most, `KDQSIZE - 1` events: one slot stays
    /// free so that a full queue and an empty one cannot look alike.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        Self::next(self.firstfree) == self.firstout
    }

    /// Drop every queued event, leaving the queue empty.
    pub const fn clear(&mut self) {
        self.firstfree = 0;
        self.firstout = 0;
    }

    /// Copy `ev` into the free slot and advance the write index; the caller
    /// has checked `is_full()`.
    pub const fn push_back(&mut self, ev: KdEvent) {
        self.events[self.firstfree as usize] = ev;
        self.firstfree = Self::next(self.firstfree);
    }

    /// Advance the read index and return the slot it left, or `None` when the
    /// queue is empty.
    pub const fn pop_front(&mut self) -> Option<&mut KdEvent> {
        if self.is_empty() {
            return None;
        }
        let result = &mut self.events[self.firstout as usize];
        self.firstout = Self::next(self.firstout);
        Some(result)
    }
}
