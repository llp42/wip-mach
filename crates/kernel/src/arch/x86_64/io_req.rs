// SPDX-License-Identifier: CMU-Mach
// Derived from device/io_req.h, include/device/device_types.h and the
// read loops of i386/i386at/kd_event.c and i386/i386at/kd_mouse.c:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `struct io_req` of <`device/io_req.h`>, the request the device layer and the
//! x86 drivers share.

use crate::kern::lock::SimpleLock;
use crate::utils::kd_queue::{KdEvent, KdEventQueue};
use crate::vm::vm_map::VmMapCopy;
use collections::simple_queue::{self, SimpleQueue};
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;

/// `dev_t` of <sys/types.h>.
pub type DevT = u16;

/// `boolean_t (*)(io_req_t)`, the C type of `io_done`.
///
/// A caller invoking one through [`IoReq`]'s `done` field must pass the
/// same live request that was queued with it; `iodone()` and its
/// completion thread call it without the request's lock held, and possibly
/// at a raised interrupt level. Returning nonzero tells the caller the
/// request is finished and may be freed or woken; returning zero means the
/// callback re-queued the request itself, as `kmsg_read_done()` and
/// `mouse_read_done()` do.
pub type IoDone = unsafe fn(*mut IoReq) -> c_int;

/// `struct io_req` of <`device/io_req.h>`: the IO request a driver is handed,
/// and the queue node its first two fields form.
#[repr(C)]
#[allow(missing_docs)]
pub struct IoReq {
    /// `io_next`/`io_prev`: the queue node the first two C fields formed.
    pub node: simple_queue::Link,
    pub device: *mut c_void,
    pub dev_ptr: *mut c_char,
    pub unit: c_int,
    pub op: c_int,
    pub mode: c_uint,
    pub recnum: c_ulong,
    pub data: *mut c_char,
    pub count: c_long,
    pub alloc_size: usize,
    pub residual: c_long,
    pub error: c_int,
    pub done: Option<IoDone>,
    pub reply_port: *mut c_void,
    pub reply_port_type: c_uint,
    pub link: *mut Self,
    pub rlink: *mut Self,
    pub copy: *mut VmMapCopy,
    pub total: c_long,
    pub lock: SimpleLock,
    pub physrec: c_long,
    pub rectotal: c_long,
}

const _: () = {
    assert!(size_of::<IoReq>() == 168);
    assert!(align_of::<IoReq>() == 8);
    assert!(offset_of!(IoReq, node) == 0);
    assert!(offset_of!(IoReq, device) == 8);
    assert!(offset_of!(IoReq, dev_ptr) == 16);
    assert!(offset_of!(IoReq, unit) == 24);
    assert!(offset_of!(IoReq, op) == 28);
    assert!(offset_of!(IoReq, mode) == 32);
    assert!(offset_of!(IoReq, recnum) == 40);
    assert!(offset_of!(IoReq, data) == 48);
    assert!(offset_of!(IoReq, count) == 56);
    assert!(offset_of!(IoReq, alloc_size) == 64);
    assert!(offset_of!(IoReq, residual) == 72);
    assert!(offset_of!(IoReq, error) == 80);
    assert!(offset_of!(IoReq, done) == 88);
    assert!(offset_of!(IoReq, reply_port) == 96);
    assert!(offset_of!(IoReq, reply_port_type) == 104);
    assert!(offset_of!(IoReq, link) == 112);
    assert!(offset_of!(IoReq, rlink) == 120);
    assert!(offset_of!(IoReq, copy) == 128);
    assert!(offset_of!(IoReq, total) == 136);
    assert!(offset_of!(IoReq, lock) == 144);
    assert!(offset_of!(IoReq, physrec) == 152);
    assert!(offset_of!(IoReq, rectotal) == 160);
};

simple_queue::adapter!(
    /// The adapter for a request's `node` in a device read queue.
    pub IoReqAdapter = IoReq { node }
);

/// A queue of requests: a device's blocked reads or delayed replies, or the
/// completed ones waiting for their callback. A request is on one at a time,
/// and a callback that returns zero has queued it again.
pub type IoReqQueue = SimpleQueue<'static, IoReqAdapter>;

const _: () = assert!(size_of::<simple_queue::Link>() == size_of::<usize>());

impl IoReq {
    /// Returns a request with every field clear, its link unlinked and its
    /// lock free.
    ///
    /// Each allocator writes a request whole, as a literal over this base,
    /// into its storage: the C left the fields a caller skips undefined.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            node: simple_queue::Link::new(),
            device: ptr::null_mut(),
            dev_ptr: ptr::null_mut(),
            unit: 0,
            op: 0,
            mode: 0,
            recnum: 0,
            data: ptr::null_mut(),
            count: 0,
            alloc_size: 0,
            residual: 0,
            error: 0,
            done: None,
            reply_port: ptr::null_mut(),
            reply_port_type: 0,
            link: ptr::null_mut(),
            rlink: ptr::null_mut(),
            copy: ptr::null_mut(),
            total: 0,
            lock: SimpleLock::new(),
            physrec: 0,
            rectotal: 0,
        }
    }

    /// `io_count`: the byte count the caller asked for.
    pub const fn count(&self) -> c_long {
        self.count
    }

    /// `io_mode`: the open/read/write mode.
    pub const fn mode(&self) -> c_uint {
        self.mode
    }

    /// Set `io_done`, the completion callback.
    pub fn set_done(&mut self, done: IoDone) {
        self.done = Some(done);
    }

    /// `io_data`: the buffer `device_read_alloc()` set up.
    pub const fn data(&self) -> *mut c_char {
        self.data
    }

    /// Set `io_residual` to the bytes not done.
    pub const fn set_residual(&mut self, residual: c_long) {
        self.residual = residual;
    }
}

impl Default for IoReq {
    fn default() -> Self {
        Self::new()
    }
}

/// Drain up to `ior`'s byte count of queued events into its data buffer, and
/// return the bytes copied.
pub const fn drain(queue: &mut KdEventQueue, ior: &mut IoReq) -> c_long {
    let mut count: c_long = 0;
    while !queue.is_empty() && count < ior.count {
        let Some(ev) = queue.pop_front() else {
            break;
        };
        let src = ptr::from_ref::<KdEvent>(ev).cast::<u8>();
        // SAFETY: `device_read_alloc()` allocated `io_count` bytes for the
        // request, and the loop condition keeps this copy inside.
        let dst = unsafe { ior.data.add(count as usize).cast::<u8>() };
        // SAFETY: `device_read_alloc()` allocated `io_count` bytes for the
        // request, and the loop condition keeps this copy inside;
        // `src` is the popped event.
        unsafe { ptr::copy_nonoverlapping(src, dst, size_of::<KdEvent>()) };
        count += size_of::<KdEvent>() as c_long;
    }
    count
}

/// `D_NOWAIT` of <`device/device_types.h`>: the request must not block.
pub const D_NOWAIT: c_uint = 0x8;
/// `DEV_GET_SIZE` of <`device/device_types.h`>: the get-status flavor that
/// reports the device and record sizes.
pub const DEV_GET_SIZE: c_uint = 0;
/// The `DEV_GET_SIZE` reply slot holding the device size.
pub const DEV_GET_SIZE_DEVICE_SIZE: usize = 0;
/// The `DEV_GET_SIZE` reply slot holding the record size.
pub const DEV_GET_SIZE_RECORD_SIZE: usize = 1;
/// The number of slots a `DEV_GET_SIZE` reply fills.
pub const DEV_GET_SIZE_COUNT: u32 = 2;
/// `KERN_SUCCESS` of <`mach/kern_return.h`>: the request succeeded.
pub const KERN_SUCCESS: c_int = 0;
