// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The I/O request the device layer hands its drivers.

use crate::platform::Platform;
use crate::r#return::DeviceError;
use collections::simple_queue::{self, SimpleQueue};
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;
use lock::RawIrqSpinLock;
use mach_vm::vm_map::VmMapCopy;

/// A device number.
pub type DevT = u16;

/// The completion callback of a request, returning whether the request is
/// finished.
///
/// A caller invoking one through [`IoReq`]'s `done` field must pass the
/// same live request that was queued with it; `iodone()` and its
/// completion thread call it without the request's lock held, and possibly
/// at a raised interrupt level. Returning `true` tells the caller the
/// request is finished and may be freed or woken; returning `false` means
/// the callback re-queued the request itself, as `kmsg_read_done()` and
/// `mouse_read_done()` do.
pub type IoDone<P> = unsafe fn(*mut IoReq<P>) -> bool;

/// The I/O request a driver is handed, and the queue node its first two fields
/// form.
#[repr(C)]
#[allow(missing_docs)]
pub struct IoReq<P: Platform> {
    /// The queue node the first two fields form.
    pub node: simple_queue::Link,
    pub device: *mut c_void,
    pub dev_ptr: *mut c_char,
    pub unit: c_int,
    pub op: IoOp,
    pub mode: DeviceMode,
    pub recnum: c_ulong,
    pub data: *mut c_char,
    pub count: c_long,
    pub alloc_size: usize,
    pub residual: c_long,
    /// How the request completed.
    pub error: Result<(), DeviceError>,
    pub done: Option<IoDone<P>>,
    pub reply_port: *mut c_void,
    pub reply_port_type: c_uint,
    pub link: *mut Self,
    pub rlink: *mut Self,
    pub copy: *mut VmMapCopy<P>,
    pub total: c_long,
    pub(crate) lock: RawIrqSpinLock<P::Lock>,
    pub physrec: c_long,
    pub rectotal: c_long,
}

impl<P: Platform> IoReq<P> {
    /// Where the fields after the request's lock start: the lock is one
    /// word, and its name in debug builds.
    const AFTER_LOCK: usize =
        (144 + size_of::<RawIrqSpinLock<P::Lock>>()).next_multiple_of(8);

    /// The record keeps its established size, alignment and field offsets.
    const LAYOUT: () = {
        assert!(size_of::<Self>() == Self::AFTER_LOCK + 16);
        assert!(align_of::<Self>() == 8);
        assert!(offset_of!(Self, node) == 0);
        assert!(offset_of!(Self, device) == 8);
        assert!(offset_of!(Self, dev_ptr) == 16);
        assert!(offset_of!(Self, unit) == 24);
        assert!(offset_of!(Self, op) == 28);
        assert!(offset_of!(Self, mode) == 32);
        assert!(offset_of!(Self, recnum) == 40);
        assert!(offset_of!(Self, data) == 48);
        assert!(offset_of!(Self, count) == 56);
        assert!(offset_of!(Self, alloc_size) == 64);
        assert!(offset_of!(Self, residual) == 72);
        assert!(offset_of!(Self, error) == 80);
        assert!(offset_of!(Self, done) == 88);
        assert!(offset_of!(Self, reply_port) == 96);
        assert!(offset_of!(Self, reply_port_type) == 104);
        assert!(offset_of!(Self, link) == 112);
        assert!(offset_of!(Self, rlink) == 120);
        assert!(offset_of!(Self, copy) == 128);
        assert!(offset_of!(Self, total) == 136);
        assert!(offset_of!(Self, lock) == 144);
        assert!(offset_of!(Self, physrec) == Self::AFTER_LOCK);
        assert!(offset_of!(Self, rectotal) == Self::AFTER_LOCK + 8);
    };
}

simple_queue::adapter!(
    /// The adapter for a request's `node` in a device read queue.
    pub IoReqAdapter<P: Platform> = IoReq<P> { node }
);

/// A queue of requests: a device's blocked reads or delayed replies, or the
/// completed ones waiting for their callback. A request is on one at a time,
/// and a callback that returns zero has queued it again.
pub type IoReqQueue<P> = SimpleQueue<'static, IoReqAdapter<P>>;

const _: () = assert!(size_of::<simple_queue::Link>() == size_of::<usize>());

impl<P: Platform> IoReq<P> {
    /// Returns a request with every field clear, its link unlinked and its
    /// lock free.
    ///
    /// Each allocator writes a request whole, as a literal over this base,
    /// into its storage: the C left the fields a caller skips undefined.
    #[must_use]
    pub const fn new() -> Self {
        let () = Self::LAYOUT;
        Self {
            node: simple_queue::Link::new(),
            device: ptr::null_mut(),
            dev_ptr: ptr::null_mut(),
            unit: 0,
            op: IoOp::empty(),
            mode: DeviceMode::empty(),
            recnum: 0,
            data: ptr::null_mut(),
            count: 0,
            alloc_size: 0,
            residual: 0,
            error: Ok(()),
            done: None,
            reply_port: ptr::null_mut(),
            reply_port_type: 0,
            link: ptr::null_mut(),
            rlink: ptr::null_mut(),
            copy: ptr::null_mut(),
            total: 0,
            lock: RawIrqSpinLock::named("io req"),
            physrec: 0,
            rectotal: 0,
        }
    }

    /// `io_count`: the byte count the caller asked for.
    pub const fn count(&self) -> c_long {
        self.count
    }

    /// The open/read/write mode.
    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    /// Sets the completion callback.
    pub fn set_done(&mut self, done: IoDone<P>) {
        self.done = Some(done);
    }

    /// The buffer `device_read_alloc()` set up.
    pub const fn data(&self) -> *mut c_char {
        self.data
    }

    /// Sets the bytes not done.
    pub const fn set_residual(&mut self, residual: c_long) {
        self.residual = residual;
    }
}

impl<P: Platform> Default for IoReq<P> {
    fn default() -> Self {
        Self::new()
    }
}

bitflags::bitflags! {
    /// A request's operation and state: the C's `IO_*` bits.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IoOp: c_int {
        /// A read; a write has the bit clear.
        const READ = 0x0000_0001;
        /// An open.
        const OPEN = 0x0000_0002;
        /// The request is complete.
        const DONE = 0x0000_0100;
        /// Someone waits for the request to complete.
        const WANTED = 0x0000_0800;
        /// Completion calls the request's done routine.
        const CALL = 0x0000_2000;
        /// The data travels in the message.
        const INBAND = 0x0000_4000;
        /// The data pages are loaned to the device.
        const LOANED = 0x0001_0000;
        // The bits drivers set that the kernel does not name.
        const _ = !0;
    }
}

impl IoOp {
    /// A write: no read bit.
    pub const WRITE: Self = Self::empty();
}

bitflags::bitflags! {
    /// The open mode of a device call, and the sides a tty flush or stop
    /// acts on.  Userspace passes the word, so the bits the kernel does not
    /// name are kept.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DeviceMode: c_uint {
        /// The read side.
        const READ = 0x1;
        /// The write side.
        const WRITE = 0x2;
        /// Open without waiting for the carrier.
        const NODELAY = 0x4;
        /// The request must not block.
        const NOWAIT = 0x8;
        // The bits the kernel does not name.
        const _ = !0;
    }
}
/// The get-status flavor that reports the device and record sizes.
pub const DEV_GET_SIZE: c_uint = 0;
/// The `DEV_GET_SIZE` reply slot holding the device size.
pub const DEV_GET_SIZE_DEVICE_SIZE: usize = 0;
/// The `DEV_GET_SIZE` reply slot holding the record size.
pub const DEV_GET_SIZE_RECORD_SIZE: usize = 1;
/// The number of slots a `DEV_GET_SIZE` reply fills.
pub const DEV_GET_SIZE_COUNT: u32 = 2;
