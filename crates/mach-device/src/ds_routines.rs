// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The native Mach device service.
//!
//! The `ds_device_*` entry points, the emulation dispatch, the device
//! open/close/read/write paths, the request completion callbacks and the
//! io-done thread all live here; the kernel's MIG server entries call the
//! entry points.

use crate::dev_lookup;
use crate::io_req::{DevT, DeviceMode, IoOp, IoReq, IoReqQueue};
use crate::platform::Platform;
use crate::r#return::{
    DeviceError, DeviceSuccess, IoResult, Reply, ReplyResult,
};
use crate::types::{DeviceCache, Message};
use collections::list;
use core::ffi::{
    c_char, c_int, c_long, c_short, c_uint, c_ulong, c_ushort, c_void,
};
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};
use kmem::KBox;
use lock::lock_api::RawMutex as _;
use mach_ipc::{IpcPort, MachMsgHeader, ipc_port, ipc_space};
use mach_thread::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_sleep,
    thread_wakeup_prim,
};
use mach_thread::thread::Thread;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::simple_lock::SimpleLock;
use mach_vm::types::MapFlags;
use mach_vm::types::{PAGE_SIZE, VmProt};
use mach_vm::vm_kern;
use mach_vm::vm_map::{VmMap, VmMapCopy, round_page, trunc_page};
use mach_vm::vm_user;

/// The state of a device that is not open yet.
const DEV_STATE_INIT: c_short = 0;
/// `DEV_STATE_OPENING`.
const DEV_STATE_OPENING: c_short = 1;
/// `DEV_STATE_OPEN`.
const DEV_STATE_OPEN: c_short = 2;
/// `DEV_STATE_CLOSING`.
const DEV_STATE_CLOSING: c_short = 3;

bitflags::bitflags! {
    /// A device's flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DeviceFlags: c_short {
        /// Only one open at a time.
        const EXCL_OPEN = 0x0001;
    }
}

/// The `d_dev_info` flavor that reports the block size.
const D_INFO_BLOCK_SIZE: c_int = 1;
/// The most bytes an in-band transfer carries.
const IO_INBAND_MAX: usize = 128;
/// The message id of a no-senders notification.
const MACH_NOTIFY_NO_SENDERS: c_int = 0o106;
/// The size of the device I/O map.
const DEVICE_IO_MAP_SIZE: VmSize = 16 * 1024 * 1024;
/// The size of an I/O request block on the trap path.
const IOTRAP_REQSIZE: usize = 2048;
/// The most loaned data a trap request carries after itself in its
/// [`IOTRAP_REQSIZE`] cache slot; the C never checked it.
const fn iotrap_data_max<P: Platform>() -> usize {
    IOTRAP_REQSIZE - size_of::<IoReq<P>>()
}
/// The `stack_iovec[16]` bound of `device_writev_trap()`.
const MAX_IOVECS: usize = 16;

/// The emulation handle embedded at the end of a [`MachDevice`].
#[repr(C)]
#[allow(missing_docs)]
pub struct Device {
    pub emul_ops: *mut DeviceEmulationOps,
    pub emul_data: *mut c_void,
}

const _: () = {
    assert!(size_of::<Device>() == 2 * size_of::<*mut c_void>());
    assert!(align_of::<Device>() == align_of::<*mut c_void>());
    assert!(offset_of!(Device, emul_ops) == 0);
    assert!(offset_of!(Device, emul_data) == size_of::<*mut c_void>());
};

impl Device {
    /// The Mach device this handle belongs to, or `None` when another
    /// emulation, such as the kernel's I/O permission ports, owns it and
    /// `emul_data` is that emulation's record.
    #[must_use]
    pub fn mach_device<P: Platform>(&self) -> Option<NonNull<MachDevice<P>>> {
        if ptr::eq(self.emul_ops, P::device_state().emulation.get()) {
            NonNull::new(self.emul_data.cast())
        } else {
            None
        }
    }
}

/// One open device record.
///
/// The mirror keeps every field of the C record; the device-lookup paths in
/// C still read `ref_count` and `number_chain`, and this module reads only the
/// fields the open/close/IO paths touch.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachDevice<P: Platform> {
    pub ref_lock: SimpleLock,
    pub ref_count: c_int,
    pub lock: SimpleLock,
    pub state: c_short,
    pub flag: DeviceFlags,
    pub open_count: c_short,
    pub io_in_progress: c_short,
    pub io_wait: c_int,
    pub port: *mut c_void,
    pub number_chain: list::Link,
    pub dev_number: c_int,
    pub bsize: c_int,
    pub dev_ops: *mut DevOps<P>,
    pub dev: Device,
}

impl<P: Platform> MachDevice<P> {
    /// The record keeps its established size, alignment and field offsets.
    pub(crate) const LAYOUT: () = {
        assert!(size_of::<Self>() == 80);
        assert!(align_of::<Self>() == 8);
        assert!(offset_of!(Self, ref_lock) == 0);
        assert!(offset_of!(Self, ref_count) == 4);
        assert!(offset_of!(Self, lock) == 8);
        assert!(offset_of!(Self, state) == 12);
        assert!(offset_of!(Self, flag) == 14);
        assert!(offset_of!(Self, open_count) == 16);
        assert!(offset_of!(Self, io_in_progress) == 18);
        assert!(offset_of!(Self, io_wait) == 20);
        assert!(offset_of!(Self, port) == 24);
        assert!(offset_of!(Self, number_chain) == 32);
        assert!(offset_of!(Self, dev_number) == 48);
        assert!(offset_of!(Self, bsize) == 52);
        assert!(offset_of!(Self, dev_ops) == 56);
        assert!(offset_of!(Self, dev) == 64);
    };
}

list::adapter!(
    /// The adapter for a device's `number_chain` in the device-number hash
    /// table.
    pub MachDeviceNumberAdapter<P: Platform> = MachDevice<P> { number_chain }
);

// The link is two words, so the offsets above hold.
const _: () = assert!(size_of::<list::Link>() == 16);

/// The signature of a driver's `d_async_in` hook: install an
/// asynchronous input filter.
///
/// [`device_set_filter()`] invokes it for an open device with a
/// validated `receive_port` send right and `filter` readable for
/// `filter_count` entries; the driver must not assume any device lock
/// is held and may notify `receive_port` from interrupt context
/// whenever matching input later arrives.
type DevAsyncIn = unsafe fn(
    DevT,
    *mut c_void,
    c_int,
    *mut c_ushort,
    c_uint,
) -> Result<(), DeviceError>;
/// The signature of a driver's `d_getstat` hook: read one status
/// flavor.
///
/// [`mach_device_get_status()`] invokes it for an open device, with
/// `status` writable for the words the caller reserved and
/// `status_count` writable for the count the driver actually fills in;
/// the driver must not assume any device lock is held.
type DevGetstat = unsafe fn(
    DevT,
    c_uint,
    *mut c_int,
    *mut c_uint,
) -> Result<(), DeviceError>;
/// The signature of a driver's `d_setstat` hook: write one status
/// flavor.
///
/// [`device_set_status()`] invokes it for an open device, with `status`
/// readable for `status_count` words; the driver must not assume any
/// device lock is held.
type DevSetstat =
    unsafe fn(DevT, c_uint, *mut c_int, c_uint) -> Result<(), DeviceError>;

/// The signature of a driver's `d_open` hook; see [`DevOps::d_open`].
type DevOpen<P> = unsafe fn(DevT, c_int, *mut IoReq<P>) -> IoResult;

/// The signature of a driver's `d_read` and `d_write` hooks; see
/// [`DevOps::d_read`] and [`DevOps::d_write`].
type DevIo<P> = unsafe fn(DevT, *mut IoReq<P>) -> IoResult;

/// The signature of a driver's `d_dev_info` hook; see [`DevOps::d_dev_info`].
type DevDevInfo =
    unsafe fn(DevT, c_int, *mut c_int) -> Result<(), DeviceError>;

/// One driver's entry points.
///
/// The mirror keeps every field; this module dispatches through `d_open`,
/// `d_close`, `d_read`, `d_write`, `d_getstat`, `d_setstat`, `d_async_in` and
/// `d_dev_info` only.
#[repr(C)]
#[allow(missing_docs)]
pub struct DevOps<P: Platform> {
    pub d_name: *mut c_char,
    /// Opens the device for I/O.
    ///
    /// `device_open()` invokes it with the device in
    /// `DEV_STATE_OPENING` and no device lock held, and `ior` a
    /// freshly built request whose `done` is [`ds_open_done()`]. The
    /// driver may finish the open synchronously in the return value, or
    /// return [`DeviceSuccess::IoQueued`] and call `(*ior).done` itself
    /// once the open completes, from any context.
    pub d_open: Option<DevOpen<P>>,
    /// Closes the device.
    ///
    /// `device_close()` invokes it once the last open reference drops,
    /// with the device in `DEV_STATE_CLOSING` and no device lock held.
    /// The driver must finish synchronously; there is no request to
    /// signal completion through.
    pub d_close: Option<unsafe fn(DevT, c_int)>,
    /// Reads from the device.
    ///
    /// `device_read()` and `device_read_inband()` invoke it for an
    /// open device, with no device lock held and `ior` a freshly built
    /// request whose `done` is [`ds_read_done()`]. The driver may
    /// complete synchronously in the return value, or return
    /// [`DeviceSuccess::IoQueued`] and call `(*ior).done` itself once the
    /// data is ready, from any context.
    pub d_read: Option<DevIo<P>>,
    /// Writes to the device.
    ///
    /// `device_write()` and `device_write_inband()` invoke it for an
    /// open device, with no device lock held and `ior` a request whose
    /// `done` is [`ds_write_done()`]; [`ds_write_done()`] itself calls
    /// back in to retry a request the driver had queued. The driver may
    /// complete synchronously in the return value, or return
    /// [`DeviceSuccess::IoQueued`] and call `(*ior).done` itself once the
    /// write completes, from any context.
    pub d_write: Option<DevIo<P>>,
    pub d_getstat: Option<DevGetstat>,
    pub d_setstat: Option<DevSetstat>,
    /// Translates an mmap offset into the device to a physical page
    /// number.
    ///
    /// `dev_pager::device_map_page()` invokes it from
    /// the page-fault path with the page-aligned offset into the device
    /// and the mapping's protection; it must return synchronously,
    /// without blocking, and answer `VmOffset::MAX` for an offset the
    /// device does not back.
    pub d_mmap: Option<unsafe fn(DevT, VmOffset, c_int) -> VmOffset>,
    pub d_async_in: Option<DevAsyncIn>,
    pub d_subdev: c_int,
    /// Reads one `D_INFO_*` info flavor into `*data`.
    ///
    /// `device_write_dealloc()` invokes it with
    /// `D_INFO_BLOCK_SIZE` to recover the device's block size when a
    /// write continuation needs to advance `recnum`; called with no
    /// device lock held.
    pub d_dev_info: Option<DevDevInfo>,
}

// SAFETY: a table of entry points is never written once built, and its name
// is a static string.
unsafe impl<P: Platform> Sync for DevOps<P> {}

impl<P: Platform> DevOps<P> {
    /// The record keeps its established size, alignment and field offsets.
    pub(crate) const LAYOUT: () = {
        assert!(size_of::<Self>() == 88);
        assert!(align_of::<Self>() == 8);
        assert!(offset_of!(Self, d_name) == 0);
        assert!(offset_of!(Self, d_open) == 8);
        assert!(offset_of!(Self, d_close) == 16);
        assert!(offset_of!(Self, d_read) == 24);
        assert!(offset_of!(Self, d_write) == 32);
        assert!(offset_of!(Self, d_getstat) == 40);
        assert!(offset_of!(Self, d_setstat) == 48);
        assert!(offset_of!(Self, d_mmap) == 56);
        assert!(offset_of!(Self, d_async_in) == 64);
        assert!(offset_of!(Self, d_subdev) == 72);
        assert!(offset_of!(Self, d_dev_info) == 80);
    };
}

/// The signature of an emulation's `open` hook.
///
/// [`ds_device_open()`] invokes it with a validated `reply_port`, the
/// port's type, the requested mode, a NUL-terminated device `name`, and
/// a writable out-param to fill with the opened handle on success.
type EmulOpen = unsafe fn(
    *mut c_void,
    c_uint,
    c_uint,
    *const c_char,
    *mut *mut c_void,
) -> ReplyResult;
/// The signature of an emulation's `write` hook.
///
/// [`ds_device_write()`] invokes it with the emulation data, the reply
/// port to answer through, the mode and record number, `data` readable
/// for `count` bytes, and a writable out-param for the byte count it
/// actually consumes.
type EmulWrite = unsafe fn(
    *mut c_void,
    *mut c_void,
    c_uint,
    c_uint,
    c_ulong,
    *mut c_char,
    c_uint,
    *mut c_int,
) -> ReplyResult;
/// The signature of an emulation's `write_inband` hook.
///
/// [`ds_device_write_inband()`] invokes it the same way as
/// [`EmulWrite`], except `data` is the bytes carried inline in the
/// request message rather than an out-of-line copy.
type EmulWriteInband = unsafe fn(
    *mut c_void,
    *mut c_void,
    c_uint,
    c_uint,
    c_ulong,
    *const c_char,
    c_uint,
    *mut c_int,
) -> ReplyResult;
/// The signature of an emulation's `read` hook.
///
/// [`ds_device_read()`] invokes it with the emulation data, the reply
/// port to answer through, the mode, record number and byte count
/// requested, an out-param the callee points at the bytes it read, and
/// a writable out-param for the count.
type EmulRead = unsafe fn(
    *mut c_void,
    *mut c_void,
    c_uint,
    c_uint,
    c_ulong,
    c_int,
    *mut *mut c_char,
    *mut c_uint,
) -> ReplyResult;
/// The signature of an emulation's `read_inband` hook.
///
/// [`ds_device_read_inband()`] invokes it the same way as [`EmulRead`],
/// except `data` is a buffer the callee fills in place for the inline
/// reply rather than an out-param pointer.
type EmulReadInband = unsafe fn(
    *mut c_void,
    *mut c_void,
    c_uint,
    c_uint,
    c_ulong,
    c_int,
    *mut c_char,
    *mut c_uint,
) -> ReplyResult;
/// The signature of an emulation's `set_status` hook.
///
/// [`ds_device_set_status()`] invokes it with the emulation data, the
/// status flavor, and `status` readable for `status_count` words.
type EmulSetStatus = unsafe fn(
    *mut c_void,
    c_uint,
    *mut c_int,
    c_uint,
) -> Result<(), DeviceError>;
/// The signature of an emulation's `get_status` hook.
///
/// [`ds_device_get_status()`] invokes it with the emulation data, the
/// status flavor, `status` writable for the words the caller reserved,
/// and a writable out-param for the count the callee actually filled
/// in.
type EmulGetStatus = unsafe fn(
    *mut c_void,
    c_uint,
    *mut c_int,
    *mut c_uint,
) -> Result<(), DeviceError>;
/// The signature of an emulation's `set_filter` hook.
///
/// [`ds_device_set_filter()`] invokes it with the emulation data, a
/// valid `receive_port`, the filter priority, and `filter` readable for
/// `filter_count` entries.
type EmulSetFilter = unsafe fn(
    *mut c_void,
    *mut c_void,
    c_int,
    *mut c_ushort,
    c_uint,
) -> Result<(), DeviceError>;
/// The signature of an emulation's `map` hook.
///
/// [`ds_device_map()`] invokes it with the emulation data, the requested
/// protection, offset and size, a writable out-param for the memory
/// object port it creates, and the `unmap` flag.
type EmulMap = unsafe fn(
    *mut c_void,
    c_int,
    VmOffset,
    VmSize,
    *mut *mut c_void,
    c_int,
) -> Result<(), DeviceError>;
/// The signature of an emulation's `write_trap` hook.
///
/// [`ds_device_write_trap()`] invokes it with the emulation data, the
/// mode, record number, and the `data`/`count` words exactly as the
/// `device_write_trap` system call passed them straight from user
/// registers; the callee must validate them itself before touching user
/// memory.
type EmulWriteTrap =
    unsafe fn(*mut c_void, c_uint, c_ulong, c_ulong, c_ulong) -> ReplyResult;
/// The signature of an emulation's `writev_trap` hook.
///
/// [`ds_device_writev_trap()`] invokes it with the emulation data, the
/// mode and record number, and `iovec` readable for `count`
/// user-space scatter/gather entries exactly as the
/// `device_writev_trap` system call passed them; the callee must
/// validate them itself before touching user memory.
type EmulWritevTrap = unsafe fn(
    *mut c_void,
    c_uint,
    c_ulong,
    *mut RpcIoBufVec,
    c_ulong,
) -> ReplyResult;

/// The signature of an emulation's `close` hook; see
/// [`DeviceEmulationOps::close`].
type EmulClose = unsafe fn(*mut c_void) -> Result<(), DeviceError>;

/// The operations one emulation layer provides.
#[repr(C)]
#[allow(missing_docs)]
pub struct DeviceEmulationOps {
    /// Takes a reference on the emulation data.
    ///
    /// [`device_reference()`] invokes it with `emul_data`, and
    /// [`dev_lookup::port_lookup()`] also invokes it while holding the
    /// device's port spinlock, so the callee must not block.
    pub reference: Option<unsafe fn(*mut c_void)>,
    /// Drops a reference on the emulation data.
    ///
    /// [`device_deallocate()`] invokes it with `emul_data` once the
    /// caller is done with a reference `reference` (or the open path)
    /// took.
    pub dealloc: Option<unsafe fn(*mut c_void)>,
    /// Converts the emulation data back to a send right on the device's
    /// port.
    ///
    /// [`dev_lookup::convert_to_port()`] invokes it with `emul_data`,
    /// consuming the reference the caller held on the device; the
    /// callee returns a send right or `IP_NULL` and must not retain
    /// that reference past the call.
    pub dev_to_port: Option<unsafe fn(*mut c_void) -> *mut c_void>,
    pub open: Option<EmulOpen>,
    /// Closes the emulation-level device handle.
    ///
    /// [`ds_device_close()`] invokes it with `emul_data`; this need not
    /// be the underlying device's last close, so the callee tears down
    /// only what this open reference set up.
    pub close: Option<EmulClose>,
    pub write: Option<EmulWrite>,
    pub write_inband: Option<EmulWriteInband>,
    pub read: Option<EmulRead>,
    pub read_inband: Option<EmulReadInband>,
    pub set_status: Option<EmulSetStatus>,
    pub get_status: Option<EmulGetStatus>,
    pub set_filter: Option<EmulSetFilter>,
    pub map: Option<EmulMap>,
    /// Handles the no-senders notification for the device's port.
    ///
    /// [`ds_notify()`] invokes it with the live notification message
    /// itself, not `emul_data`, once [`dev_lookup::port_lookup()`]
    /// resolves the dying port back to this device; the callee reads
    /// the message, it does not receive the device record.
    pub no_senders: Option<unsafe fn(*mut c_void)>,
    pub write_trap: Option<EmulWriteTrap>,
    pub writev_trap: Option<EmulWritevTrap>,
}

const _: () = {
    assert!(size_of::<DeviceEmulationOps>() == 128);
    assert!(align_of::<DeviceEmulationOps>() == 8);
    assert!(offset_of!(DeviceEmulationOps, reference) == 0);
    assert!(offset_of!(DeviceEmulationOps, dealloc) == 8);
    assert!(offset_of!(DeviceEmulationOps, dev_to_port) == 16);
    assert!(offset_of!(DeviceEmulationOps, open) == 24);
    assert!(offset_of!(DeviceEmulationOps, close) == 32);
    assert!(offset_of!(DeviceEmulationOps, write) == 40);
    assert!(offset_of!(DeviceEmulationOps, write_inband) == 48);
    assert!(offset_of!(DeviceEmulationOps, read) == 56);
    assert!(offset_of!(DeviceEmulationOps, read_inband) == 64);
    assert!(offset_of!(DeviceEmulationOps, set_status) == 72);
    assert!(offset_of!(DeviceEmulationOps, get_status) == 80);
    assert!(offset_of!(DeviceEmulationOps, set_filter) == 88);
    assert!(offset_of!(DeviceEmulationOps, map) == 96);
    assert!(offset_of!(DeviceEmulationOps, no_senders) == 104);
    assert!(offset_of!(DeviceEmulationOps, write_trap) == 112);
    assert!(offset_of!(DeviceEmulationOps, writev_trap) == 120);
};

/// `mach_no_senders_notification_t`: the notification [`ds_notify`] handles.
#[repr(C)]
#[allow(missing_docs)]
struct NoSendersNotification {
    header: MachMsgHeader,
    /// The C's `mach_msg_type_t` word, present for the layout only.
    not_type: usize,
    not_count: c_uint,
}

const _: () = {
    assert!(size_of::<NoSendersNotification>() == 48);
    assert!(align_of::<NoSendersNotification>() == 8);
    assert!(offset_of!(NoSendersNotification, header) == 0);
    assert!(offset_of!(NoSendersNotification, not_type) == 32);
    assert!(offset_of!(NoSendersNotification, not_count) == 40);
};

/// `io_buf_vec_t`: one scatter/gather segment of kernel addresses.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct IoBufVec {
    data: VmOffset,
    count: VmSize,
}

const _: () = {
    assert!(size_of::<IoBufVec>() == 16);
    assert!(align_of::<IoBufVec>() == 8);
    assert!(offset_of!(IoBufVec, data) == 0);
    assert!(offset_of!(IoBufVec, count) == 8);
};

/// `rpc_io_buf_vec_t`: one scatter/gather segment of user addresses, as MIG
/// passes them.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct RpcIoBufVec {
    pub data: c_ulong,
    pub count: c_ulong,
}

const _: () = {
    assert!(size_of::<RpcIoBufVec>() == 2 * size_of::<c_ulong>());
    assert!(align_of::<RpcIoBufVec>() == align_of::<c_ulong>());
    assert!(offset_of!(RpcIoBufVec, data) == 0);
    assert!(offset_of!(RpcIoBufVec, count) == size_of::<c_ulong>());
};

/// The map every device I/O buffer is mapped through.
#[must_use]
pub fn device_io_map<P: Platform>() -> *mut VmMap<P> {
    P::device_state().io_map.get()
}

/// The io-done list's address, the event every wakeup of the io-done thread
/// names.
fn io_done_event<P: Platform>() -> *mut c_void {
    P::device_state().io_done_list.get().cast()
}

/// The live io-done list head.
///
/// # Safety
///
/// The caller must hold the io-done lock for as long as it uses the list.
unsafe fn io_done_list<P: Platform>() -> Pin<&'static mut IoReqQueue<P>> {
    // SAFETY: the state never moves, and the lock the caller holds keeps
    // anything else from reaching the list.
    unsafe { Pin::new_unchecked(&mut *P::device_state().io_done_list.get()) }
}

impl DeviceEmulationOps {
    /// The native Mach device emulation every device lookup installs.
    pub(crate) const fn mach<P: Platform>() -> Self {
        Self {
            reference: Some(dev_lookup::mach_device_reference::<P>),
            dealloc: Some(dev_lookup::mach_device_deallocate::<P>),
            dev_to_port: Some(mach_convert_device_to_port::<P>),
            open: Some(device_open::<P>),
            close: Some(device_close::<P>),
            write: Some(device_write::<P>),
            write_inband: Some(device_write_inband::<P>),
            read: Some(device_read::<P>),
            read_inband: Some(device_read_inband::<P>),
            set_status: Some(device_set_status::<P>),
            get_status: Some(mach_device_get_status::<P>),
            set_filter: Some(device_set_filter::<P>),
            map: Some(device_map::<P>),
            no_senders: Some(ds_no_senders::<P>),
            write_trap: Some(device_write_trap::<P>),
            writev_trap: Some(device_writev_trap::<P>),
        }
    }
}

/// The device number of a driver call: a device number comes from the device
/// table and fits in sixteen bits.
pub(crate) const fn driver_unit(dev_number: c_int) -> DevT {
    dev_number as DevT
}

/// The C's implicit `unsigned int` to `long` conversion of an IO byte count.
const fn io_count(count: c_uint) -> c_long {
    count as c_long
}

/// Moves `ior` into a fresh heap block, or returns `None` when the heap is
/// exhausted.
fn io_req_alloc<P: Platform>(
    ior: IoReq<P>,
) -> Option<KBox<IoReq<P>, <P as mach_ipc::Platform>::Heap>> {
    KBox::try_new(ior, <P as mach_ipc::Platform>::Heap::default()).ok()
}

/// Frees a request block [`io_req_alloc`] made.
///
/// # Safety
///
/// `ior` must be a request [`io_req_alloc()`] built, released with
/// [`KBox::into_raw`], that nothing uses.
unsafe fn io_req_free<P: Platform>(ior: *mut IoReq<P>) {
    drop(unsafe {
        KBox::from_raw(ior, <P as mach_ipc::Platform>::Heap::default())
    });
}

/// Opens the device `name` with `mode` for the master device port `open_port`,
/// replying through `reply_port` when the open completes later.
///
/// # Safety
///
/// `open_port` is the master device port, `reply_port` is a valid port or
/// `IP_NULL`, `name` is a NUL-terminated device name, and `devp` is writable.
pub unsafe fn ds_device_open<P: Platform>(
    open_port: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    name: *const c_char,
    devp: *mut *mut c_void,
) -> ReplyResult {
    if open_port != master_device_port() {
        return Err(DeviceError::InvalidOperation);
    }

    if IpcPort::valid(reply_port).is_none() {
        P::print(format_args!("ds_* invalid reply port\n"));
        P::soft_debugger(c"ds_* reply_port");
        return Ok(Reply::Withheld);
    }

    let ops = P::device_state().emulation.get();
    // SAFETY: the emulation registered a real open with the C signature.
    unsafe { (*ops).open }.map_or(Ok(Reply::Now), |open| unsafe {
        open(reply_port, reply_port_type, mode, name, devp)
    })
}

/// Closes the device.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub unsafe fn ds_device_close(
    dev: NonNull<c_void>,
) -> Result<(), DeviceError> {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).close.map_or(Ok(()), |close| close((*dev).emul_data))
    }
}

/// Writes the `count` out-of-line bytes at `data` to the device at `recnum`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `data` readable for `count` bytes,
/// and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
pub unsafe fn ds_device_write(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: NonNull<c_char>,
    count: c_uint,
    bytes_written: *mut c_int,
) -> ReplyResult {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).write.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |write| {
                write(
                    (*dev).emul_data,
                    reply_port,
                    reply_port_type,
                    mode,
                    recnum,
                    data.as_ptr(),
                    count,
                    bytes_written,
                )
            },
        )
    }
}

/// Writes the `count` in-band bytes at `data` to the device at `recnum`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `data` readable for `count` bytes,
/// and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
pub unsafe fn ds_device_write_inband(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: NonNull<c_char>,
    count: c_uint,
    bytes_written: *mut c_int,
) -> ReplyResult {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).write_inband.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |write| {
                write(
                    (*dev).emul_data,
                    reply_port,
                    reply_port_type,
                    mode,
                    recnum,
                    data.as_ptr(),
                    count,
                    bytes_written,
                )
            },
        )
    }
}

/// Reads `count` bytes from the device at `recnum`, out of line.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `data` and `bytes_read` must be
/// writable.
#[expect(clippy::too_many_arguments)]
pub unsafe fn ds_device_read(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    count: c_int,
    data: *mut *mut c_char,
    bytes_read: *mut c_uint,
) -> ReplyResult {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).read.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |read| {
                read(
                    (*dev).emul_data,
                    reply_port,
                    reply_port_type,
                    mode,
                    recnum,
                    count,
                    data,
                    bytes_read,
                )
            },
        )
    }
}

/// Reads `count` bytes from the device at `recnum`, in band.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `data` writable for the reply, and
/// `bytes_read` writable.
#[expect(clippy::too_many_arguments)]
pub unsafe fn ds_device_read_inband(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    count: c_int,
    data: *mut c_char,
    bytes_read: *mut c_uint,
) -> ReplyResult {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).read_inband.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |read| {
                read(
                    (*dev).emul_data,
                    reply_port,
                    reply_port_type,
                    mode,
                    recnum,
                    count,
                    data,
                    bytes_read,
                )
            },
        )
    }
}

/// Applies the status flavor `flavor` from `status` to the device.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `status` readable for
/// `status_count` integers when the emulation reads it.
pub unsafe fn ds_device_set_status(
    dev: NonNull<c_void>,
    flavor: c_uint,
    status: *mut c_int,
    status_count: c_uint,
) -> Result<(), DeviceError> {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).set_status.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |set_status| {
                set_status((*dev).emul_data, flavor, status, status_count)
            },
        )
    }
}

/// Reports the device's status flavor `flavor` into `status`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `status` writable for
/// `*status_count` integers, and `status_count` writable.
pub unsafe fn ds_device_get_status(
    dev: NonNull<c_void>,
    flavor: c_uint,
    status: *mut c_int,
    status_count: *mut c_uint,
) -> Result<(), DeviceError> {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).get_status.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |get_status| {
                get_status((*dev).emul_data, flavor, status, status_count)
            },
        )
    }
}

/// Installs the packet `filter` on the device for `receive_port`, at
/// `priority`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `receive_port` a valid port, and
/// `filter` readable for `filter_count` entries.
pub unsafe fn ds_device_set_filter(
    dev: NonNull<c_void>,
    receive_port: *mut c_void,
    priority: c_int,
    filter: *mut c_ushort,
    filter_count: c_uint,
) -> Result<(), DeviceError> {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).set_filter.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |set_filter| {
                set_filter(
                    (*dev).emul_data,
                    receive_port,
                    priority,
                    filter,
                    filter_count,
                )
            },
        )
    }
}

/// Makes a pager that maps `size` bytes of the device at `offset` with
/// `protection`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `pager` writable.
pub unsafe fn ds_device_map(
    dev: NonNull<c_void>,
    protection: c_int,
    offset: VmOffset,
    size: VmSize,
    pager: *mut *mut c_void,
    unmap: c_int,
) -> Result<(), DeviceError> {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).map.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |map| {
                map((*dev).emul_data, protection, offset, size, pager, unmap)
            },
        )
    }
}

/// Handles a notification sent to a device port, returning whether it was one.
///
/// # Safety
///
/// `msg` must be a live message whose header and no-senders body are
/// readable.
pub unsafe fn ds_notify<P: Platform>(msg: *mut c_void) -> bool {
    let msg = msg.cast::<NoSendersNotification>();
    unsafe {
        let header = ptr::addr_of!((*msg).header);
        if (*header).id() == MACH_NOTIFY_NO_SENDERS {
            let port =
                ptr::with_exposed_provenance_mut::<c_void>((*header).remote());
            let dev = dev_lookup::port_lookup(port);
            let ops = (*dev).emul_ops;
            if let Some(no_senders) = (*ops).no_senders {
                no_senders(msg.cast::<c_void>());
            }
            return true;
        }

        P::print(format_args!(
            "ds_notify: strange notification {}\n",
            (*header).id()
        ));
    }
    false
}

/// Writes `count` bytes at the user address `data` to the device at `recnum`,
/// as a trap.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub unsafe fn ds_device_write_trap(
    dev: NonNull<c_void>,
    mode: c_uint,
    recnum: c_ulong,
    data: c_ulong,
    count: c_ulong,
) -> ReplyResult {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).write_trap.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |write_trap| {
                write_trap((*dev).emul_data, mode, recnum, data, count)
            },
        )
    }
}

/// Writes the user segments at `iovec` to the device at `recnum`, as a trap.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `iovec` readable for `count`
/// user-space entries.
pub unsafe fn ds_device_writev_trap(
    dev: NonNull<c_void>,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut RpcIoBufVec,
    count: c_ulong,
) -> ReplyResult {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).writev_trap.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |writev_trap| {
                writev_trap((*dev).emul_data, mode, recnum, iovec, count)
            },
        )
    }
}

/// Takes a reference on the device.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub unsafe fn device_reference(dev: NonNull<c_void>) {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        if let Some(reference) = (*ops).reference {
            reference((*dev).emul_data);
        }
    }
}

/// Drops a reference on the device.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub unsafe fn device_deallocate(dev: NonNull<c_void>) {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        if let Some(dealloc) = (*ops).dealloc {
            dealloc((*dev).emul_data);
        }
    }
}

/// A send right for the device's port, consuming the caller's device
/// reference.
///
/// # Safety
///
/// `device` is null or a live [`MachDevice`].
unsafe fn mach_convert_device_to_port<P: Platform>(
    device: *mut c_void,
) -> *mut c_void {
    if device.is_null() {
        return ptr::null_mut();
    }
    let device = device.cast::<MachDevice<P>>();
    unsafe {
        (*device).lock.lock();
        let port = if (*device).state == DEV_STATE_OPEN {
            let port = IpcPort::from_raw((*device).port);
            ipc_port::make_send(port).as_ptr()
        } else {
            ptr::null_mut()
        };
        (*device).lock.unlock();

        dev_lookup::deallocate(device);

        port
    }
}

/// Opens the device with `mode`, through its driver, replying through
/// `reply_port` when the driver queues the open.
///
/// # Safety
///
/// `name` must be a NUL-terminated device name, and `device_p` writable.
unsafe fn device_open<P: Platform>(
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    name: *const c_char,
    device_p: *mut *mut c_void,
) -> ReplyResult {
    let Some(device) = (unsafe { dev_lookup::lookup(name) }) else {
        return Err(DeviceError::NoSuchDevice);
    };
    let device = device.as_ptr();

    // The C allocated the request after marking the device opening; failing
    // there would strand the device in that state, so the request comes
    // first and the early returns below drop it.
    // SAFETY: `lookup()` returned a live device.
    let request = unsafe {
        IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::OPEN | IoOp::CALL,
            mode: DeviceMode::from_bits_retain(mode),
            done: Some(ds_open_done),
            reply_port,
            reply_port_type,
            ..IoReq::<P>::new()
        }
    };
    let Some(ior) = io_req_alloc(request) else {
        // SAFETY: the reference is the one `lookup()` took.
        unsafe { dev_lookup::deallocate(device) };
        return Err(DeviceError::NoMemory);
    };

    // SAFETY: a live mach device owns its lock, and the caller promises the
    // writable handle slot.
    unsafe {
        (*device).lock.lock();
        while (*device).state == DEV_STATE_OPENING
            || (*device).state == DEV_STATE_CLOSING
        {
            (*device).io_wait = c_int::from(true);
            thread_sleep::<P>(
                device.cast::<c_void>(),
                ptr::addr_of_mut!((*device).lock),
                c_int::from(true),
            );
            (*device).lock.lock();
        }

        if (*device).state == DEV_STATE_OPEN {
            if (*device).flag.contains(DeviceFlags::EXCL_OPEN) {
                (*device).lock.unlock();
                dev_lookup::deallocate(device);
                return Err(DeviceError::AlreadyOpen);
            }

            (*device).open_count += 1;
            (*device).lock.unlock();
            device_p.write(ptr::addr_of_mut!((*device).dev).cast::<c_void>());
            return Ok(Reply::Now);
        }

        (*device).state = DEV_STATE_OPENING;
        (*device).lock.unlock();

        (*device).port = ipc_port::alloc_special::<P>(ipc_space::kernel())
            .map_or(ptr::null_mut(), IpcPort::as_ptr);
        if (*device).port.is_null() {
            (*device).lock.lock();
            (*device).state = DEV_STATE_INIT;
            (*device).port = ptr::null_mut();
            if (*device).io_wait != 0 {
                (*device).io_wait = c_int::from(false);
                thread_wakeup_prim::<P>(
                    device.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*device).lock.unlock();
            dev_lookup::deallocate(device);
            return Err(DeviceError::ResourceShortage);
        }

        dev_lookup::port_enter(device);

        let port = IpcPort::from_raw((*device).port);
        let notify = ipc_port::make_sonce(port);
        port.lock();
        // A fresh device port has no previous no-senders request to return.
        let _ = ipc_port::nsrequest::<P>(port, 1, Some(notify.as_non_null()));

        let ior = KBox::into_raw(ior);
        let d_open = (*(*device).dev_ops).d_open;
        let result = d_open.map_or(Ok(DeviceSuccess::Success), |d_open| {
            d_open(driver_unit((*device).dev_number), mode as c_int, ior)
        });
        (*ior).error = match result {
            Ok(DeviceSuccess::IoQueued) => return Ok(Reply::Withheld),
            Ok(DeviceSuccess::Success) => Ok(()),
            Err(error) => Err(error),
        };
        // The completion sends the reply.
        let _ = ds_open_done(ior);
        io_req_free(ior);
    }

    Ok(Reply::Withheld)
}

/// Completes an open: binds the device to its port on success, and replies.
///
/// # Safety
///
/// `ior` must be the live open request `device_open()` built.
pub unsafe fn ds_open_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    unsafe {
        let mut device = (*ior).device.cast::<MachDevice<P>>();
        let result = (*ior).error;

        if result.is_ok() {
            (*device).lock.lock();
            (*device).state = DEV_STATE_OPEN;
            (*device).open_count = 1;
            if (*device).io_wait != 0 {
                (*device).io_wait = c_int::from(false);
                thread_wakeup_prim::<P>(
                    device.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*device).lock.unlock();
        } else {
            dev_lookup::port_remove(device);
            ipc_port::dealloc_special::<P>(IpcPort::from_raw((*device).port));
            (*device).port = ptr::null_mut();

            (*device).lock.lock();
            (*device).state = DEV_STATE_INIT;
            if (*device).io_wait != 0 {
                (*device).io_wait = c_int::from(false);
                thread_wakeup_prim::<P>(
                    device.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*device).lock.unlock();

            dev_lookup::deallocate(device);
            device = ptr::null_mut();
        }

        if IpcPort::valid((*ior).reply_port).is_some() {
            let _ = P::send(Message::OpenReply {
                reply_port: (*ior).reply_port,
                reply_port_type: (*ior).reply_port_type,
                result,
                device_port: mach_convert_device_to_port::<P>(
                    device.cast::<c_void>(),
                ),
            });
        } else if !device.is_null() {
            dev_lookup::deallocate(device);
        }
    }

    true
}

/// Closes the device through its driver, once its pending requests are done.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the emulation's close entry has this signature"
)]
unsafe fn device_close<P: Platform>(
    dev: *mut c_void,
) -> Result<(), DeviceError> {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        (*device).lock.lock();

        (*device).open_count -= 1;
        if (*device).open_count > 0 {
            (*device).lock.unlock();
            return Ok(());
        }

        if (*device).state == DEV_STATE_CLOSING {
            (*device).lock.unlock();
            return Ok(());
        }

        (*device).state = DEV_STATE_CLOSING;
        (*device).lock.unlock();

        dev_lookup::port_remove(device);
        ipc_port::dealloc_special::<P>(IpcPort::from_raw((*device).port));

        if let Some(d_close) = (*(*device).dev_ops).d_close {
            d_close(driver_unit((*device).dev_number), 0);
        }

        (*device).lock.lock();
        (*device).state = DEV_STATE_INIT;
        if (*device).io_wait != 0 {
            (*device).io_wait = c_int::from(false);
            thread_wakeup_prim::<P>(
                device.cast::<c_void>(),
                0,
                THREAD_AWAKENED,
            );
        }
        (*device).lock.unlock();
    }

    Ok(())
}

/// Writes an out-of-line buffer to the device through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, `data` readable
/// for `data_count` bytes, and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_write<P: Platform>(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: *mut c_char,
    data_count: c_uint,
    bytes_written: *mut c_int,
) -> ReplyResult {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        let Some(ior) = io_req_alloc(IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::WRITE | IoOp::CALL,
            mode: DeviceMode::from_bits_retain(mode),
            recnum,
            data,
            count: io_count(data_count),
            total: io_count(data_count),
            done: Some(ds_write_done),
            reply_port,
            reply_port_type,
            ..IoReq::<P>::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory);
        };

        dev_lookup::reference(device);

        let result = loop {
            let d_write = (*(*device).dev_ops).d_write;
            let result = d_write
                .map_or(Ok(DeviceSuccess::Success), |d_write| {
                    d_write(driver_unit((*device).dev_number), ior)
                });

            if result == Ok(DeviceSuccess::IoQueued) {
                return Ok(Reply::Withheld);
            }

            if device_write_dealloc(ior) {
                break result;
            }
        };

        bytes_written.write(((*ior).total - (*ior).residual) as c_int);

        dev_lookup::deallocate(device);

        io_req_free(ior);
        result.map(|_| Reply::Now)
    }
}

/// Writes an in-band buffer to the device through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, `data` readable
/// for `data_count` bytes, and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_write_inband<P: Platform>(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: *const c_char,
    data_count: c_uint,
    bytes_written: *mut c_int,
) -> ReplyResult {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        let Some(ior) = io_req_alloc(IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::WRITE | IoOp::CALL | IoOp::INBAND,
            mode: DeviceMode::from_bits_retain(mode),
            recnum,
            data: data.cast_mut(),
            count: io_count(data_count),
            total: io_count(data_count),
            done: Some(ds_write_done),
            reply_port,
            reply_port_type,
            ..IoReq::<P>::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory);
        };

        dev_lookup::reference(device);

        let d_write = (*(*device).dev_ops).d_write;
        let result = d_write.map_or(Ok(DeviceSuccess::Success), |d_write| {
            d_write(driver_unit((*device).dev_number), ior)
        });

        if result == Ok(DeviceSuccess::IoQueued) {
            return Ok(Reply::Withheld);
        }

        bytes_written.write(((*ior).total - (*ior).residual) as c_int);

        dev_lookup::deallocate(device);

        io_req_free(ior);
        result.map(|_| Reply::Now)
    }
}

/// Frees a write request's buffer, returning whether the request is finished
/// with it.
///
/// # Safety
///
/// `ior` must be a live request from [`io_req_alloc()`].
pub(crate) unsafe fn device_write_dealloc<P: Platform>(
    ior: *mut IoReq<P>,
) -> bool {
    unsafe {
        if (*ior).alloc_size == 0 {
            return true;
        }

        if (*ior).op.contains(IoOp::INBAND) {
            if let Some(data) = NonNull::new((*ior).data.cast::<u8>()) {
                P::device_cache_free(DeviceCache::IoInband, data);
            }
            return true;
        }

        let io_copy = (*ior).copy;
        if io_copy.is_null() {
            return true;
        }

        vm_kern::kmem_io_map_deallocate(
            &mut *device_io_map::<P>(),
            trunc_page((*ior).data.addr()),
            (*ior).alloc_size,
        );

        let mut new_copy: *mut VmMapCopy<P> = ptr::null_mut();
        if VmMapCopy::<P>::has_cont(NonNull::new_unchecked(io_copy)) {
            let size_to_do =
                (*io_copy).size.wrapping_sub((*ior).count as VmSize);
            let continued = if (*ior).error.is_ok() {
                let (result, next) = VmMapCopy::<P>::invoke_cont(
                    NonNull::new_unchecked(io_copy),
                );
                new_copy = next;
                result.is_ok()
            } else {
                VmMapCopy::<P>::abort_cont(NonNull::new_unchecked(io_copy));
                false
            };

            if continued && !new_copy.is_null() {
                (*ior).op &= !IoOp::DONE;
                (*ior).op |= IoOp::CALL;

                let device = (*ior).device.cast::<MachDevice<P>>();
                let mut bsize: c_int = 0;
                let d_dev_info = (*(*device).dev_ops).d_dev_info;
                let res = d_dev_info.map(|d_dev_info| {
                    d_dev_info(
                        driver_unit((*device).dev_number),
                        D_INFO_BLOCK_SIZE,
                        &raw mut bsize,
                    )
                });
                assert!(
                    res == Some(Ok(())),
                    "device_write_dealloc: No block size"
                );

                (*ior).recnum = (*ior).recnum.wrapping_add(
                    ((*ior).count / c_long::from(bsize)) as c_ulong,
                );
                (*ior).count = (*new_copy).size as c_long;
            } else {
                (*ior).residual =
                    (*ior).residual.wrapping_add(size_to_do as c_long);
            }
        }

        VmMapCopy::<P>::discard(NonNull::new_unchecked(io_copy));
        (*ior).copy = ptr::null_mut();
        (*ior).data = new_copy.cast::<c_char>();

        new_copy.is_null()
    }
}

/// Completes a write and replies with the count written.
///
/// # Safety
///
/// `ior` must be the live write request `device_write()` queued.
pub unsafe fn ds_write_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    unsafe {
        loop {
            if device_write_dealloc(ior) {
                break;
            }

            let device = (*ior).device.cast::<MachDevice<P>>();
            let d_write = (*(*device).dev_ops).d_write;
            let result = d_write
                .map_or(Ok(DeviceSuccess::Success), |d_write| {
                    d_write(driver_unit((*device).dev_number), ior)
                });

            if result == Ok(DeviceSuccess::IoQueued) {
                return false;
            }
        }

        if IpcPort::valid((*ior).reply_port).is_some() {
            let _ = P::send(Message::WriteReply {
                reply_port: (*ior).reply_port,
                reply_port_type: (*ior).reply_port_type,
                inband: (*ior).op.contains(IoOp::INBAND),
                result: (*ior).error,
                bytes_written: ((*ior).total - (*ior).residual) as c_int,
            });
        }
        dev_lookup::deallocate((*ior).device.cast::<MachDevice<P>>());
    }

    true
}

/// Reads from the device into an out-of-line buffer through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `data` and
/// `data_count` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_read<P: Platform>(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    bytes_wanted: c_int,
    _data: *mut *mut c_char,
    _data_count: *mut c_uint,
) -> ReplyResult {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        if IpcPort::valid(reply_port).is_none() {
            P::print(format_args!("ds_* invalid reply port\n"));
            P::soft_debugger(c"ds_* reply_port");
            return Ok(Reply::Withheld);
        }

        let Some(ior) = io_req_alloc(IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::READ | IoOp::CALL,
            mode: DeviceMode::from_bits_retain(mode),
            recnum,
            count: c_long::from(bytes_wanted),
            done: Some(ds_read_done),
            reply_port,
            reply_port_type,
            ..IoReq::<P>::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory);
        };

        dev_lookup::reference(device);

        let d_read = (*(*device).dev_ops).d_read;
        let result = d_read.map_or(Ok(DeviceSuccess::Success), |d_read| {
            d_read(driver_unit((*device).dev_number), ior)
        });

        (*ior).error = match result {
            Ok(DeviceSuccess::IoQueued) => return Ok(Reply::Withheld),
            Ok(DeviceSuccess::Success) => Ok(()),
            Err(error) => Err(error),
        };
        // The completion sends the reply.
        let _ = ds_read_done(ior);
        io_req_free(ior);
    }

    Ok(Reply::Withheld)
}

/// Reads from the device into an in-band buffer through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `data` and
/// `data_count` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_read_inband<P: Platform>(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    bytes_wanted: c_int,
    _data: *mut c_char,
    _data_count: *mut c_uint,
) -> ReplyResult {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        if IpcPort::valid(reply_port).is_none() {
            P::print(format_args!("ds_* invalid reply port\n"));
            P::soft_debugger(c"ds_* reply_port");
            return Ok(Reply::Withheld);
        }

        // The C compared the int against the `size_t` array bound, so a
        // negative wish became a huge one and picked the bound.
        let wanted = bytes_wanted as usize;
        let count = if wanted < IO_INBAND_MAX {
            c_long::from(bytes_wanted)
        } else {
            IO_INBAND_MAX as c_long
        };
        let Some(ior) = io_req_alloc(IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::READ | IoOp::CALL | IoOp::INBAND,
            mode: DeviceMode::from_bits_retain(mode),
            recnum,
            count,
            done: Some(ds_read_done),
            reply_port,
            reply_port_type,
            ..IoReq::<P>::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory);
        };

        dev_lookup::reference(device);

        let d_read = (*(*device).dev_ops).d_read;
        let result = d_read.map_or(Ok(DeviceSuccess::Success), |d_read| {
            d_read(driver_unit((*device).dev_number), ior)
        });

        (*ior).error = match result {
            Ok(DeviceSuccess::IoQueued) => return Ok(Reply::Withheld),
            Ok(DeviceSuccess::Success) => Ok(()),
            Err(error) => Err(error),
        };
        // The completion sends the reply.
        let _ = ds_read_done(ior);
        io_req_free(ior);
    }

    Ok(Reply::Withheld)
}

/// Allocates the buffer a read request reads into, `size` bytes or the in-band
/// maximum.
///
/// # Safety
///
/// `ior` must be a live request with `io_count` bytes to allocate.
pub unsafe fn device_read_alloc<P: Platform>(
    ior: *mut IoReq<P>,
    size: VmSize,
) -> Result<(), DeviceError> {
    unsafe {
        if (*ior).count == 0 {
            return Ok(());
        }

        if (*ior).op.contains(IoOp::INBAND) {
            (*ior).data = P::device_cache_alloc(DeviceCache::IoInband)
                .map_or(ptr::null_mut(), |data| {
                    data.as_ptr().cast::<c_char>()
                });
            (*ior).alloc_size = IO_INBAND_MAX;
        } else {
            let size = round_page(size);
            // SAFETY: the kernel map is live.
            let map = NonNull::new_unchecked(P::state().kernel_map());
            let addr =
                vm_kern::kmem_alloc(map, size).map_err(DeviceError::Vm)?;

            (*ior).data = ptr::with_exposed_provenance_mut::<c_char>(addr);
            (*ior).alloc_size = size;
        }

        Ok(())
    }
}

/// Completes a read and replies with the data.
///
/// # Safety
///
/// `ior` must be the live read request `device_read()` or
/// `device_read_inband()` queued.
///
/// # Panics
///
/// When the read data cannot be copied out of the kernel map.
pub unsafe fn ds_read_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    unsafe {
        let inband = (*ior).op.contains(IoOp::INBAND);
        let size_read = if (*ior).error.is_err() {
            0
        } else {
            (*ior).count.wrapping_sub((*ior).residual) as VmSize
        };

        let start_data = (*ior).data.addr();
        let end_data = start_data.wrapping_add(size_read);
        let start_sent = if inband {
            start_data
        } else {
            trunc_page(start_data)
        };
        let end_sent = if inband {
            start_data.wrapping_add((*ior).alloc_size)
        } else {
            round_page(end_data)
        };

        if start_sent < start_data {
            ptr::write_bytes(
                start_sent as *mut u8,
                0,
                start_data - start_sent,
            );
        }
        if end_sent > end_data {
            ptr::write_bytes(end_data as *mut u8, 0, end_sent - end_data);
        }

        let mut touch = start_sent;
        while touch < end_sent {
            let byte = ptr::read_volatile(touch as *const u8);
            ptr::write_volatile(touch as *mut u8, byte);
            touch = touch.wrapping_add(PAGE_SIZE);
        }

        if inband {
            let _ = P::send(Message::ReadReply {
                reply_port: (*ior).reply_port,
                reply_port_type: (*ior).reply_port_type,
                inband: true,
                result: (*ior).error,
                data: (*ior).data,
                data_count: size_read as c_uint,
            });
        } else {
            let copy = (*P::state().kernel_map())
                .copyin_page_list(start_data, size_read, true, true, false)
                .map_or_else(
                    |_| panic!("read_done: vm_map_copyin_page_list failed"),
                    |copy| copy.map_or(ptr::null_mut(), NonNull::as_ptr),
                );

            let _ = P::send(Message::ReadReply {
                reply_port: (*ior).reply_port,
                reply_port_type: (*ior).reply_port_type,
                inband: false,
                result: (*ior).error,
                data: copy.cast::<c_char>(),
                data_count: size_read as c_uint,
            });
        }

        if (*ior).count != 0 {
            if inband {
                if (*ior).alloc_size > 0
                    && let Some(data) = NonNull::new((*ior).data.cast::<u8>())
                {
                    P::device_cache_free(DeviceCache::IoInband, data);
                }
            } else {
                let end_alloc =
                    start_sent.wrapping_add(round_page((*ior).alloc_size));
                if end_alloc > end_sent {
                    // SAFETY: the kernel map is live, and the
                    // request still owns the range.
                    let _ = vm_user::deallocate(
                        &mut *P::state().kernel_map(),
                        end_sent,
                        end_alloc - end_sent,
                    );
                }
            }
        }

        dev_lookup::deallocate((*ior).device.cast::<MachDevice<P>>());
    }

    true
}

/// Applies a status flavor to the device through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device.
unsafe fn device_set_status<P: Platform>(
    dev: *mut c_void,
    flavor: c_uint,
    status: *mut c_int,
    status_count: c_uint,
) -> Result<(), DeviceError> {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        let d_setstat = (*(*device).dev_ops).d_setstat;
        d_setstat.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |d_setstat| {
                d_setstat(
                    driver_unit((*device).dev_number),
                    flavor,
                    status,
                    status_count,
                )
            },
        )
    }
}

/// Reports a status flavor of the device through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device.
unsafe fn mach_device_get_status<P: Platform>(
    dev: *mut c_void,
    flavor: c_uint,
    status: *mut c_int,
    status_count: *mut c_uint,
) -> Result<(), DeviceError> {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        let d_getstat = (*(*device).dev_ops).d_getstat;
        d_getstat.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |d_getstat| {
                d_getstat(
                    driver_unit((*device).dev_number),
                    flavor,
                    status,
                    status_count,
                )
            },
        )
    }
}

/// Installs a packet filter on the device through its driver.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `filter`
/// readable for `filter_count` entries.
unsafe fn device_set_filter<P: Platform>(
    dev: *mut c_void,
    receive_port: *mut c_void,
    priority: c_int,
    filter: *mut c_ushort,
    filter_count: c_uint,
) -> Result<(), DeviceError> {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        if IpcPort::valid(receive_port).is_none() {
            return Err(DeviceError::InvalidOperation);
        }

        let d_async_in = (*(*device).dev_ops).d_async_in;
        d_async_in.map_or_else(
            || Err(DeviceError::InvalidOperation),
            |d_async_in| {
                d_async_in(
                    driver_unit((*device).dev_number),
                    receive_port,
                    priority,
                    filter,
                    filter_count,
                )
            },
        )
    }
}

/// Makes the device pager for a mapping of the device.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `pager`
/// writable.
unsafe fn device_map<P: Platform>(
    dev: *mut c_void,
    protection: c_int,
    offset: VmOffset,
    // The size of the mapping is not kept, so the pager setup does not take
    // it.
    _size: VmSize,
    pager: *mut *mut c_void,
    _unmap: c_int,
) -> Result<(), DeviceError> {
    let device = dev.cast::<MachDevice<P>>();
    unsafe {
        if protection & !VmProt::ALL.bits() != 0 {
            return Err(DeviceError::InvalidArgument);
        }

        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        let port = crate::dev_pager::setup(device, protection, offset)?;
        *pager = port.as_ptr();
        Ok(())
    }
}

/// Reports a no-senders notification on a device port, which needs nothing
/// else.
///
/// # Safety
///
/// `notification` must be a live no-senders notification.
unsafe fn ds_no_senders<P: Platform>(notification: *mut c_void) {
    let notification = notification.cast::<NoSendersNotification>();
    unsafe {
        P::print(format_args!(
            "ds_no_senders called! device_port=0x{:x} count={}\n",
            (*notification).header.remote(),
            (*notification).not_count,
        ));
    }
}

/// Completes `ior`: wakes its waiter, or queues it for the I/O-done thread to
/// call its done routine.
///
/// # Safety
///
/// `ior` must be a live request whose completion path is not already running.
pub unsafe fn iodone<P: Platform>(ior: *mut IoReq<P>) {
    unsafe {
        if (*ior).op.contains(IoOp::LOANED) {
            if let Some(done) = (*ior).done {
                done(ior);
            }
            return;
        }

        if (*ior).op.contains(IoOp::CALL) {
            (*ior).op |= IoOp::DONE;
            let _guard = P::device_state().io_done_lock.lock();
            io_done_list::<P>().push_back_ptr(NonNull::new_unchecked(ior));
            thread_wakeup_prim::<P>(io_done_event::<P>(), 0, THREAD_AWAKENED);
        } else {
            (*ior).lock.lock();
            (*ior).op |= IoOp::DONE;
            (*ior).op &= !IoOp::WANTED;
            (*ior).lock.unlock();
            thread_wakeup_prim::<P>(ior.cast::<c_void>(), 0, THREAD_AWAKENED);
        }
    }
}

/// The I/O-done thread's loop: calls the done routine of every completed
/// request.
unsafe extern "C" fn io_done_thread_continue<P: Platform>() {
    loop {
        loop {
            let guard = P::device_state().io_done_lock.lock();
            // SAFETY: the list is this module's static and the lock is held.
            let popped = unsafe { io_done_list::<P>() }.pop_front();
            match popped {
                None => {
                    // SAFETY: the event is the list head every wakeup names,
                    // and the lock is held.
                    unsafe {
                        assert_wait::<P>(
                            NonNull::new(io_done_event::<P>()),
                            0,
                        );
                    }
                    drop(guard);
                    break;
                }
                Some(entry) => {
                    drop(guard);
                    let ior = ptr::from_mut(entry);
                    // SAFETY: every list entry is a live request.
                    let finished =
                        unsafe { (*ior).done.is_none_or(|done| done(ior)) };
                    if finished {
                        // SAFETY: the completion released the request.
                        unsafe { io_req_free(ior) };
                    }
                }
            }
        }
        unsafe { thread_block::<P>(Some(io_done_thread_continue::<P>)) };
    }
}

/// Starts the I/O-done thread.
///
/// # Safety
///
/// Runs only as the io-done kernel thread.
pub unsafe extern "C" fn io_done_thread<P: Platform>() {
    // SAFETY: the running thread is the io-done thread.
    unsafe {
        let thread = P::cpu_thread();
        (*thread).vm_privilege = 1;
        (*thread).stack_privilege();
        Thread::<P>::set_own_priority(0);

        io_done_thread_continue::<P>();
    }
}

/// The port the device service answers on, published by [`init`] before any
/// device open can race it.
static MASTER_DEVICE_PORT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The master device port, or null before [`init`] runs.
///
/// The load is `Acquire` to see the port the `Release` store published.
pub fn master_device_port() -> *mut c_void {
    MASTER_DEVICE_PORT.load(Ordering::Acquire)
}

/// Creates the master device port and sets up the device service: the
/// device I/O map, the in-band and trap-path caches, the device lookup and
/// the device pager.
///
/// # Safety
///
/// Called once, by the boot sequence after the kernel's IPC space exists, and
/// never concurrently with a device open.
///
/// # Panics
///
/// When the master device port or the device I/O map cannot be allocated.
pub unsafe fn init<P: Platform>() {
    // SAFETY: the kernel space is the global `ipc_init()` built earlier in
    // the boot; the allocator only reads it and takes its own locks.
    let master = unsafe { ipc_port::alloc_special::<P>(ipc_space::kernel()) };
    let port = master.map_or(ptr::null_mut(), IpcPort::as_ptr);
    // The `Release` store publishes the initialized port to the CPUs that
    // compare an incoming open port against it.
    MASTER_DEVICE_PORT.store(port, Ordering::Release);
    assert!(master.is_some(), "can't allocate master device port");

    // SAFETY: the map storage is this module's static and the kernel map is
    // the live boot map.
    unsafe {
        vm_kern::kmem_submap(
            &mut *device_io_map::<P>(),
            NonNull::new_unchecked(P::state().kernel_map()),
            DEVICE_IO_MAP_SIZE,
        )
        .unwrap_or_else(|_| panic!("kmem_submap"));
    }

    // SAFETY: this boot step is the map's only writer.
    unsafe {
        (*device_io_map::<P>()).flags |= MapFlags::WAIT_FOR_SPACE;
    }

    // SAFETY: the caches are this module's statics, unshared during boot.
    unsafe {
        P::device_cache_init(
            DeviceCache::IoInband,
            b"io_buf_ptr_inband",
            IO_INBAND_MAX,
        );
        P::device_cache_init(DeviceCache::IoTrap, b"io_req", IOTRAP_REQSIZE);
    }

    // SAFETY: the two initializers build separate module state, once, before
    // any device is opened.
    unsafe {
        dev_lookup::init::<P>();
        crate::dev_pager::init::<P>();
    }
}

/// Allocates a request block for the trap path.
///
/// Returns a recycled cache slot, or null: the caller writes the request
/// whole over it, with the loaned data right after it.
///
/// # Safety
///
/// The trap-path cache must be set up.
unsafe fn ds_trap_req_alloc<P: Platform>(
    _device: *mut MachDevice<P>,
    _data_size: VmSize,
) -> *mut IoReq<P> {
    unsafe { P::device_cache_alloc(DeviceCache::IoTrap) }
        .map_or(ptr::null_mut(), |block| block.as_ptr().cast::<IoReq<P>>())
}

/// Completes a trap-path write: drops the device reference and frees the
/// block.
///
/// # Safety
///
/// `ior` must be the live trap request [`device_write_trap()`] built.
unsafe fn ds_trap_write_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    unsafe {
        let dev = (*ior).device;

        if let Some(block) = NonNull::new(ior.cast::<u8>()) {
            P::device_cache_free(DeviceCache::IoTrap, block);
        }
        dev_lookup::deallocate(dev.cast::<MachDevice<P>>());
    }

    true
}

/// Writes a user buffer to the device as a trap, through its driver.
///
/// # Safety
///
/// `device` must be the emulation data of a live mach device, and `data`
/// readable for `data_count` bytes of user memory.
unsafe fn device_write_trap<P: Platform>(
    device: *mut c_void,
    mode: c_uint,
    recnum: c_ulong,
    data: c_ulong,
    data_count: c_ulong,
) -> ReplyResult {
    let device = device.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        if data_count > iotrap_data_max::<P>() as c_ulong {
            return Err(DeviceError::InvalidSize);
        }

        let ior = ds_trap_req_alloc(device, data_count as VmSize);
        if ior.is_null() {
            return Err(DeviceError::NoMemory);
        }
        ior.write(IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::WRITE | IoOp::CALL | IoOp::LOANED,
            mode: DeviceMode::from_bits_retain(mode),
            recnum,
            data: ior.cast::<u8>().add(size_of::<IoReq<P>>()).cast::<c_char>(),
            count: data_count as c_long,
            total: data_count as c_long,
            done: Some(ds_trap_write_done),
            ..IoReq::<P>::new()
        });

        if data_count > 0 {
            let _ = P::copyin(
                ptr::with_exposed_provenance::<c_void>(data as usize),
                (*ior).data.cast::<c_void>(),
                data_count as usize,
            );
        }

        dev_lookup::reference(device);

        let d_write = (*(*device).dev_ops).d_write;
        let result = d_write.map_or(Ok(DeviceSuccess::Success), |d_write| {
            d_write(driver_unit((*device).dev_number), ior)
        });

        if result == Ok(DeviceSuccess::IoQueued) {
            return Ok(Reply::Withheld);
        }

        dev_lookup::deallocate(device);

        if let Some(block) = NonNull::new(ior.cast::<u8>()) {
            P::device_cache_free(DeviceCache::IoTrap, block);
        }
        result.map(|_| Reply::Now)
    }
}

/// Writes user segments to the device as a trap, through its driver.
///
/// # Safety
///
/// `device` must be the emulation data of a live mach device, and `iovec`
/// readable for `iocount` user-space entries.
unsafe fn device_writev_trap<P: Platform>(
    device: *mut c_void,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut RpcIoBufVec,
    iocount: c_ulong,
) -> ReplyResult {
    let device = device.cast::<MachDevice<P>>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice);
        }

        if iocount > MAX_IOVECS as c_ulong {
            return Err(DeviceError::InvalidValue);
        }
        let iocount = iocount as usize;

        let mut stack_iovec = [IoBufVec { data: 0, count: 0 }; MAX_IOVECS];
        let mut data_count: VmSize = 0;
        for (i, slot) in stack_iovec.iter_mut().enumerate().take(iocount) {
            let mut riov = RpcIoBufVec { data: 0, count: 0 };
            let kr = P::copyin(
                iovec.add(i).cast::<c_void>(),
                ptr::addr_of_mut!(riov).cast::<c_void>(),
                size_of::<RpcIoBufVec>(),
            );
            if kr.is_err() {
                return Err(DeviceError::InvalidArgument);
            }
            *slot = IoBufVec {
                data: riov.data as VmOffset,
                count: riov.count as VmSize,
            };
            data_count = match data_count.checked_add(slot.count) {
                Some(total) if total <= iotrap_data_max::<P>() => total,
                _ => return Err(DeviceError::InvalidSize),
            };
        }

        let ior = ds_trap_req_alloc(device, data_count);
        if ior.is_null() {
            return Err(DeviceError::NoMemory);
        }
        ior.write(IoReq::<P> {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IoOp::WRITE | IoOp::CALL | IoOp::LOANED,
            mode: DeviceMode::from_bits_retain(mode),
            recnum,
            data: ior.cast::<u8>().add(size_of::<IoReq<P>>()).cast::<c_char>(),
            count: data_count as c_long,
            total: data_count as c_long,
            done: Some(ds_trap_write_done),
            ..IoReq::<P>::new()
        });

        if data_count > 0 {
            let mut p = (*ior).data;
            for iovec in stack_iovec.iter().take(iocount) {
                let _ = P::copyin(
                    ptr::with_exposed_provenance::<c_void>(iovec.data),
                    p.cast::<c_void>(),
                    iovec.count,
                );
                p = p.add(iovec.count);
            }
        }

        dev_lookup::reference(device);

        let d_write = (*(*device).dev_ops).d_write;
        let result = d_write.map_or(Ok(DeviceSuccess::Success), |d_write| {
            d_write(driver_unit((*device).dev_number), ior)
        });

        if result == Ok(DeviceSuccess::IoQueued) {
            return Ok(Reply::Withheld);
        }

        dev_lookup::deallocate(device);

        if let Some(block) = NonNull::new(ior.cast::<u8>()) {
            P::device_cache_free(DeviceCache::IoTrap, block);
        }
        result.map(|_| Reply::Now)
    }
}
