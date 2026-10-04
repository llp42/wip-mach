// SPDX-License-Identifier: CMU-Mach
// Derived from device/ds_routines.c:
//   Copyright (c) 1993,1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1996 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The native Mach device service, which `device/ds_routines.c` used to
//! define and <`device/ds_routines.h`> declares.
//!
//! The `ds_device_*` entry points, the emulation dispatch, the device
//! open/close/read/write paths, the request completion callbacks and the
//! io-done thread all live here; [`ds_routines_ffi`] keeps only the
//! `device_deallocate` export the generated C names.
//!
//! [`ds_routines_ffi`]: crate::device::ds_routines_ffi

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::io_req::{DevT, IoReq, IoReqQueue};
use crate::arch::x86_64::irq;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::spl;
use crate::arch::x86_64::user_access;
use crate::config::NINTR;
use crate::device::dev_lookup;
use crate::device::r#return::{DeviceError, IoResultExt};
use crate::glue;
use crate::ipc::ipc_port_ffi;
use crate::ipc::{IpcPort, MachMsgHeader, ipc_object, ipc_port, ipc_space};
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::debug::soft_debugger;
use crate::kern::kheap::Kalloc;
use crate::kern::lock::SimpleLock;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_sleep,
    thread_wakeup_prim,
};
use crate::kern::slab::{
    KmemCache, kmem_cache_alloc, kmem_cache_free, kmem_cache_init,
};
use crate::kern::thread::Thread;
use crate::utils::cell::SyncCell;
use crate::vm::types::VmProt;
use crate::vm::vm_kern::{self, KERNEL_MAP};
use crate::vm::vm_map::{
    VM_MAP_WAIT_FOR_SPACE, VmMap, VmMapCopy, round_page, trunc_page,
};
use crate::vm::vm_user;
use collections::list;
use core::cell::UnsafeCell;
use core::ffi::{
    c_char, c_int, c_long, c_short, c_uint, c_ulong, c_ushort, c_void,
};
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use kmem::KBox;
use spin::Mutex;

/// `DEV_STATE_INIT` of <`device/dev_hdr.h`>.
const DEV_STATE_INIT: c_short = 0;
/// `DEV_STATE_OPENING`.
const DEV_STATE_OPENING: c_short = 1;
/// `DEV_STATE_OPEN`.
const DEV_STATE_OPEN: c_short = 2;
/// `DEV_STATE_CLOSING`.
const DEV_STATE_CLOSING: c_short = 3;

/// `D_EXCL_OPEN` of <`device/dev_hdr.h`>.
const D_EXCL_OPEN: c_short = 0x0001;

/// `IO_WRITE` of <`device/io_req.h`>.
const IO_WRITE: c_int = 0x0000_0000;
/// `IO_READ`.
const IO_READ: c_int = 0x0000_0001;
/// `IO_OPEN`.
const IO_OPEN: c_int = 0x0000_0002;
/// `IO_DONE`.
const IO_DONE: c_int = 0x0000_0100;
/// `IO_WANTED`.
const IO_WANTED: c_int = 0x0000_0800;
/// `IO_CALL`.
const IO_CALL: c_int = 0x0000_2000;
/// `IO_INBAND` of <`device/io_req.h`>.
const IO_INBAND: c_int = 0x0000_4000;
/// `IO_LOANED`.
const IO_LOANED: c_int = 0x0001_0000;

/// `D_SUCCESS` of <`device/device_types.h`>.
const D_SUCCESS: c_int = 0;
/// `D_IO_QUEUED` of <`device/device_types.h`>.
const D_IO_QUEUED: c_int = -1;
/// `MIG_NO_REPLY` of <`mach/mig_errors.h`>.
pub(crate) const MIG_NO_REPLY: c_int = -305;
/// `KERN_SUCCESS`.
pub(crate) const KERN_SUCCESS: c_int = 0;
/// `KERN_INVALID_ARGUMENT`.
const KERN_INVALID_ARGUMENT: c_int = 4;
/// `KERN_FAILURE`.
const KERN_FAILURE: c_int = 5;
/// `KERN_RESOURCE_SHORTAGE`.
const KERN_RESOURCE_SHORTAGE: c_int = 6;
/// `KERN_INVALID_VALUE`.
const KERN_INVALID_VALUE: c_int = 18;
/// `D_INFO_BLOCK_SIZE` of <device/conf.h>.
const D_INFO_BLOCK_SIZE: c_int = 1;
/// `IO_INBAND_MAX` of <`device/device_types.h`>.
const IO_INBAND_MAX: usize = 128;
/// `MACH_NOTIFY_NO_SENDERS` of <mach/notify.h>.
const MACH_NOTIFY_NO_SENDERS: c_int = 0o106;
/// `DEVICE_IO_MAP_SIZE` of `device/ds_routines.c`.
const DEVICE_IO_MAP_SIZE: VmSize = 16 * 1024 * 1024;
/// `IOTRAP_REQSIZE` of `device/ds_routines.c`.
const IOTRAP_REQSIZE: usize = 2048;
/// The most loaned data a trap request carries after itself in its
/// [`IOTRAP_REQSIZE`] cache slot; the C never checked it.
const IOTRAP_DATA_MAX: usize = IOTRAP_REQSIZE - size_of::<IoReq>();
/// The `stack_iovec[16]` bound of `device_writev_trap()`.
const MAX_IOVECS: usize = 16;

/// `struct device` of <`device/dev_hdr.h>`: the emulation handle embedded at
/// the end of a [`MachDevice`].
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

/// `struct mach_device` of <`device/dev_hdr.h>`: one open device record.
///
/// The mirror keeps every field of the C record; the device-lookup paths in
/// C still read `ref_count` and `number_chain`, and this module reads only the
/// fields the open/close/IO paths touch.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachDevice {
    pub ref_lock: SimpleLock,
    pub ref_count: c_int,
    pub lock: SimpleLock,
    pub state: c_short,
    pub flag: c_short,
    pub open_count: c_short,
    pub io_in_progress: c_short,
    pub io_wait: c_int,
    pub port: *mut c_void,
    pub number_chain: list::Link,
    pub dev_number: c_int,
    pub bsize: c_int,
    pub dev_ops: *mut DevOps,
    pub dev: Device,
}

const _: () = {
    assert!(size_of::<MachDevice>() == 80);
    assert!(align_of::<MachDevice>() == 8);
    assert!(offset_of!(MachDevice, ref_lock) == 0);
    assert!(offset_of!(MachDevice, ref_count) == 4);
    assert!(offset_of!(MachDevice, lock) == 8);
    assert!(offset_of!(MachDevice, state) == 12);
    assert!(offset_of!(MachDevice, flag) == 14);
    assert!(offset_of!(MachDevice, open_count) == 16);
    assert!(offset_of!(MachDevice, io_in_progress) == 18);
    assert!(offset_of!(MachDevice, io_wait) == 20);
    assert!(offset_of!(MachDevice, port) == 24);
    assert!(offset_of!(MachDevice, number_chain) == 32);
    assert!(offset_of!(MachDevice, dev_number) == 48);
    assert!(offset_of!(MachDevice, bsize) == 52);
    assert!(offset_of!(MachDevice, dev_ops) == 56);
    assert!(offset_of!(MachDevice, dev) == 64);
};

list::adapter!(
    /// The adapter for a device's `number_chain` in the device-number hash
    /// table.
    pub MachDeviceNumberAdapter = MachDevice { number_chain }
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
type DevAsyncIn =
    unsafe fn(DevT, *mut c_void, c_int, *mut c_ushort, c_uint) -> c_int;
/// The signature of a driver's `d_getstat` hook: read one status
/// flavor.
///
/// [`mach_device_get_status()`] invokes it for an open device, with
/// `status` writable for the words the caller reserved and
/// `status_count` writable for the count the driver actually fills in;
/// the driver must not assume any device lock is held.
type DevGetstat = unsafe fn(DevT, c_uint, *mut c_int, *mut c_uint) -> c_int;
/// The signature of a driver's `d_setstat` hook: write one status
/// flavor.
///
/// [`device_set_status()`] invokes it for an open device, with `status`
/// readable for `status_count` words; the driver must not assume any
/// device lock is held.
type DevSetstat = unsafe fn(DevT, c_uint, *mut c_int, c_uint) -> c_int;

/// `struct dev_ops` of <device/conf.h>: one driver's entry points.
///
/// The mirror keeps every field; this module dispatches through `d_open`,
/// `d_close`, `d_read`, `d_write`, `d_getstat`, `d_setstat`, `d_async_in` and
/// `d_dev_info` only.
#[repr(C)]
#[allow(missing_docs)]
pub struct DevOps {
    pub d_name: *mut c_char,
    /// Opens the device for I/O.
    ///
    /// [`device_open()`] invokes it with the device in
    /// [`DEV_STATE_OPENING`] and no device lock held, and `ior` a
    /// freshly built request whose `done` is [`ds_open_done()`]. The
    /// driver may finish the open synchronously in the return value, or
    /// return `D_IO_QUEUED` and call `(*ior).done` itself once the open
    /// completes, from any context.
    pub d_open: Option<unsafe fn(DevT, c_int, *mut IoReq) -> c_int>,
    /// Closes the device.
    ///
    /// [`device_close()`] invokes it once the last open reference drops,
    /// with the device in [`DEV_STATE_CLOSING`] and no device lock held.
    /// The driver must finish synchronously; there is no request to
    /// signal completion through.
    pub d_close: Option<unsafe fn(DevT, c_int)>,
    /// Reads from the device.
    ///
    /// [`device_read()`] and [`device_read_inband()`] invoke it for an
    /// open device, with no device lock held and `ior` a freshly built
    /// request whose `done` is [`ds_read_done()`]. The driver may
    /// complete synchronously in the return value, or return
    /// `D_IO_QUEUED` and call `(*ior).done` itself once the data is
    /// ready, from any context.
    pub d_read: Option<unsafe fn(DevT, *mut IoReq) -> c_int>,
    /// Writes to the device.
    ///
    /// [`device_write()`] and [`device_write_inband()`] invoke it for an
    /// open device, with no device lock held and `ior` a request whose
    /// `done` is [`ds_write_done()`]; [`ds_write_done()`] itself calls
    /// back in to retry a request the driver had queued. The driver may
    /// complete synchronously in the return value, or return
    /// `D_IO_QUEUED` and call `(*ior).done` itself once the write
    /// completes, from any context.
    pub d_write: Option<unsafe fn(DevT, *mut IoReq) -> c_int>,
    pub d_getstat: Option<DevGetstat>,
    pub d_setstat: Option<DevSetstat>,
    /// Translates an mmap offset into the device to a physical page
    /// number.
    ///
    /// [`crate::device::dev_pager::device_map_page()`] invokes it from
    /// the page-fault path with the page-aligned offset into the device
    /// and the mapping's protection; it must return synchronously,
    /// without blocking, and answer `VmOffset::MAX` for an offset the
    /// device does not back.
    pub d_mmap: Option<unsafe fn(DevT, VmOffset, c_int) -> VmOffset>,
    pub d_async_in: Option<DevAsyncIn>,
    /// Resets the device to a known state.
    ///
    /// Called with no device lock held and no live request to signal
    /// completion through; the driver must finish synchronously.
    pub d_reset: Option<unsafe fn(DevT) -> c_int>,
    /// Notifies the driver that a port tied to one of its requests
    /// (an open reply port, or a `d_async_in` receive port) has died.
    ///
    /// `port` is that dead port, cast to a [`VmOffset`]; the driver
    /// drops whatever it associated with it, such as queued requests
    /// waiting to reply through it.
    pub d_port_death: Option<unsafe fn(DevT, VmOffset) -> c_int>,
    pub d_subdev: c_int,
    /// Reads one `D_INFO_*` info flavor into `*data`.
    ///
    /// [`device_write_dealloc()`] invokes it with
    /// [`D_INFO_BLOCK_SIZE`] to recover the device's block size when a
    /// write continuation needs to advance `recnum`; called with no
    /// device lock held.
    pub d_dev_info: Option<unsafe fn(DevT, c_int, *mut c_int) -> c_int>,
}

const _: () = {
    assert!(size_of::<DevOps>() == 104);
    assert!(align_of::<DevOps>() == 8);
    assert!(offset_of!(DevOps, d_name) == 0);
    assert!(offset_of!(DevOps, d_open) == 8);
    assert!(offset_of!(DevOps, d_close) == 16);
    assert!(offset_of!(DevOps, d_read) == 24);
    assert!(offset_of!(DevOps, d_write) == 32);
    assert!(offset_of!(DevOps, d_getstat) == 40);
    assert!(offset_of!(DevOps, d_setstat) == 48);
    assert!(offset_of!(DevOps, d_mmap) == 56);
    assert!(offset_of!(DevOps, d_async_in) == 64);
    assert!(offset_of!(DevOps, d_reset) == 72);
    assert!(offset_of!(DevOps, d_port_death) == 80);
    assert!(offset_of!(DevOps, d_subdev) == 88);
    assert!(offset_of!(DevOps, d_dev_info) == 96);
};

/// The signature of a `device_emulation_ops::open` hook.
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
) -> c_int;
/// The signature of a `device_emulation_ops::write` hook.
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
) -> c_int;
/// The signature of a `device_emulation_ops::write_inband` hook.
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
) -> c_int;
/// The signature of a `device_emulation_ops::read` hook.
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
) -> c_int;
/// The signature of a `device_emulation_ops::read_inband` hook.
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
) -> c_int;
/// The signature of a `device_emulation_ops::set_status` hook.
///
/// [`ds_device_set_status()`] invokes it with the emulation data, the
/// status flavor, and `status` readable for `status_count` words.
type EmulSetStatus =
    unsafe fn(*mut c_void, c_uint, *mut c_int, c_uint) -> c_int;
/// The signature of a `device_emulation_ops::get_status` hook.
///
/// [`ds_device_get_status()`] invokes it with the emulation data, the
/// status flavor, `status` writable for the words the caller reserved,
/// and a writable out-param for the count the callee actually filled
/// in.
type EmulGetStatus =
    unsafe fn(*mut c_void, c_uint, *mut c_int, *mut c_uint) -> c_int;
/// The signature of a `device_emulation_ops::set_filter` hook.
///
/// [`ds_device_set_filter()`] invokes it with the emulation data, a
/// valid `receive_port`, the filter priority, and `filter` readable for
/// `filter_count` entries.
type EmulSetFilter =
    unsafe fn(*mut c_void, *mut c_void, c_int, *mut c_ushort, c_uint) -> c_int;
/// The signature of a `device_emulation_ops::map` hook.
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
) -> c_int;
/// The signature of a `device_emulation_ops::write_trap` hook.
///
/// [`ds_device_write_trap()`] invokes it with the emulation data, the
/// mode, record number, and the `data`/`count` words exactly as the
/// `device_write_trap` system call passed them straight from user
/// registers; the callee must validate them itself before touching user
/// memory.
type EmulWriteTrap =
    unsafe fn(*mut c_void, c_uint, c_ulong, c_ulong, c_ulong) -> c_int;
/// The signature of a `device_emulation_ops::writev_trap` hook.
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
) -> c_int;

/// `struct device_emulation_ops` of <`device/device_emul.h>`: the operations
/// one emulation layer provides.
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
    pub close: Option<unsafe fn(*mut c_void) -> c_int>,
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

/// `mach_no_senders_notification_t` of <mach/notify.h>: the notification
/// `ds_notify()` handles.
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

/// `io_buf_vec_t` of <`device/device_types.h>`: one scatter/gather segment of
/// kernel addresses.
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

/// `rpc_io_buf_vec_t` of <`device/device_types.h>`: one scatter/gather segment
/// of user addresses, as MIG passes them.
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

/// `emulation_list[]` of `device/ds_routines.c`: the emulations
/// [`ds_device_open()`] tries in order.
static mut EMULATION_LIST: [*mut DeviceEmulationOps; 1] =
    [&raw mut MACH_DEVICE_EMULATION_OPS];

/// `device_io_map_store` of `device/ds_routines.c`: the storage of the map
/// every device IO buffer is mapped through.
static mut DEVICE_IO_MAP_STORE: VmMap = VmMap::zeroed();

/// `device_io_map` of <`device/ds_routines.h`>.
pub static mut DEVICE_IO_MAP: *mut VmMap = &raw mut DEVICE_IO_MAP_STORE;

/// `io_inband_cache` of <`device/io_req.h>`: the cache for inband read
/// buffers.
static mut IO_INBAND_CACHE: KmemCache = KmemCache::zeroed();

/// `io_trap_cache` of `device/ds_routines.c`: the cache for the trap path's
/// `io_req` blocks.
static mut IO_TRAP_CACHE: KmemCache = KmemCache::zeroed();

/// `io_done_list` of <`device/ds_routines.h>`: the requests the io-done thread
/// still has to complete.
static IO_DONE_LIST: SyncCell<IoReqQueue> =
    SyncCell(UnsafeCell::new(IoReqQueue::new()));

/// The io-done list's address, the event every wakeup of the io-done thread
/// names.
fn io_done_event() -> *mut c_void {
    IO_DONE_LIST.0.get().cast()
}

/// The live io-done list head.
///
/// # Safety
///
/// The caller must hold `IO_DONE_LIST_LOCK` for as long as it uses the list.
unsafe fn io_done_list() -> Pin<&'static mut IoReqQueue> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the list.
    unsafe { Pin::new_unchecked(&mut *IO_DONE_LIST.0.get()) }
}

/// `io_done_list_lock` of `device/ds_routines.c`.  The C held it at
/// `splhigh()`; the callers keep that interrupt level.
static IO_DONE_LIST_LOCK: Mutex<()> = Mutex::new(());

/// `mach_device_emulation_ops` of `device/ds_routines.c`: the native Mach
/// device emulation every device lookup installs.
pub(crate) static mut MACH_DEVICE_EMULATION_OPS: DeviceEmulationOps =
    DeviceEmulationOps {
        reference: Some(dev_lookup::mach_device_reference),
        dealloc: Some(dev_lookup::mach_device_deallocate),
        dev_to_port: Some(mach_convert_device_to_port),
        open: Some(device_open),
        close: Some(device_close),
        write: Some(device_write),
        write_inband: Some(device_write_inband),
        read: Some(device_read),
        read_inband: Some(device_read_inband),
        set_status: Some(device_set_status),
        get_status: Some(mach_device_get_status),
        set_filter: Some(device_set_filter),
        map: Some(device_map),
        no_senders: Some(ds_no_senders),
        write_trap: Some(device_write_trap),
        writev_trap: Some(device_writev_trap),
    };

/// The C's implicit `int` to `dev_t` truncation at every driver call; a
/// device number comes from the device table and fits in sixteen bits.
pub(crate) const fn driver_unit(dev_number: c_int) -> DevT {
    dev_number as DevT
}

/// The C's implicit `unsigned int` to `long` conversion of an IO byte count.
const fn io_count(count: c_uint) -> c_long {
    count as c_long
}

/// `io_req_alloc` of <`device/io_req.h`>: moves `ior` into a fresh heap
/// block, or returns `None` when the heap is exhausted, where the C
/// dereferenced the null pointer.
fn io_req_alloc(ior: IoReq) -> Option<KBox<IoReq, Kalloc>> {
    KBox::try_new(ior, Kalloc).ok()
}

/// `io_req_free` of <`device/io_req.h`>.
///
/// # Safety
///
/// `ior` must be a request [`io_req_alloc()`] built, released with
/// [`KBox::into_raw`], that nothing uses.
unsafe fn io_req_free(ior: *mut IoReq) {
    drop(unsafe { KBox::from_raw(ior, Kalloc) });
}

/// `ds_device_open()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `open_port` is the master device port, `reply_port` is a valid port or
/// `IP_NULL`, `name` is a NUL-terminated device name, and `devp` is writable.
pub(crate) unsafe fn ds_device_open(
    open_port: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    name: *const c_char,
    devp: *mut *mut c_void,
) -> c_int {
    if open_port != crate::device::device_init::master_device_port() {
        return Err(DeviceError::InvalidOperation).as_io_return();
    }

    if IpcPort::valid(reply_port).is_none() {
        kprint!("ds_* invalid reply port\n");
        // SAFETY: the literal argument is NUL-terminated.
        unsafe { soft_debugger(c"ds_* reply_port".as_ptr()) };
        return MIG_NO_REPLY;
    }

    // SAFETY: the list is this module's one-entry static, and its entry is the
    // address of the live ops table.
    let ops = unsafe {
        *ptr::addr_of!(EMULATION_LIST).cast::<*mut DeviceEmulationOps>()
    };
    // SAFETY: the emulation registered a real open with the C signature.
    unsafe { (*ops).open }.map_or(D_SUCCESS, |open| unsafe {
        open(reply_port, reply_port_type, mode, name, devp)
    })
}

/// `ds_device_close()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub(crate) unsafe fn ds_device_close(dev: NonNull<c_void>) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops)
            .close
            .map_or(D_SUCCESS, |close| close((*dev).emul_data))
    }
}

/// `ds_device_write()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `data` readable for `count` bytes,
/// and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn ds_device_write(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: NonNull<c_char>,
    count: c_uint,
    bytes_written: *mut c_int,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).write.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `ds_device_write_inband()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `data` readable for `count` bytes,
/// and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn ds_device_write_inband(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: NonNull<c_char>,
    count: c_uint,
    bytes_written: *mut c_int,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).write_inband.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `ds_device_read()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `data` and `bytes_read` must be
/// writable.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn ds_device_read(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    count: c_int,
    data: *mut *mut c_char,
    bytes_read: *mut c_uint,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).read.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `ds_device_read_inband()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `data` writable for the reply, and
/// `bytes_read` writable.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn ds_device_read_inband(
    dev: NonNull<c_void>,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    count: c_int,
    data: *mut c_char,
    bytes_read: *mut c_uint,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).read_inband.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `ds_device_set_status()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `status` readable for
/// `status_count` integers when the emulation reads it.
pub(crate) unsafe fn ds_device_set_status(
    dev: NonNull<c_void>,
    flavor: c_uint,
    status: *mut c_int,
    status_count: c_uint,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).set_status.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
            |set_status| {
                set_status((*dev).emul_data, flavor, status, status_count)
            },
        )
    }
}

/// `ds_device_get_status()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `status` writable for
/// `*status_count` integers, and `status_count` writable.
pub(crate) unsafe fn ds_device_get_status(
    dev: NonNull<c_void>,
    flavor: c_uint,
    status: *mut c_int,
    status_count: *mut c_uint,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).get_status.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
            |get_status| {
                get_status((*dev).emul_data, flavor, status, status_count)
            },
        )
    }
}

/// `ds_device_set_filter()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, `receive_port` a valid port, and
/// `filter` readable for `filter_count` entries.
pub(crate) unsafe fn ds_device_set_filter(
    dev: NonNull<c_void>,
    receive_port: *mut c_void,
    priority: c_int,
    filter: *mut c_ushort,
    filter_count: c_uint,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).set_filter.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `ds_device_map()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `pager` writable.
pub(crate) unsafe fn ds_device_map(
    dev: NonNull<c_void>,
    protection: c_int,
    offset: VmOffset,
    size: VmSize,
    pager: *mut *mut c_void,
    unmap: c_int,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).map.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
            |map| {
                map((*dev).emul_data, protection, offset, size, pager, unmap)
            },
        )
    }
}

/// `ds_device_intr_register()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device` for a mach device, and `receive_port`
/// a valid port.
pub(crate) unsafe fn ds_device_intr_register(
    dev: NonNull<c_void>,
    id: c_int,
    flags: c_int,
    receive_port: *mut c_void,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    let mdev = unsafe { (*dev).emul_data.cast::<MachDevice>() };

    if flags != 0 {
        return Err(DeviceError::InvalidOperation).as_io_return();
    }

    let same_name = unsafe {
        crate::device::dev_name::name_equal(
            (*(*mdev).dev_ops).d_name,
            3,
            c"irq".as_ptr(),
        )
    };
    if !same_name {
        return Err(DeviceError::InvalidOperation).as_io_return();
    }

    if id < 0 {
        return Err(DeviceError::InvalidOperation).as_io_return();
    }
    // The C compared the non-negative id against the NINTR-sized table.
    if id as usize >= NINTR {
        return Err(DeviceError::InvalidOperation).as_io_return();
    }

    // SAFETY: `irqtab` is the live interrupt table, and the id is inside its
    // NINTR entries.
    let Some(entry) = (unsafe {
        crate::device::intr::insert_intr_entry(
            ptr::addr_of_mut!(irq::IRQTAB),
            id,
            receive_port,
        )
    }) else {
        return Err(DeviceError::NoMemory).as_io_return();
    };

    // SAFETY: the entry belongs to the table, which serializes its use.
    match unsafe {
        crate::device::intr::install_user_intr_handler(
            ptr::addr_of_mut!(irq::IRQTAB),
            id,
            flags as c_ulong,
            entry.as_ptr(),
        )
    } {
        Ok(()) => {
            // SAFETY: the handler holds a reference to the live port from
            // here on, as the C's `ip_reference()` recorded.
            unsafe { ipc_object::reference(receive_port) };
            D_SUCCESS
        }
        Err(error) => Err(error).as_io_return(),
    }
}

/// `ds_device_intr_ack()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device` for a mach device, and `receive_port`
/// a valid port.
pub(crate) unsafe fn ds_device_intr_ack(
    dev: NonNull<c_void>,
    receive_port: *mut c_void,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    let mdev = unsafe { (*dev).emul_data.cast::<MachDevice>() };

    let same_name = unsafe {
        crate::device::dev_name::name_equal(
            (*(*mdev).dev_ops).d_name,
            3,
            c"irq".as_ptr(),
        )
    };
    if !same_name {
        return Err(DeviceError::InvalidOperation).as_io_return();
    }

    match unsafe { crate::device::intr::irq_acknowledge(receive_port) } {
        Ok(id) => {
            crate::device::intr::enable_line(id);
            // SAFETY: the acknowledge consumed the send right the
            // registration held.
            unsafe { ipc_port_ffi::ipc_port_release_send(receive_port) };
            D_SUCCESS
        }
        Err(code) => code,
    }
}

/// `ds_notify()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `msg` must be a live message whose header and no-senders body are
/// readable.
pub(crate) unsafe fn ds_notify(msg: *mut c_void) -> c_int {
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
            return c_int::from(true);
        }

        kprint!("ds_notify: strange notification {}\n", (*header).id());
    }
    c_int::from(false)
}

/// `ds_device_write_trap()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub(crate) unsafe fn ds_device_write_trap(
    dev: NonNull<c_void>,
    mode: c_uint,
    recnum: c_ulong,
    data: c_ulong,
    count: c_ulong,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).write_trap.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
            |write_trap| {
                write_trap((*dev).emul_data, mode, recnum, data, count)
            },
        )
    }
}

/// `ds_device_writev_trap()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`, and `iovec` readable for `count`
/// user-space entries.
pub(crate) unsafe fn ds_device_writev_trap(
    dev: NonNull<c_void>,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut RpcIoBufVec,
    count: c_ulong,
) -> c_int {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        (*ops).writev_trap.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
            |writev_trap| {
                writev_trap((*dev).emul_data, mode, recnum, iovec, count)
            },
        )
    }
}

/// `device_reference()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub(crate) unsafe fn device_reference(dev: NonNull<c_void>) {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        if let Some(reference) = (*ops).reference {
            reference((*dev).emul_data);
        }
    }
}

/// `device_deallocate()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be a live `struct device`.
pub(crate) unsafe fn device_deallocate(dev: NonNull<c_void>) {
    let dev = dev.as_ptr().cast::<Device>();
    unsafe {
        let ops = (*dev).emul_ops;
        if let Some(dealloc) = (*ops).dealloc {
            dealloc((*dev).emul_data);
        }
    }
}

/// `mach_convert_device_to_port()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `device` is null or a live `mach_device`.
unsafe fn mach_convert_device_to_port(device: *mut c_void) -> *mut c_void {
    if device.is_null() {
        return ptr::null_mut();
    }
    let device = device.cast::<MachDevice>();
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

/// `device_open()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `name` must be a NUL-terminated device name, and `device_p` writable.
unsafe fn device_open(
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    name: *const c_char,
    device_p: *mut *mut c_void,
) -> c_int {
    let Some(device) = (unsafe { dev_lookup::lookup(name) }) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    let device = device.as_ptr();

    // The C allocated the request after marking the device opening; failing
    // there would strand the device in that state, so the request comes
    // first and the early returns below drop it.
    // SAFETY: `lookup()` returned a live device.
    let request = unsafe {
        IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_OPEN | IO_CALL,
            mode,
            done: Some(ds_open_done),
            reply_port,
            reply_port_type,
            ..IoReq::new()
        }
    };
    let Some(ior) = io_req_alloc(request) else {
        // SAFETY: the reference is the one `lookup()` took.
        unsafe { dev_lookup::deallocate(device) };
        return Err(DeviceError::NoMemory).as_io_return();
    };

    // SAFETY: a live mach device owns its lock, and the caller promises the
    // writable handle slot.
    unsafe {
        (*device).lock.lock();
        while (*device).state == DEV_STATE_OPENING
            || (*device).state == DEV_STATE_CLOSING
        {
            (*device).io_wait = c_int::from(true);
            thread_sleep(
                device.cast::<c_void>(),
                ptr::addr_of_mut!((*device).lock),
                c_int::from(true),
            );
            (*device).lock.lock();
        }

        if (*device).state == DEV_STATE_OPEN {
            if (*device).flag & D_EXCL_OPEN != 0 {
                (*device).lock.unlock();
                dev_lookup::deallocate(device);
                return Err(DeviceError::AlreadyOpen).as_io_return();
            }

            (*device).open_count += 1;
            (*device).lock.unlock();
            device_p.write(ptr::addr_of_mut!((*device).dev).cast::<c_void>());
            return D_SUCCESS;
        }

        (*device).state = DEV_STATE_OPENING;
        (*device).lock.unlock();

        (*device).port = ipc_port::alloc_special(ipc_space::kernel())
            .map_or(ptr::null_mut(), IpcPort::as_ptr);
        if (*device).port.is_null() {
            (*device).lock.lock();
            (*device).state = DEV_STATE_INIT;
            (*device).port = ptr::null_mut();
            if (*device).io_wait != 0 {
                (*device).io_wait = c_int::from(false);
                thread_wakeup_prim(
                    device.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*device).lock.unlock();
            dev_lookup::deallocate(device);
            return KERN_RESOURCE_SHORTAGE;
        }

        dev_lookup::port_enter(device);

        let port = IpcPort::from_raw((*device).port);
        let notify = ipc_port::make_sonce(port);
        port.lock();
        ipc_port::nsrequest(port, 1, Some(notify.as_non_null()));

        let ior = KBox::into_raw(ior);
        let d_open = (*(*device).dev_ops).d_open;
        let result = d_open.map_or(D_SUCCESS, |d_open| {
            d_open(driver_unit((*device).dev_number), mode as c_int, ior)
        });
        if result == D_IO_QUEUED {
            return MIG_NO_REPLY;
        }

        (*ior).error = result;
        ds_open_done(ior);
        io_req_free(ior);
    }

    MIG_NO_REPLY
}

/// `ds_open_done()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `ior` must be the live open request [`device_open()`] built.
pub(crate) unsafe fn ds_open_done(ior: *mut IoReq) -> c_int {
    unsafe {
        let mut device = (*ior).device.cast::<MachDevice>();
        let result = (*ior).error;

        if result == D_SUCCESS {
            (*device).lock.lock();
            (*device).state = DEV_STATE_OPEN;
            (*device).open_count = 1;
            if (*device).io_wait != 0 {
                (*device).io_wait = c_int::from(false);
                thread_wakeup_prim(
                    device.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*device).lock.unlock();
        } else {
            dev_lookup::port_remove(device);
            ipc_port::dealloc_special(IpcPort::from_raw((*device).port));
            (*device).port = ptr::null_mut();

            (*device).lock.lock();
            (*device).state = DEV_STATE_INIT;
            if (*device).io_wait != 0 {
                (*device).io_wait = c_int::from(false);
                thread_wakeup_prim(
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
            glue::ds_device_open_reply(
                (*ior).reply_port,
                (*ior).reply_port_type,
                result,
                mach_convert_device_to_port(device.cast::<c_void>()),
            );
        } else if !device.is_null() {
            dev_lookup::deallocate(device);
        }
    }

    c_int::from(true)
}

/// `device_close()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device.
unsafe fn device_close(dev: *mut c_void) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        (*device).lock.lock();

        (*device).open_count -= 1;
        if (*device).open_count > 0 {
            (*device).lock.unlock();
            return D_SUCCESS;
        }

        if (*device).state == DEV_STATE_CLOSING {
            (*device).lock.unlock();
            return D_SUCCESS;
        }

        (*device).state = DEV_STATE_CLOSING;
        (*device).lock.unlock();

        dev_lookup::port_remove(device);
        ipc_port::dealloc_special(IpcPort::from_raw((*device).port));

        if let Some(d_close) = (*(*device).dev_ops).d_close {
            d_close(driver_unit((*device).dev_number), 0);
        }

        (*device).lock.lock();
        (*device).state = DEV_STATE_INIT;
        if (*device).io_wait != 0 {
            (*device).io_wait = c_int::from(false);
            thread_wakeup_prim(device.cast::<c_void>(), 0, THREAD_AWAKENED);
        }
        (*device).lock.unlock();
    }

    D_SUCCESS
}

/// `device_write()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, `data` readable
/// for `data_count` bytes, and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_write(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: *mut c_char,
    data_count: c_uint,
    bytes_written: *mut c_int,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        let Some(ior) = io_req_alloc(IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_WRITE | IO_CALL,
            mode,
            recnum,
            data,
            count: io_count(data_count),
            total: io_count(data_count),
            done: Some(ds_write_done),
            reply_port,
            reply_port_type,
            ..IoReq::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory).as_io_return();
        };

        dev_lookup::reference(device);

        let result = loop {
            let d_write = (*(*device).dev_ops).d_write;
            let result = d_write.map_or(D_SUCCESS, |d_write| {
                d_write(driver_unit((*device).dev_number), ior)
            });

            if result == D_IO_QUEUED {
                return MIG_NO_REPLY;
            }

            if device_write_dealloc(ior) != 0 {
                break result;
            }
        };

        bytes_written.write(((*ior).total - (*ior).residual) as c_int);

        dev_lookup::deallocate(device);

        io_req_free(ior);
        result
    }
}

/// `device_write_inband()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, `data` readable
/// for `data_count` bytes, and `bytes_written` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_write_inband(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: *const c_char,
    data_count: c_uint,
    bytes_written: *mut c_int,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        let Some(ior) = io_req_alloc(IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_WRITE | IO_CALL | IO_INBAND,
            mode,
            recnum,
            data: data.cast_mut(),
            count: io_count(data_count),
            total: io_count(data_count),
            done: Some(ds_write_done),
            reply_port,
            reply_port_type,
            ..IoReq::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory).as_io_return();
        };

        dev_lookup::reference(device);

        let d_write = (*(*device).dev_ops).d_write;
        let result = d_write.map_or(D_SUCCESS, |d_write| {
            d_write(driver_unit((*device).dev_number), ior)
        });

        if result == D_IO_QUEUED {
            return MIG_NO_REPLY;
        }

        bytes_written.write(((*ior).total - (*ior).residual) as c_int);

        dev_lookup::deallocate(device);

        io_req_free(ior);
        result
    }
}

/// `device_write_dealloc()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `ior` must be a live request from [`io_req_alloc()`].
pub(crate) unsafe fn device_write_dealloc(ior: *mut IoReq) -> c_int {
    unsafe {
        if (*ior).alloc_size == 0 {
            return c_int::from(true);
        }

        if (*ior).op & IO_INBAND != 0 {
            kmem_cache_free(
                ptr::addr_of_mut!(IO_INBAND_CACHE),
                (*ior).data.addr(),
            );
            return c_int::from(true);
        }

        let io_copy = (*ior).copy;
        if io_copy.is_null() {
            return c_int::from(true);
        }

        vm_kern::kmem_io_map_deallocate(
            &mut *DEVICE_IO_MAP,
            trunc_page((*ior).data.addr()),
            (*ior).alloc_size,
        );

        let mut new_copy: *mut VmMapCopy = ptr::null_mut();
        if VmMapCopy::has_cont(NonNull::new_unchecked(io_copy)) {
            let size_to_do =
                (*io_copy).size.wrapping_sub((*ior).count as VmSize);
            let result;
            if (*ior).error == 0 {
                let invoked =
                    VmMapCopy::invoke_cont(NonNull::new_unchecked(io_copy));
                result = invoked.0;
                new_copy = invoked.1;
            } else {
                VmMapCopy::abort_cont(NonNull::new_unchecked(io_copy));
                result = KERN_FAILURE;
            }

            if result == KERN_SUCCESS && !new_copy.is_null() {
                (*ior).op &= !IO_DONE;
                (*ior).op |= IO_CALL;

                let device = (*ior).device.cast::<MachDevice>();
                let mut bsize: c_int = 0;
                let d_dev_info = (*(*device).dev_ops).d_dev_info;
                let res = d_dev_info.map_or(KERN_FAILURE, |d_dev_info| {
                    d_dev_info(
                        driver_unit((*device).dev_number),
                        D_INFO_BLOCK_SIZE,
                        &raw mut bsize,
                    )
                });
                if res != D_SUCCESS {
                    kpanic!(
                        "device_write_dealloc",
                        "device_write_dealloc: No block size"
                    );
                }

                (*ior).recnum = (*ior).recnum.wrapping_add(
                    ((*ior).count / c_long::from(bsize)) as c_ulong,
                );
                (*ior).count = (*new_copy).size as c_long;
            } else {
                (*ior).residual =
                    (*ior).residual.wrapping_add(size_to_do as c_long);
            }
        }

        VmMapCopy::discard(NonNull::new_unchecked(io_copy));
        (*ior).copy = ptr::null_mut();
        (*ior).data = new_copy.cast::<c_char>();

        c_int::from(new_copy.is_null())
    }
}

/// `ds_write_done()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `ior` must be the live write request [`device_write()`] queued.
pub(crate) unsafe fn ds_write_done(ior: *mut IoReq) -> c_int {
    unsafe {
        loop {
            if device_write_dealloc(ior) != 0 {
                break;
            }

            let device = (*ior).device.cast::<MachDevice>();
            let d_write = (*(*device).dev_ops).d_write;
            let result = d_write.map_or(D_SUCCESS, |d_write| {
                d_write(driver_unit((*device).dev_number), ior)
            });

            if result == D_IO_QUEUED {
                return c_int::from(false);
            }
        }

        if IpcPort::valid((*ior).reply_port).is_some() {
            let bytes = ((*ior).total - (*ior).residual) as c_int;
            if (*ior).op & IO_INBAND != 0 {
                glue::ds_device_write_reply_inband(
                    (*ior).reply_port,
                    (*ior).reply_port_type,
                    (*ior).error,
                    bytes,
                );
            } else {
                glue::ds_device_write_reply(
                    (*ior).reply_port,
                    (*ior).reply_port_type,
                    (*ior).error,
                    bytes,
                );
            }
        }
        dev_lookup::deallocate((*ior).device.cast::<MachDevice>());
    }

    c_int::from(true)
}

/// `device_read()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `data` and
/// `data_count` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_read(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    bytes_wanted: c_int,
    _data: *mut *mut c_char,
    _data_count: *mut c_uint,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        if IpcPort::valid(reply_port).is_none() {
            kprint!("ds_* invalid reply port\n");
            soft_debugger(c"ds_* reply_port".as_ptr());
            return MIG_NO_REPLY;
        }

        let Some(ior) = io_req_alloc(IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_READ | IO_CALL,
            mode,
            recnum,
            count: c_long::from(bytes_wanted),
            done: Some(ds_read_done),
            reply_port,
            reply_port_type,
            ..IoReq::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory).as_io_return();
        };

        dev_lookup::reference(device);

        let d_read = (*(*device).dev_ops).d_read;
        let result = d_read.map_or(D_SUCCESS, |d_read| {
            d_read(driver_unit((*device).dev_number), ior)
        });

        if result == D_IO_QUEUED {
            return MIG_NO_REPLY;
        }

        (*ior).error = result;
        ds_read_done(ior);
        io_req_free(ior);
    }

    MIG_NO_REPLY
}

/// `device_read_inband()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `data` and
/// `data_count` writable.
#[expect(clippy::too_many_arguments)]
unsafe fn device_read_inband(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    bytes_wanted: c_int,
    _data: *mut c_char,
    _data_count: *mut c_uint,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        if IpcPort::valid(reply_port).is_none() {
            kprint!("ds_* invalid reply port\n");
            soft_debugger(c"ds_* reply_port".as_ptr());
            return MIG_NO_REPLY;
        }

        // The C compared the int against the `size_t` array bound, so a
        // negative wish became a huge one and picked the bound.
        let wanted = bytes_wanted as usize;
        let count = if wanted < IO_INBAND_MAX {
            c_long::from(bytes_wanted)
        } else {
            IO_INBAND_MAX as c_long
        };
        let Some(ior) = io_req_alloc(IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_READ | IO_CALL | IO_INBAND,
            mode,
            recnum,
            count,
            done: Some(ds_read_done),
            reply_port,
            reply_port_type,
            ..IoReq::new()
        })
        .map(KBox::into_raw) else {
            return Err(DeviceError::NoMemory).as_io_return();
        };

        dev_lookup::reference(device);

        let d_read = (*(*device).dev_ops).d_read;
        let result = d_read.map_or(D_SUCCESS, |d_read| {
            d_read(driver_unit((*device).dev_number), ior)
        });

        if result == D_IO_QUEUED {
            return MIG_NO_REPLY;
        }

        (*ior).error = result;
        ds_read_done(ior);
        io_req_free(ior);
    }

    MIG_NO_REPLY
}

/// `device_read_alloc()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `ior` must be a live request with `io_count` bytes to allocate.
pub(crate) unsafe fn device_read_alloc(
    ior: *mut IoReq,
    size: VmSize,
) -> c_int {
    unsafe {
        if (*ior).count == 0 {
            return KERN_SUCCESS;
        }

        if (*ior).op & IO_INBAND != 0 {
            let addr = kmem_cache_alloc(ptr::addr_of_mut!(IO_INBAND_CACHE));
            (*ior).data = ptr::with_exposed_provenance_mut::<c_char>(addr);
            (*ior).alloc_size = IO_INBAND_MAX;
        } else {
            let size = round_page(size);
            // SAFETY: the kernel map is live.
            let map = NonNull::new_unchecked(KERNEL_MAP.cast::<VmMap>());
            let addr = match vm_kern::kmem_alloc(map, size) {
                Ok(addr) => addr,
                Err(error) => return error.as_kern_return(),
            };

            (*ior).data = ptr::with_exposed_provenance_mut::<c_char>(addr);
            (*ior).alloc_size = size;
        }

        KERN_SUCCESS
    }
}

/// `ds_read_done()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `ior` must be the live read request [`device_read()`] or
/// [`device_read_inband()`] queued.
pub(crate) unsafe fn ds_read_done(ior: *mut IoReq) -> c_int {
    unsafe {
        let inband = (*ior).op & IO_INBAND != 0;
        let size_read = if (*ior).error != 0 {
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
            glue::ds_device_read_reply_inband(
                (*ior).reply_port,
                (*ior).reply_port_type,
                (*ior).error,
                (*ior).data,
                size_read as c_uint,
            );
        } else {
            let mut copy: *mut VmMapCopy = ptr::null_mut();
            let kr = crate::vm::vm_map::vm_map_copyin_page_list(
                KERNEL_MAP.cast::<VmMap>(),
                start_data,
                size_read,
                1,
                1,
                &raw mut copy,
                0,
            );
            if kr != KERN_SUCCESS {
                kpanic!(
                    "ds_read_done",
                    "read_done: vm_map_copyin_page_list failed"
                );
            }

            glue::ds_device_read_reply(
                (*ior).reply_port,
                (*ior).reply_port_type,
                (*ior).error,
                copy.cast::<c_char>(),
                size_read as c_uint,
            );
        }

        if (*ior).count != 0 {
            if inband {
                if (*ior).alloc_size > 0 {
                    kmem_cache_free(
                        ptr::addr_of_mut!(IO_INBAND_CACHE),
                        (*ior).data.addr(),
                    );
                }
            } else {
                let end_alloc =
                    start_sent.wrapping_add(round_page((*ior).alloc_size));
                if end_alloc > end_sent {
                    // SAFETY: `KERNEL_MAP` is the live kernel map, and the
                    // request still owns the range.
                    let _ = vm_user::deallocate(
                        &mut *KERNEL_MAP.cast::<VmMap>(),
                        end_sent,
                        end_alloc - end_sent,
                    );
                }
            }
        }

        dev_lookup::deallocate((*ior).device.cast::<MachDevice>());
    }

    c_int::from(true)
}

/// `device_set_status()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device.
unsafe fn device_set_status(
    dev: *mut c_void,
    flavor: c_uint,
    status: *mut c_int,
    status_count: c_uint,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        let d_setstat = (*(*device).dev_ops).d_setstat;
        d_setstat.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `mach_device_get_status()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device.
unsafe fn mach_device_get_status(
    dev: *mut c_void,
    flavor: c_uint,
    status: *mut c_int,
    status_count: *mut c_uint,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        let d_getstat = (*(*device).dev_ops).d_getstat;
        d_getstat.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `device_set_filter()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `filter`
/// readable for `filter_count` entries.
unsafe fn device_set_filter(
    dev: *mut c_void,
    receive_port: *mut c_void,
    priority: c_int,
    filter: *mut c_ushort,
    filter_count: c_uint,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        if IpcPort::valid(receive_port).is_none() {
            return Err(DeviceError::InvalidOperation).as_io_return();
        }

        let d_async_in = (*(*device).dev_ops).d_async_in;
        d_async_in.map_or_else(
            || Err(DeviceError::InvalidOperation).as_io_return(),
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

/// `device_map()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` must be the emulation data of a live mach device, and `pager`
/// writable.
unsafe fn device_map(
    dev: *mut c_void,
    protection: c_int,
    offset: VmOffset,
    // The C's `device_pager_setup()` stored the size and never read it
    // back, so the core does not take it.
    _size: VmSize,
    pager: *mut *mut c_void,
    _unmap: c_int,
) -> c_int {
    let device = dev.cast::<MachDevice>();
    unsafe {
        if protection & !VmProt::ALL.bits() != 0 {
            return KERN_INVALID_ARGUMENT;
        }

        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        match crate::device::dev_pager::setup(device, protection, offset) {
            Ok(port) => {
                *pager = port.as_ptr();
                KERN_SUCCESS
            }
            Err(error) => error.code(),
        }
    }
}

/// `ds_no_senders()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `notification` must be a live no-senders notification.
unsafe fn ds_no_senders(notification: *mut c_void) {
    let notification = notification.cast::<NoSendersNotification>();
    unsafe {
        kprint!(
            "ds_no_senders called! device_port=0x{:x} count={}\n",
            (*notification).header.remote(),
            (*notification).not_count,
        );
    }
}

/// `iodone()` of <`device/io_req.h`>.
///
/// # Safety
///
/// `ior` must be a live request whose completion path is not already running.
pub(crate) unsafe fn iodone(ior: *mut IoReq) {
    unsafe {
        if (*ior).op & IO_LOANED != 0 {
            if let Some(done) = (*ior).done {
                done(ior);
            }
            return;
        }

        let s = spl::splsched();
        if (*ior).op & IO_CALL == 0 {
            (*ior).lock.lock();
            (*ior).op |= IO_DONE;
            (*ior).op &= !IO_WANTED;
            (*ior).lock.unlock();
            thread_wakeup_prim(ior.cast::<c_void>(), 0, THREAD_AWAKENED);
        } else {
            (*ior).op |= IO_DONE;
            {
                let _guard = IO_DONE_LIST_LOCK.lock();
                io_done_list().push_back_ptr(NonNull::new_unchecked(ior));
                thread_wakeup_prim(io_done_event(), 0, THREAD_AWAKENED);
            }
        }
        spl::splx(s);
    }
}

/// `io_done_thread_continue()` of `device/ds_routines.c`.
unsafe extern "C" fn io_done_thread_continue() {
    loop {
        // SAFETY: the interrupt level and the list lock serialize the list
        // against `iodone()`.
        let mut s = unsafe { spl::splhigh() };
        loop {
            let guard = IO_DONE_LIST_LOCK.lock();
            // SAFETY: the list is this module's static and the lock is held.
            let popped = unsafe { io_done_list() }.pop_front();
            match popped {
                None => {
                    // SAFETY: the event is the list head every wakeup names,
                    // and the lock is held.
                    unsafe {
                        assert_wait(NonNull::new(io_done_event()), 0);
                    }
                    drop(guard);
                    // SAFETY: `s` is this iteration's `splhigh()`.
                    unsafe { spl::splx(s) };
                    break;
                }
                Some(entry) => {
                    drop(guard);
                    // SAFETY: `s` is this iteration's `splhigh()`.
                    unsafe { spl::splx(s) };
                    let ior = ptr::from_mut(entry);
                    // SAFETY: every list entry is a live request.
                    let finished = unsafe {
                        (*ior).done.map_or_else(
                            || c_int::from(true),
                            |done| done(ior),
                        )
                    };
                    if finished != 0 {
                        // SAFETY: the completion released the request.
                        unsafe { io_req_free(ior) };
                    }
                    // SAFETY: `splhigh()` is the asm entry of
                    // <machine/spl.h>.
                    s = unsafe { spl::splhigh() };
                }
            }
        }
        unsafe { thread_block(Some(io_done_thread_continue)) };
    }
}

/// `io_done_thread()` of `device/ds_routines.c`.
///
/// # Safety
///
/// Runs only as the io-done kernel thread.
pub(crate) unsafe extern "C" fn io_done_thread() {
    // SAFETY: the running thread is the io-done thread.
    unsafe {
        let thread = per_cpu::thread();
        (*thread).vm_privilege = 1;
        (*thread).stack_privilege();
        Thread::set_own_priority(0);

        io_done_thread_continue();
    }
}

/// `mach_device_init()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `device_service_create()` is the only caller; it runs this once during
/// boot before any device can be opened.
pub(crate) unsafe fn mach_device_init() {
    // SAFETY: the map storage is this module's static and the kernel map is
    // the live boot map.
    unsafe {
        vm_kern::kmem_submap(
            &mut *DEVICE_IO_MAP,
            NonNull::new_unchecked(KERNEL_MAP.cast::<VmMap>()),
            DEVICE_IO_MAP_SIZE,
        )
        .unwrap_or_else(|_| kpanic!("kmem_submap", "kmem_submap"));
    }

    // SAFETY: this boot step is the map's only writer.
    unsafe {
        (*DEVICE_IO_MAP).flags |= VM_MAP_WAIT_FOR_SPACE;
    }

    // SAFETY: the caches are this module's statics, unshared during boot.
    unsafe {
        kmem_cache_init(
            ptr::addr_of_mut!(IO_INBAND_CACHE),
            c"io_buf_ptr_inband".as_ptr(),
            IO_INBAND_MAX,
            0,
            None,
            0,
        );
    }
    mach_device_trap_init();
}

/// `mach_device_trap_init()` of `device/ds_routines.c`.
fn mach_device_trap_init() {
    // SAFETY: the cache is this module's static, unshared during boot.
    unsafe {
        kmem_cache_init(
            ptr::addr_of_mut!(IO_TRAP_CACHE),
            c"io_req".as_ptr(),
            IOTRAP_REQSIZE,
            0,
            None,
            0,
        );
    }
}

/// `ds_trap_req_alloc()` of `device/ds_routines.c`.
///
/// Returns a recycled cache slot, or null: the caller writes the request
/// whole over it, with the loaned data right after it.
///
/// # Safety
///
/// The `io_trap_cache` must be initialized.
unsafe fn ds_trap_req_alloc(
    _device: *mut MachDevice,
    _data_size: VmSize,
) -> *mut IoReq {
    let addr = unsafe { kmem_cache_alloc(ptr::addr_of_mut!(IO_TRAP_CACHE)) };
    ptr::with_exposed_provenance_mut::<IoReq>(addr)
}

/// `ds_trap_write_done()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `ior` must be the live trap request [`device_write_trap()`] built.
unsafe fn ds_trap_write_done(ior: *mut IoReq) -> c_int {
    unsafe {
        let dev = (*ior).device;

        kmem_cache_free(ptr::addr_of_mut!(IO_TRAP_CACHE), ior.addr());
        dev_lookup::deallocate(dev.cast::<MachDevice>());
    }

    c_int::from(true)
}

/// `device_write_trap()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `device` must be the emulation data of a live mach device, and `data`
/// readable for `data_count` bytes of user memory.
unsafe fn device_write_trap(
    device: *mut c_void,
    mode: c_uint,
    recnum: c_ulong,
    data: c_ulong,
    data_count: c_ulong,
) -> c_int {
    let device = device.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        if data_count > IOTRAP_DATA_MAX as c_ulong {
            return Err(DeviceError::InvalidSize).as_io_return();
        }

        let ior = ds_trap_req_alloc(device, data_count as VmSize);
        if ior.is_null() {
            return Err(DeviceError::NoMemory).as_io_return();
        }
        ior.write(IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_WRITE | IO_CALL | IO_LOANED,
            mode,
            recnum,
            data: ior.cast::<u8>().add(size_of::<IoReq>()).cast::<c_char>(),
            count: data_count as c_long,
            total: data_count as c_long,
            done: Some(ds_trap_write_done),
            ..IoReq::new()
        });

        if data_count > 0 {
            user_access::copyin(
                ptr::with_exposed_provenance::<c_void>(data as usize),
                (*ior).data.cast::<c_void>(),
                data_count as usize,
            );
        }

        dev_lookup::reference(device);

        let d_write = (*(*device).dev_ops).d_write;
        let result = d_write.map_or(D_SUCCESS, |d_write| {
            d_write(driver_unit((*device).dev_number), ior)
        });

        if result == D_IO_QUEUED {
            return MIG_NO_REPLY;
        }

        dev_lookup::deallocate(device);

        kmem_cache_free(ptr::addr_of_mut!(IO_TRAP_CACHE), ior.addr());
        result
    }
}

/// `device_writev_trap()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `device` must be the emulation data of a live mach device, and `iovec`
/// readable for `iocount` user-space entries.
unsafe fn device_writev_trap(
    device: *mut c_void,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut RpcIoBufVec,
    iocount: c_ulong,
) -> c_int {
    let device = device.cast::<MachDevice>();
    unsafe {
        if (*device).state != DEV_STATE_OPEN {
            return Err(DeviceError::NoSuchDevice).as_io_return();
        }

        if iocount > MAX_IOVECS as c_ulong {
            return KERN_INVALID_VALUE;
        }
        let iocount = iocount as usize;

        let mut stack_iovec = [IoBufVec { data: 0, count: 0 }; MAX_IOVECS];
        let mut data_count: VmSize = 0;
        for (i, slot) in stack_iovec.iter_mut().enumerate().take(iocount) {
            let mut riov = RpcIoBufVec { data: 0, count: 0 };
            let kr = user_access::copyin(
                iovec.add(i).cast::<c_void>(),
                ptr::addr_of_mut!(riov).cast::<c_void>(),
                size_of::<RpcIoBufVec>(),
            );
            if kr != 0 {
                return KERN_INVALID_ARGUMENT;
            }
            *slot = IoBufVec {
                data: riov.data as VmOffset,
                count: riov.count as VmSize,
            };
            data_count = match data_count.checked_add(slot.count) {
                Some(total) if total <= IOTRAP_DATA_MAX => total,
                _ => return Err(DeviceError::InvalidSize).as_io_return(),
            };
        }

        let ior = ds_trap_req_alloc(device, data_count);
        if ior.is_null() {
            return Err(DeviceError::NoMemory).as_io_return();
        }
        ior.write(IoReq {
            device: device.cast::<c_void>(),
            unit: (*device).dev_number,
            op: IO_WRITE | IO_CALL | IO_LOANED,
            mode,
            recnum,
            data: ior.cast::<u8>().add(size_of::<IoReq>()).cast::<c_char>(),
            count: data_count as c_long,
            total: data_count as c_long,
            done: Some(ds_trap_write_done),
            ..IoReq::new()
        });

        if data_count > 0 {
            let mut p = (*ior).data;
            for iovec in stack_iovec.iter().take(iocount) {
                user_access::copyin(
                    ptr::with_exposed_provenance::<c_void>(iovec.data),
                    p.cast::<c_void>(),
                    iovec.count,
                );
                p = p.add(iovec.count);
            }
        }

        dev_lookup::reference(device);

        let d_write = (*(*device).dev_ops).d_write;
        let result = d_write.map_or(D_SUCCESS, |d_write| {
            d_write(driver_unit((*device).dev_number), ior)
        });

        if result == D_IO_QUEUED {
            return MIG_NO_REPLY;
        }

        dev_lookup::deallocate(device);

        kmem_cache_free(ptr::addr_of_mut!(IO_TRAP_CACHE), ior.addr());
        result
    }
}
