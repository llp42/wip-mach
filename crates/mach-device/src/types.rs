// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The plain data the device service hands the kernel.

use crate::r#return::DeviceError;
use core::ffi::{c_char, c_int, c_uint, c_void};
use mach_vm::error::Error as VmError;
use mach_vm::param::{VmOffset, VmSize};

/// A message the device service sends: the reply to a device call a request
/// finished after the call returned, or a memory-object call a device pager
/// makes on the kernel's port for its object.
///
/// The ports are rights the send consumes, so a message is sent at most
/// once.
#[derive(Clone, Copy, Debug)]
pub enum Message {
    /// `device_open`'s reply.
    OpenReply {
        /// The reply right, of type `reply_port_type`.
        reply_port: *mut c_void,
        /// The MIG type of `reply_port`.
        reply_port_type: c_uint,
        /// The outcome of the open.
        result: Result<(), DeviceError>,
        /// A send right to the device for the reply to carry, or null.
        device_port: *mut c_void,
    },
    /// `device_write`'s reply, or `device_write_inband`'s when `inband`.
    WriteReply {
        /// The reply right, of type `reply_port_type`.
        reply_port: *mut c_void,
        /// The MIG type of `reply_port`.
        reply_port_type: c_uint,
        /// Whether the call was `device_write_inband`.
        inband: bool,
        /// The outcome of the write.
        result: Result<(), DeviceError>,
        /// How many bytes the device took.
        bytes_written: c_int,
    },
    /// `device_read`'s reply, or `device_read_inband`'s when `inband`.
    ReadReply {
        /// The reply right, of type `reply_port_type`.
        reply_port: *mut c_void,
        /// The MIG type of `reply_port`.
        reply_port_type: c_uint,
        /// Whether the call was `device_read_inband`.
        inband: bool,
        /// The outcome of the read.
        result: Result<(), DeviceError>,
        /// The data: a page-list copy the reply consumes, or null; when
        /// `inband`, a buffer readable for `data_count` bytes, at most the
        /// inband limit.
        data: *mut c_char,
        /// The number of bytes at `data`.
        data_count: c_uint,
    },
    /// `memory_object_data_error()`: the pager could not supply a range.
    DataError {
        /// The object's pager request port.
        memory_control: *mut c_void,
        /// The start of the range.
        offset: VmOffset,
        /// The length of the range.
        size: VmSize,
        /// Why the range could not be supplied.
        error: VmError,
    },
    /// `memory_object_ready()`: the pager has set its object up.
    Ready {
        /// The object's pager request port.
        memory_control: *mut c_void,
        /// Whether the kernel may cache the object's pages.
        may_cache: bool,
        /// The object's copy strategy.
        copy_strategy: c_int,
    },
}

/// The slab caches the device service allocates its records from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceCache {
    /// Open-device records.
    Device,
    /// In-band read buffers.
    IoInband,
    /// The trap path's request blocks.
    IoTrap,
    /// Device pager records.
    Pager,
    /// Entries of the table of pagers by port.
    PagerEntry,
    /// Entries of the table of pagers by device and offset.
    DeviceEntry,
}

impl DeviceCache {
    /// The number of caches.
    pub const COUNT: usize = 6;
}
