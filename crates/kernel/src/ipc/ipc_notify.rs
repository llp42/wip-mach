// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_notify.c and ipc/ipc_notify.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The notification-sending routines, which `ipc/ipc_notify.c` used to
//! define and `ipc/ipc_notify.h` declares.
//!
//! The C built six static templates once and copied one into each message.
//! The layouts are fixed, so the senders here build the message where they
//! send it and `ipc_notify_init()` has nothing left to initialize.

use crate::ipc::ipc_kmsg::{self, Kmsg};
use crate::ipc::ipc_mqueue;
use crate::ipc::ipc_port;
use crate::ipc::{IpcPort, MachMsgHeader};
use crate::kern::console::kprint;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull};

/// `MACH_NOTIFY_PORT_DELETED` of <mach/notify.h>.
const PORT_DELETED: c_int = 0o101;
/// `MACH_NOTIFY_MSG_ACCEPTED` of <mach/notify.h>.
const MSG_ACCEPTED: c_int = 0o102;
/// `MACH_NOTIFY_PORT_DESTROYED` of <mach/notify.h>.
const PORT_DESTROYED: c_int = 0o105;
/// `MACH_NOTIFY_NO_SENDERS` of <mach/notify.h>.
const NO_SENDERS: c_int = 0o106;
/// `MACH_NOTIFY_SEND_ONCE` of <mach/notify.h>.
const SEND_ONCE: c_int = 0o107;
/// `MACH_NOTIFY_DEAD_NAME` of <mach/notify.h>.
const DEAD_NAME: c_int = 0o110;

/// `NOTIFY_MSGH_SEQNO` of `ipc/ipc_notify.c`.
const NOTIFY_MSGH_SEQNO: c_uint = 0;

/// `MACH_MSG_TYPE_PORT_NAME` of <mach/message.h>.
const MACH_MSG_TYPE_PORT_NAME: c_uint = 15;
/// `MACH_MSG_TYPE_PORT_RECEIVE` of <mach/message.h>.
const MACH_MSG_TYPE_PORT_RECEIVE: c_uint = 16;
/// `MACH_MSG_TYPE_INTEGER_32` of <mach/message.h>.
const MACH_MSG_TYPE_INTEGER_32: c_uint = 2;
/// `MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, 0)` of <mach/message.h>.
const MACH_SEND_ONCE_BITS: u32 = 18;
/// `MACH_MSGH_BITS_COMPLEX` of <mach/message.h>.
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;

/// `PORT_NAME_T_SIZE_IN_BITS` of <`ipc/ipc_machdep.h`>.
const PORT_NAME_T_SIZE_IN_BITS: c_uint = 32;
/// `PORT_T_SIZE_IN_BITS` of <`ipc/ipc_machdep.h`>.
const PORT_T_SIZE_IN_BITS: c_uint = 8 * size_of::<*mut c_void>() as c_uint;

/// `mach_msg_type_t` of <mach/message.h>: the bitfield word and the
/// `msgt_number` member that follows it.
#[repr(C)]
#[allow(missing_docs)]
struct MsgType {
    /// The packed `msgt_name`, `msgt_size` and inline-flag bits;
    /// [`MsgType::inline()`] builds it.
    word: u32,
    number: u32,
}

impl MsgType {
    /// The descriptor of one inline, short-form datum of `size` bits.
    const fn inline(name: u32, size: u32, number: u32) -> Self {
        let word = name | (size << 8) | (1 << 29);

        Self { word, number }
    }
}

/// The notification record of <mach/notify.h>: the message header and the
/// type descriptor and payload that follow it.
#[repr(C)]
#[allow(missing_docs)]
struct Notification {
    header: MachMsgHeader,
    type_descriptor: MsgType,
    /// `not_port` or `not_count`, one pointer-wide word; the C stores a port
    /// name, a count or a receive right here.
    payload: usize,
}

const _: () = {
    assert!(size_of::<MsgType>() == 8);
    assert!(align_of::<MsgType>() == 4);
    assert!(offset_of!(MsgType, word) == 0);
    assert!(offset_of!(MsgType, number) == 4);

    assert!(size_of::<Notification>() == 48);
    assert!(align_of::<Notification>() == 8);
    assert!(offset_of!(Notification, header) == 0);
    assert!(offset_of!(Notification, type_descriptor) == 32);
    assert!(offset_of!(Notification, payload) == 40);
};

/// The payload a notification carries after its type descriptor.
#[derive(Clone, Copy)]
enum Body {
    /// `mach_send_once_notification_t`: the header alone.
    Bare,
    /// A port name, as `mach_port_deleted_notification_t`,
    /// `mach_msg_accepted_notification_t` and
    /// `mach_dead_name_notification_t` carry.
    Name(c_uint),
    /// `mach_no_senders_notification_t`: the send-right count.
    Count(c_uint),
    /// `mach_port_destroyed_notification_t`: the receive right itself.
    Receive(*mut c_void),
}

impl Body {
    /// `sizeof *n` for the notification this body belongs to.
    const fn size(&self) -> usize {
        match self {
            Self::Bare => size_of::<MachMsgHeader>(),
            Self::Name(_) | Self::Count(_) | Self::Receive(_) => {
                size_of::<Notification>()
            }
        }
    }

    /// The value of `not_port`/`not_count`.
    fn payload(&self) -> usize {
        match self {
            Self::Bare => 0,
            Self::Name(name) | Self::Count(name) => *name as usize,
            Self::Receive(port) => *port as usize,
        }
    }

    /// The `msgt_name` of the body's type descriptor.
    const fn type_name(&self) -> c_uint {
        match self {
            Self::Bare | Self::Name(_) => MACH_MSG_TYPE_PORT_NAME,
            Self::Count(_) => MACH_MSG_TYPE_INTEGER_32,
            Self::Receive(_) => MACH_MSG_TYPE_PORT_RECEIVE,
        }
    }

    /// The `msgt_size` of the body's type descriptor.
    const fn type_size(&self) -> c_uint {
        match self {
            Self::Bare | Self::Name(_) => PORT_NAME_T_SIZE_IN_BITS,
            Self::Count(_) => 32,
            Self::Receive(_) => PORT_T_SIZE_IN_BITS,
        }
    }

    /// The `msgh_bits` of the notification this body belongs to.
    const fn bits(&self) -> u32 {
        match self {
            Self::Receive(_) => MACH_SEND_ONCE_BITS | MACH_MSGH_BITS_COMPLEX,
            _ => MACH_SEND_ONCE_BITS,
        }
    }
}

/// Builds the notification message `id`, addressed to `port`, carrying
/// `body`.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes, and the caller permits an allocation.  The result, when `Some`,
/// is a live message this call owns.
unsafe fn build(id: c_int, port: *mut c_void, body: Body) -> Option<Kmsg> {
    let size = body.size();
    let kmsg = unsafe { ipc_kmsg::alloc(size) }?;
    // SAFETY: the fresh message is owned by this call.
    let header = unsafe { kmsg.header() };

    // The C copied a zero-initialized template over the buffer; zeroing
    // first and writing the fields below leaves the same bytes, padding
    // included.
    // SAFETY: the message's buffer holds `size` writable bytes.
    unsafe { ptr::write_bytes(header.cast::<u8>(), 0, size) };

    // SAFETY: the message is live and this call owns it; the size is one of
    // the two `sizeof` values above, so the narrowing cannot lose anything.
    unsafe {
        (*header).bits = body.bits();
        (*header).size = size as u32;
        (*header).remote_port = port.addr();
        (*header).seqno = NOTIFY_MSGH_SEQNO;
        (*header).id = id;
    }

    if !matches!(body, Body::Bare) {
        // SAFETY: the buffer's layout is `Notification`, most of it already
        // written as the header.
        unsafe {
            let notification = header.cast::<Notification>();
            (*notification).type_descriptor =
                MsgType::inline(body.type_name(), body.type_size(), 1);
            (*notification).payload = body.payload();
        }
    }

    Some(kmsg)
}

/// `ipc_notify_init()` in C.
pub(crate) const fn init() {}

/// `ipc_notify_port_deleted()` in C.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes; nothing may be locked.
pub(crate) unsafe fn port_deleted(port: *mut c_void, name: c_uint) {
    let Some(kmsg) = (unsafe { build(PORT_DELETED, port, Body::Name(name)) })
    else {
        kprint!(
            "dropped port-deleted (0x{:x}, 0x{:x})\n",
            port.expose_provenance(),
            name,
        );
        unsafe { ipc_port::release_sonce(IpcPort::from_raw(port)) };
        return;
    };

    // SAFETY: the message holds the right the queue consumes.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
}

/// `ipc_notify_msg_accepted()` in C.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes; nothing may be locked.
pub(crate) unsafe fn msg_accepted(port: *mut c_void, name: c_uint) {
    let Some(kmsg) = (unsafe { build(MSG_ACCEPTED, port, Body::Name(name)) })
    else {
        kprint!(
            "dropped msg-accepted (0x{:x}, 0x{:x})\n",
            port.expose_provenance(),
            name,
        );
        unsafe { ipc_port::release_sonce(IpcPort::from_raw(port)) };
        return;
    };

    // SAFETY: the message holds the right the queue consumes.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
}

/// `ipc_notify_port_destroyed()` in C.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes, and `right` a receive right the message takes over; nothing may
/// be locked.
pub(crate) unsafe fn port_destroyed(port: *mut c_void, right: *mut c_void) {
    let Some(kmsg) =
        (unsafe { build(PORT_DESTROYED, port, Body::Receive(right)) })
    else {
        kprint!(
            "dropped port-destroyed (0x{:x}, 0x{:x})\n",
            port.expose_provenance(),
            right.expose_provenance(),
        );
        unsafe {
            ipc_port::release_sonce(IpcPort::from_raw(port));
            ipc_port::release_receive(IpcPort::from_raw(right));
        }
        return;
    };

    // SAFETY: the message holds the right the queue consumes.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
}

/// `ipc_notify_no_senders()` in C.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes; nothing may be locked.
pub(crate) unsafe fn no_senders(port: NonNull<c_void>, mscount: c_uint) {
    let Some(kmsg) =
        (unsafe { build(NO_SENDERS, port.as_ptr(), Body::Count(mscount)) })
    else {
        kprint!(
            "dropped no-senders (0x{:x}, {})\n",
            port.as_ptr().expose_provenance(),
            mscount,
        );
        unsafe { ipc_port::release_sonce(IpcPort::from_raw(port.as_ptr())) };
        return;
    };

    // SAFETY: the message holds the right the queue consumes.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
}

/// `ipc_notify_send_once()` in C.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes; nothing may be locked.
pub(crate) unsafe fn send_once(port: NonNull<c_void>) {
    let Some(kmsg) = (unsafe { build(SEND_ONCE, port.as_ptr(), Body::Bare) })
    else {
        kprint!(
            "dropped send-once (0x{:x})\n",
            port.as_ptr().expose_provenance(),
        );
        unsafe { ipc_port::release_sonce(IpcPort::from_raw(port.as_ptr())) };
        return;
    };

    // SAFETY: the message holds the right the queue consumes.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
}

/// `ipc_notify_dead_name()` in C.
///
/// # Safety
///
/// `port` must be a live port holding the send-once right the notification
/// consumes; nothing may be locked.
pub(crate) unsafe fn dead_name(port: *mut c_void, name: c_uint) {
    let Some(kmsg) = (unsafe { build(DEAD_NAME, port, Body::Name(name)) })
    else {
        kprint!(
            "dropped dead-name (0x{:x}, 0x{:x})\n",
            port.expose_provenance(),
            name,
        );
        unsafe { ipc_port::release_sonce(IpcPort::from_raw(port)) };
        return;
    };

    // SAFETY: the message holds the right the queue consumes.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
}
