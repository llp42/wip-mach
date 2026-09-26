// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_kobject.c and kern/ipc_kobject.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel-object ports, which `kern/ipc_kobject.c` used to define and
//! `kern/ipc_kobject.h` declares.

use crate::arch::types::VmOffset;
use crate::glue;
use crate::glue::MigRoutine;
use crate::ipc::ipc_kmsg::{self, Kmsg};
use crate::ipc::ipc_port;
use crate::ipc::{IpcPort, MachMsgHeader, MachMsgType, MigReplyHeader};
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::task::KERNEL_TASK;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr;

/// `IKOT_THREAD` of <`kern/ipc_kobject.h>`: a thread port.
pub(crate) const IKOT_THREAD: c_uint = 1;
/// `IKOT_PAGER` of <`kern/ipc_kobject.h>`: a memory object's pager.
const IKOT_PAGER: c_uint = 8;
/// `IKOT_DEVICE` of <`kern/ipc_kobject.h`>.
const IKOT_DEVICE: c_uint = 10;
/// `IKOT_PAGER_TERMINATING` of <`kern/ipc_kobject.h`>.
const IKOT_PAGER_TERMINATING: c_uint = 15;
/// `IKOT_PAGER_PROXY` of <`kern/ipc_kobject.h`>.
const IKOT_PAGER_PROXY: c_uint = 27;

/// `MACH_MSGH_BITS_LOCAL_MASK` of <mach/message.h>.
const MACH_MSGH_BITS_LOCAL_MASK: u32 = 0x0000_ff00;
/// `MACH_MSGH_BITS_REMOTE_MASK` of <mach/message.h>.
const MACH_MSGH_BITS_REMOTE_MASK: u32 = 0x0000_00ff;
/// `MACH_MSG_TYPE_PORT_SEND`, the wire alias `MACH_MSG_TYPE_MOVE_SEND`.
const MACH_MSG_TYPE_PORT_SEND: u32 = 17;
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`, the wire alias
/// `MACH_MSG_TYPE_MOVE_SEND_ONCE`.
const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = 18;
/// `MACH_MSG_TYPE_INTEGER_32` of <mach/message.h>.
const MACH_MSG_TYPE_INTEGER_32: u32 = 2;

/// `MACH_NOTIFY_PORT_DELETED` of <mach/notify.h>.
const MACH_NOTIFY_PORT_DELETED: c_int = 65;
/// `MACH_NOTIFY_MSG_ACCEPTED` of <mach/notify.h>.
const MACH_NOTIFY_MSG_ACCEPTED: c_int = 66;
/// `MACH_NOTIFY_PORT_DESTROYED` of <mach/notify.h>.
const MACH_NOTIFY_PORT_DESTROYED: c_int = 67;
/// `MACH_NOTIFY_NO_SENDERS` of <mach/notify.h>.
const MACH_NOTIFY_NO_SENDERS: c_int = 68;
/// `MACH_NOTIFY_SEND_ONCE` of <mach/notify.h>.
const MACH_NOTIFY_SEND_ONCE: c_int = 69;
/// `MACH_NOTIFY_DEAD_NAME` of <mach/notify.h>.
const MACH_NOTIFY_DEAD_NAME: c_int = 70;

/// `KERN_SUCCESS` of <`mach/kern_return.h`>.
const KERN_SUCCESS: c_int = 0;
/// `MIG_BAD_ID` of <`mach/mig_errors.h`>.
const MIG_BAD_ID: c_int = -303;
/// `MIG_NO_REPLY` of <`mach/mig_errors.h`>.
const MIG_NO_REPLY: c_int = -305;

/// The `8192`-byte bound `ipc_kobject_server()` gives a reply body, before
/// the message overhead is subtracted.
const MAX_REPLY_BODY: usize = 8192;

/// The descriptor word of a `mach_msg_type_t` initializer under the 64-bit
/// bitfield layout.
const fn descriptor_word(name: u32, size: u32) -> u32 {
    name | (size << 8) | (1 << 29)
}

/// The `RetCodeType` of `ipc_kobject_server()`: an inline 32-bit integer.
const RETCODE_TYPE: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_INTEGER_32, 32), 1);

/// `ipc_kobject_set()` in C: name a kernel object in a port, taking and
/// releasing the port lock.
///
/// # Safety
///
/// `port` must be a live, active port and nothing may be locked.
pub(crate) unsafe fn set(port: *mut c_void, kobject: VmOffset, type_: c_uint) {
    let port = unsafe { IpcPort::from_raw(port) };
    unsafe {
        port.lock();
        port.set_kobject_locked(
            ptr::with_exposed_provenance_mut(kobject),
            type_,
        );
        port.unlock();
    }
}

/// `ipc_kobject_set_locked()` in C: the same naming with the port lock
/// already held.
///
/// # Safety
///
/// `port` must be a live, active port whose lock the caller holds.
pub(crate) unsafe fn set_locked(
    port: *mut c_void,
    kobject: VmOffset,
    type_: c_uint,
) {
    let port = unsafe { IpcPort::from_raw(port) };
    unsafe {
        port.set_kobject_locked(
            ptr::with_exposed_provenance_mut(kobject),
            type_,
        );
    };
}

/// `ipc_kobject_destroy()` in C: release the resources a destroyed port
/// still names.
///
/// # Safety
///
/// `port` must be a live but inactive port that nothing holds a lock on.
pub(crate) unsafe fn destroy(port: *mut c_void) {
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live; the kobject is only read to identify it.
    match unsafe { port.kotype() } {
        IKOT_PAGER => {
            // SAFETY: a port of this type names a live memory object.
            unsafe { crate::vm::vm_object::destroy(port.as_ptr()) }
        }
        IKOT_PAGER_TERMINATING => {
            // SAFETY: a port of this type names a live memory object.
            unsafe { crate::vm::vm_object::pager_wakeup(port.as_ptr()) }
        }
        kotype => {
            // SAFETY: a port of this type names a live kobject.
            let kobject = unsafe { port.kobject() };
            kprint!(
                "ipc_kobject_destroy: port 0x{:x}, kobj 0x{}, type {}\n",
                port.as_ptr().expose_provenance(),
                kobject.addr(),
                kotype,
            );
        }
    }
}

/// `ipc_kobject_notify()` in C: deliver a notification to a port whose
/// kernel object wants it.
///
/// # Safety
///
/// `request_header` must be a live notification request and `reply_header` a
/// writable MIG reply header.
pub(crate) unsafe fn notify(
    request_header: *mut MachMsgHeader,
    reply_header: *mut MachMsgHeader,
) -> bool {
    let remote = unsafe { (*request_header).remote() };
    let Some(port) = IpcPort::valid(ptr::with_exposed_provenance_mut(remote))
    else {
        return false;
    };

    unsafe {
        (*reply_header.cast::<MigReplyHeader>()).ret_code = MIG_NO_REPLY;
    }

    match unsafe { (*request_header).id() } {
        MACH_NOTIFY_PORT_DELETED
        | MACH_NOTIFY_MSG_ACCEPTED
        | MACH_NOTIFY_PORT_DESTROYED
        | MACH_NOTIFY_NO_SENDERS
        | MACH_NOTIFY_SEND_ONCE
        | MACH_NOTIFY_DEAD_NAME => (),
        _ => return false,
    }

    // SAFETY: the port is live.
    match unsafe { port.kotype() } {
        // SAFETY: a device port's notification handler takes the header.
        IKOT_DEVICE => unsafe {
            crate::device::ds_routines::ds_notify(request_header.cast()) != 0
        },
        // SAFETY: a proxy pager's handler takes the header.
        IKOT_PAGER_PROXY => unsafe {
            crate::vm::memory_object_proxy::notify(request_header.cast())
        },
        _ => false,
    }
}

/// `ipc_kobject_server()` in C: handle a message sent to the kernel and
/// generate its reply.
///
/// # Safety
///
/// `request` must be a live kernel message the caller owns, and nothing may
/// be locked.
pub(crate) unsafe fn server(request: Kmsg) -> Option<Kmsg> {
    let reply_body = MAX_REPLY_BODY - ipc_kmsg::IKM_OVERHEAD;
    let Some(reply) = ipc_kmsg::ikm_alloc(reply_body) else {
        // SAFETY: the request is owned and live.
        unsafe {
            kprint!("ipc_kobject_server: dropping request\n");
            ipc_kmsg::destroy(request);
        }
        return None;
    };
    // SAFETY: the reply is freshly allocated and owned here.
    unsafe { ipc_kmsg::ikm_init(reply, reply_body) };

    // SAFETY: both messages are live, and the C copied exactly these fields
    // from the request header into the reply preamble.
    unsafe {
        let out = reply.header().cast::<MigReplyHeader>();
        let input = request.header();
        (*out)
            .head
            .set_bits(((*input).bits() & MACH_MSGH_BITS_LOCAL_MASK) >> 8);
        (*out).head.set_size(size_of::<MigReplyHeader>() as u32);
        (*out).head.set_remote((*input).local());
        (*out).head.set_local(0);
        (*out).head.set_id((*input).id() + 100);
        (*out).ret_code_type = RETCODE_TYPE;
        reply.set_header_seqno(0);
    }

    let head = unsafe { request.header() };
    match server_routine(unsafe { (*head).id() }) {
        Some(routine) => {
            // SAFETY: the MIG routine takes the request and reply headers and
            // the kernel task is live from `task_init()`.
            unsafe {
                routine(head.cast(), reply.header().cast());
                (*KERNEL_TASK).messages_received =
                    (*KERNEL_TASK).messages_received.wrapping_add(1);
            }
        }
        None => {
            // SAFETY: the headers are live and writable.
            if unsafe { notify(head, reply.header()) } {
                unsafe {
                    (*KERNEL_TASK).messages_received =
                        (*KERNEL_TASK).messages_received.wrapping_add(1);
                }
            } else {
                // SAFETY: the reply header is live and writable.
                unsafe {
                    (*reply.header().cast::<MigReplyHeader>()).ret_code =
                        MIG_BAD_ID;
                }
            }
        }
    }
    unsafe {
        (*KERNEL_TASK).messages_sent =
            (*KERNEL_TASK).messages_sent.wrapping_add(1);
    };

    // SAFETY: the request header is live; the switch handles exactly the two
    // destination rights the C expected.
    unsafe {
        let dest = request.header();
        let dest_port = (*dest).remote();
        match (*dest).bits() & MACH_MSGH_BITS_REMOTE_MASK {
            MACH_MSG_TYPE_PORT_SEND => ipc_port::release_send(
                IpcPort::from_raw(ptr::with_exposed_provenance_mut(dest_port)),
            ),
            MACH_MSG_TYPE_PORT_SEND_ONCE => ipc_port::release_sonce(
                IpcPort::from_raw(ptr::with_exposed_provenance_mut(dest_port)),
            ),
            _ => strange_destination(),
        }
        (*dest).set_remote(0);
    }

    // SAFETY: the reply header is live.
    let kr = unsafe { (*reply.header().cast::<MigReplyHeader>()).ret_code };
    if kr == KERN_SUCCESS || kr == MIG_NO_REPLY {
        // SAFETY: the request's rights were consumed above and it is owned
        // here.
        unsafe { ipc_kmsg::cache_free(request) };
    } else {
        // SAFETY: the message is live and owned here; the reply port right
        // must survive into the reply.
        unsafe {
            (*request.header()).set_local(0);
            ipc_kmsg::destroy(request);
        }
    }

    if kr == MIG_NO_REPLY {
        // SAFETY: the reply is live and owned here.
        unsafe { ipc_kmsg::ikm_free(reply) };
        return None;
    }

    // SAFETY: the reply header is live.
    let reply_port = unsafe { (*reply.header()).remote() };
    if IpcPort::valid(ptr::with_exposed_provenance_mut(reply_port)).is_none() {
        // SAFETY: the reply is live and owned here.
        unsafe { ipc_kmsg::destroy(reply) };
        return None;
    }

    Some(reply)
}

/// The C `default: panic()` of the destination-rights switch.
fn strange_destination() -> ! {
    kpanic!(
        "ipc_kobject_server",
        "ipc_object_destroy: strange destination rights"
    )
}

/// The `*_server_routine()` inline functions of the generated `*.server.h`
/// headers: pick the MIG entry point for `msgh_id`, or `None`.
fn server_routine(msgh_id: c_int) -> MigRoutine {
    let tables: [(*const MigRoutine, c_int, c_int); 10] = [
        (&raw const glue::mach_server_routines, 2000, 100),
        (&raw const glue::mach_port_server_routines, 3200, 23),
        (&raw const glue::mach_host_server_routines, 2600, 49),
        (&raw const glue::device_server_routines, 2800, 14),
        (&raw const glue::device_pager_server_routines, 2200, 9),
        (&raw const glue::mach_debug_server_routines, 3000, 24),
        (&raw const glue::mach4_server_routines, 4000, 11),
        (&raw const glue::gnumach_server_routines, 4200, 16),
        (&raw const glue::experimental_server_routines, 424_242, -1),
        (&raw const glue::mach_i386_server_routines, 3800, 9),
    ];

    for (table, base, max) in tables {
        if let Some(routine) = table_routine(table, msgh_id, base, max) {
            return Some(routine);
        }
    }
    None
}

/// One generated server table's lookup, with the `msgh_id` base and the
/// largest index its own header allowed.
fn table_routine(
    table: *const MigRoutine,
    msgh_id: c_int,
    base: c_int,
    max: c_int,
) -> MigRoutine {
    let index = msgh_id.wrapping_sub(base);
    if 0 <= index && index <= max {
        // SAFETY: the generated array holds one routine per index up to
        // `max`, and the caller passes the table's own base and size.
        unsafe { *table.add(index as usize) }
    } else {
        None
    }
}
