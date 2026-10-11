// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kernel-object ports.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::platform::MachPlatform;
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::mig;
use crate::mig::MigRoutine;
use crate::mig::code::{KERN_SUCCESS, MIG_BAD_ID, MIG_NO_REPLY};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use mach_ipc::ipc_kmsg::{self, Kmsg};
use mach_ipc::ipc_port;
use mach_ipc::types::MsghBits;
use mach_ipc::{IpcPort, MachMsgHeader, MachMsgType, MigReplyHeader};
use mach_thread::task::kernel_task;

/// A memory object's pager.
const IKOT_PAGER: c_uint = 8;
/// The kernel-object type of a device port.
const IKOT_DEVICE: c_uint = 10;
/// The kernel-object type of a pager port whose object is terminating.
const IKOT_PAGER_TERMINATING: c_uint = 15;
/// The kernel-object type of a proxy pager port.
const IKOT_PAGER_PROXY: c_uint = 27;

/// `MACH_MSG_TYPE_PORT_SEND`, the wire alias `MACH_MSG_TYPE_MOVE_SEND`.
const MACH_MSG_TYPE_PORT_SEND: u32 = 17;
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`, the wire alias
/// `MACH_MSG_TYPE_MOVE_SEND_ONCE`.
const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = 18;
/// The type of a 32-bit integer in a message body.
const MACH_MSG_TYPE_INTEGER_32: u32 = 2;

/// The message id of a port-deleted notification.
const MACH_NOTIFY_PORT_DELETED: c_int = 65;
/// The message id of a msg-accepted notification.
const MACH_NOTIFY_MSG_ACCEPTED: c_int = 66;
/// The message id of a port-destroyed notification.
const MACH_NOTIFY_PORT_DESTROYED: c_int = 67;
/// The message id of a no-senders notification.
const MACH_NOTIFY_NO_SENDERS: c_int = 68;
/// The message id of a send-once notification.
const MACH_NOTIFY_SEND_ONCE: c_int = 69;
/// The message id of a dead-name notification.
const MACH_NOTIFY_DEAD_NAME: c_int = 70;

/// The bound [`server`] gives a reply body, before the message overhead is
/// subtracted.
const MAX_REPLY_BODY: usize = 8192;

/// The descriptor word of a `mach_msg_type_t` initializer under the 64-bit
/// bitfield layout.
const fn descriptor_word(name: u32, size: u32) -> u32 {
    name | (size << 8) | (1 << 29)
}

/// The type of a reply's return code: an inline 32-bit integer.
const RETCODE_TYPE: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_INTEGER_32, 32), 1);

/// Names a kernel object in a port, taking and releasing the port lock.
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

/// Releases the resources a destroyed port still names.
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
            unsafe {
                mach_vm::vm_object::destroy::<MachPlatform>(port.as_ptr());
            }
        }
        IKOT_PAGER_TERMINATING => {
            // SAFETY: a port of this type names a live memory object.
            unsafe {
                mach_vm::vm_object::pager_wakeup::<MachPlatform>(
                    port.as_ptr(),
                );
            }
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

/// Delivers a notification to a port whose kernel object wants it.
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
            mach_device::ds_routines::ds_notify::<MachPlatform>(
                request_header.cast(),
            )
        },
        // SAFETY: the remote port is the one the notification names.
        IKOT_PAGER_PROXY => unsafe {
            mach_vm::memory_object_proxy::notify::<MachPlatform>(
                (*request_header).id(),
                port.as_ptr(),
            )
        },
        _ => false,
    }
}

/// Handles a message sent to the kernel and generates its reply.
///
/// # Safety
///
/// `request` must be a live kernel message the caller owns, and nothing may
/// be locked.
pub(crate) unsafe fn server(request: Kmsg) -> Option<Kmsg> {
    let reply_body = MAX_REPLY_BODY - ipc_kmsg::IKM_OVERHEAD;
    let Some(reply) = ipc_kmsg::ikm_alloc::<MachPlatform>(reply_body) else {
        // SAFETY: the request is owned and live.
        unsafe {
            kprint!("ipc_kobject_server: dropping request\n");
            ipc_kmsg::destroy::<MachPlatform>(request);
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
            .set_bits(MsghBits::new((*input).bits().local(), 0));
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
            // SAFETY: the MIG routine takes the request and reply headers, and
            // the kernel task is live from boot.
            unsafe {
                routine(head.cast(), reply.header().cast());
                (*kernel_task::<MachPlatform>()).messages_received =
                    (*kernel_task::<MachPlatform>())
                        .messages_received
                        .wrapping_add(1);
            }
        }
        None => {
            // SAFETY: the headers are live and writable.
            if unsafe { notify(head, reply.header()) } {
                unsafe {
                    (*kernel_task::<MachPlatform>()).messages_received =
                        (*kernel_task::<MachPlatform>())
                            .messages_received
                            .wrapping_add(1);
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
        (*kernel_task::<MachPlatform>()).messages_sent =
            (*kernel_task::<MachPlatform>())
                .messages_sent
                .wrapping_add(1);
    };

    // SAFETY: the request header is live; the switch handles exactly the two
    // destination rights the C expected.
    unsafe {
        let dest = request.header();
        let dest_port = (*dest).remote();
        match (*dest).bits().remote() {
            MACH_MSG_TYPE_PORT_SEND => ipc_port::release_send::<MachPlatform>(
                IpcPort::from_raw(ptr::with_exposed_provenance_mut(dest_port)),
            ),
            MACH_MSG_TYPE_PORT_SEND_ONCE => {
                ipc_port::release_sonce::<MachPlatform>(IpcPort::from_raw(
                    ptr::with_exposed_provenance_mut(dest_port),
                ));
            }
            _ => strange_destination(),
        }
        (*dest).set_remote(0);
    }

    // SAFETY: the reply header is live.
    let kr = unsafe { (*reply.header().cast::<MigReplyHeader>()).ret_code };
    if kr == KERN_SUCCESS || kr == MIG_NO_REPLY {
        // SAFETY: the request's rights were consumed above and it is owned
        // here.
        unsafe { ipc_kmsg::cache_free::<MachPlatform>(request) };
    } else {
        // SAFETY: the message is live and owned here; the reply port right
        // must survive into the reply.
        unsafe {
            (*request.header()).set_local(0);
            ipc_kmsg::destroy::<MachPlatform>(request);
        }
    }

    if kr == MIG_NO_REPLY {
        // SAFETY: the reply is live and owned here.
        unsafe { ipc_kmsg::ikm_free::<MachPlatform>(reply) };
        return None;
    }

    // SAFETY: the reply header is live.
    let reply_port = unsafe { (*reply.header()).remote() };
    if IpcPort::valid(ptr::with_exposed_provenance_mut(reply_port)).is_none() {
        // SAFETY: the reply is live and owned here.
        unsafe { ipc_kmsg::destroy::<MachPlatform>(reply) };
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

/// Picks the generated MIG entry point for `msgh_id`, or `None`.
///
/// Each table answers the ids from its base on, one per entry.
fn server_routine(msgh_id: c_int) -> MigRoutine {
    let tables: [(&[MigRoutine], c_int); 9] = [
        (&mig::mach_server_routines, 2000),
        (&mig::mach_port_server_routines, 3200),
        (&mig::mach_host_server_routines, 2600),
        (&mig::device_server_routines, 2800),
        (&mig::device_pager_server_routines, 2200),
        (&mig::mach_debug_server_routines, 3000),
        (&mig::mach4_server_routines, 4000),
        (&mig::gnumach_server_routines, 4200),
        (&mig::mach_i386_server_routines, 3800),
    ];

    tables.into_iter().find_map(|(table, base)| {
        let index = usize::try_from(msgh_id.wrapping_sub(base)).ok()?;
        table.get(index).copied().flatten()
    })
}
