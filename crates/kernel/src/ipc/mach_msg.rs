// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/mach_msg.c and ipc/mach_msg.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The exported message traps.
//!
//! The C's `mach_msg_trap()` carried a second, hand-optimized copy of the
//! send and receive paths: it validated the request's destination and reply
//! ports before copyin, and it handed a blocked receiver the sender's stack
//! instead of queueing.  Every one of its fallbacks ran the generic path in
//! this module, so the two halves returned the same results; the port keeps
//! the generic path and drops the duplicate.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::user_access;
use crate::ipc::error::{MsgError, ReceiveError, SendError};
use crate::ipc::ipc_kmsg;
use crate::ipc::ipc_marequest;
use crate::ipc::ipc_mqueue::{self, Received};
use crate::ipc::ipc_object;
use crate::ipc::ipc_thread::{self, IpcThreadQueue, IpcWait};
use crate::ipc::{IpcMqueue, IpcPort, IpcSpace, MachMsgHeader};
use crate::kern::ipc_mig::{current_map, current_space};
use crate::kern::thread::Thread;
use crate::mig::code::kern_return;
use crate::vm::vm_map::VmMap;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, with_exposed_provenance_mut};

/// The option to send a message.
const MACH_SEND_MSG: c_uint = 0x0000_0001;
/// The option to receive a message.
const MACH_RCV_MSG: c_uint = 0x0000_0002;
/// The send option asking for a timeout.
const MACH_SEND_TIMEOUT: c_uint = 0x0000_0010;
/// The send option asking for a msg-accepted notification on a full queue.
const MACH_SEND_NOTIFY: c_uint = 0x0000_0020;
/// The send option that cancels a msg-accepted request instead of sending.
const MACH_SEND_CANCEL: c_uint = 0x0000_0080;
/// The receive option asking for a timeout.
const MACH_RCV_TIMEOUT: c_uint = 0x0000_0100;
/// The receive option naming a reply destination in the notify name.
const MACH_RCV_NOTIFY: c_uint = 0x0000_0200;
/// The receive option that reports the needed size instead of discarding an
/// oversized message.
const MACH_RCV_LARGE: c_uint = 0x0000_0800;
/// No timeout.
const MACH_MSG_TIMEOUT_NONE: c_uint = 0;
/// The largest message size, an unbounded receive.
const MACH_MSG_SIZE_MAX: c_uint = c_uint::MAX;
/// The null port name.
const MACH_PORT_NULL: c_uint = 0;
/// `sizeof(mach_msg_user_header_t)`: the user header's size.
const MESSAGE_HEADER_SIZE: c_uint = size_of::<MachMsgHeader>() as c_uint;

/// A `mach_port_t` back to the kernel pointer it carries.
const fn ptr_at(address: usize) -> *mut c_void {
    with_exposed_provenance_mut(address)
}

/// The `copyout(&real_size, &msg->msgh_size, sizeof real_size)` of a
/// `MACH_RCV_LARGE` receive that did not fit; the C ignored the status.
///
/// # Safety
///
/// `user` must name a writable user message header.
unsafe fn write_back_size(user: *mut c_void, size: c_uint) {
    let real_size = size;
    let header = user.cast::<MachMsgHeader>();

    let _ = unsafe {
        user_access::copyout(
            ptr::addr_of!(real_size).cast(),
            ptr::addr_of_mut!((*header).size).cast(),
            size_of::<c_uint>(),
        )
    };
}

/// The tail both receive entries share: the sequence number, the size check
/// and the copyout of one [`ipc_mqueue::receive`] result.
///
/// # Safety
///
/// `user` must name a writable user message of `rcv_size` bytes; `space` and
/// `map` must be live and unlocked; `received` must be one result of a
/// receive whose queue reference the caller already released, and on the
/// `Kmsg` arm that message is this call's to consume.
// The match below moves the owned `Kmsg` out of `received`; the lint misses
// the partial move and asks for a reference that cannot own the message.
#[allow(clippy::needless_pass_by_value)]
unsafe fn complete_receive(
    received: Received,
    user: *mut c_void,
    option: c_uint,
    rcv_size: c_uint,
    notify: c_uint,
    space: IpcSpace,
    map: *mut VmMap,
) -> Result<(), ReceiveError> {
    let (kmsg, seqno) = match received {
        Received::Kmsg { kmsg, seqno } => (kmsg, seqno),
        Received::TooLarge { size } => {
            if option & MACH_RCV_LARGE != 0 {
                unsafe { write_back_size(user, size) };
            }
            return Err(ReceiveError::TooLarge);
        }
        Received::Failed { error } => return Err(error),
    };

    // SAFETY: the message is live and this call owns it.
    unsafe { kmsg.set_header_seqno(seqno) };

    // SAFETY: the message is live and this call owns it.
    if option & MACH_RCV_LARGE == 0 && unsafe { kmsg.msgh_size() } > rcv_size {
        // SAFETY: the message is live and this call owns it.
        unsafe {
            ipc_kmsg::copyout_dest(kmsg, space);
            let _ = ipc_kmsg::put(user, kmsg, MESSAGE_HEADER_SIZE);
        }
        return Err(ReceiveError::TooLarge);
    }

    let copied = if option & MACH_RCV_NOTIFY != 0 {
        if notify == MACH_PORT_NULL {
            Err(ReceiveError::InvalidNotify)
        } else {
            // SAFETY: the message holds the rights the copyout consumes, and
            // the space and map are live and unlocked.
            unsafe { ipc_kmsg::copyout(kmsg, space, &mut *map, notify) }
        }
    } else {
        unsafe { ipc_kmsg::copyout(kmsg, space, &mut *map, MACH_PORT_NULL) }
    };

    if let Err(error) = copied {
        if matches!(error, ReceiveError::Body(_)) {
            // SAFETY: the message is live and this call owns it.
            let size = unsafe { kmsg.header_size() };
            let _ = unsafe { ipc_kmsg::put(user, kmsg, size) };
        } else {
            unsafe {
                ipc_kmsg::copyout_dest(kmsg, space);
                let _ = ipc_kmsg::put(user, kmsg, MESSAGE_HEADER_SIZE);
            }
        }

        return Err(error);
    }

    // SAFETY: the message is live and this call owns it.
    let size = unsafe { kmsg.header_size() };
    unsafe { ipc_kmsg::put(user, kmsg, size) }
}

/// Copies in a user message and queues it on its destination.
///
/// # Safety
///
/// `user` must name a readable user message of `send_size` bytes; `option`,
/// `time_out` and `notify` are plain values, and the caller permits an
/// allocation.
pub(crate) unsafe fn send(
    user: *mut c_void,
    option: c_int,
    send_size: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> Result<(), MsgError> {
    // The C option word is an `int` whose low bits the masks below select;
    // reading its pattern as unsigned keeps the same bits.
    let bits = option as c_uint;
    let space = current_space();
    let map = current_map();

    let kmsg = unsafe { ipc_kmsg::get(user, send_size) }?;

    let copied = if bits & MACH_SEND_CANCEL != 0 {
        if notify == MACH_PORT_NULL {
            Err(SendError::InvalidNotify)
        } else {
            // SAFETY: the message is live; the space and map are live and
            // unlocked.
            unsafe { ipc_kmsg::copyin(kmsg, space, &mut *map, notify) }
        }
    } else {
        unsafe { ipc_kmsg::copyin(kmsg, space, &mut *map, MACH_PORT_NULL) }
    };
    if let Err(error) = copied {
        // SAFETY: the message is live and this call owns it.
        unsafe { ipc_kmsg::free(kmsg) };
        return Err(error.into());
    }

    let sent = if bits & MACH_SEND_NOTIFY != 0 {
        // The C passes the timeout bit unconditionally: without
        // `MACH_SEND_TIMEOUT` the send is one non-blocking attempt, and a
        // full queue leaves `kmsg` for the msg-accepted request below.
        let effective_timeout = if bits & MACH_SEND_TIMEOUT != 0 {
            time_out
        } else {
            MACH_MSG_TIMEOUT_NONE
        };
        // SAFETY: the message holds the rights the queue consumes.
        let mut sent = unsafe {
            ipc_mqueue::send(
                kmsg.as_ptr(),
                MACH_SEND_TIMEOUT,
                effective_timeout,
            )
        };

        if sent == Err(SendError::TimedOut) {
            if notify == MACH_PORT_NULL {
                sent = Err(SendError::InvalidNotify);
            } else {
                // SAFETY: the message's destination right is live.
                let dest =
                    unsafe { IpcPort::from_raw(ptr_at(kmsg.remote_port())) };
                // SAFETY: the space is live and unlocked; the caller permits
                // the allocation.
                match unsafe { ipc_marequest::create(space, dest, notify) } {
                    Ok(marequest) => {
                        // SAFETY: the message is live and uniquely owned.
                        unsafe { kmsg.set_marequest(marequest.cast()) };
                        sent = Ok(());
                    }
                    Err(error) => sent = Err(error),
                }
            }

            if sent.is_ok() {
                // SAFETY: the message holds the rights the queue consumes;
                // an unlimited send always queues it.
                let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
                return Err(SendError::WillNotify.into());
            }
        }

        sent
    } else {
        // SAFETY: the message holds the rights the queue consumes.
        unsafe {
            ipc_mqueue::send(kmsg.as_ptr(), bits & MACH_SEND_TIMEOUT, time_out)
        }
    };

    if let Err(error) = sent {
        // SAFETY: the message is live, the space is live and unlocked,
        // and the map is the running task's.
        let lost = unsafe { ipc_kmsg::copyout_pseudo(kmsg, space, &mut *map) };

        // SAFETY: the message is live and this call owns it; the size is
        // read after the pseudo-copyout, as the C read `msgh_size`.
        let size = unsafe { kmsg.header_size() };
        let _ = unsafe { ipc_kmsg::put(user, kmsg, size) };
        return Err(MsgError::Send(error, lost));
    }

    Ok(())
}

/// Receives a message into the user buffer.
///
/// # Safety
///
/// `user` must name a writable user message of `rcv_size` bytes; `option`,
/// `rcv_name`, `time_out` and `notify` are plain values; `space` must be
/// live and unlocked.
pub(crate) unsafe fn receive(
    user: *mut c_void,
    option: c_int,
    rcv_size: c_uint,
    rcv_name: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> Result<(), ReceiveError> {
    // The C option word is an `int` whose low bits the masks below select;
    // reading its pattern as unsigned keeps the same bits.
    let bits = option as c_uint;
    let self_ = per_cpu::thread();
    let space = current_space();
    let map = current_map();

    // SAFETY: the space is live and unlocked; on success the copyin holds a
    // reference for the returned object and leaves its queue locked.
    let copyin = unsafe { ipc_mqueue::copyin(space, rcv_name) }?;

    // The stack may be discarded if the receive blocks, so the state the
    // continuation needs is saved in the thread first.
    // SAFETY: the current thread is live, and its saved-receive fields take
    // these plain values.
    unsafe {
        (*self_).saved.receive.msg = user;
        (*self_).saved.receive.option = option;
        (*self_).saved.receive.rcv_size = rcv_size;
        (*self_).saved.receive.timeout = time_out;
        (*self_).saved.receive.notify = notify;
        (*self_).saved.receive.object = copyin.object;
        (*self_).saved.receive.mqueue = copyin.mqueue.cast();
    }

    let max_size = if bits & MACH_RCV_LARGE != 0 {
        rcv_size
    } else {
        MACH_MSG_SIZE_MAX
    };
    // SAFETY: the copyin's reference keeps the object alive and it left the
    // queue locked; the continuation resumes a blocked receive.
    let received = unsafe {
        ipc_mqueue::receive(
            copyin.mqueue,
            bits & MACH_RCV_TIMEOUT,
            max_size,
            time_out,
            false,
            Some(mach_msg_receive_continue),
        )
    };
    // SAFETY: the receive released the queue lock; the copyin's reference to
    // the object is the one this releases.
    unsafe { ipc_object::release(copyin.object) };

    // SAFETY: the receive released the queue lock and owns the message on
    // success.
    unsafe {
        complete_receive(received, user, bits, rcv_size, notify, space, map)
    }
}

/// The continuation a receive resumes through after its wait.
///
/// # Safety
///
/// Called as the continuation [`ipc_mqueue::receive`] stored in the current
/// thread, with the receive state saved by [`receive()`]; the thread's stack
/// is the one the wakeup supplied.
pub(crate) unsafe extern "C" fn mach_msg_receive_continue() {
    let self_ = per_cpu::thread();
    let space = current_space();
    let map = current_map();

    let (user, option, rcv_size, time_out, notify, object, mqueue) = unsafe {
        (
            (*self_).saved.receive.msg,
            (*self_).saved.receive.option,
            (*self_).saved.receive.rcv_size,
            (*self_).saved.receive.timeout,
            (*self_).saved.receive.notify,
            (*self_).saved.receive.object,
            (*self_).saved.receive.mqueue.cast::<IpcMqueue>(),
        )
    };
    // The C option word is an `int` whose low bits the masks below select;
    // reading its pattern as unsigned keeps the same bits.
    let bits = option as c_uint;

    let max_size = if bits & MACH_RCV_LARGE != 0 {
        rcv_size
    } else {
        MACH_MSG_SIZE_MAX
    };
    // SAFETY: the handoff left the queue unlocked and this thread queued in
    // it; the resume picks the message up.
    let received = unsafe {
        ipc_mqueue::receive(
            mqueue,
            bits & MACH_RCV_TIMEOUT,
            max_size,
            time_out,
            true,
            Some(mach_msg_receive_continue),
        )
    };
    // SAFETY: the receive released the queue lock; the object reference is the
    // one the copyin in `receive()` took.
    unsafe { ipc_object::release(object) };

    let completed = unsafe {
        complete_receive(received, user, bits, rcv_size, notify, space, map)
    };
    // SAFETY: `thread_syscall_return` returns to user space and never
    // returns to this continuation.
    unsafe {
        crate::arch::x86_64::locore::thread_syscall_return(kern_return(
            completed,
        ));
    }
}

/// Sends, receives or does both, as the options ask.
///
/// # Safety
///
/// `user` must name a readable and writable user message of the sizes
/// `option` selects; `option`, `send_size`, `rcv_size`, `rcv_name`,
/// `time_out` and `notify` are plain values; the caller holds no locks.
pub(crate) unsafe fn trap(
    user: *mut c_void,
    option: c_int,
    send_size: c_uint,
    rcv_size: c_uint,
    rcv_name: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> Result<(), MsgError> {
    // The C option word is an `int` whose low bits the masks below select;
    // reading its pattern as unsigned keeps the same bits.
    let bits = option as c_uint;

    if bits == 0 {
        // The C returned through `thread_syscall_return()`; the trap's
        // normal return reaches user space with the same code.
        return Ok(());
    }

    if bits & MACH_SEND_MSG != 0 {
        unsafe { send(user, option, send_size, time_out, notify) }?;
    }

    if bits & MACH_RCV_MSG != 0 {
        unsafe {
            receive(user, option, rcv_size, rcv_name, time_out, notify)
        }?;
    }

    Ok(())
}

/// The continuation the send-and-receive trap resumes through after its wait.
///
/// # Safety
///
/// Called as the continuation [`ipc_mqueue::receive`] stored in the current
/// thread, with the receive state saved by the send-and-receive trap path; the
/// thread's stack is the one the wakeup supplied.
pub(crate) unsafe extern "C" fn mach_msg_continue() {
    let self_ = per_cpu::thread();
    let space = current_space();
    let map = current_map();

    let (user, rcv_size, object, mqueue) = unsafe {
        (
            (*self_).saved.receive.msg,
            (*self_).saved.receive.rcv_size,
            (*self_).saved.receive.object,
            (*self_).saved.receive.mqueue.cast::<IpcMqueue>(),
        )
    };

    // SAFETY: the combined path uses no options; the handoff left the queue
    // unlocked and this thread queued in it.
    let received = unsafe {
        ipc_mqueue::receive(
            mqueue,
            0,
            MACH_MSG_SIZE_MAX,
            MACH_MSG_TIMEOUT_NONE,
            true,
            Some(mach_msg_continue),
        )
    };
    // SAFETY: the receive released the queue lock; the object reference is
    // the one the copyin in the trap path took.
    unsafe { ipc_object::release(object) };

    // SAFETY: the combined path copies out with no options and no notify
    // name; the message is owned on success.
    let completed = unsafe {
        complete_receive(
            received,
            user,
            0,
            rcv_size,
            MACH_PORT_NULL,
            space,
            map,
        )
    };
    // SAFETY: `thread_syscall_return` returns to user space and never
    // returns to this continuation.
    unsafe {
        crate::arch::x86_64::locore::thread_syscall_return(kern_return(
            completed,
        ));
    }
}

/// Interrupts the message wait `thread` is in, returning whether it was in
/// one.
///
/// # Safety
///
/// `thread` must be a live thread that is not runnable, and its receive
/// state must be the one a blocked `mach_msg` left; nothing may be locked.
pub(crate) unsafe fn interrupt(thread: *mut Thread) -> bool {
    let mqueue = unsafe { (*thread).saved.receive.mqueue.cast::<IpcMqueue>() };

    // SAFETY: a blocked receive left the queue live; the lock serializes
    // its thread list.
    unsafe { (*mqueue).lock() };

    // SAFETY: the thread is live.
    if unsafe { (*thread).ith_state } != IpcWait::Receiving {
        // SAFETY: the queue is live and locked.
        unsafe { (*mqueue).unlock() };
        return false;
    }

    // SAFETY: the queue is live and locked and the thread is queued in it.
    unsafe {
        ipc_thread::ipc_thread_rmqueue(
            (*mqueue).threads().cast::<IpcThreadQueue>(),
            thread.cast(),
        );
    };
    // SAFETY: the queue is live and locked.
    unsafe { (*mqueue).unlock() };

    // SAFETY: the thread holds the receive's reference to the object.
    unsafe { ipc_object::release((*thread).saved.receive.object) };
    // SAFETY: the thread is live and not runnable, so storing its syscall
    // return and its resume point is safe.
    unsafe {
        crate::arch::x86_64::pcb::thread_set_syscall_return(
            thread,
            c_int::from(ReceiveError::Interrupted),
        );
        (*thread).swap_func =
            Some(crate::arch::x86_64::locore::thread_exception_return);
    }

    true
}
/// The `mach_msg` trap entry the trap table holds.
///
/// # Safety
///
/// `msg` must name a readable and writable user message of the sizes
/// `option` selects; the caller is the trap dispatcher and holds no locks.
pub(crate) unsafe extern "C" fn mach_msg_trap(
    msg: *mut c_void,
    option: c_int,
    send_size: c_uint,
    rcv_size: c_uint,
    rcv_name: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> c_int {
    kern_return(unsafe {
        trap(msg, option, send_size, rcv_size, rcv_name, time_out, notify)
    })
}
