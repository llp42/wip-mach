// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The send and receive paths behind the `mach_msg` trap.
//!
//! The C's `mach_msg_trap()` carried a second, hand-optimized copy of the
//! send and receive paths: it validated the request's destination and reply
//! ports before copyin, and it handed a blocked receiver the sender's stack
//! instead of queueing.  Every one of its fallbacks ran the generic path in
//! this module, so the two halves returned the same results; the port keeps
//! the generic path and drops the duplicate.

use crate::error::{MsgError, ReceiveError, SendError};
use crate::ipc_kmsg;
use crate::ipc_marequest;
use crate::ipc_mqueue::{self, Received};
use crate::ipc_object;
use crate::ipc_thread::{self, IpcThreadQueue, IpcWait, ThreadRef};
use crate::platform::Platform;
use crate::types::MsgOption;
use crate::{IpcMqueue, IpcPort, IpcSpace, MachMsgHeader};
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, with_exposed_provenance_mut};
use mach_vm::vm_map::VmMap;

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
unsafe fn write_back_size<P: Platform>(user: *mut c_void, size: c_uint) {
    let real_size = size;
    let header = user.cast::<MachMsgHeader>();

    let _ = unsafe {
        P::copyout(
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
unsafe fn complete_receive<P: Platform>(
    received: Received,
    user: *mut c_void,
    option: MsgOption,
    rcv_size: c_uint,
    notify: c_uint,
    space: IpcSpace,
    map: *mut VmMap<P>,
) -> Result<(), ReceiveError> {
    let (kmsg, seqno) = match received {
        Received::Kmsg { kmsg, seqno } => (kmsg, seqno),
        Received::TooLarge { size } => {
            if option.contains(MsgOption::RCV_LARGE) {
                unsafe { write_back_size::<P>(user, size) };
            }
            return Err(ReceiveError::TooLarge);
        }
        Received::Failed { error } => return Err(error),
    };

    // SAFETY: the message is live and this call owns it.
    unsafe { kmsg.set_header_seqno(seqno) };

    // SAFETY: the message is live and this call owns it.
    if !option.contains(MsgOption::RCV_LARGE)
        && unsafe { kmsg.msgh_size() } > rcv_size
    {
        // SAFETY: the message is live and this call owns it.
        unsafe {
            ipc_kmsg::copyout_dest::<P>(kmsg, space);
            let _ = ipc_kmsg::put::<P>(user, kmsg, MESSAGE_HEADER_SIZE);
        }
        return Err(ReceiveError::TooLarge);
    }

    let copied = if option.contains(MsgOption::RCV_NOTIFY) {
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
            let _ = unsafe { ipc_kmsg::put::<P>(user, kmsg, size) };
        } else {
            unsafe {
                ipc_kmsg::copyout_dest::<P>(kmsg, space);
                let _ = ipc_kmsg::put::<P>(user, kmsg, MESSAGE_HEADER_SIZE);
            }
        }

        return Err(error);
    }

    // SAFETY: the message is live and this call owns it.
    let size = unsafe { kmsg.header_size() };
    unsafe { ipc_kmsg::put::<P>(user, kmsg, size) }
}

/// Copies in a user message and queues it on its destination.
///
/// # Safety
///
/// `user` must name a readable user message of `send_size` bytes; `option`,
/// `time_out` and `notify` are plain values, and the caller permits an
/// allocation.
pub(crate) unsafe fn send<P: Platform>(
    user: *mut c_void,
    option: MsgOption,
    send_size: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> Result<(), MsgError> {
    let space = P::current_space();
    let map = P::current_map();

    let kmsg = unsafe { ipc_kmsg::get::<P>(user, send_size) }?;

    let copied = if option.contains(MsgOption::SEND_CANCEL) {
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
        unsafe { ipc_kmsg::free::<P>(kmsg) };
        return Err(error.into());
    }

    let sent = if option.contains(MsgOption::SEND_NOTIFY) {
        // The C passes the timeout bit unconditionally: without
        // `MACH_SEND_TIMEOUT` the send is one non-blocking attempt, and a
        // full queue leaves `kmsg` for the msg-accepted request below.
        let effective_timeout = if option.contains(MsgOption::SEND_TIMEOUT) {
            time_out
        } else {
            MACH_MSG_TIMEOUT_NONE
        };
        // SAFETY: the message holds the rights the queue consumes.
        let mut sent = unsafe {
            ipc_mqueue::send::<P>(
                kmsg.as_ptr(),
                MsgOption::SEND_TIMEOUT,
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
                match unsafe {
                    ipc_marequest::create::<P>(space, dest, notify)
                } {
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
                let _ = unsafe { ipc_mqueue::send_always::<P>(kmsg.as_ptr()) };
                return Err(SendError::WillNotify.into());
            }
        }

        sent
    } else {
        // SAFETY: the message holds the rights the queue consumes.
        unsafe {
            ipc_mqueue::send::<P>(
                kmsg.as_ptr(),
                option & MsgOption::SEND_TIMEOUT,
                time_out,
            )
        }
    };

    if let Err(error) = sent {
        // SAFETY: the message is live, the space is live and unlocked,
        // and the map is the running task's.
        let lost = unsafe { ipc_kmsg::copyout_pseudo(kmsg, space, &mut *map) };

        // SAFETY: the message is live and this call owns it; the size is
        // read after the pseudo-copyout, as the C read `msgh_size`.
        let size = unsafe { kmsg.header_size() };
        let _ = unsafe { ipc_kmsg::put::<P>(user, kmsg, size) };
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
pub(crate) unsafe fn receive<P: Platform>(
    user: *mut c_void,
    option: MsgOption,
    rcv_size: c_uint,
    rcv_name: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> Result<(), ReceiveError> {
    // SAFETY: the running thread is live.
    let saved = unsafe { P::saved_receive(P::current_thread()) }.as_ptr();
    let space = P::current_space();
    let map = P::current_map();

    // SAFETY: the space is live and unlocked; on success the copyin holds a
    // reference for the returned object and leaves its queue locked.
    let copyin = unsafe { ipc_mqueue::copyin::<P>(space, rcv_name) }?;

    // The stack may be discarded if the receive blocks, so the state the
    // continuation needs is saved in the thread first.
    // SAFETY: the current thread is live, and its saved-receive fields take
    // these plain values.
    unsafe {
        (*saved).msg = user;
        (*saved).option = option;
        (*saved).rcv_size = rcv_size;
        (*saved).timeout = time_out;
        (*saved).notify = notify;
        (*saved).object = copyin.object;
        (*saved).mqueue = copyin.mqueue.cast();
    }

    let max_size = if option.contains(MsgOption::RCV_LARGE) {
        rcv_size
    } else {
        MACH_MSG_SIZE_MAX
    };
    // SAFETY: the copyin's reference keeps the object alive and it left the
    // queue locked; the continuation resumes a blocked receive.
    let received = unsafe {
        ipc_mqueue::receive::<P>(
            copyin.mqueue,
            option & MsgOption::RCV_TIMEOUT,
            max_size,
            time_out,
            false,
            Some(P::RECEIVE_CONTINUE),
        )
    };
    // SAFETY: the receive released the queue lock; the copyin's reference to
    // the object is the one this releases.
    unsafe { ipc_object::release::<P>(copyin.object) };

    // SAFETY: the receive released the queue lock and owns the message on
    // success.
    unsafe {
        complete_receive(received, user, option, rcv_size, notify, space, map)
    }
}

/// Resumes a receive after its wait: the body of the receive continuation.
///
/// # Safety
///
/// Called from the continuation [`ipc_mqueue::receive`] stored in the
/// current thread, with the receive state saved by `receive()`; the
/// thread's stack is the one the wakeup supplied.
pub unsafe fn receive_continue<P: Platform>() -> Result<(), ReceiveError> {
    // SAFETY: the running thread is live.
    let saved = unsafe { P::saved_receive(P::current_thread()) }.as_ptr();
    let space = P::current_space();
    let map = P::current_map();

    let (user, option, rcv_size, time_out, notify, object, mqueue) = unsafe {
        (
            (*saved).msg,
            (*saved).option,
            (*saved).rcv_size,
            (*saved).timeout,
            (*saved).notify,
            (*saved).object,
            (*saved).mqueue.cast::<IpcMqueue>(),
        )
    };

    let max_size = if option.contains(MsgOption::RCV_LARGE) {
        rcv_size
    } else {
        MACH_MSG_SIZE_MAX
    };
    // SAFETY: the handoff left the queue unlocked and this thread queued in
    // it; the resume picks the message up.
    let received = unsafe {
        ipc_mqueue::receive::<P>(
            mqueue,
            option & MsgOption::RCV_TIMEOUT,
            max_size,
            time_out,
            true,
            Some(P::RECEIVE_CONTINUE),
        )
    };
    // SAFETY: the receive released the queue lock; the object reference is the
    // one the copyin in `receive()` took.
    unsafe { ipc_object::release::<P>(object) };

    unsafe {
        complete_receive(received, user, option, rcv_size, notify, space, map)
    }
}

/// Sends, receives or does both, as the options ask.
///
/// # Safety
///
/// `user` must name a readable and writable user message of the sizes
/// `option` selects; `option`, `send_size`, `rcv_size`, `rcv_name`,
/// `time_out` and `notify` are plain values; the caller holds no locks.
pub unsafe fn trap<P: Platform>(
    user: *mut c_void,
    option: MsgOption,
    send_size: c_uint,
    rcv_size: c_uint,
    rcv_name: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> Result<(), MsgError> {
    if option.is_empty() {
        // The C returned through `thread_syscall_return()`; the trap's
        // normal return reaches user space with the same code.
        return Ok(());
    }

    if option.contains(MsgOption::SEND_MSG) {
        unsafe { send::<P>(user, option, send_size, time_out, notify) }?;
    }

    if option.contains(MsgOption::RCV_MSG) {
        unsafe {
            receive::<P>(user, option, rcv_size, rcv_name, time_out, notify)
        }?;
    }

    Ok(())
}

/// Resumes a send-and-receive after its wait: the body of its continuation.
///
/// # Safety
///
/// Called from the continuation [`ipc_mqueue::receive`] stored in the
/// current thread, with the receive state saved by the send-and-receive trap
/// path; the thread's stack is the one the wakeup supplied.
pub unsafe fn msg_continue<P: Platform>() -> Result<(), ReceiveError> {
    // SAFETY: the running thread is live.
    let saved = unsafe { P::saved_receive(P::current_thread()) }.as_ptr();
    let space = P::current_space();
    let map = P::current_map();

    let (user, rcv_size, object, mqueue) = unsafe {
        (
            (*saved).msg,
            (*saved).rcv_size,
            (*saved).object,
            (*saved).mqueue.cast::<IpcMqueue>(),
        )
    };

    // SAFETY: the combined path uses no options; the handoff left the queue
    // unlocked and this thread queued in it.
    let received = unsafe {
        ipc_mqueue::receive::<P>(
            mqueue,
            MsgOption::empty(),
            MACH_MSG_SIZE_MAX,
            MACH_MSG_TIMEOUT_NONE,
            true,
            Some(P::MSG_CONTINUE),
        )
    };
    // SAFETY: the receive released the queue lock; the object reference is
    // the one the copyin in the trap path took.
    unsafe { ipc_object::release::<P>(object) };

    // SAFETY: the combined path copies out with no options and no notify
    // name; the message is owned on success.
    unsafe {
        complete_receive(
            received,
            user,
            MsgOption::empty(),
            rcv_size,
            MACH_PORT_NULL,
            space,
            map,
        )
    }
}

/// Takes `thread` out of the message wait it is in, returning whether it was
/// in one; the caller then makes the thread's receive return
/// [`ReceiveError::Interrupted`].
///
/// # Safety
///
/// `thread` must be a live thread that is not runnable, and its receive
/// state must be the one a blocked `mach_msg` left; nothing may be locked.
#[must_use]
pub unsafe fn interrupt<P: Platform>(thread: ThreadRef) -> bool {
    let saved = unsafe { P::saved_receive(thread) }.as_ptr();
    let mqueue = unsafe { (*saved).mqueue.cast::<IpcMqueue>() };

    // SAFETY: a blocked receive left the queue live; the lock serializes
    // its thread list.
    unsafe { (*mqueue).lock() };

    // SAFETY: the thread is live.
    if unsafe { (*P::thread_ipc(thread).as_ptr()).state } != IpcWait::Receiving
    {
        // SAFETY: the queue is live and locked.
        unsafe { (*mqueue).unlock() };
        return false;
    }

    // SAFETY: the queue is live and locked and the thread is queued in it.
    unsafe {
        ipc_thread::ipc_thread_rmqueue::<P>(
            (*mqueue).threads().cast::<IpcThreadQueue>(),
            thread.as_ptr(),
        );
    };
    // SAFETY: the queue is live and locked.
    unsafe { (*mqueue).unlock() };

    // SAFETY: the thread holds the receive's reference to the object.
    unsafe { ipc_object::release::<P>((*saved).object) };

    true
}
