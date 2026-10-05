// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_mqueue.c and ipc/ipc_mqueue.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The message-queue routines, which `ipc/ipc_mqueue.c` used to define and
//! `ipc/ipc_mqueue.h` declares.

use crate::arch::x86_64::per_cpu;
use crate::ipc::error::{ReceiveError, SendError};
use crate::ipc::ipc_kmsg::{self, Kmsg};
use crate::ipc::ipc_marequest;
use crate::ipc::ipc_pset;
use crate::ipc::ipc_space;
use crate::ipc::ipc_thread;
use crate::ipc::ipc_thread::{IpcThreadQueue, IpcWait};
use crate::ipc::{
    IpcMarequest, IpcMqueue, IpcPort, IpcSpace, IpcTarget,
    MACH_PORT_TYPE_PORT_SET, MACH_PORT_TYPE_RECEIVE,
};
use crate::kern::debug::kpanic;
use crate::kern::ipc_kobject;
use crate::kern::ipc_sched::{
    thread_go, thread_will_wait, thread_will_wait_with_timeout,
};
use crate::kern::sched_prim::thread_block;
use crate::kern::task::current_task;
use crate::kern::thread::{Continuation, IpcKmsgQueue, Thread};
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, with_exposed_provenance_mut};

/// `MACH_MSGH_BITS_REMOTE_MASK` of <mach/message.h>.
const MACH_MSGH_BITS_REMOTE_MASK: u32 = 0x0000_00ff;
/// `MACH_MSGH_BITS_CIRCULAR` of <mach/message.h>: a message sent to itself.
const MACH_MSGH_BITS_CIRCULAR: u32 = 0x4000_0000;
/// `MACH_MSG_TYPE_PORT_SEND_ONCE` of <mach/message.h>.
const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = 18;
/// `MACH_SEND_TIMEOUT` of <mach/message.h>: the caller wants a timeout.
const MACH_SEND_TIMEOUT: c_uint = 0x0000_0010;
/// `MACH_RCV_TIMEOUT` of <mach/message.h>: the caller wants a timeout.
const MACH_RCV_TIMEOUT: c_uint = 0x0000_0100;
/// `MACH_SEND_ALWAYS` of <mach/message.h>: internal, ignore the queue limit.
const MACH_SEND_ALWAYS: c_uint = 0x0001_0000;
/// `MACH_MSG_TIMEOUT_NONE` of <mach/message.h>.
const MACH_MSG_TIMEOUT_NONE: c_uint = 0;
/// `MACH_PORT_NULL` of <mach/port.h>.
const MACH_PORT_NULL: usize = 0;
/// `THREAD_TIMED_OUT` of <`kern/sched_prim.h`>.
const THREAD_TIMED_OUT: c_int = 1;
/// `THREAD_INTERRUPTED` of <`kern/sched_prim.h`>.
const THREAD_INTERRUPTED: c_int = 2;

/// The object and locked queue `ipc_mqueue_copyin()` returned.
pub(crate) struct Copyin {
    pub(crate) object: *mut c_void,
    pub(crate) mqueue: *mut IpcMqueue,
}

/// What `ipc_mqueue_receive()` produced.
pub(crate) enum Received {
    /// A message and the sequence number of its delivery.
    Kmsg { kmsg: Kmsg, seqno: c_uint },
    /// The receiver's buffer is too small; this is the size it needs.
    TooLarge { size: c_uint },
    /// The receive failed.
    Failed { error: ReceiveError },
}

/// Which object a copyin holds locked.
enum Held {
    Port(IpcPort),
    Target(*mut IpcTarget),
}

/// A `mach_port_t` back to the kernel pointer it carries.
const fn ptr_at(address: usize) -> *mut c_void {
    with_exposed_provenance_mut(address)
}

/// `ipc_mqueue_init()` in C.
///
/// # Safety
///
/// `mqueue` must point at writable storage for a fresh message queue that no
/// other thread can see.
pub(crate) unsafe fn init(mqueue: *mut IpcMqueue) {
    unsafe {
        (*mqueue).lock.init();
        (*(*mqueue).messages().cast::<IpcKmsgQueue>()).base = ptr::null_mut();
        (*(*mqueue).threads().cast::<IpcThreadQueue>()).init();
    }
}

/// `ipc_mqueue_move()` in C.
///
/// # Safety
///
/// `dest` and `source` must point at live queues, both locked, and `port` must
/// be a live port those locks keep alive.
pub(crate) unsafe fn move_messages(
    dest: *mut IpcMqueue,
    source: *mut IpcMqueue,
    port: IpcPort,
) {
    unsafe {
        let oldq = (*source).messages().cast::<IpcKmsgQueue>();
        let newq = (*dest).messages().cast::<IpcKmsgQueue>();
        let blockedq = (*dest).threads().cast::<IpcThreadQueue>();

        let mut kmsg = (*oldq).base;
        while !kmsg.is_null() {
            let message = Kmsg::from_raw(kmsg);
            let next = ipc_kmsg::queue_next(oldq, message);

            if message.remote_port() == port.as_ptr().addr() {
                ipc_kmsg::rmqueue(oldq, message);

                let mut delivered = false;
                loop {
                    let th = ipc_thread::ipc_thread_dequeue(blockedq);
                    if th.is_null() {
                        break;
                    }

                    let th = th.cast::<Thread>();
                    thread_go(th);

                    if message.msgh_size() <= (*th).data.msize {
                        (*th).ith_state = IpcWait::Done;
                        (*th).data.kmsg = message.as_ptr();
                        (*th).ith_seqno = port.seqno();
                        port.set_seqno(port.seqno().wrapping_add(1));
                        delivered = true;
                        break;
                    }

                    (*th).ith_state = IpcWait::TooLarge;
                    (*th).data.msize = message.msgh_size();
                }

                if !delivered {
                    ipc_kmsg::enqueue(newq, message);
                }
            }

            kmsg = next.map_or(ptr::null_mut(), Kmsg::as_ptr);
        }
    }
}

/// `ipc_mqueue_changed()` in C: wake every receiver with `state`, the port
/// dying or moving into a port set.
///
/// # Safety
///
/// `mqueue` must point at a live locked queue.
pub(crate) unsafe fn changed(mqueue: *mut IpcMqueue, state: IpcWait) {
    unsafe {
        let threads = (*mqueue).threads().cast::<IpcThreadQueue>();

        loop {
            let th = ipc_thread::ipc_thread_dequeue(threads);
            if th.is_null() {
                break;
            }

            let th = th.cast::<Thread>();
            (*th).ith_state = state;
            thread_go(th);
        }
    }
}

/// `ipc_mqueue_send()` in C.
///
/// # Safety
///
/// `kmsg` must be a live message the caller owns, holding a reference for the
/// destination port; nothing may be locked.
pub(crate) unsafe fn send(
    kmsg: *mut c_void,
    option: c_uint,
    time_out: c_uint,
) -> Result<(), SendError> {
    let kmsg = unsafe { Kmsg::from_raw(kmsg) };
    // SAFETY: the message's destination right is live.
    let port = unsafe { IpcPort::from_raw(ptr_at(kmsg.remote_port())) };

    unsafe { port.lock() };

    // SAFETY: the port is live and locked.
    if unsafe { port.receiver() } == ipc_space::kernel().as_ptr() {
        // SAFETY: the port is live and locked.
        unsafe { port.unlock() };

        // SAFETY: a kernel port's message goes to its server, which consumes
        // it; the port lock is already dropped.
        if let Some(reply) = unsafe { ipc_kobject::server(kmsg) } {
            // The `ipc_mqueue_send_always()` macro.
            // SAFETY: the reply is a live message the server handed over.
            let _ = unsafe {
                send(reply.as_ptr(), MACH_SEND_ALWAYS, MACH_MSG_TIMEOUT_NONE)
            };
        }
        return Ok(());
    }

    let blocked = unsafe { wait_send_room(port, kmsg, option, time_out) };
    if let Some(result) = blocked {
        return result;
    }

    // SAFETY: the port is live and locked.
    if unsafe { kmsg.bits() } & MACH_MSGH_BITS_CIRCULAR != 0 {
        // SAFETY: the port is live and locked.
        unsafe { port.unlock() };
        // SAFETY: the message is live and owned by this call.
        unsafe { ipc_kmsg::destroy(kmsg) };
        return Ok(());
    }

    // SAFETY: the port is live and locked.
    unsafe { port.set_msgcount(port.msgcount().wrapping_add(1)) };

    // SAFETY: the port is live and locked.
    let pset = unsafe { port.pset() };
    let mqueue = if pset.is_null() {
        // SAFETY: the port is live and locked.
        unsafe { port.messages() }
    } else {
        // SAFETY: a non-null `ip_pset` names a live locked target.
        unsafe { (*pset.cast::<IpcTarget>()).messages() }
    };

    // SAFETY: the queue is live; the port keeps it alive until its lock is
    // dropped below.
    unsafe { (*mqueue).lock() };
    // SAFETY: the queue is live and locked.
    let receivers = unsafe { (*mqueue).threads().cast::<IpcThreadQueue>() };

    // The message queue lock now owns the message and `ip_seqno`, as the C
    // commented; the message's reference keeps the port alive.
    // SAFETY: the port is live and locked.
    unsafe { port.unlock() };

    loop {
        // SAFETY: the queue is locked.
        let receiver =
            unsafe { ipc_thread::ipc_thread_queue_first(receivers) };
        if receiver.is_null() {
            // SAFETY: the message is live and unqueued, and the queue is
            // locked.
            unsafe { ipc_kmsg::enqueue((*mqueue).messages().cast(), kmsg) };
            // SAFETY: the queue is locked.
            unsafe { (*mqueue).unlock() };
            break;
        }

        // SAFETY: `receiver` is the first thread of the locked queue.
        unsafe { ipc_thread::ipc_thread_rmqueue_first(receivers, receiver) };
        let receiver = receiver.cast::<Thread>();

        // SAFETY: the receiver is live, and the queue lock serializes
        // `ip_seqno` now that the port lock is gone.
        if unsafe { kmsg.msgh_size() <= (*receiver).data.msize } {
            // SAFETY: the receiver is live and the queue is locked.
            unsafe {
                (*receiver).ith_state = IpcWait::Done;
                (*receiver).data.kmsg = kmsg.as_ptr();
                (*receiver).ith_seqno = port.seqno();
                port.set_seqno(port.seqno().wrapping_add(1));
                (*mqueue).unlock();
                thread_go(receiver);
            }
            break;
        }

        // SAFETY: the receiver is live and the queue is locked.
        unsafe {
            (*receiver).ith_state = IpcWait::TooLarge;
            (*receiver).data.msize = kmsg.msgh_size();
            thread_go(receiver);
        }
    }

    // SAFETY: the current task is live.
    unsafe {
        let task = current_task();
        (*task).messages_sent = (*task).messages_sent.wrapping_add(1);
    }

    Ok(())
}

/// The wait loop of [`send()`]: block until the destination queue has room.
///
/// Returns [`None`] once there is room, or the result the send must report
/// when the port dies or the wait fails.
///
/// # Safety
///
/// `port` must be live and locked, `kmsg` a live message the caller owns,
/// and nothing else may be locked.
unsafe fn wait_send_room(
    port: IpcPort,
    kmsg: Kmsg,
    option: c_uint,
    mut time_out: c_uint,
) -> Option<Result<(), SendError>> {
    loop {
        // SAFETY: the port is live and locked.
        if !unsafe { port.is_active() } {
            // SAFETY: the port is live and locked; the C's `ip_release()`
            // and `ip_check_unlock()` consume its reference.
            unsafe {
                port.decrement_references();
                port.check_unlock();
                kmsg.set_remote_port(MACH_PORT_NULL);
                ipc_kmsg::destroy(kmsg);
            }
            return Some(Ok(()));
        }

        // SAFETY: the port is live and locked.
        let room = unsafe {
            port.msgcount() < port.qlimit()
                || option & MACH_SEND_ALWAYS != 0
                || kmsg.bits() & MACH_MSGH_BITS_REMOTE_MASK
                    == MACH_MSG_TYPE_PORT_SEND_ONCE
        };
        if room {
            break;
        }

        let self_ = per_cpu::thread();

        if option & MACH_SEND_TIMEOUT != 0 {
            if time_out == 0 {
                // SAFETY: the port is live and locked.
                unsafe { port.unlock() };
                return Some(Err(SendError::TimedOut));
            }
            unsafe { thread_will_wait_with_timeout(self_, time_out) };
        } else {
            unsafe { thread_will_wait(self_) };
        }

        // SAFETY: the port is live and locked, so its blocked queue is
        // serialized and the thread is not queued.
        unsafe {
            ipc_thread::ipc_thread_enqueue(port.blocked(), self_.cast());
            (*self_).ith_state = IpcWait::Sending;
            port.unlock();
        }

        // SAFETY: the caller's stack may be discarded here, as the C
        // documented.
        unsafe { thread_block(None) };

        // SAFETY: the port is live; the wakeup left it unlocked.
        unsafe { port.lock() };

        // SAFETY: the thread is live and the port lock is held.
        if unsafe { (*self_).ith_state } == IpcWait::Done {
            continue;
        }

        // SAFETY: the port is live and locked, and the thread is queued.
        unsafe {
            ipc_thread::ipc_thread_rmqueue(port.blocked(), self_.cast());
        };

        // SAFETY: the thread is live.
        match unsafe { (*self_).wait_result } {
            THREAD_INTERRUPTED => {
                // SAFETY: the port is live and locked.
                unsafe { port.unlock() };
                return Some(Err(SendError::Interrupted));
            }
            THREAD_TIMED_OUT => {
                time_out = 0;
            }
            _ => kpanic!("ipc_mqueue_send", "ipc_mqueue_send"),
        }
    }

    None
}

/// `ipc_mqueue_send_always()` of <`ipc/ipc_mqueue.h`>.
///
/// # Safety
///
/// `kmsg` must be a live message the caller owns, holding a reference for the
/// destination port; nothing may be locked.
pub(crate) unsafe fn send_always(kmsg: *mut c_void) -> Result<(), SendError> {
    unsafe { send(kmsg, MACH_SEND_ALWAYS, MACH_MSG_TIMEOUT_NONE) }
}

/// `ipc_mqueue_copyin()` in C.
///
/// # Safety
///
/// `space` must be live and unlocked; on success the returned object holds a
/// reference and the returned queue is locked.
pub(crate) unsafe fn copyin(
    space: IpcSpace,
    name: c_uint,
) -> Result<Copyin, ReceiveError> {
    unsafe { space.lock_read() };

    // SAFETY: the space is live and locked.
    if !unsafe { space.is_active() } {
        // SAFETY: the space is live and locked.
        unsafe { space.lock_done() };
        return Err(ReceiveError::InvalidName);
    }

    // SAFETY: the space is live and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup(name) }) else {
        // SAFETY: the space is live and locked.
        unsafe { space.lock_done() };
        return Err(ReceiveError::InvalidName);
    };

    // SAFETY: the entry is live.
    let (bits, object) = unsafe { ((*entry).bits(), (*entry).object()) };

    let (mqueue, held) = if bits & MACH_PORT_TYPE_RECEIVE != 0 {
        // SAFETY: a receive-rights entry names a live port.
        let port = unsafe { IpcPort::from_raw(object) };
        // SAFETY: the port is live and unlocked.
        unsafe { port.lock() };
        // SAFETY: the space is live and read-locked.
        unsafe { space.lock_done() };

        // SAFETY: the port is live and locked.
        let pset = unsafe { port.pset() };
        if !pset.is_null() {
            let target = pset.cast::<IpcTarget>();
            // SAFETY: a non-null `ip_pset` names a live port set.
            unsafe { (*target).lock() };

            // SAFETY: the target is live and locked.
            if unsafe { (*target).is_active() } {
                // SAFETY: the set and the port are live and locked.
                unsafe {
                    (*target).unlock();
                    port.unlock();
                }
                return Err(ReceiveError::InSet);
            }

            // SAFETY: the port is live and active, and the set is locked.
            unsafe { ipc_pset::remove(target, port) };
            // SAFETY: the set is live and locked, and `remove` consumed the
            // port's reference to it.
            unsafe { IpcTarget::check_unlock(target) };
        }

        // SAFETY: the port is live and locked.
        (unsafe { port.messages() }, Held::Port(port))
    } else if bits & MACH_PORT_TYPE_PORT_SET != 0 {
        // SAFETY: a port-set entry names a live target.
        let target = object.cast::<IpcTarget>();
        // SAFETY: the target is live and unlocked.
        unsafe { (*target).lock() };
        // SAFETY: the space is live and read-locked.
        unsafe { space.lock_done() };
        // SAFETY: the target is live and locked.
        (unsafe { (*target).messages() }, Held::Target(target))
    } else {
        // SAFETY: the space is live and locked.
        unsafe { space.lock_done() };
        return Err(ReceiveError::InvalidName);
    };

    match held {
        // The C's `io_reference(object)` runs with the object lock held.
        // SAFETY: the port is live and locked.
        Held::Port(port) => unsafe { port.increment_references() },
        // SAFETY: the target is live and locked.
        Held::Target(target) => unsafe {
            IpcTarget::increment_references(target);
        },
    }

    // SAFETY: the queue is live, and the object lock keeps the port or set
    // alive until it is dropped below.
    unsafe { (*mqueue).lock() };

    match held {
        // SAFETY: the port is live and locked.
        Held::Port(port) => unsafe { port.unlock() },
        // SAFETY: the target is live and locked.
        Held::Target(target) => unsafe { (*target).unlock() },
    }

    Ok(Copyin { object, mqueue })
}

/// `ipc_mqueue_receive()` in C.
///
/// # Safety
///
/// The message queue must be locked unless `resume` is set, in which case the
/// call resumes the receive that `continuation` began; the caller must hold a
/// reference for the port or port set the queue belongs to.  On return the
/// queue is unlocked.
pub(crate) unsafe fn receive(
    mqueue: *mut IpcMqueue,
    option: c_uint,
    max_size: c_uint,
    time_out: c_uint,
    resume: bool,
    continuation: Continuation,
) -> Received {
    let kmsgs = unsafe { (*mqueue).messages().cast::<IpcKmsgQueue>() };
    let self_ = per_cpu::thread();
    // SAFETY: the queue is live.
    let threads = unsafe { (*mqueue).threads().cast::<IpcThreadQueue>() };
    let mut time_out = time_out;
    let mut after_block = resume;

    let (kmsg, port, seqno) = loop {
        if !after_block {
            // SAFETY: the queue is locked.
            let first = unsafe { (*kmsgs).base };
            if !first.is_null() {
                // SAFETY: a queued head is a live message.
                let kmsg = unsafe { Kmsg::from_raw(first) };

                // SAFETY: the message is live.  Both builds the Rust half
                // targets have the user and kernel headers the same size, so
                // the C's `msg_usize()` is this header size.
                let size = unsafe { kmsg.msgh_size() };
                if size > max_size {
                    // SAFETY: the queue is locked.
                    unsafe { (*mqueue).unlock() };
                    return Received::TooLarge { size };
                }

                // SAFETY: the message is live and is the queue's head.
                unsafe { ipc_kmsg::rmqueue_first(kmsgs, kmsg) };

                // SAFETY: the message's destination right is live and the
                // queue lock is held.
                let port =
                    unsafe { IpcPort::from_raw(ptr_at(kmsg.remote_port())) };
                // SAFETY: the queue lock serializes `ip_seqno`.
                let seqno = unsafe { port.seqno() };
                unsafe { port.set_seqno(seqno.wrapping_add(1)) };

                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                break (kmsg, port, seqno);
            }

            if option & MACH_RCV_TIMEOUT != 0 {
                if time_out == 0 {
                    // SAFETY: the queue is locked.
                    unsafe { (*mqueue).unlock() };
                    return Received::Failed {
                        error: ReceiveError::TimedOut,
                    };
                }
                unsafe { thread_will_wait_with_timeout(self_, time_out) };
            } else {
                unsafe { thread_will_wait(self_) };
            }

            // SAFETY: the queue is locked, which serializes its thread list,
            // and the thread is not queued.
            unsafe {
                ipc_thread::ipc_thread_enqueue(threads, self_.cast());
                (*self_).ith_state = IpcWait::Receiving;
                (*self_).data.msize = max_size;
                (*mqueue).unlock();
            }

            // SAFETY: the caller's stack may be discarded here, as the C
            // documented; the continuation resumes this receive.
            unsafe { thread_block(continuation) };
        }

        after_block = false;

        // SAFETY: the queue was locked before the block and the wakeup does
        // not leave it locked.
        unsafe { (*mqueue).lock() };

        // SAFETY: the thread is live.
        match unsafe { (*self_).ith_state } {
            IpcWait::Done => {
                // SAFETY: a successful handoff stores a live message.
                let kmsg = unsafe { Kmsg::from_raw((*self_).data.kmsg) };
                // SAFETY: the thread is live.
                let seqno = unsafe { (*self_).ith_seqno };
                // SAFETY: the message's destination right is live.
                let port =
                    unsafe { IpcPort::from_raw(ptr_at(kmsg.remote_port())) };
                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                break (kmsg, port, seqno);
            }
            IpcWait::TooLarge => {
                // SAFETY: the thread is live.
                let size = unsafe { (*self_).data.msize };
                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                return Received::TooLarge { size };
            }
            IpcWait::PortDied => {
                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                return Received::Failed {
                    error: ReceiveError::PortDied,
                };
            }
            IpcWait::PortChanged => {
                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                return Received::Failed {
                    error: ReceiveError::PortChanged,
                };
            }
            IpcWait::Receiving => {}
            IpcWait::Sending => kpanic!(
                "ipc_mqueue_receive",
                "ipc_mqueue_receive: strange ith_state"
            ),
        }

        // SAFETY: the queue is locked and the thread is queued in it.
        unsafe { ipc_thread::ipc_thread_rmqueue(threads, self_.cast()) };

        // SAFETY: the thread is live.
        match unsafe { (*self_).wait_result } {
            THREAD_INTERRUPTED => {
                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                return Received::Failed {
                    error: ReceiveError::Interrupted,
                };
            }
            THREAD_TIMED_OUT => {
                time_out = 0;
            }
            _ => kpanic!("ipc_mqueue_receive", "ipc_mqueue_receive"),
        }
    };

    // SAFETY: the message is live and owned by this call, and the port is
    // live; the helper locks the port itself.
    unsafe { finish_receive(kmsg, port, seqno) }
}

/// The tail of [`receive()`]: drop a pending request, account the message,
/// and wake a blocked sender if the queue has room.
///
/// # Safety
///
/// `kmsg` must be the live received message, `port` the live port it names,
/// and `seqno` that delivery's sequence number.
unsafe fn finish_receive(
    kmsg: Kmsg,
    port: IpcPort,
    seqno: c_uint,
) -> Received {
    // SAFETY: the message is live and owned by this call.
    let marequest = unsafe { kmsg.marequest() };
    if !marequest.is_null() {
        // SAFETY: a pending request is live and the message owns it.
        unsafe { ipc_marequest::destroy(marequest.cast::<IpcMarequest>()) };
        // SAFETY: the message is live and uniquely owned.
        unsafe { kmsg.set_marequest(ptr::null_mut()) };
    }

    // SAFETY: the port is live; the message holds a reference to it.
    unsafe { port.lock() };

    // SAFETY: the port is live and locked.
    if unsafe { port.is_active() } {
        // SAFETY: the port is live and locked.
        unsafe { port.set_msgcount(port.msgcount().wrapping_sub(1)) };

        // SAFETY: the port is live and locked.
        let senders = unsafe { port.blocked() };
        // SAFETY: the port lock serializes the blocked queue.
        let sender = unsafe { ipc_thread::ipc_thread_queue_first(senders) };
        // SAFETY: the port is live and locked.
        let room = unsafe { port.msgcount() < port.qlimit() };

        if !sender.is_null() && room {
            // SAFETY: the sender is live and queued, and the port lock is
            // held.
            unsafe {
                ipc_thread::ipc_thread_rmqueue(senders, sender);
                (*sender.cast::<Thread>()).ith_state = IpcWait::Done;
                thread_go(sender.cast::<Thread>());
            }
        }
    }

    // SAFETY: the port is live and locked.
    unsafe { port.unlock() };

    // SAFETY: the current task is live.
    unsafe {
        let task = current_task();
        (*task).messages_received = (*task).messages_received.wrapping_add(1);
    }

    Received::Kmsg { kmsg, seqno }
}
