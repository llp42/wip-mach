// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The message-queue routines.

use crate::error::{ReceiveError, SendError};
use crate::ipc_kmsg::IpcKmsgQueue;
use crate::ipc_kmsg::{self, Kmsg};
use crate::ipc_marequest;
use crate::ipc_pset;
use crate::ipc_space;
use crate::ipc_thread;
use crate::ipc_thread::{IpcThreadQueue, IpcWait, ThreadRef};
use crate::platform::{MessageEvent, Platform};
use crate::types::MsgOption;
use crate::types::MsghBits;
use crate::types::PortType;
use crate::{IpcMarequest, IpcMqueue, IpcPort, IpcSpace, IpcTarget};
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, with_exposed_provenance_mut};
use mach_vm::platform::Continuation;

/// The send-once right disposition.
const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = 18;
/// No timeout.
const MACH_MSG_TIMEOUT_NONE: c_uint = 0;
/// The null port name.
const MACH_PORT_NULL: usize = 0;
/// The wait result of a timed-out wait.
const THREAD_TIMED_OUT: c_int = 1;
/// The wait result of an interrupted wait.
const THREAD_INTERRUPTED: c_int = 2;

/// The object and locked queue [`copyin`] returned.
pub(crate) struct Copyin {
    pub(crate) object: *mut c_void,
    pub(crate) mqueue: *mut IpcMqueue,
}

/// What [`receive`] produced.
pub enum Received {
    /// A message and the sequence number of its delivery.
    Kmsg {
        /// The message, now the receiver's.
        kmsg: Kmsg,
        /// The sequence number the port gave it.
        seqno: c_uint,
    },
    /// The receiver's buffer is too small.
    TooLarge {
        /// The size the message needs.
        size: c_uint,
    },
    /// The receive failed.
    Failed {
        /// Why.
        error: ReceiveError,
    },
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

/// Initializes `mqueue` empty.
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

/// Moves the messages of `source` sent to `port` into `dest`, handing each to
/// a waiting receiver of `dest` when one can take it.
///
/// # Safety
///
/// `dest` and `source` must point at live queues, both locked, and `port` must
/// be a live port those locks keep alive.
pub(crate) unsafe fn move_messages<P: Platform>(
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
                    let th = ipc_thread::ipc_thread_dequeue::<P>(blockedq);
                    if th.is_null() {
                        break;
                    }

                    let th = ThreadRef::new(th);
                    P::thread_go(th);
                    let ipc = P::thread_ipc(th).as_ptr();

                    if message.msgh_size() <= (*ipc).data.msize {
                        (*ipc).state = IpcWait::Done;
                        (*ipc).data.kmsg = message.as_ptr();
                        (*ipc).seqno = port.seqno();
                        port.set_seqno(port.seqno().wrapping_add(1));
                        delivered = true;
                        break;
                    }

                    (*ipc).state = IpcWait::TooLarge;
                    (*ipc).data.msize = message.msgh_size();
                }

                if !delivered {
                    ipc_kmsg::enqueue(newq, message);
                }
            }

            kmsg = next.map_or(ptr::null_mut(), Kmsg::as_ptr);
        }
    }
}

/// Wakes every receiver with `state`, the port dying or moving into a port
/// set.
///
/// # Safety
///
/// `mqueue` must point at a live locked queue.
pub(crate) unsafe fn changed<P: Platform>(
    mqueue: *mut IpcMqueue,
    state: IpcWait,
) {
    unsafe {
        let threads = (*mqueue).threads().cast::<IpcThreadQueue>();

        loop {
            let th = ipc_thread::ipc_thread_dequeue::<P>(threads);
            if th.is_null() {
                break;
            }

            let th = ThreadRef::new(th);
            (*P::thread_ipc(th).as_ptr()).state = state;
            P::thread_go(th);
        }
    }
}

/// Queues `kmsg` on its destination port, waiting for room unless the options
/// say otherwise.
///
/// # Safety
///
/// `kmsg` must be a live message the caller owns, holding a reference for the
/// destination port; nothing may be locked.
pub unsafe fn send<P: Platform>(
    kmsg: *mut c_void,
    option: MsgOption,
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
        if let Some(reply) = unsafe { P::kobject_server(kmsg) } {
            // SAFETY: the reply is a live message the server handed over.
            let _ = unsafe {
                send::<P>(
                    reply.as_ptr(),
                    MsgOption::SEND_ALWAYS,
                    MACH_MSG_TIMEOUT_NONE,
                )
            };
        }
        return Ok(());
    }

    let blocked = unsafe { wait_send_room::<P>(port, kmsg, option, time_out) };
    if let Some(result) = blocked {
        return result;
    }

    // SAFETY: the port is live and locked.
    if unsafe { kmsg.bits() }.contains(MsghBits::CIRCULAR) {
        // SAFETY: the port is live and locked.
        unsafe { port.unlock() };
        // SAFETY: the message is live and owned by this call.
        unsafe { ipc_kmsg::destroy::<P>(kmsg) };
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

    // The message queue lock now owns the message and the sequence number; the
    // message's reference keeps the port alive.
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
        unsafe {
            ipc_thread::ipc_thread_rmqueue_first::<P>(receivers, receiver);
        };
        // SAFETY: a queued receiver is a live thread.
        let receiver = unsafe { ThreadRef::new(receiver) };
        // SAFETY: the receiver is live.
        let ipc = unsafe { P::thread_ipc(receiver) }.as_ptr();

        // SAFETY: the receiver is live, and the queue lock serializes the
        // sequence number now that the port lock is gone.
        if unsafe { kmsg.msgh_size() <= (*ipc).data.msize } {
            // SAFETY: the receiver is live and the queue is locked.
            unsafe {
                (*ipc).state = IpcWait::Done;
                (*ipc).data.kmsg = kmsg.as_ptr();
                (*ipc).seqno = port.seqno();
                port.set_seqno(port.seqno().wrapping_add(1));
                (*mqueue).unlock();
                P::thread_go(receiver);
            }
            break;
        }

        // SAFETY: the receiver is live and the queue is locked.
        unsafe {
            (*ipc).state = IpcWait::TooLarge;
            (*ipc).data.msize = kmsg.msgh_size();
            P::thread_go(receiver);
        }
    }

    P::count_message(MessageEvent::Sent);

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
unsafe fn wait_send_room<P: Platform>(
    port: IpcPort,
    kmsg: Kmsg,
    option: MsgOption,
    mut time_out: c_uint,
) -> Option<Result<(), SendError>> {
    loop {
        // SAFETY: the port is live and locked.
        if !unsafe { port.is_active() } {
            // SAFETY: the port is live and locked; dropping the reference and
            // `check_unlock` consume it.
            unsafe {
                port.decrement_references();
                port.check_unlock::<P>();
                kmsg.set_remote_port(MACH_PORT_NULL);
                ipc_kmsg::destroy::<P>(kmsg);
            }
            return Some(Ok(()));
        }

        // SAFETY: the port is live and locked.
        let room = unsafe {
            port.msgcount() < port.qlimit()
                || option.contains(MsgOption::SEND_ALWAYS)
                || kmsg.bits().remote() == MACH_MSG_TYPE_PORT_SEND_ONCE
        };
        if room {
            break;
        }

        let self_ = P::current_thread();
        // SAFETY: the running thread is live.
        let ipc = unsafe { P::thread_ipc(self_) }.as_ptr();

        if option.contains(MsgOption::SEND_TIMEOUT) {
            if time_out == 0 {
                // SAFETY: the port is live and locked.
                unsafe { port.unlock() };
                return Some(Err(SendError::TimedOut));
            }
            unsafe { P::will_wait(Some(time_out)) };
        } else {
            unsafe { P::will_wait(None) };
        }

        // SAFETY: the port is live and locked, so its blocked queue is
        // serialized and the thread is not queued.
        unsafe {
            ipc_thread::ipc_thread_enqueue::<P>(
                port.blocked(),
                self_.as_ptr(),
            );
            (*ipc).state = IpcWait::Sending;
            port.unlock();
        }

        // SAFETY: the caller's stack may be discarded here, as the C
        // documented.
        unsafe { P::thread_block(None) };

        // SAFETY: the port is live; the wakeup left it unlocked.
        unsafe { port.lock() };

        // SAFETY: the thread is live and the port lock is held.
        if unsafe { (*ipc).state } == IpcWait::Done {
            continue;
        }

        // SAFETY: the port is live and locked, and the thread is queued.
        unsafe {
            ipc_thread::ipc_thread_rmqueue::<P>(
                port.blocked(),
                self_.as_ptr(),
            );
        };

        // SAFETY: the thread is live.
        match unsafe { P::wait_result() } {
            THREAD_INTERRUPTED => {
                // SAFETY: the port is live and locked.
                unsafe { port.unlock() };
                return Some(Err(SendError::Interrupted));
            }
            THREAD_TIMED_OUT => {
                time_out = 0;
            }
            _ => panic!("ipc_mqueue_send"),
        }
    }

    None
}

/// [`send`] with the queue limit ignored, for the messages the kernel sends.
///
/// # Safety
///
/// `kmsg` must be a live message the caller owns, holding a reference for the
/// destination port; nothing may be locked.
pub unsafe fn send_always<P: Platform>(
    kmsg: *mut c_void,
) -> Result<(), SendError> {
    unsafe { send::<P>(kmsg, MsgOption::SEND_ALWAYS, MACH_MSG_TIMEOUT_NONE) }
}

/// Translates the receive name `name` in `space` into its port or set and
/// locks its queue.
///
/// # Safety
///
/// `space` must be live and unlocked; on success the returned object holds a
/// reference and the returned queue is locked.
pub(crate) unsafe fn copyin<P: Platform>(
    space: IpcSpace,
    name: c_uint,
) -> Result<Copyin, ReceiveError> {
    unsafe { space.lock_read::<P>() };

    // SAFETY: the space is live and locked.
    if !unsafe { space.is_active::<P>() } {
        // SAFETY: the space is live and locked.
        unsafe { space.unlock_read::<P>() };
        return Err(ReceiveError::InvalidName);
    }

    // SAFETY: the space is live and read-locked.
    let Some(entry) = (unsafe { space.entry_lookup::<P>(name) }) else {
        // SAFETY: the space is live and locked.
        unsafe { space.unlock_read::<P>() };
        return Err(ReceiveError::InvalidName);
    };

    // SAFETY: the entry is live.
    let (bits, object) = unsafe { ((*entry).bits(), (*entry).object()) };

    let (mqueue, held) = if bits.type_.intersects(PortType::RECEIVE) {
        // SAFETY: a receive-rights entry names a live port.
        let port = unsafe { IpcPort::from_raw(object) };
        // SAFETY: the port is live and unlocked.
        unsafe { port.lock() };
        // SAFETY: the space is live and read-locked.
        unsafe { space.unlock_read::<P>() };

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
            unsafe { ipc_pset::remove::<P>(target, port) };
            // SAFETY: the set is live and locked, and `remove` consumed the
            // port's reference to it.
            unsafe { IpcTarget::check_unlock::<P>(target) };
        }

        // SAFETY: the port is live and locked.
        (unsafe { port.messages() }, Held::Port(port))
    } else if bits.type_.intersects(PortType::PORT_SET) {
        // SAFETY: a port-set entry names a live target.
        let target = object.cast::<IpcTarget>();
        // SAFETY: the target is live and unlocked.
        unsafe { (*target).lock() };
        // SAFETY: the space is live and read-locked.
        unsafe { space.unlock_read::<P>() };
        // SAFETY: the target is live and locked.
        (unsafe { (*target).messages() }, Held::Target(target))
    } else {
        // SAFETY: the space is live and locked.
        unsafe { space.unlock_read::<P>() };
        return Err(ReceiveError::InvalidName);
    };

    match held {
        // The object's reference is taken with the object lock held.
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

/// Receives a message from `mqueue`, waiting for one unless the options say
/// otherwise.
///
/// # Safety
///
/// The message queue must be locked unless `resume` is set, in which case the
/// call resumes the receive that `continuation` began; the caller must hold a
/// reference for the port or port set the queue belongs to.  On return the
/// queue is unlocked.
///
/// # Panics
///
/// If the wakeup left the thread in a send's wait state, or the wait ended
/// with a result no receive produces.
pub unsafe fn receive<P: Platform>(
    mqueue: *mut IpcMqueue,
    option: MsgOption,
    max_size: c_uint,
    time_out: c_uint,
    resume: bool,
    continuation: Continuation,
) -> Received {
    let kmsgs = unsafe { (*mqueue).messages().cast::<IpcKmsgQueue>() };
    let self_ = P::current_thread();
    // SAFETY: the running thread is live.
    let ipc = unsafe { P::thread_ipc(self_) }.as_ptr();
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

                // SAFETY: the message is live.  The user and kernel headers
                // are the same size, so this is the size the receiver sees.
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
                // SAFETY: the queue lock serializes the sequence number.
                let seqno = unsafe { port.seqno() };
                unsafe { port.set_seqno(seqno.wrapping_add(1)) };

                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                break (kmsg, port, seqno);
            }

            if option.contains(MsgOption::RCV_TIMEOUT) {
                if time_out == 0 {
                    // SAFETY: the queue is locked.
                    unsafe { (*mqueue).unlock() };
                    return Received::Failed {
                        error: ReceiveError::TimedOut,
                    };
                }
                unsafe { P::will_wait(Some(time_out)) };
            } else {
                unsafe { P::will_wait(None) };
            }

            // SAFETY: the queue is locked, which serializes its thread list,
            // and the thread is not queued.
            unsafe {
                ipc_thread::ipc_thread_enqueue::<P>(threads, self_.as_ptr());
                (*ipc).state = IpcWait::Receiving;
                (*ipc).data.msize = max_size;
                (*mqueue).unlock();
            }

            // SAFETY: the caller's stack may be discarded here, as the C
            // documented; the continuation resumes this receive.
            unsafe { P::thread_block(continuation) };
        }

        after_block = false;

        // SAFETY: the queue was locked before the block and the wakeup does
        // not leave it locked.
        unsafe { (*mqueue).lock() };

        // SAFETY: the thread is live.
        match unsafe { (*ipc).state } {
            IpcWait::Done => {
                // SAFETY: a successful handoff stores a live message.
                let kmsg = unsafe { Kmsg::from_raw((*ipc).data.kmsg) };
                // SAFETY: the thread is live.
                let seqno = unsafe { (*ipc).seqno };
                // SAFETY: the message's destination right is live.
                let port =
                    unsafe { IpcPort::from_raw(ptr_at(kmsg.remote_port())) };
                // SAFETY: the queue is locked.
                unsafe { (*mqueue).unlock() };
                break (kmsg, port, seqno);
            }
            IpcWait::TooLarge => {
                // SAFETY: the thread is live.
                let size = unsafe { (*ipc).data.msize };
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
            IpcWait::Sending => {
                panic!("ipc_mqueue_receive: strange ith_state")
            }
        }

        // SAFETY: the queue is locked and the thread is queued in it.
        unsafe {
            ipc_thread::ipc_thread_rmqueue::<P>(threads, self_.as_ptr());
        };

        // SAFETY: the thread is live.
        match unsafe { P::wait_result() } {
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
            _ => panic!("ipc_mqueue_receive"),
        }
    };

    // SAFETY: the message is live and owned by this call, and the port is
    // live; the helper locks the port itself.
    unsafe { finish_receive::<P>(kmsg, port, seqno) }
}

/// The tail of [`receive()`]: drop a pending request, account the message,
/// and wake a blocked sender if the queue has room.
///
/// # Safety
///
/// `kmsg` must be the live received message, `port` the live port it names,
/// and `seqno` that delivery's sequence number.
unsafe fn finish_receive<P: Platform>(
    kmsg: Kmsg,
    port: IpcPort,
    seqno: c_uint,
) -> Received {
    // SAFETY: the message is live and owned by this call.
    let marequest = unsafe { kmsg.marequest() };
    if !marequest.is_null() {
        // SAFETY: a pending request is live and the message owns it.
        unsafe {
            ipc_marequest::destroy::<P>(marequest.cast::<IpcMarequest>());
        };
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
                ipc_thread::ipc_thread_rmqueue::<P>(senders, sender);
                let sender = ThreadRef::new(sender);
                (*P::thread_ipc(sender).as_ptr()).state = IpcWait::Done;
                P::thread_go(sender);
            }
        }
    }

    // SAFETY: the port is live and locked.
    unsafe { port.unlock() };

    P::count_message(MessageEvent::Received);

    Received::Kmsg { kmsg, seqno }
}
