// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/exception.h:
//   Copyright (c) 2013 Free Software Foundation.
// Derived from kern/exception.c:
//   Copyright (c) 1993,1992,1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The exception up-call and its continuations, which `kern/exception.c` used
//! to define for <kern/exception.h>.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::user_access;
use crate::ipc::error::ReceiveError;
use crate::ipc::ipc_entry::{self, IE_BITS_GEN_ONE};
use crate::ipc::ipc_kmsg::{self, Kmsg};
use crate::ipc::ipc_mqueue::{self, Received};
use crate::ipc::ipc_object;
use crate::ipc::ipc_port;
use crate::ipc::ipc_space;
use crate::ipc::ipc_thread::{IpcThreadQueue, IpcWait, ThreadRef};
use crate::ipc::{
    IpcMqueue, IpcPort, IpcSpace, IpcTarget, MachMsgHeader, MachMsgType,
    MigReplyHeader,
};
use crate::kern::ast::AstReason;
use crate::kern::debug::kpanic;
use crate::kern::ipc_sched;
use crate::kern::ipc_tt::{
    retrieve_task_self_fast, retrieve_thread_self_fast,
};
use crate::kern::thread::Thread;
use crate::mig::code::{KERN_SUCCESS, MACH_MSG_SUCCESS, kern_return};
use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/// The exception number zero, which names no exception.
const NO_EXCEPTION: c_int = 0;
/// `MACH_RCV_NOTIFY` of <mach/message.h>.
const MACH_RCV_NOTIFY: c_int = 0x0000_0200;
/// `MACH_MSG_OPTION_NONE` of <mach/message.h>.
const MACH_MSG_OPTION_NONE: c_uint = 0;
/// `MACH_MSG_TIMEOUT_NONE` of <mach/message.h>.
const MACH_MSG_TIMEOUT_NONE: c_uint = 0;
/// `MACH_MSG_SIZE_MAX` of <mach/message.h>.
const MACH_MSG_SIZE_MAX: c_uint = 0xffff_ffff;
/// `MACH_MSGH_BITS_COMPLEX` of <mach/message.h>.
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
/// `MACH_MSG_TYPE_MOVE_SEND` of <mach/message.h>.
const MACH_MSG_TYPE_MOVE_SEND: u32 = 17;
/// `MACH_MSG_TYPE_MOVE_SEND_ONCE` of <mach/message.h>.
const MACH_MSG_TYPE_MOVE_SEND_ONCE: u32 = 18;
/// `MACH_MSG_TYPE_INTEGER_32` of <mach/message.h>.
const MACH_MSG_TYPE_INTEGER_32: u32 = 2;
/// `MACH_MSG_TYPE_INTEGER_64` of <mach/message.h>.
const MACH_MSG_TYPE_INTEGER_64: u32 = 11;
/// `MACH_EXCEPTION_ID` of mach/exc.defs.
const MACH_EXCEPTION_ID: c_int = 2400;
/// `MACH_EXCEPTION_REPLY_ID`: the reply's `msgh_id`.
const MACH_EXCEPTION_REPLY_ID: c_int = 2500;
/// `MACH_PORT_NAME_NULL` of <mach/port.h>.
const MACH_PORT_NAME_NULL: c_uint = 0;
/// `MACH_PORT_TYPE_SEND_ONCE` of <mach/port.h>: `1 << (right + 16)` for the
/// send-once right.
const MACH_PORT_TYPE_SEND_ONCE: u32 = 1 << 18;
/// `PORT_T_SIZE_IN_BITS` of `ipc/ipc_machdep.h`.
const PORT_T_BITS: u32 = 64;
/// `RPC_LONG_INTEGER_T_SIZE_IN_BITS` of kern/exception.c.
const RPC_LONG_T_BITS: u32 = 64;
/// `RPC_LONG_INTEGER_T_TYPE` of kern/exception.c.
const RPC_LONG_T_TYPE: u32 = MACH_MSG_TYPE_INTEGER_64;

/// `MACH_MSGH_BITS(remote, local)` of <mach/message.h>.
const fn mach_msg_bits(remote: u32, local: u32) -> u32 {
    remote | (local << 8)
}

/// The descriptor word of a `mach_msg_type_t` initializer under the 64-bit
/// bitfield layout.
const fn descriptor_word(name: u32, size: u32) -> u32 {
    name | (size << 8) | (1 << 29)
}

/// `exc_port_proto` of kern/exception.c: a send right to the destination
/// port.
const EXC_PORT_PROTO: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_MOVE_SEND, PORT_T_BITS), 1);
/// `exc_code_proto` of kern/exception.c: the exception code.
const EXC_CODE_PROTO: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_INTEGER_32, 32), 1);
/// `exc_subcode_proto` of kern/exception.c: the exception subcode.
const EXC_SUBCODE_PROTO: MachMsgType =
    MachMsgType::new(descriptor_word(RPC_LONG_T_TYPE, RPC_LONG_T_BITS), 1);
/// `exc_RetCode_proto` of kern/exception.c: the reply's return code.
const EXC_RETCODE_PROTO: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_INTEGER_32, 32), 1);

const _: () = {
    assert!(EXC_PORT_PROTO.word() == 0x2000_4011);
    assert!(EXC_CODE_PROTO.word() == 0x2000_2002);
    assert!(EXC_SUBCODE_PROTO.word() == 0x2000_400b);
    assert!(EXC_RETCODE_PROTO.word() == 0x2000_2002);
};

/// `struct mach_exception` of kern/exception.c: the message this module
/// synthesizes for an exception server.
#[repr(C)]
#[allow(missing_docs)]
struct MachException {
    head: MachMsgHeader,
    thread_type: MachMsgType,
    thread: usize,
    task_type: MachMsgType,
    task: usize,
    exception_type: MachMsgType,
    exception: c_int,
    code_type: MachMsgType,
    code: c_int,
    subcode_type: MachMsgType,
    subcode: c_long,
}

const _: () = {
    assert!(size_of::<MachException>() == 112);
    assert!(align_of::<MachException>() == 8);
    assert!(offset_of!(MachException, head) == 0);
    assert!(offset_of!(MachException, thread_type) == 32);
    assert!(offset_of!(MachException, thread) == 40);
    assert!(offset_of!(MachException, task_type) == 48);
    assert!(offset_of!(MachException, task) == 56);
    assert!(offset_of!(MachException, exception_type) == 64);
    assert!(offset_of!(MachException, exception) == 72);
    assert!(offset_of!(MachException, code_type) == 80);
    assert!(offset_of!(MachException, code) == 88);
    assert!(offset_of!(MachException, subcode_type) == 96);
    assert!(offset_of!(MachException, subcode) == 104);
};

/// `exception_raise_misses` of kern/exception.c: how often the optimized
/// handoff failed, a counter for a debugger to read.
static EXCEPTION_RAISE_MISSES: AtomicU32 = AtomicU32::new(0);

/// Whether `thread` has a halt or terminate reason pending.
const fn should_halt(thread: *const Thread) -> bool {
    // SAFETY: `thread` is the running thread, live for as long as it runs, and
    // `ast` is readable for that whole time.
    let ast = unsafe { (*thread).ast };
    ast.intersects(AstReason::SHOULD_HALT)
}

/// A port as the C pointer, with `IP_NULL` for the absent case.
fn port_ptr(port: Option<IpcPort>) -> *mut c_void {
    port.map_or(ptr::null_mut(), IpcPort::as_ptr)
}

/// The continuation `thread_halt_self()` resumes a halted thread through,
/// <`kern/sched_prim.h`>'s `thread_exception_return`.
unsafe extern "C" fn exception_return() {
    // SAFETY: the routine returns to user mode and never comes back.
    unsafe { crate::arch::x86_64::locore::thread_exception_return() }
}

/// The continuation `thread_halt_self()` resumes a halted thread through in
/// `exception_raise_continue_slow()`.
unsafe extern "C" fn thread_release_and_exception_return() {
    let self_ = per_cpu::thread();
    // SAFETY: the thread is at a clean point, and `ith_port` is the live
    // reply port whose reference this continuation releases.
    let reply_port =
        unsafe { IpcPort::from_raw((*self_).saved.exception.port) };
    // SAFETY: the reference the receive path was holding is this call's.
    unsafe { reply_port.release() };
    // SAFETY: the routine returns to user mode and never comes back.
    unsafe { crate::arch::x86_64::locore::thread_exception_return() }
}

/// `exception_no_server()` of kern/exception.c.
///
/// # Safety
///
/// The caller must be the running thread, entering with no locks held: this
/// halts or terminates the thread's task, as [`Thread::halt_self()`] and
/// `task::terminate()` require.
pub(crate) unsafe fn no_server() -> ! {
    let thread = per_cpu::thread();

    while should_halt(thread) {
        // SAFETY: `thread_exception_return` never returns; it is the
        // continuation the C passed, and `thread_halt_self()` only comes back
        // when the thread is released to halt cleanly.
        unsafe {
            Thread::halt_self(Some(exception_return));
        }
    }

    // SAFETY: the running thread is inside a live task.
    let task = unsafe { (*thread).task };
    let _ = unsafe { crate::kern::task::terminate(task) };

    unsafe {
        Thread::halt_self(Some(exception_return));
    }

    kpanic!("exception_no_server", "terminating the task didn't kill us")
}

/// `exception()` of kern/exception.c: make an up-call to the thread's
/// exception server, or to the task's when the thread has none.
///
/// # Safety
///
/// The caller must be the running thread, entering from the trap or FPU
/// path with no locks held.
pub(crate) unsafe fn exception(
    exception_: c_int,
    code: c_int,
    subcode: c_long,
) -> ! {
    let self_ = per_cpu::thread();

    if exception_ == NO_EXCEPTION {
        kpanic!("exception", "exception")
    }

    // SAFETY: the running thread is live; the IPC lock covers
    // `ith_exception`, and the port lock taken under it keeps the port alive.
    let exc_port = unsafe {
        (*self_).ith_lock_data.lock();
        IpcPort::valid((*self_).ith_exception).map_or_else(
            || {
                (*self_).ith_lock_data.unlock();
                try_task(exception_, code, subcode)
            },
            |port| {
                port.lock();
                (*self_).ith_lock_data.unlock();
                port
            },
        )
    };

    // SAFETY: the port is live and locked.
    if !unsafe { exc_port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { exc_port.unlock() };
        // SAFETY: the exception path holds no lock here.
        unsafe { try_task(exception_, code, subcode) }
    }

    // SAFETY: the port is live and locked; the C's bare `ip_reference()` and
    // `ip_srights++` are the increments, and `ith_exc*` save the state for
    // the task fallback.
    unsafe {
        exc_port.increment_references();
        exc_port.increment_srights();
        exc_port.unlock();

        (*self_).saved.exception.exc = exception_;
        (*self_).saved.exception.code = code;
        (*self_).saved.exception.subcode = subcode;
    }

    // SAFETY: the running thread and its task are live.
    let (thread_self, task_self) = unsafe {
        (
            retrieve_thread_self_fast(self_),
            retrieve_task_self_fast((*self_).task),
        )
    };
    unsafe {
        raise(
            exc_port.as_ptr(),
            port_ptr(thread_self),
            port_ptr(task_self),
            exception_,
            code,
            subcode,
        )
    }
}

/// `exception_try_task()` of kern/exception.c: make an up-call to the task's
/// exception server.
///
/// # Safety
///
/// Same contract as [`exception()`]: the caller must be the running thread,
/// with no locks held.
pub(crate) unsafe fn try_task(
    exception_: c_int,
    code: c_int,
    subcode: c_long,
) -> ! {
    let self_ = per_cpu::thread();
    // SAFETY: the running thread's task is live.
    let task = unsafe { (*self_).task };

    // SAFETY: the task is live; its IPC lock covers `itk_exception`, and the
    // port lock taken under it keeps the port alive.
    let exc_port = unsafe {
        (*task).itk_lock_data.lock();
        IpcPort::valid((*task).itk_exception).map_or_else(
            || {
                (*task).itk_lock_data.unlock();
                no_server()
            },
            |port| {
                port.lock();
                (*task).itk_lock_data.unlock();
                port
            },
        )
    };

    // SAFETY: the port is live and locked.
    if !unsafe { exc_port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { exc_port.unlock() };
        // SAFETY: the exception path holds no lock here.
        unsafe { no_server() }
    }

    // SAFETY: the port is live and locked; the increments are the C's bare
    // `ip_reference()` and `ip_srights++`, and the saved state is cleared for
    // the last chance.
    unsafe {
        exc_port.increment_references();
        exc_port.increment_srights();
        exc_port.unlock();

        (*self_).saved.exception.exc = NO_EXCEPTION;
    }

    // SAFETY: the running thread and its task are live.
    let (thread_self, task_self) = unsafe {
        (
            retrieve_thread_self_fast(self_),
            retrieve_task_self_fast(task),
        )
    };
    unsafe {
        raise(
            exc_port.as_ptr(),
            port_ptr(thread_self),
            port_ptr(task_self),
            exception_,
            code,
            subcode,
        )
    }
}

/// The rights and state `exception_raise()` carries into its arms.
struct Rights {
    /// `self`: the thread that entered `exception_raise()`, which the handoff
    /// swaps out while the receiver runs.
    self_: *mut Thread,
    kmsg: Kmsg,
    dest: IpcPort,
    thread_port: *mut c_void,
    task_port: *mut c_void,
    exception: c_int,
    code: c_int,
    subcode: c_long,
    reply_port: IpcPort,
    reply_mqueue: *mut IpcMqueue,
}

impl Rights {
    /// The `slow_exception_raise` arm: synthesize the kmsg and send it, then
    /// wait for the reply.
    ///
    /// # Safety
    ///
    /// The caller owns the message, the destination right and the reply
    /// port's send-once right, and holds no lock.
    unsafe fn slow(self) -> ! {
        EXCEPTION_RAISE_MISSES.fetch_add(1, Ordering::Relaxed);

        let head = unsafe { self.kmsg.header() };
        let exc = head.cast::<MachException>();
        // SAFETY: the message buffer holds the whole record, and the two
        // ports are the caller's live rights.
        unsafe {
            (*head).set_bits(
                mach_msg_bits(
                    MACH_MSG_TYPE_MOVE_SEND,
                    MACH_MSG_TYPE_MOVE_SEND_ONCE,
                ) | MACH_MSGH_BITS_COMPLEX,
            );
            (*head).set_size(size_of::<MachException>() as u32);
            (*head).set_remote(self.dest.as_ptr().addr());
            (*head).set_local(self.reply_port.as_ptr().addr());
            self.kmsg.set_header_seqno(0);
            (*head).set_id(MACH_EXCEPTION_ID);
            ptr::addr_of_mut!((*exc).thread_type).write(EXC_PORT_PROTO);
            ptr::addr_of_mut!((*exc).thread).write(self.thread_port.addr());
            ptr::addr_of_mut!((*exc).task_type).write(EXC_PORT_PROTO);
            ptr::addr_of_mut!((*exc).task).write(self.task_port.addr());
            ptr::addr_of_mut!((*exc).exception_type).write(EXC_CODE_PROTO);
            ptr::addr_of_mut!((*exc).exception).write(self.exception);
            ptr::addr_of_mut!((*exc).code_type).write(EXC_CODE_PROTO);
            ptr::addr_of_mut!((*exc).code).write(self.code);
            ptr::addr_of_mut!((*exc).subcode_type).write(EXC_SUBCODE_PROTO);
            ptr::addr_of_mut!((*exc).subcode).write(self.subcode);

            // An unlimited send always queues the message.
            let _ = ipc_mqueue::send_always(self.kmsg.as_ptr());
        }

        // SAFETY: the reply port is the live special-space port this call
        // owns a reference to.
        unsafe { self.reply_port.lock() };
        // SAFETY: the reply port is live and its lock is held.
        if !unsafe { self.reply_port.is_active() } {
            // SAFETY: the port lock is held.
            unsafe { self.reply_port.unlock() };
            // SAFETY: nothing is locked and this call owns the message.
            unsafe { continue_slow(Err(ReceiveError::PortDied)) }
        }
        // SAFETY: the reply queue is live; the lock order is the C's.
        unsafe {
            (*self.reply_mqueue).lock();
            self.reply_port.unlock();
        }

        // SAFETY: the queue was just locked and is unlocked by the receive,
        // and the current thread holds the reply port's reference.
        match unsafe {
            ipc_mqueue::receive(
                self.reply_mqueue,
                MACH_MSG_OPTION_NONE,
                MACH_MSG_SIZE_MAX,
                MACH_MSG_TIMEOUT_NONE,
                false,
                Some(exception_raise_continue),
            )
        } {
            Received::Kmsg { kmsg, .. } => {
                // SAFETY: the receive handed over a live message.
                unsafe { continue_slow(Ok(kmsg)) }
            }
            Received::TooLarge { .. } => unsafe {
                continue_slow(Err(ReceiveError::TooLarge))
            },
            Received::Failed { error } => unsafe { continue_slow(Err(error)) },
        }
    }

    /// The optimized arm's body, after `thread_handoff()` succeeded: run as
    /// the receiver and copy the message into its buffer.
    ///
    /// # Safety
    ///
    /// The caller ran as the handoff target: both message queues are locked,
    /// `receiver` was removed from the destination queue, and this call owns
    /// the message plus the destination and reply rights.
    unsafe fn finish_fast(
        self,
        receiver: *mut Thread,
        dest_mqueue: *mut IpcMqueue,
    ) -> ! {
        // SAFETY: both queues are locked and the receiver is waiting on the
        // destination queue.
        let space = unsafe {
            finish_queues(self.self_, self.reply_mqueue, receiver, dest_mqueue)
        };

        let head = unsafe { self.kmsg.header() };
        let exc = head.cast::<MachException>();
        // SAFETY: the message buffer holds the whole record.
        unsafe {
            fill_exception_record(
                head,
                exc,
                self.kmsg,
                self.exception,
                self.code,
                self.subcode,
            );
        }

        // SAFETY: the receiver is a live handoff target and its saved receive
        // state is the buffer the caller of the send set up.
        if unsafe { (*receiver).saved.receive.rcv_size }
            < size_of::<MachException>() as c_uint
        {
            unsafe {
                (*head).set_bits(
                    mach_msg_bits(
                        MACH_MSG_TYPE_MOVE_SEND,
                        MACH_MSG_TYPE_MOVE_SEND_ONCE,
                    ) | MACH_MSGH_BITS_COMPLEX,
                );
                (*head).set_remote(self.dest.as_ptr().addr());
                (*head).set_local(self.reply_port.as_ptr().addr());
                ptr::addr_of_mut!((*exc).thread)
                    .write(self.thread_port.addr());
                ptr::addr_of_mut!((*exc).task).write(self.task_port.addr());
                ipc_kmsg::destroy(self.kmsg);
                crate::arch::x86_64::locore::thread_syscall_return(
                    c_int::from(ReceiveError::TooLarge),
                );
            }
        }

        // SAFETY: the space is unlocked and the destination is a live send
        // right.
        unsafe {
            space.lock_write();
            self.dest.lock();
        }

        let mut abort = false;
        // SAFETY: the destination and space locks are held.
        if !unsafe { self.dest.is_active() }
            // SAFETY: the reply port is live, and its lock is free.
            || !unsafe { self.reply_port.try_lock() }
        {
            abort = true;
        // SAFETY: the reply port is live and its lock is held.
        } else if !unsafe { self.reply_port.is_active() } {
            // SAFETY: the reply port's lock is held.
            unsafe { self.reply_port.unlock() };
            abort = true;
        } else {
            // SAFETY: the reply port's lock is held.
            unsafe { self.reply_port.unlock() };

            // SAFETY: the space is write-locked.
            match unsafe { ipc_entry::entry_get(space) } {
                Some((port_name, entry)) => {
                    // SAFETY: the entry is live in the write-locked space;
                    // the writes and the unlock are the C's optimized entry
                    // setup.
                    unsafe {
                        (*head).set_remote(port_name as usize);
                        let generation =
                            (*entry).bits().wrapping_add(IE_BITS_GEN_ONE);
                        (*entry).set_bits(
                            generation | (MACH_PORT_TYPE_SEND_ONCE | 1),
                        );
                        (*entry).set_object(self.reply_port.as_ptr());
                        space.lock_done();
                    }

                    // SAFETY: the destination port is live, locked and
                    // active.
                    unsafe {
                        self.dest.decrement_references();
                        let name = if self.dest.receiver() == space.as_ptr() {
                            self.dest.receiver_name()
                        } else {
                            MACH_PORT_NAME_NULL
                        };
                        (*head).set_local(name as usize);

                        self.dest.decrement_srights();
                        if self.dest.srights() == 0 {
                            if let Some(nsrequest) = self.dest.nsrequest() {
                                self.dest.set_nsrequest(None);
                                let mscount = self.dest.mscount();
                                self.dest.unlock();
                                crate::ipc::ipc_notify::no_senders(
                                    nsrequest, mscount,
                                );
                            } else {
                                self.dest.unlock();
                            }
                        } else {
                            self.dest.unlock();
                        }
                    }
                }
                None => abort = true,
            }
        }

        if abort {
            // SAFETY: the destination and space locks are held, and the
            // record is live.
            unsafe { finish_abort(&self, space, head, exc, receiver) };
        }

        // SAFETY: nothing is locked, and the slow path above has run.
        unsafe { finish_copyout(&self, space, head, exc, receiver) }
    }
}

/// Return the current thread to its reply queue and pull `receiver` off the
/// destination queue, releasing the receive object it had saved.
///
/// # Safety
///
/// The reply and destination message queues must be locked, and `receiver`
/// must be a live thread waiting on the destination queue.
unsafe fn finish_queues(
    self_: *mut Thread,
    reply_mqueue: *mut IpcMqueue,
    receiver: *mut Thread,
    dest_mqueue: *mut IpcMqueue,
) -> IpcSpace {
    // SAFETY: the reply queue is locked and the current thread is not
    // queued in it.
    unsafe {
        let threads = (*reply_mqueue).threads().cast::<IpcThreadQueue>();
        (*threads).enqueue(ThreadRef::new(self_.cast()));
        (*self_).ith_state = IpcWait::Receiving;
        (*self_).data.msize = MACH_MSG_SIZE_MAX;
        (*reply_mqueue).unlock();

        let dest_threads = (*dest_mqueue).threads().cast::<IpcThreadQueue>();
        (*dest_threads).rmqueue_first(ThreadRef::new(receiver.cast()));
        (*dest_mqueue).unlock();
    }

    // SAFETY: the receiver was waiting, so its saved object is live and
    // holds the reference this call releases.
    let object = unsafe { (*receiver).saved.receive.object };
    // SAFETY: the reference is the receiver's.
    unsafe { ipc_object::release(object) };

    // SAFETY: the receiver's task and its space are live.
    unsafe { IpcSpace::from_raw((*(*receiver).task).itk_space) }
}

/// Fill the exception record of `head` with the raise's own values.
///
/// # Safety
///
/// `head` and `exc` must point into a live message whose buffer holds the
/// whole record.
unsafe fn fill_exception_record(
    head: *mut MachMsgHeader,
    exc: *mut MachException,
    kmsg: Kmsg,
    exception_: c_int,
    code: c_int,
    subcode: c_long,
) {
    unsafe {
        (*head).set_bits(
            mach_msg_bits(
                MACH_MSG_TYPE_MOVE_SEND_ONCE,
                MACH_MSG_TYPE_MOVE_SEND,
            ) | MACH_MSGH_BITS_COMPLEX,
        );
        (*head).set_size(size_of::<MachException>() as u32);
        kmsg.set_header_seqno(0);
        (*head).set_id(MACH_EXCEPTION_ID);
        ptr::addr_of_mut!((*exc).thread_type).write(EXC_PORT_PROTO);
        ptr::addr_of_mut!((*exc).task_type).write(EXC_PORT_PROTO);
        ptr::addr_of_mut!((*exc).exception_type).write(EXC_CODE_PROTO);
        ptr::addr_of_mut!((*exc).exception).write(exception_);
        ptr::addr_of_mut!((*exc).code_type).write(EXC_CODE_PROTO);
        ptr::addr_of_mut!((*exc).code).write(code);
        ptr::addr_of_mut!((*exc).subcode_type).write(EXC_SUBCODE_PROTO);
        ptr::addr_of_mut!((*exc).subcode).write(subcode);
    }
}

/// The C's abort path of the optimized receive: hand the reply port's
/// send-once right back and return the record through the slow header
/// copy-out.
///
/// # Safety
///
/// The destination and space locks must be held; `head`, `exc`, `receiver`
/// and `self_` must be live as the caller established.
unsafe fn finish_abort(
    self_: &Rights,
    space: IpcSpace,
    head: *mut MachMsgHeader,
    exc: *mut MachException,
    receiver: *mut Thread,
) {
    // SAFETY: the destination and space locks are held.
    unsafe {
        self_.dest.unlock();
        space.lock_done();
        (*head).set_bits(
            mach_msg_bits(
                MACH_MSG_TYPE_MOVE_SEND,
                MACH_MSG_TYPE_MOVE_SEND_ONCE,
            ) | MACH_MSGH_BITS_COMPLEX,
        );
        (*head).set_remote(self_.dest.as_ptr().addr());
        (*head).set_local(self_.reply_port.as_ptr().addr());
    }

    // SAFETY: the header is live and owned by this call, and nothing is
    // locked.
    match unsafe { ipc_kmsg::copyout_header(head, space, MACH_PORT_NAME_NULL) }
    {
        Ok(()) => {}
        Err(error) => {
            // SAFETY: the slow header copyout consumes the two body rights
            // and the message.
            unsafe {
                ptr::addr_of_mut!((*exc).thread)
                    .write(self_.thread_port.addr());
                ptr::addr_of_mut!((*exc).task).write(self_.task_port.addr());
                ipc_kmsg::copyout_dest(self_.kmsg, space);
            }
            // SAFETY: the copyout failure leaves the message to this call,
            // and the receiver's buffer is writable.
            let _ = unsafe {
                ipc_kmsg::put(
                    (*receiver).saved.receive.msg,
                    self_.kmsg,
                    size_of::<MachMsgHeader>() as c_uint,
                )
            };
            // SAFETY: `thread_syscall_return` never returns.
            unsafe {
                crate::arch::x86_64::locore::thread_syscall_return(
                    c_int::from(error),
                );
            };
        }
    }
}

/// The optimized receive's final copy-out: the body rights, the record, and
/// the receiver's buffer, then return to user space.
///
/// # Safety
///
/// Nothing must be locked; `space`, `head`, `exc`, `receiver` and `self_`
/// must be live as the caller established.
unsafe fn finish_copyout(
    self_: &Rights,
    space: IpcSpace,
    head: *mut MachMsgHeader,
    exc: *mut MachException,
    receiver: *mut Thread,
) -> ! {
    // SAFETY: nothing is locked and the caller owns both body rights.
    let (thread_lost, thread_name) = unsafe {
        ipc_kmsg::copyout_object(
            space,
            self_.thread_port,
            MACH_MSG_TYPE_MOVE_SEND,
        )
    };
    let (task_lost, task_name) = unsafe {
        ipc_kmsg::copyout_object(
            space,
            self_.task_port,
            MACH_MSG_TYPE_MOVE_SEND,
        )
    };
    let lost = thread_lost | task_lost;
    // SAFETY: the record's two name slots are writable.
    unsafe {
        ptr::addr_of_mut!((*exc).thread).write(thread_name as usize);
        ptr::addr_of_mut!((*exc).task).write(task_name as usize);
    }
    if !lost.is_none() {
        // SAFETY: the failed body copyout leaves the message to this call,
        // and the receiver's buffer is writable.
        let _ = unsafe {
            ipc_kmsg::put(
                (*receiver).saved.receive.msg,
                self_.kmsg,
                self_.kmsg.msgh_size(),
            )
        };
        // SAFETY: `thread_syscall_return` never returns.
        unsafe {
            crate::arch::x86_64::locore::thread_syscall_return(c_int::from(
                ReceiveError::Body(lost),
            ));
        };
    }

    // SAFETY: the receiver's buffer is writable for the whole record,
    // which its `ith_rcv_size` check established, and the message is live
    // and owned by this call.
    if unsafe {
        user_access::copyout(
            head.cast(),
            (*receiver).saved.receive.msg,
            size_of::<MachException>(),
        )
    }
    .is_err()
    {
        // SAFETY: the failed copyout leaves the message to this call, and
        // the receiver's buffer is writable.
        let put = unsafe {
            ipc_kmsg::put(
                (*receiver).saved.receive.msg,
                self_.kmsg,
                self_.kmsg.msgh_size(),
            )
        };
        // SAFETY: `thread_syscall_return` never returns.
        unsafe {
            crate::arch::x86_64::locore::thread_syscall_return(kern_return(
                put,
            ));
        };
    }

    // SAFETY: the message was copied out and this call owns it.
    if !unsafe { ipc_kmsg::cache_free_try(self_.kmsg) } {
        // SAFETY: the free failed, so this call owns the message.
        let put = unsafe {
            ipc_kmsg::put(
                (*receiver).saved.receive.msg,
                self_.kmsg,
                self_.kmsg.msgh_size(),
            )
        };
        // SAFETY: `thread_syscall_return` never returns.
        unsafe {
            crate::arch::x86_64::locore::thread_syscall_return(kern_return(
                put,
            ));
        };
    }

    // SAFETY: `thread_syscall_return` never returns.
    unsafe {
        crate::arch::x86_64::locore::thread_syscall_return(MACH_MSG_SUCCESS)
    };
}

/// `exception_raise()` of kern/exception.c: make an `exception_raise`
/// up-call to an exception server.
///
/// # Safety
///
/// `dest_port`, `thread_port` and `task_port` must be live naked send rights
/// this call consumes; nothing may be locked, and the caller runs in an
/// exception context.
pub(crate) unsafe fn raise(
    dest_port: *mut c_void,
    thread_port: *mut c_void,
    task_port: *mut c_void,
    exception_: c_int,
    code: c_int,
    subcode: c_long,
) -> ! {
    let self_ = per_cpu::thread();

    // SAFETY: nothing is locked, and `cache_alloc()` returns a live message.
    let Some(kmsg) = ipc_kmsg::cache_alloc() else {
        kpanic!("exception_raise", "exception_raise")
    };

    // SAFETY: the running thread is live and nothing is locked yet.
    let (reply_port, reply_mqueue) = unsafe { resolve_reply_port(self_) };

    let rights = Rights {
        self_,
        kmsg,
        dest: unsafe { IpcPort::from_raw(dest_port) },
        thread_port,
        task_port,
        exception: exception_,
        code,
        subcode,
        reply_port,
        reply_mqueue,
    };

    let dest_mqueue =
        // SAFETY: `rights` is live and this call is the only user.
        unsafe { handoff(&rights, self_) };

    let Some((dest_mqueue, receiver)) = dest_mqueue else {
        // SAFETY: neither queue is locked and this call owns the rights the
        // slow path needs.
        unsafe { rights.slow() }
    };

    // SAFETY: the handoff succeeded: both queues are locked, `receiver` was
    // the first waiter on the destination, and this call now runs as the
    // receiver.
    unsafe { rights.finish_fast(receiver, dest_mqueue) }
}

/// The C's cached reply port for `self_`, allocated and locked on first use.
///
/// # Safety
///
/// `self_` must be the live running thread and no locks may be held.
unsafe fn resolve_reply_port(self_: *mut Thread) -> (IpcPort, *mut IpcMqueue) {
    // SAFETY: the running thread is live; its IPC lock covers
    // `ith_rpc_reply`, and the port lock taken under it keeps the cached port
    // alive.
    let reply_port = unsafe {
        (*self_).ith_lock_data.lock();
        let mut raw = (*self_).ith_rpc_reply;
        if raw.is_null() {
            (*self_).ith_lock_data.unlock();
            let Some(port) = ipc_port::alloc_special(ipc_space::reply())
            else {
                kpanic!("exception_raise", "exception_raise")
            };
            raw = port.as_ptr();
            (*self_).ith_lock_data.lock();
            if !(*self_).ith_rpc_reply.is_null() {
                kpanic!("exception_raise", "exception_raise")
            }
            (*self_).ith_rpc_reply = raw;
        }
        let port = IpcPort::from_raw(raw);
        port.lock();
        (*self_).ith_lock_data.unlock();
        port
    };

    // SAFETY: the reply port is live and locked; the C's bare
    // `ip_sorights++` and two `ip_reference()` calls, then the second
    // reference is saved in `ith_port`.
    unsafe {
        reply_port.increment_sorights();
        reply_port.increment_references();
        reply_port.increment_references();
        (*self_).saved.exception.port = reply_port.as_ptr();
    }
    // SAFETY: the reply port is live.
    let reply_mqueue = unsafe { reply_port.messages() };
    // SAFETY: the reply queue is live; the port lock is held.
    unsafe {
        (*reply_mqueue).lock();
        reply_port.unlock();
    }
    (reply_port, reply_mqueue)
}

/// Find the destination's message queue and first waiter, and hand the
/// raise off to it when its continuation allows.
///
/// # Safety
///
/// `rights` must be live, as `exception_raise()` set it up.
unsafe fn handoff(
    rights: &Rights,
    self_: *mut Thread,
) -> Option<(*mut IpcMqueue, *mut Thread)> {
    // SAFETY: the destination is a live send right this call owns.
    if !unsafe { rights.dest.try_lock() } {
        // SAFETY: the reply queue is locked.
        unsafe { (*rights.reply_mqueue).unlock() };
        return None;
    }

    // SAFETY: the destination lock is held.
    if !unsafe { rights.dest.is_active() }
        // SAFETY: the destination lock is held.
        || unsafe { rights.dest.receiver() } == ipc_space::kernel().as_ptr()
    {
        // SAFETY: the destination and reply queue locks are held.
        unsafe {
            (*rights.reply_mqueue).unlock();
            rights.dest.unlock();
        }
        return None;
    }

    // SAFETY: a live port's `ip_pset` names a live target's queue.
    let mqueue = unsafe {
        let pset = rights.dest.pset();
        if pset.is_null() {
            rights.dest.messages()
        } else {
            (*pset.cast::<IpcTarget>()).messages()
        }
    };

    // SAFETY: the destination queue is live and free.
    if !unsafe { (*mqueue).try_lock() } {
        // SAFETY: the destination and reply queue locks are held.
        unsafe {
            (*rights.reply_mqueue).unlock();
            rights.dest.unlock();
        }
        return None;
    }
    // SAFETY: the destination lock is held.
    unsafe { rights.dest.unlock() };

    // SAFETY: the destination queue is locked, so its thread list is stable
    // and every entry is a live thread.
    let receiver =
        unsafe { (*(*mqueue).threads().cast::<IpcThreadQueue>()).first() };
    let Some(receiver) = receiver else {
        // SAFETY: both message queues are locked.
        unsafe {
            (*rights.reply_mqueue).unlock();
            (*mqueue).unlock();
        }
        return None;
    };
    let receiver = receiver.as_ptr().cast::<Thread>();

    // The C compared the stored continuation against the two message entry
    // points by address; the bindings give the function items the pointer
    // type that comparison needs.
    let continue_fn: unsafe extern "C" fn() =
        crate::ipc::mach_msg::mach_msg_continue;
    let receive_continue_fn: unsafe extern "C" fn() =
        crate::ipc::mach_msg::mach_msg_receive_continue;
    // SAFETY: the receiver is a live queued thread.
    let swap_func = unsafe { (*receiver).swap_func };
    let can_handoff = swap_func
        .is_some_and(|f| ptr::fn_addr_eq(f, continue_fn))
        || (swap_func.is_some_and(|f| ptr::fn_addr_eq(f, receive_continue_fn))
            && size_of::<MachException>() as c_uint
                // SAFETY: the receiver is a live queued thread.
                <= unsafe { (*receiver).data.msize }
                // SAFETY: the receiver is a live queued thread.
                && unsafe { (*receiver).saved.receive.option }
                    & MACH_RCV_NOTIFY
                    == 0);

    let handed = can_handoff
        && unsafe {
            ipc_sched::thread_handoff(
                self_,
                Some(exception_raise_continue),
                receiver,
            )
        };
    if !handed {
        // SAFETY: both message queues are locked.
        unsafe {
            (*rights.reply_mqueue).unlock();
            (*mqueue).unlock();
        }
        return None;
    }

    Some((mqueue, receiver))
}

/// `exception_parse_reply()` of kern/exception.c: check and consume the reply
/// the server sent back, and return whether the server handled the
/// exception, its reply well formed and its return code `KERN_SUCCESS`.
///
/// # Safety
///
/// The caller must own the live reply message and pass it to no one else:
/// this call always consumes it, either destroying it if malformed or
/// freeing it to the cache once its return code is read.
pub(crate) unsafe fn parse_reply(kmsg: Kmsg) -> bool {
    let msg = unsafe { kmsg.header().cast::<MigReplyHeader>() };
    let head = unsafe { ptr::addr_of_mut!((*msg).head) };

    // SAFETY: the reply header is live; the C's `BAD_TYPECHECK` compares the
    // descriptor's first word.
    let misformatted = unsafe {
        (*head).bits() != mach_msg_bits(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0)
            || (*head).size() != size_of::<MigReplyHeader>() as u32
            || (*head).id() != MACH_EXCEPTION_REPLY_ID
            || (*ptr::addr_of!((*msg).ret_code_type)).word()
                != EXC_RETCODE_PROTO.word()
    };
    if misformatted {
        // SAFETY: the header is live and owned by this call; the destroyed
        // message consumes the reply right.
        unsafe {
            (*head).set_remote(MACH_PORT_NAME_NULL as usize);
            ipc_kmsg::destroy(kmsg);
        }
        return false;
    }

    // SAFETY: the checked header is a whole record.
    let code = unsafe { (*msg).ret_code };
    // SAFETY: the reply is clean and this call owns it.
    unsafe { ipc_kmsg::cache_free(kmsg) };
    code == KERN_SUCCESS
}

/// `exception_raise_continue()` of kern/exception.c: resume the receive after
/// the handoff put this thread to sleep.
///
/// # Safety
///
/// Must run as the continuation `exception_raise()` left in the thread,
/// with `ith_port` naming the live reply port and that port's message
/// queue left locked for this resumption.
pub(crate) unsafe fn raise_continue() -> ! {
    let self_ = per_cpu::thread();
    // SAFETY: the thread's `ith_port` was set by `exception_raise()`.
    let reply_port =
        unsafe { IpcPort::from_raw((*self_).saved.exception.port) };
    let reply_mqueue = unsafe { reply_port.messages() };

    // SAFETY: the queue was left locked by `exception_raise()` for this
    // resumption, and the current thread holds the reply port's reference.
    match unsafe {
        ipc_mqueue::receive(
            reply_mqueue,
            MACH_MSG_OPTION_NONE,
            MACH_MSG_SIZE_MAX,
            MACH_MSG_TIMEOUT_NONE,
            true,
            Some(exception_raise_continue),
        )
    } {
        Received::Kmsg { kmsg, .. } => {
            // SAFETY: the receive handed over a live message.
            unsafe { continue_slow(Ok(kmsg)) }
        }
        Received::TooLarge { .. } => unsafe {
            continue_slow(Err(ReceiveError::TooLarge))
        },
        Received::Failed { error } => unsafe { continue_slow(Err(error)) },
    }
}

/// `exception_raise_continue_slow()` of kern/exception.c: finish an exception
/// reply receive, retrying while the thread is interrupted.
///
/// # Safety
///
/// The caller must be the running thread, entering with no locks held and
/// with `ith_port` naming the live reply port; when `received` holds a
/// message, the caller owns it.
pub(crate) unsafe fn continue_slow(
    mut received: Result<Kmsg, ReceiveError>,
) -> ! {
    let self_ = per_cpu::thread();
    // SAFETY: the thread's `ith_port` was set by `exception_raise()`.
    let reply_port =
        unsafe { IpcPort::from_raw((*self_).saved.exception.port) };
    let reply_mqueue = unsafe { reply_port.messages() };

    while matches!(received, Err(ReceiveError::Interrupted)) {
        while should_halt(self_) {
            // SAFETY: the AST and the port are the running thread's.
            if unsafe { (*self_).ast }.contains(AstReason::TERMINATE) {
                // SAFETY: the reference `ith_port` names is this call's.
                unsafe { reply_port.release() };
            }
            // SAFETY: the thread halts at a clean point; the continuation
            // releases the port and returns to user space.
            unsafe {
                Thread::halt_self(Some(thread_release_and_exception_return));
            };
        }

        // SAFETY: the reply port is live and this call owns its reference.
        unsafe { reply_port.lock() };
        // SAFETY: the reply port is live and its lock is held.
        if !unsafe { reply_port.is_active() } {
            // SAFETY: the port lock is held.
            unsafe { reply_port.unlock() };
            received = Err(ReceiveError::PortDied);
            break;
        }
        // SAFETY: the reply queue is live; the lock order is the C's.
        unsafe {
            (*reply_mqueue).lock();
            reply_port.unlock();
        }

        // SAFETY: the queue was just locked and is unlocked by the receive,
        // and this call holds the reply port's reference.
        received = match unsafe {
            ipc_mqueue::receive(
                reply_mqueue,
                MACH_MSG_OPTION_NONE,
                MACH_MSG_SIZE_MAX,
                MACH_MSG_TIMEOUT_NONE,
                false,
                Some(exception_raise_continue),
            )
        } {
            Received::Kmsg { kmsg, .. } => Ok(kmsg),
            Received::TooLarge { .. } => Err(ReceiveError::TooLarge),
            Received::Failed { error } => Err(error),
        };
    }

    // SAFETY: the reference `ith_port` names is the one this call releases.
    unsafe { reply_port.release() };

    let handled = match received {
        Ok(reply) => {
            // SAFETY: the successful receive handed over the reply's
            // send-once right.
            unsafe { ipc_port::release_sonce(reply_port) };
            // SAFETY: the reply message is live and this call owns it.
            unsafe { parse_reply(reply) }
        }
        Err(error) => error == ReceiveError::PortDied,
    };

    if handled {
        // SAFETY: the routine returns to user mode and never comes back.
        unsafe { crate::arch::x86_64::locore::thread_exception_return() };
    }

    // SAFETY: the saved exception state belongs to the running thread.
    let (exception, code, subcode) = unsafe {
        (
            (*self_).saved.exception.exc,
            (*self_).saved.exception.code,
            (*self_).saved.exception.subcode,
        )
    };
    if exception != NO_EXCEPTION {
        // SAFETY: the exception path holds no lock here.
        unsafe { try_task(exception, code, subcode) };
    }

    unsafe { no_server() }
}
/// `exception_raise_continue()` of kern/exception.c; the receive path passes
/// it as its continuation.
///
/// # Safety
///
/// Runs as the continuation `exception_raise()` left in the thread, with
/// `ith_port` naming the live reply port.
pub(crate) unsafe extern "C" fn exception_raise_continue() {
    unsafe { raise_continue() }
}
