// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The crate's plain data: flag words, the records the C laid out for
//! the machine code and MIG, and the small enums the calls pass.

use crate::ipc_tt::{
    TASK_BOOTSTRAP_PORT, TASK_EXCEPTION_PORT, TASK_KERNEL_PORT,
    THREAD_EXCEPTION_PORT, THREAD_KERNEL_PORT,
};
use crate::platform::Platform;
use crate::processor::Processor;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use mach_ipc::ipc_thread::SavedReceive;
use mach_vm::param::{VmOffset, VmSize};

bitflags::bitflags! {
    /// A thread's state: C's `TH_*` bits.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ThreadState: u32 {
        /// The thread is queued for waiting.
        const WAIT = 0x01;
        /// The thread has been asked to stop.
        const SUSP = 0x02;
        /// The thread is running or on a run queue.
        const RUN = 0x04;
        /// The thread is waiting uninterruptibly.
        const UNINT = 0x08;
        /// The thread is halted at a clean point.
        const HALTED = 0x10;
        /// The thread is an idle thread.
        const IDLE = 0x80;
        /// The thread has no kernel stack.
        const SWAPPED = 0x0100;
        /// The thread waits for a kernel stack.
        const SW_COMING_IN = 0x0200;
    }
}

impl ThreadState {
    /// The bits the state switches look at.
    pub const SCHED_STATE: Self = Self::WAIT
        .union(Self::SUSP)
        .union(Self::RUN)
        .union(Self::UNINT);
    /// The bits `thread_dispatch()` masks off.
    pub const SWAP_STATE: Self = Self::SWAPPED.union(Self::SW_COMING_IN);
    /// Waiting, and not to be interrupted.
    pub const WAIT_UNINT: Self = Self::WAIT.union(Self::UNINT);
    /// Waiting, and suspended.
    pub const WAIT_SUSP: Self = Self::WAIT.union(Self::SUSP);
    /// Waiting and suspended, and not to be interrupted.
    pub const WAIT_SUSP_UNINT: Self = Self::WAIT_SUSP.union(Self::UNINT);
    /// Runnable, but waiting on an event.
    pub const RUN_WAIT: Self = Self::RUN.union(Self::WAIT);
    /// Runnable, waiting and suspended.
    pub const RUN_WAIT_SUSP: Self = Self::RUN_WAIT.union(Self::SUSP);
    /// Runnable and waiting, and not to be interrupted.
    pub const RUN_WAIT_UNINT: Self = Self::RUN_WAIT.union(Self::UNINT);
    /// Runnable, waiting and suspended, and not to be interrupted.
    pub const RUN_WAIT_SUSP_UNINT: Self =
        Self::RUN_WAIT_SUSP.union(Self::UNINT);
    /// Runnable, and not to be interrupted.
    pub const RUN_UNINT: Self = Self::RUN.union(Self::UNINT);
    /// Runnable, and suspended.
    pub const RUN_SUSP: Self = Self::RUN.union(Self::SUSP);
    /// Runnable, suspended and halted at a clean point.
    pub const RUN_SUSP_HALTED: Self = Self::RUN_SUSP.union(Self::HALTED);
    /// Runnable and suspended, and not to be interrupted.
    pub const RUN_SUSP_UNINT: Self = Self::RUN_SUSP.union(Self::UNINT);
    /// The state of a processor's idle thread.
    pub const RUN_IDLE: Self = Self::RUN.union(Self::IDLE);
}

bitflags::bitflags! {
    /// The word of `struct thread` that C declares as `unsigned state:16;
    /// unsigned wake_active:1; unsigned active:1`: the thread's
    /// [`ThreadState`] in the low half, two flags above it.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct StateBits: u32 {
        /// Someone waits for the thread to become suspended.
        const WAKE_ACTIVE = 1 << 16;
        /// The thread is alive.
        const ACTIVE = 1 << 17;
        // The thread's state.
        const _ = 0xffff;
    }
}

/// The anonymous union of `struct thread` holding the bitfield word and
/// `event_key`.
#[repr(C)]
#[allow(missing_docs)]
pub union StateEvent {
    pub(crate) state: StateBits,
    pub(crate) event_key: *mut c_void,
}

/// The `exception` arm of `thread.saved`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct SavedException {
    pub port: *mut c_void,
    pub exc: c_int,
    pub code: c_int,
    pub subcode: c_long,
}

/// The `saved` union of `struct thread`: what the state selection keeps if the
/// thread's stack is discarded.
#[repr(C)]
#[allow(missing_docs)]
pub union Saved {
    pub receive: SavedReceive,
    pub exception: SavedException,
    pub other: *mut c_void,
}

const _: () = assert!(
    size_of::<StateEvent>()
        == if size_of::<*mut c_void>() > size_of::<u32>() {
            size_of::<*mut c_void>()
        } else {
            size_of::<u32>()
        }
);

const _: () = {
    assert!(size_of::<SavedException>() == 24);
    assert!(size_of::<Saved>() == 40);
};

/// The stack accounting `host_stack_usage()` and
/// `processor_set_stack_usage()` report.
pub struct StackUsage {
    /// The number of stacks counted.
    pub total: c_uint,
    /// The VM space they reserve, equal to the resident space.
    pub space: VmSize,
    /// The largest usage seen, when `STACK_CHECK_USAGE` is on.
    pub maxusage: VmSize,
    /// The address of the thread with the largest stack.
    pub maxstack: VmOffset,
}

/// The state of a [`Processor`], as its `state` member stores it.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessorState {
    /// Not in the system.
    OffLine = 0,
    /// In service and running threads.
    Running = 1,
    /// In service and on its set's idle queue.
    Idle = 2,
    /// Woken with a thread to run, not yet running it.
    Dispatching = 3,
    /// Being moved to another processor set.
    Assign = 4,
    /// Being taken out of service.
    Shutdown = 5,
}

/// A processor record on cache lines of its own.
#[repr(align(64))]
pub(crate) struct ProcessorSlot<P: Platform>(
    pub(crate) UnsafeCell<Processor<P>>,
);

// SAFETY: code reaches the record's atomic fields from any CPU, and its other
// fields only under the locks that guard them.
unsafe impl<P: Platform> Sync for ProcessorSlot<P> {}

/// Which member list `ProcessorSet::things()` copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Thing {
    Task,
    Thread,
}

/// How [`create_kernel_task()`](crate::task::create_kernel_task) chooses the
/// new task's map: the C's `child_task == &kernel_task` test and
/// `inherit_memory` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapSource {
    /// The kernel task's `kernel_map`, already built.
    Kernel,
    /// A fork of the parent's map.
    Inherit,
    /// A fresh user map, limited like the parent's when there is one.
    Fresh,
}

/// The `which` domain of `task_get_special_port()` and
/// `task_set_special_port()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskSpecialPort {
    /// `TASK_KERNEL_PORT`.
    Kernel,
    /// `TASK_EXCEPTION_PORT`.
    Exception,
    /// `TASK_BOOTSTRAP_PORT`.
    Bootstrap,
}

impl TaskSpecialPort {
    /// The port a C `which` names, or `None` for anything else.
    #[must_use]
    pub const fn from_int(which: c_int) -> Option<Self> {
        match which {
            TASK_KERNEL_PORT => Some(Self::Kernel),
            TASK_EXCEPTION_PORT => Some(Self::Exception),
            TASK_BOOTSTRAP_PORT => Some(Self::Bootstrap),
            _ => None,
        }
    }
}

/// The `which` domain of `thread_get_special_port()` and
/// `thread_set_special_port()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSpecialPort {
    /// `THREAD_KERNEL_PORT`.
    Kernel,
    /// `THREAD_EXCEPTION_PORT`.
    Exception,
}

impl ThreadSpecialPort {
    /// The port a C `which` names, or `None` for anything else.
    #[must_use]
    pub const fn from_int(which: c_int) -> Option<Self> {
        match which {
            THREAD_KERNEL_PORT => Some(Self::Kernel),
            THREAD_EXCEPTION_PORT => Some(Self::Exception),
            _ => None,
        }
    }
}

/// A slab cache the records of tasks, threads and processor sets come from;
/// the platform keeps one of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskCache {
    /// Tasks.
    Task,
    /// Threads.
    Thread,
    /// Kernel stacks.
    Stack,
    /// Processor sets.
    Pset,
}

impl TaskCache {
    /// The number of caches.
    pub const COUNT: usize = 4;
}
