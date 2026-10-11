// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The task record.

use crate::platform::Platform;
use crate::types::TaskFlags;
use collections::tail_queue::{self, TailQueue};
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::pin::Pin;
use core::ptr::addr_of_mut;
use mach_emulation::EmlDispatch;
use mach_sched::time_value::TimeValue64;
use mach_vm::simple_lock::SimpleLock;

/// The registered send rights a task holds.
pub const TASK_PORT_REGISTER_MAX: usize = 4;

/// The length of a task's name, with its NUL.
pub const TASK_NAME_SIZE: usize = 32;

/// A fresh user task's priority.
pub const BASEPRI_USER: c_int = 25;

/// The task record itself.  The three boolean flags pack into one byte:
/// `active` in bit 0, `may_assign` in bit 1 and `essential` in bit 2.
#[repr(C)]
#[allow(missing_docs)]
pub struct Task<P: Platform, L, S> {
    /// `lock`: the task lock.
    pub lock: SimpleLock,
    pub ref_count: c_int,
    /// `assign_active`: waiting for `may_assign`.
    pub assign_active: u8,
    /// `active`, `may_assign` and `essential`, in that bit order.
    pub flags: TaskFlags,
    /// `map`: the address space.  `vm_map_t`, opaque here.
    pub map: *mut c_void,
    /// `pset_tasks`: link in the assigned processor set's task queue.
    pub pset_tasks: tail_queue::Link,
    pub suspend_count: c_int,
    /// `thread_list`: the task's thread queue head.
    pub thread_list: L,
    pub thread_count: c_int,
    pub processor_set: *mut S,
    pub user_stop_count: c_int,
    pub priority: c_int,
    pub max_priority: c_int,
    pub total_user_time: TimeValue64,
    pub total_system_time: TimeValue64,
    pub creation_time: TimeValue64,
    /// `itk_lock_data`: protects the registered-port fields below.
    pub itk_lock_data: SimpleLock,
    pub itk_self: *mut c_void,
    pub itk_sself: *mut c_void,
    pub itk_exception: *mut c_void,
    pub itk_bootstrap: *mut c_void,
    pub itk_registered: [*mut c_void; TASK_PORT_REGISTER_MAX],
    pub itk_space: *mut c_void,
    pub eml_dispatch: *mut EmlDispatch,
    pub machine: <P as Platform>::MachineTask,
    pub faults: c_ulong,
    pub zero_fills: c_ulong,
    pub reactivations: c_ulong,
    pub pageins: c_ulong,
    pub cow_faults: c_ulong,
    pub messages_sent: c_ulong,
    pub messages_received: c_ulong,
    pub name: [c_char; TASK_NAME_SIZE],
}

tail_queue::adapter!(
    /// The adapter for a task's `pset_tasks` in its processor set.
    pub TaskPsetAdapter<P: Platform, L, S> = Task<P, L, S> { pset_tasks }
);

/// A processor set's tasks, in the order they joined.
pub type PsetTaskList<P, L, S> = TailQueue<'static, TaskPsetAdapter<P, L, S>>;

impl<P: Platform, L, S> Task<P, L, S> {
    /// The task's threads, pinned.
    ///
    /// # Safety
    ///
    /// `task` must be live and never move, as a slab object or a static
    /// does, and the caller must hold its lock for as long as it uses the
    /// list.
    pub unsafe fn threads_pinned<'a>(task: *mut Self) -> Pin<&'a mut L> {
        // SAFETY: the task never moves, and the lock the caller holds keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut *addr_of_mut!((*task).thread_list)) }
    }

    /// Whether the task is alive.
    #[must_use]
    pub const fn active(&self) -> bool {
        self.flags.contains(TaskFlags::ACTIVE)
    }

    /// Marks the task alive or dead.
    pub const fn set_active(&mut self, active: bool) {
        self.set_flag(TaskFlags::ACTIVE, active);
    }

    /// Whether the task may move to another processor set.
    #[must_use]
    pub const fn may_assign(&self) -> bool {
        self.flags.contains(TaskFlags::MAY_ASSIGN)
    }

    /// Lets the task move to another processor set, or not.
    pub const fn set_may_assign(&mut self, may_assign: bool) {
        self.set_flag(TaskFlags::MAY_ASSIGN, may_assign);
    }

    /// Marks the task essential to the system, or not.
    pub const fn set_essential(&mut self, essential: bool) {
        self.set_flag(TaskFlags::ESSENTIAL, essential);
    }

    /// Sets or clears one flag.
    const fn set_flag(&mut self, flag: TaskFlags, on: bool) {
        self.flags = if on {
            self.flags.union(flag)
        } else {
            self.flags.difference(flag)
        };
    }
}
