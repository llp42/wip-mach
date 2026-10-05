// SPDX-License-Identifier: CMU-Mach
// Derived from kern/task.c and kern/task.h:
//   Copyright (c) 1993-1988 Carnegie Mellon University.
// Derived from include/mach/vm_statistics.h:
//   Copyright (c) 1993-1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The task module's cores and the task record.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::machine_task::{self, MachineTask};
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::pmap::pmap_collect;
use crate::arch::x86_64::pmap::pmap_create;
use crate::arch::x86_64::pmap::pmap_destroy;
use crate::arch::x86_64::spl;
use crate::ipc::ipc_space;
use crate::ipc::{IpcPort, IpcSpace};
use crate::kern::ast::{self, AstReason};
use crate::kern::console::{CStrArg, write_cstr};
use crate::kern::debug::kpanic;
use crate::kern::error::Error;
use crate::kern::host_time;
use crate::kern::ipc_tt::{
    convert_task_to_port, convert_thread_to_port, ipc_task_disable,
    ipc_task_enable, ipc_task_init, ipc_task_terminate, ipc_thread_disable,
    ipc_thread_terminate,
};
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
use crate::kern::processor::{self, ProcessorSet};
use crate::kern::sched::invalid_pri;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, compute_priority, sched_tick, thread_block,
    thread_wakeup_prim,
};
use crate::kern::slab::{CacheInitFlags, KmemCache, kalloc, kfree};
use crate::kern::syscall_emulation::EmlDispatch;
use crate::kern::thread::{TaskThreadList, Thread};
use crate::mig;
use crate::mig::time_value::{TIME_NANOS_MAX, TimeValue64};
use crate::vm::types::Pmap;
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_map::{VmMap, round_page, trunc_page};
use collections::tail_queue::{self, TailQueue};
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::ptr::{
    self, NonNull, addr_of, addr_of_mut, null_mut, with_exposed_provenance_mut,
};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

/// The registered send rights a task holds.
pub(crate) const TASK_PORT_REGISTER_MAX: usize = 4;

/// The length of a task's name, with its NUL.
const TASK_NAME_SIZE: usize = 32;

/// A fresh user task's priority.
pub(crate) const BASEPRI_USER: c_int = 25;

/// The bounds of a fresh user map.
const VM_MIN_USER_ADDRESS: VmOffset = 0;
const VM_MAX_USER_ADDRESS: VmOffset = 0x8000_0000_0000;

/// The kernel-object types of a plain port, the host name port and the
/// privileged host port.
const IKOT_NONE: c_uint = 0;
const IKOT_HOST: c_uint = 3;
const IKOT_HOST_PRIV: c_uint = 4;

/// The dead port value: the one non-null pointer a valid port check rejects.
const IP_DEAD: usize = usize::MAX;

/// `TASK_ACTIVE`, `TASK_MAY_ASSIGN` and `TASK_ESSENTIAL`: the three
/// single-bit fields `struct task` packs into one `unsigned char`.
const TASK_ACTIVE: u8 = 1 << 0;
const TASK_MAY_ASSIGN: u8 = 1 << 1;
const TASK_ESSENTIAL: u8 = 1 << 2;

/// The task record itself.  The three boolean flags pack into one byte:
/// `active` in bit 0, `may_assign` in bit 1 and `essential` in bit 2.
#[repr(C)]
#[allow(missing_docs)]
pub struct Task {
    /// `lock`: the task lock.
    pub lock: SimpleLock,
    pub ref_count: c_int,
    /// `assign_active`: waiting for `may_assign`.
    pub assign_active: u8,
    /// `active`, `may_assign` and `essential`, in that bit order.
    pub flags: u8,
    /// `map`: the address space.  `vm_map_t`, opaque here.
    pub map: *mut c_void,
    /// `pset_tasks`: link in the assigned processor set's task queue.
    pub pset_tasks: tail_queue::Link,
    pub suspend_count: c_int,
    /// `thread_list`: the task's thread queue head.
    pub thread_list: TaskThreadList,
    pub thread_count: c_int,
    pub processor_set: *mut ProcessorSet,
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
    pub machine: MachineTask,
    pub faults: c_ulong,
    pub zero_fills: c_ulong,
    pub reactivations: c_ulong,
    pub pageins: c_ulong,
    pub cow_faults: c_ulong,
    pub messages_sent: c_ulong,
    pub messages_received: c_ulong,
    pub name: [c_char; TASK_NAME_SIZE],
}

const _: () = {
    assert!(size_of::<Task>() == 336);
    assert!(align_of::<Task>() == 8);
    assert!(offset_of!(Task, lock) == 0);
    assert!(offset_of!(Task, ref_count) == 4);
    assert!(offset_of!(Task, assign_active) == 8);
    assert!(offset_of!(Task, flags) == 9);
    assert!(offset_of!(Task, map) == 16);
    assert!(offset_of!(Task, pset_tasks) == 24);
    assert!(offset_of!(Task, suspend_count) == 40);
    assert!(offset_of!(Task, thread_list) == 48);
    assert!(offset_of!(Task, thread_count) == 64);
    assert!(offset_of!(Task, processor_set) == 72);
    assert!(offset_of!(Task, user_stop_count) == 80);
    assert!(offset_of!(Task, priority) == 84);
    assert!(offset_of!(Task, max_priority) == 88);
    assert!(offset_of!(Task, total_user_time) == 96);
    assert!(offset_of!(Task, total_system_time) == 112);
    assert!(offset_of!(Task, creation_time) == 128);
    assert!(offset_of!(Task, itk_lock_data) == 144);
    assert!(offset_of!(Task, itk_self) == 152);
    assert!(offset_of!(Task, itk_sself) == 160);
    assert!(offset_of!(Task, itk_exception) == 168);
    assert!(offset_of!(Task, itk_bootstrap) == 176);
    assert!(offset_of!(Task, itk_registered) == 184);
    assert!(offset_of!(Task, itk_space) == 216);
    assert!(offset_of!(Task, eml_dispatch) == 224);
    assert!(offset_of!(Task, machine) == 232);
    assert!(offset_of!(Task, faults) == 248);
    assert!(offset_of!(Task, zero_fills) == 256);
    assert!(offset_of!(Task, reactivations) == 264);
    assert!(offset_of!(Task, pageins) == 272);
    assert!(offset_of!(Task, cow_faults) == 280);
    assert!(offset_of!(Task, messages_sent) == 288);
    assert!(offset_of!(Task, messages_received) == 296);
    assert!(offset_of!(Task, name) == 304);
};

tail_queue::adapter!(
    /// The adapter for a task's `pset_tasks` in its processor set.
    pub TaskPsetAdapter = Task { pset_tasks }
);

/// A processor set's tasks, in the order they joined.
pub type PsetTaskList = TailQueue<'static, TaskPsetAdapter>;

// The links and heads are two words each, so the offsets above hold.
const _: () = assert!(size_of::<tail_queue::Link>() == 16);
const _: () = assert!(size_of::<PsetTaskList>() == 16);
const _: () = assert!(size_of::<TaskThreadList>() == 16);

impl Task {
    /// The task's threads, pinned.
    ///
    /// # Safety
    ///
    /// `task` must be live and never move, as a slab object or a static
    /// does, and the caller must hold its lock for as long as it uses the
    /// list.
    pub(crate) unsafe fn threads_pinned<'a>(
        task: *mut Self,
    ) -> Pin<&'a mut TaskThreadList> {
        // SAFETY: the task never moves, and the lock the caller holds keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut *addr_of_mut!((*task).thread_list)) }
    }

    pub(crate) const fn active(&self) -> bool {
        self.flags & TASK_ACTIVE != 0
    }

    pub(crate) const fn set_active(&mut self, active: bool) {
        if active {
            self.flags |= TASK_ACTIVE;
        } else {
            self.flags &= !TASK_ACTIVE;
        }
    }

    const fn may_assign(&self) -> bool {
        self.flags & TASK_MAY_ASSIGN != 0
    }

    const fn set_may_assign(&mut self, may_assign: bool) {
        if may_assign {
            self.flags |= TASK_MAY_ASSIGN;
        } else {
            self.flags &= !TASK_MAY_ASSIGN;
        }
    }

    const fn set_essential(&mut self, essential: bool) {
        if essential {
            self.flags |= TASK_ESSENTIAL;
        } else {
            self.flags &= !TASK_ESSENTIAL;
        }
    }
}

/// `struct pmap_statistics`: a physical map's page counts.
#[repr(C)]
#[allow(missing_docs)]
struct PmapStatistics {
    resident_count: c_int,
    wired_count: c_int,
}

/// The physical map's prefix through `stats`, whose `resident_count`
/// [`resident_count`] reads.
#[repr(C)]
#[allow(missing_docs)]
struct PmapPrefix {
    /// `l4base` on `x86_64`: a pointer.
    _page_table: *mut c_void,
    ref_count: c_int,
    lock: SimpleLock,
    stats: PmapStatistics,
}

const _: () = {
    assert!(offset_of!(PmapPrefix, ref_count) == 8);
    assert!(offset_of!(PmapPrefix, lock) == 12);
    assert!(offset_of!(PmapPrefix, stats) == 16);
    assert!(offset_of!(PmapStatistics, resident_count) == 0);
    assert!(offset_of!(PmapStatistics, wired_count) == 4);
    assert!(size_of::<PmapStatistics>() == 8);
};

/// The kernel's own task, the first created.
static KERNEL_TASK: AtomicPtr<Task> = AtomicPtr::new(null_mut());

/// The kernel's own task, live from [`init`] on.
#[must_use]
pub(crate) fn kernel_task() -> *mut Task {
    KERNEL_TASK.load(Ordering::Relaxed)
}

/// The kernel task's self port, live from [`init`] on.
#[must_use]
pub(crate) fn kernel_task_self_port() -> *mut c_void {
    // SAFETY: `init` created the kernel task before any caller.
    unsafe { (*kernel_task()).itk_self }
}

/// The slab cache of [`Task`] records.
static mut TASK_CACHE: KmemCache = KmemCache::zeroed();

/// The port new-task notifications go to, or null.  Set at most once, by
/// `register_new_task_notification`.
pub static NEW_TASK_NOTIFICATION: AtomicPtr<c_void> =
    AtomicPtr::new(null_mut());

/// Whether the collector may run, a switch a debugger sets.
static TASK_COLLECT_ALLOWED: AtomicI32 = AtomicI32::new(1);

/// The last tick the collector ran and the minimum interval, in ticks.  Only
/// the pageout daemon writes them, so a load and a later store need no
/// read-modify-write between them.
static TASK_COLLECT_LAST_TICK: AtomicU32 = AtomicU32::new(0);
static TASK_COLLECT_MAX_RATE: AtomicU32 = AtomicU32::new(0);

/// Returns the running thread's task.
///
/// The task is live for as long as the thread runs. The pointer stays raw:
/// other threads write the task's fields concurrently.
///
/// # Panics
///
/// If the CPU runs no thread: early in boot, before its first one, or after
/// its processor shut down.
pub(crate) fn current_task() -> *mut Task {
    let thread = per_cpu::thread();
    assert!(!thread.is_null(), "current_task: no current thread");
    // SAFETY: a non-null per-CPU thread is the one this CPU runs or is
    // switching to, and a thread is freed only once stopped, so it is live.
    // Its `task` is written once, before it first runs, and it holds a
    // reference to that task until it is freed: the task is live while the
    // thread runs.
    unsafe { (*thread).task }
}

/// The pages the pmap has resident.
///
/// # Safety
///
/// `pmap` must point at a live physical map.
pub(crate) unsafe fn resident_count(pmap: *mut Pmap) -> c_int {
    unsafe { (*pmap.cast::<PmapPrefix>()).stats.resident_count }
}

/// Adds `addend` to `result`, carrying nanoseconds into seconds.
pub(crate) const fn add_time64(result: &mut TimeValue64, addend: TimeValue64) {
    result.seconds = result.seconds.wrapping_add(addend.seconds);
    result.nanoseconds = result.nanoseconds.wrapping_add(addend.nanoseconds);
    if result.nanoseconds >= TIME_NANOS_MAX {
        result.nanoseconds = result.nanoseconds.wrapping_sub(TIME_NANOS_MAX);
        result.seconds = result.seconds.wrapping_add(1);
    }
}

/// How [`create_kernel_task()`] chooses the new task's map: the C's
/// `child_task == &kernel_task` test and `inherit_memory` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MapSource {
    /// The kernel task's `kernel_map`, already built.
    Kernel,
    /// A fork of the parent's map.
    Inherit,
    /// A fresh user map, limited like the parent's when there is one.
    Fresh,
}

/// Sets up the task cache and creates the kernel task.
///
/// # Safety
///
/// Runs once, from the boot sequence, after the slab and IPC packages are
/// initialized and before any other task exists.
pub(crate) unsafe fn init() {
    unsafe {
        (*addr_of_mut!(TASK_CACHE)).init(
            b"task",
            size_of::<Task>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
    unsafe { machine_task::module_init() };

    // SAFETY: the cache is live and the caller holds no locks.
    let Ok(task) = (unsafe { create_kernel_task(None, MapSource::Kernel) })
    else {
        // The C ignored the failure and dereferenced the null `kernel_task`
        // on its next line; a shortage this early is fatal either way.
        kpanic!("task_init", "task_init: cannot create the kernel task")
    };
    KERNEL_TASK.store(task, Ordering::Relaxed);

    // SAFETY: the new kernel task is live and the name is static.
    let _ = unsafe { set_name(task, b"gnumach") };
    // SAFETY: the kernel task's map is `kernel_map`, live since the VM
    // bootstrap, and its name points at the task's own name buffer.
    unsafe {
        let map = KERNEL_MAP.cast::<VmMap>();
        (*map).name = addr_of!((*task).name).cast::<c_char>();
    }
}

/// Create the fresh, empty map a `MapSource::Fresh` task receives.
///
/// # Safety
///
/// The pmap layer must be up, a non-null `parent` must point at a live task,
/// and the caller must hold no locks.
unsafe fn fresh_task_map(parent: Option<NonNull<Task>>) -> *mut VmMap {
    let pmap = unsafe { pmap_create(0) };
    if pmap.is_null() {
        return null_mut();
    }
    let created = VmMap::create(
        pmap,
        round_page(VM_MIN_USER_ADDRESS),
        trunc_page(VM_MAX_USER_ADDRESS),
    );
    let Some(map) = created else {
        // SAFETY: the pmap came from `pmap_create()` just above.
        unsafe { pmap_destroy(NonNull::new(pmap)) };
        return null_mut();
    };
    if let Some(parent) = parent {
        unsafe {
            let parent_map =
                NonNull::new_unchecked((*parent.as_ptr()).map.cast::<VmMap>());
            (*parent_map.as_ptr()).lock.lock();
            VmMap::copy_limits(map, parent_map);
            (*parent_map.as_ptr()).lock.unlock();
        }
    }
    map.as_ptr()
}

/// Take the processor-set reference the new task receives and copy the
/// parent's priorities, or raise the fresh task's to the default set's.
///
/// # Safety
///
/// `task` must be the fresh, unshared task being initialized, and a non-null
/// `parent` must point at a live task whose lock is free.
unsafe fn task_processor_set(
    parent: Option<NonNull<Task>>,
    task: *mut Task,
) -> *mut ProcessorSet {
    let pset;
    if let Some(parent) = parent {
        unsafe {
            (*parent.as_ptr()).lock.lock();
            let parent_pset = (*parent.as_ptr()).processor_set;
            pset = if (*parent_pset).active != 0 {
                parent_pset
            } else {
                // `default_pset` is live for the life of the kernel.
                processor::default_pset()
            };
            (*pset).reference();
            addr_of_mut!((*task).priority).write((*parent.as_ptr()).priority);
            addr_of_mut!((*task).max_priority)
                .write((*parent.as_ptr()).max_priority);
            (*parent.as_ptr()).lock.unlock();
        }
    } else {
        // `default_pset` is live for the life of the kernel.
        pset = processor::default_pset();
        // SAFETY: `default_pset` is the live default set.
        unsafe { (*pset).reference() };
        // SAFETY: the new task is unshared; the C raised the priority to the
        // set's own when that is higher than `BASEPRI_USER`.
        unsafe {
            addr_of_mut!((*task).priority).write(BASEPRI_USER);
            let max_priority = (*pset).max_priority;
            addr_of_mut!((*task).max_priority).write(max_priority);
            if max_priority > BASEPRI_USER {
                addr_of_mut!((*task).priority).write(max_priority);
            }
        }
    }
    pset
}

/// Creates a task as a child of `parent`, with the map `source` asks for.
///
/// # Safety
///
/// A non-null `parent` must point at a live task whose map outlives the
/// call, and the caller must hold no locks: creation may block on the memory
/// it takes.
pub(crate) unsafe fn create_kernel_task(
    parent: Option<NonNull<Task>>,
    source: MapSource,
) -> Result<*mut Task, Error> {
    let Some(buf) = (unsafe { (*addr_of_mut!(TASK_CACHE)).alloc() }) else {
        return Err(Error::ResourceShortage);
    };
    let task = buf.as_ptr().cast::<Task>();

    // SAFETY: the task is fresh, unshared storage and every field is written
    // before anything reads it.
    unsafe {
        addr_of_mut!((*task).ref_count).write(2);
    }

    let map = match source {
        // SAFETY: `kernel_map` is live from the VM bootstrap on.
        MapSource::Kernel => unsafe { KERNEL_MAP }.cast::<VmMap>(),
        MapSource::Inherit => {
            let Some(parent) = parent else {
                return Err(Error::InvalidArgument);
            };
            let parent_map = unsafe {
                NonNull::new_unchecked((*parent.as_ptr()).map.cast::<VmMap>())
            };
            VmMap::fork(parent_map).map_or(null_mut(), NonNull::as_ptr)
        }
        MapSource::Fresh => unsafe { fresh_task_map(parent) },
    };

    if map.is_null() {
        // SAFETY: the task is the allocation just made, with no other
        // holder.
        unsafe {
            (*addr_of_mut!(TASK_CACHE)).free(buf);
        }
        return Err(Error::ResourceShortage);
    }

    // SAFETY: the task is unshared storage and the map is live; each field
    // is written once, before any read.
    unsafe {
        addr_of_mut!((*task).map).write(map.cast());
        if source != MapSource::Kernel {
            // The map takes the task's name.
            (*map).name = addr_of!((*task).name).cast();
        }
        addr_of_mut!((*task).flags).write(TASK_ACTIVE);
        addr_of_mut!((*task).assign_active).write(0);
        (*task).lock.init();
        addr_of_mut!((*task).pset_tasks).write(tail_queue::Link::new());
        addr_of_mut!((*task).thread_list).write(TaskThreadList::new());
        addr_of_mut!((*task).suspend_count).write(0);
        addr_of_mut!((*task).user_stop_count).write(0);
        addr_of_mut!((*task).thread_count).write(0);
        addr_of_mut!((*task).faults).write(0);
        addr_of_mut!((*task).zero_fills).write(0);
        addr_of_mut!((*task).reactivations).write(0);
        addr_of_mut!((*task).pageins).write(0);
        addr_of_mut!((*task).cow_faults).write(0);
        addr_of_mut!((*task).messages_sent).write(0);
        addr_of_mut!((*task).messages_received).write(0);
    }

    // SAFETY: the new task is live and unshared; the parent, when there is
    // one, is live as the caller promised.  All four calls only read the
    // parent and initialize the task's own fields.
    unsafe {
        crate::kern::syscall_emulation::task_reference(task, parent);
        ipc_task_init(task, parent);
        (*task).machine.init();

        addr_of_mut!((*task).total_user_time).write(TimeValue64::default());
        addr_of_mut!((*task).total_system_time).write(TimeValue64::default());
        host_time::record_time_stamp(addr_of_mut!((*task).creation_time));
    }

    let pset = unsafe { task_processor_set(parent, task) };

    // SAFETY: the set is live and referenced; the C took its lock around the
    // queue insert.
    unsafe {
        (*pset).lock.lock();
        (*pset).add_task(task);
        (*pset).lock.unlock();

        addr_of_mut!((*task).flags).write(TASK_ACTIVE | TASK_MAY_ASSIGN);
    }

    match parent {
        None => {
            // SAFETY: the task's name buffer is live and unshared in this
            // initializer.
            let name = unsafe { &mut (*task).name };
            write_cstr(name, format_args!("{:x}", task.expose_provenance()));
        }
        Some(parent) => unsafe {
            let name = &mut (*task).name;
            let parent_name =
                CStrArg::from_ptr((*parent.as_ptr()).name.as_ptr());
            write_cstr(
                name,
                format_args!("({:.1$})", parent_name, TASK_NAME_SIZE - 3),
            );
        },
    }

    let notification = NEW_TASK_NOTIFICATION.load(Ordering::Acquire);
    // SAFETY: the notification is the C's `ipc_port_t`; both conversions and
    // the references follow the C body.  `reference()` accepts a null
    // parent.
    unsafe {
        if !notification.is_null() {
            reference(task);
            reference(parent.map_or(null_mut(), NonNull::as_ptr));
            let _ = mig::mach_notify_new_task(
                notification,
                convert_task_to_port(task).map_or(null_mut(), IpcPort::as_ptr),
                parent.map_or(null_mut(), |parent| {
                    convert_task_to_port(parent.as_ptr())
                        .map_or(null_mut(), IpcPort::as_ptr)
                }),
            );
        }
        ipc_task_enable(task);
    }

    Ok(task)
}

/// Drops a reference on `task`, freeing it on the last one.
///
/// # Safety
///
/// `task` must be null or point at a live task the caller holds a reference
/// to, and the caller must hold no locks: the cleanup may block.
pub(crate) unsafe fn deallocate(task: *mut Task) {
    if task.is_null() {
        return;
    }

    let count = unsafe {
        (*task).lock.lock();
        let count = (*task).ref_count.wrapping_sub(1);
        (*task).ref_count = count;
        (*task).lock.unlock();
        count
    };
    if count != 0 {
        return;
    }

    // SAFETY: this is the last reference, so the machine data and emulation
    // vector belong to this call.
    unsafe {
        (*task).machine.terminate();
        crate::kern::syscall_emulation::task_deallocate(task);
    }

    // SAFETY: a live task's processor-set field was set when the set added it.
    let pset = unsafe { (*task).processor_set };
    // SAFETY: the set is live; its lock serializes the removal.
    unsafe {
        (*pset).lock.lock();
        (*pset).remove_task(task);
        (*pset).lock.unlock();
    }
    // SAFETY: the set is live and the reference taken at creation moves
    // here.
    unsafe { (*pset).deallocate() };

    // SAFETY: the task's map and IPC space are live, and each holds one of
    // the task's own references.
    unsafe {
        if let Some(map) = NonNull::new((*task).map.cast::<VmMap>()) {
            VmMap::deallocate(map);
        }
        ipc_space::release(IpcSpace::from_raw((*task).itk_space));
    }

    // SAFETY: the task came from the cache and nothing references it now.
    unsafe {
        (*addr_of_mut!(TASK_CACHE))
            .free(NonNull::new_unchecked(task.cast::<u8>()));
    }
}

/// Takes a reference on `task`, when it is not null.
///
/// # Safety
///
/// `task` must be null or point at a live task.
pub(crate) unsafe fn reference(task: *mut Task) {
    if task.is_null() {
        return;
    }

    unsafe {
        (*task).lock.lock();
        (*task).ref_count = (*task).ref_count.wrapping_add(1);
        (*task).lock.unlock();
    }
}

/// Terminates `task`: stops its threads, releases its rights and its address
/// space, and drops the reference its life held.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks: the routine blocks and deallocates.
pub(crate) unsafe fn terminate(task: *mut Task) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    let cur_task = current_task();
    let cur_thread = per_cpu::thread();

    if task == cur_task {
        unsafe {
            (*task).lock.lock();
            if !(*task).active() {
                (*task).lock.unlock();
                return Err(Error::Failure);
            }
            let s = spl::splsched();
            (*cur_thread).lock.lock();
            if !(*cur_thread).active() {
                (*cur_thread).lock.unlock();
                spl::splx(s);
                (*task).lock.unlock();
                let _ = Thread::terminate(cur_thread);
                return Err(Error::Failure);
            }
            hold_locked(task);
            (*task).set_active(false);
            Task::threads_pinned(task)
                .remove_ptr(NonNull::new_unchecked(cur_thread));
            (*cur_thread).lock.unlock();
            spl::splx(s);
            (*task).lock.unlock();

            // The current thread must be left alone to terminate the task.
            ipc_thread_disable(cur_thread);
            ipc_thread_terminate(cur_thread);
        }
    } else {
        unsafe {
            if task.addr() < cur_task.addr() {
                (*task).lock.lock();
                (*cur_task).lock.lock();
            } else {
                (*cur_task).lock.lock();
                (*task).lock.lock();
            }

            let s = spl::splsched();
            (*cur_thread).lock.lock();
            if !(*cur_task).active() || !(*cur_thread).active() {
                (*cur_thread).lock.unlock();
                spl::splx(s);
                (*task).lock.unlock();
                (*cur_task).lock.unlock();
                let _ = Thread::terminate(cur_thread);
                return Err(Error::Failure);
            }
            (*cur_thread).lock.unlock();
            spl::splx(s);
            (*cur_task).lock.unlock();

            if !(*task).active() {
                (*task).lock.unlock();
                return Err(Error::Failure);
            }
            hold_locked(task);
            (*task).set_active(false);
            (*task).lock.unlock();
        }
    }

    let _ = unsafe { dowait(task, true) };

    unsafe { ipc_task_disable(task) };

    // SAFETY: the task is live and unlocked here, as the C's loop needs.
    unsafe { terminate_threads(task) };

    unsafe { ipc_task_terminate(task) };

    unsafe { deallocate(task) };

    // SAFETY: the current thread's `task` field is live; when it names this
    // task, the thread still holds a reference, so the task was not freed
    // above.
    unsafe {
        if (*cur_thread).task == task {
            (*task).lock.lock();
            let s = spl::splsched();
            Task::threads_pinned(task)
                .push_back_ptr(NonNull::new_unchecked(cur_thread));
            spl::splx(s);
            (*task).lock.unlock();
            let _ = Thread::terminate(cur_thread);
        }
    }

    Ok(())
}

/// The thread after `thread` on `task`'s list, or `None` past the last.
///
/// # Safety
///
/// The caller must hold the task lock, and `thread` must be on the list.
unsafe fn next_thread(
    task: *mut Task,
    thread: *mut Thread,
) -> Option<NonNull<Thread>> {
    // SAFETY: the lock is held and `thread` is on the list.
    let mut cursor = unsafe {
        Task::threads_pinned(task)
            .cursor_mut_from_ptr(NonNull::new_unchecked(thread))
    };
    cursor.move_next();
    cursor.current_ptr()
}

/// The task after `task` on `pset`'s list, or `None` past the last.
///
/// # Safety
///
/// The caller must hold the set's lock, and `task` must be on its list.
unsafe fn next_task(
    pset: *mut ProcessorSet,
    task: *mut Task,
) -> Option<NonNull<Task>> {
    // SAFETY: the lock is held and `task` is on the list.
    let mut cursor = unsafe {
        (*pset)
            .tasks_pinned()
            .cursor_mut_from_ptr(NonNull::new_unchecked(task))
    };
    cursor.move_next();
    cursor.current_ptr()
}

/// Drains and force-terminates every thread on `task`'s list.
///
/// # Safety
///
/// `task` must be live and unlocked.
unsafe fn terminate_threads(task: *mut Task) {
    // SAFETY: the task is live and unlocked here, as the C's loop needs;
    // each removed thread holds a reference while it is walked.
    unsafe {
        (*task).lock.lock();
        while let Some(first) =
            (*task).thread_list.cursor_front().current_ptr()
        {
            let mut thread = first.as_ptr();
            Thread::reference(thread);

            loop {
                // Capture the successor before `force_terminate()` unlinks
                // `thread`.
                let next = next_thread(task, thread);

                if let Some(next) = next {
                    Thread::reference(next.as_ptr());
                }

                (*task).lock.unlock();
                Thread::force_terminate(thread);
                Thread::deallocate(thread);
                thread_block(None);
                (*task).lock.lock();
                let Some(next) = next else {
                    break;
                };
                thread = next.as_ptr();
            }
        }
        (*task).lock.unlock();
    }
}

/// Holds every thread of `task` but the current one, counting one more
/// suspension.
///
/// # Safety
///
/// The caller must hold `task`'s lock, and `task` must be live.
pub(crate) unsafe fn hold_locked(task: *mut Task) {
    let cur_thread = per_cpu::thread();

    unsafe {
        (*task).suspend_count = (*task).suspend_count.wrapping_add(1);

        let list = addr_of_mut!((*task).thread_list);
        let mut cursor = (*list).cursor_front();
        while let Some(thread) = cursor.current_ptr() {
            cursor.move_next();
            let thread = thread.as_ptr();
            if thread != cur_thread {
                Thread::hold(thread);
            }
        }
    }
}

/// Holds every thread of `task` but the current one.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks.
pub(crate) unsafe fn hold(task: *mut Task) -> Result<(), Error> {
    unsafe {
        (*task).lock.lock();
        if !(*task).active() {
            (*task).lock.unlock();
            return Err(Error::Failure);
        }
        hold_locked(task);
        (*task).lock.unlock();
    }
    Ok(())
}

/// Waits for the held threads of `task` to stop, when `must_wait` is set.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks: the routine waits and may block.
pub(crate) unsafe fn dowait(
    task: *mut Task,
    must_wait: bool,
) -> Result<(), Error> {
    let cur_thread = per_cpu::thread();
    let list = unsafe { addr_of_mut!((*task).thread_list) };
    let mut prev_thread: *mut Thread = null_mut();
    let mut result = Ok(());

    unsafe {
        (*task).lock.lock();
        let mut thread = (*list).cursor_front().current_ptr();
        while let Some(current) = thread {
            let current = current.as_ptr();

            if !(*task).active() && !must_wait {
                result = Err(Error::Failure);
                break;
            }

            if current != cur_thread {
                Thread::reference(current);
                (*task).lock.unlock();
                if !prev_thread.is_null() {
                    Thread::deallocate(prev_thread);
                }
                let _ = Thread::dowait(current, true);
                prev_thread = current;
                (*task).lock.lock();
            }

            // The reference held on `current` keeps it linked, so its
            // successor is the list's current one.
            thread = next_thread(task, current);
        }
        (*task).lock.unlock();

        if !prev_thread.is_null() {
            Thread::deallocate(prev_thread);
        }
    }

    result
}

/// Releases one hold on every thread of `task`.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks.
pub(crate) unsafe fn release(task: *mut Task) -> Result<(), Error> {
    unsafe {
        (*task).lock.lock();
        if !(*task).active() {
            (*task).lock.unlock();
            return Err(Error::Failure);
        }

        (*task).suspend_count = (*task).suspend_count.wrapping_sub(1);

        let list = addr_of_mut!((*task).thread_list);
        let mut entry = (*list).cursor_front().current_ptr();
        while let Some(thread) = entry {
            let thread = thread.as_ptr();
            // Capture the successor before `release()` may unlink `thread`.
            entry = next_thread(task, thread);
            Thread::release(thread);
        }
        (*task).lock.unlock();
    }

    Ok(())
}

/// The live threads of `task`, each converted to a port name the caller owns.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks: the routine allocates.
pub(crate) unsafe fn threads(
    task: *mut Task,
) -> Result<(Option<NonNull<VmOffset>>, c_uint), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    let mut size: VmSize = 0;
    let mut addr: Option<NonNull<u8>> = None;
    let mut actual: c_uint;
    let mut size_needed: usize;

    loop {
        unsafe {
            (*task).lock.lock();
            if !(*task).active() {
                (*task).lock.unlock();
                return Err(Error::Failure);
            }

            // The C read the `int` count into an `unsigned int`; it is the
            // number of threads and never negative.
            actual = (*task).thread_count as c_uint;
            // `sizeof(mach_port_t)` is a `vm_offset_t` on the kernel side,
            // and the `unsigned int` count widens to `usize`.
            size_needed = actual as usize * size_of::<VmOffset>();
            if size_needed <= size {
                break;
            }

            (*task).lock.unlock();
        }

        if let Some(old) = addr {
            // SAFETY: the old buffer is the live allocation of `size` bytes
            // made above.
            unsafe { kfree(old, size) };
        }
        size = size_needed;
        // SAFETY: `kalloc_init()` ran during the boot this MIG entry
        // follows.
        let Some(buf) = kalloc(size) else {
            return Err(Error::ResourceShortage);
        };
        addr = Some(buf);
    }

    let Some(buf) = addr else {
        // The count was zero on the first look, so nothing was allocated.
        // SAFETY: the task lock was left held by the break above.
        unsafe { (*task).lock.unlock() };
        return Ok((None, 0));
    };

    if actual == 0 {
        // SAFETY: the task lock is still held by the break above, and the
        // buffer is the live allocation of `size` bytes.
        unsafe {
            (*task).lock.unlock();
            kfree(buf, size);
        }
        return Ok((None, 0));
    }

    let mut threads = buf.as_ptr().cast::<VmOffset>();
    // SAFETY: the task lock is held, so every queue entry is a live thread,
    // and the references taken here keep them alive.  An address is the same
    // width as the thread pointers the C stored.
    unsafe {
        let list = addr_of_mut!((*task).thread_list);
        let mut cursor = (*list).cursor_front();
        for i in 0..actual as usize {
            let Some(thread) = cursor.current_ptr() else {
                break;
            };
            let thread = thread.as_ptr();
            Thread::reference(thread);
            threads.add(i).write(thread.addr());
            cursor.move_next();
        }
        (*task).lock.unlock();
    }

    if size_needed < size {
        // `actual` is nonzero here, so the smaller size is too.
        // SAFETY: `kalloc_init()` ran during the boot.
        let Some(new) = kalloc(size_needed) else {
            // SAFETY: every slot holds a referenced thread, and the buffer
            // is the live allocation of `size` bytes.
            unsafe {
                for i in 0..actual as usize {
                    Thread::deallocate(with_exposed_provenance_mut(
                        threads.add(i).read(),
                    ));
                }
                kfree(buf, size);
            }
            return Err(Error::ResourceShortage);
        };

        // SAFETY: both buffers are live and distinct, the copy fits the
        // smaller one, and the old allocation is released.
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), new.as_ptr(), size_needed);
            kfree(buf, size);
        }
        threads = new.as_ptr().cast::<VmOffset>();
    }

    // SAFETY: every slot holds a referenced thread whose port conversion
    // hands the reference on; the buffer has room for all of them.
    unsafe {
        for i in 0..actual as usize {
            let port = convert_thread_to_port(with_exposed_provenance_mut(
                threads.add(i).read(),
            ));
            threads
                .add(i)
                .write(port.map_or(0, |port| port.as_ptr().addr()));
        }

        Ok((Some(NonNull::new_unchecked(threads)), actual))
    }
}

/// Suspends `task`: holds its threads and waits for them to stop.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks.
pub(crate) unsafe fn suspend(task: *mut Task) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    let first_stop = unsafe {
        (*task).lock.lock();
        let first_stop = (*task).user_stop_count == 0;
        (*task).user_stop_count = (*task).user_stop_count.wrapping_add(1);
        (*task).lock.unlock();
        first_stop
    };

    if !first_stop {
        return Ok(());
    }

    unsafe { hold(task) }?;
    unsafe { dowait(task, false) }?;

    if current_task() == task {
        let thread = per_cpu::thread();
        // SAFETY: the current thread is live.
        unsafe { Thread::hold(thread) };
        // SAFETY: the AST write is atomic, and the level is restored before
        // the call returns.
        unsafe {
            let s = spl::splsched();
            ast::on(cpu_id(), AstReason::BLOCK);
            spl::splx(s);
        }
    }

    Ok(())
}

/// Resumes `task`: releases the hold of its last suspension.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks.
pub(crate) unsafe fn resume(task: *mut Task) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    let release_now = unsafe {
        (*task).lock.lock();
        if (*task).user_stop_count > 0 {
            (*task).user_stop_count = (*task).user_stop_count.wrapping_sub(1);
            let release_now = (*task).user_stop_count == 0;
            (*task).lock.unlock();
            release_now
        } else {
            (*task).lock.unlock();
            return Err(Error::Failure);
        }
    };

    if release_now {
        unsafe { release(task) }
    } else {
        Ok(())
    }
}

/// Assign every thread of `task` to `new_pset`, holding the task lock
/// as the C did.
///
/// # Safety
///
/// `task` must be live with its lock held and its `may_assign` clear,
/// and `new_pset` must be live and referenced.
unsafe fn assign_task_threads(
    task: *mut Task,
    new_pset: *mut ProcessorSet,
) -> Result<(), Error> {
    // SAFETY: the task lock is held; every queue entry is a live thread,
    // and the reference keeps the one between iterations alive.
    unsafe {
        let list = addr_of_mut!((*task).thread_list);
        let mut prev_thread: *mut Thread = null_mut();
        let mut result = Ok(());
        let mut thread = (*list).cursor_front().current_ptr();
        while let Some(current) = thread {
            let current = current.as_ptr();

            if !(*task).active() {
                result = Err(Error::Failure);
                break;
            }

            if current != per_cpu::thread() {
                Thread::reference(current);
                (*task).lock.unlock();
                if !prev_thread.is_null() {
                    Thread::deallocate(prev_thread);
                }
                let _ = Thread::assign(current, new_pset);
                prev_thread = current;
                (*task).lock.lock();
            }

            // The reference held on `current` keeps it linked, so its
            // successor is the list's current one.
            thread = next_thread(task, current);
        }

        (*task).set_may_assign(true);
        if (*task).assign_active != 0 {
            (*task).assign_active = 0;
            thread_wakeup_prim(
                addr_of_mut!((*task).assign_active).cast::<c_void>(),
                0,
                THREAD_AWAKENED,
            );
        }
        (*task).lock.unlock();

        if !prev_thread.is_null() {
            Thread::deallocate(prev_thread);
        }

        if current_task() == task {
            Thread::doassign(per_cpu::thread(), new_pset, true);
        }

        result
    }
}

/// Moves `task` into `new_pset`, with its threads when `assign_threads` is
/// set.
///
/// # Safety
///
/// `task` must be null or point at a live task, `new_pset` must be null or
/// point at a live processor set, and the caller must hold no locks: the
/// routine waits and may block.
pub(crate) unsafe fn assign(
    task: *mut Task,
    new_pset: *mut ProcessorSet,
    assign_threads: bool,
) -> Result<(), Error> {
    if task.is_null() || new_pset.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*task).lock.lock();
        while !(*task).may_assign() {
            (*task).assign_active = 1;
            assert_wait(
                NonNull::new(addr_of_mut!((*task).assign_active).cast()),
                c_int::from(true),
            );
            (*task).lock.unlock();
            thread_block(None);
            (*task).lock.lock();
        }

        if (*task).processor_set == new_pset {
            (*task).lock.unlock();
            return Ok(());
        }

        (*task).set_may_assign(false);
        (*task).lock.unlock();
    }

    // SAFETY: the task lock was dropped above, so the set field is stable
    // for the freeze; a live task's set is live.
    let pset = unsafe { (*task).processor_set };
    let mut new_pset = new_pset;

    // SAFETY: both sets are live; the C locks them in address order to avoid
    // deadlock and re-checks the new one under the locks.
    unsafe {
        loop {
            if pset.addr() < new_pset.addr() {
                (*pset).lock.lock();
                (*new_pset).lock.lock();
            } else {
                (*new_pset).lock.lock();
                (*pset).lock.lock();
            }

            if (*new_pset).active == 0 {
                (*pset).lock.unlock();
                (*new_pset).lock.unlock();
                new_pset = processor::default_pset();
                continue;
            }

            (*new_pset).reference();
            break;
        }

        (*task).lock.lock();
        (*pset).remove_task(task);
        (*new_pset).add_task(task);
        (*pset).lock.unlock();
        (*new_pset).lock.unlock();
    }

    if !assign_threads {
        // SAFETY: the task lock is held here.
        unsafe {
            (*task).set_may_assign(true);
            if (*task).assign_active != 0 {
                (*task).assign_active = 0;
                thread_wakeup_prim(
                    addr_of_mut!((*task).assign_active).cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*task).lock.unlock();
        }
        // SAFETY: the set is live and referenced.
        unsafe { (*pset).deallocate() };
        return Ok(());
    }

    if current_task() == task {
        // SAFETY: the task lock is held, and the current thread is live.
        unsafe {
            (*task).lock.unlock();
            Thread::freeze(per_cpu::thread());
            (*task).lock.lock();
        }
    }

    // SAFETY: the task lock is held; every queue entry is a live thread, and
    // the reference keeps the one between iterations alive.
    // SAFETY: the task lock is held, and the new set is referenced.
    let result = unsafe { assign_task_threads(task, new_pset) };

    // SAFETY: the set is live and referenced.
    unsafe { (*pset).deallocate() };
    result
}

/// The processor set `task` is assigned to, with a reference.
///
/// # Safety
///
/// `task` must be null or point at a live task.
pub(crate) unsafe fn get_assignment(
    task: *mut Task,
) -> Result<*mut ProcessorSet, Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        if !(*task).active() {
            return Err(Error::Failure);
        }
        let pset = (*task).processor_set;
        (*pset).reference();
        Ok(pset)
    }
}

/// Sets `task`'s priority, and its threads' when `change_threads` is set.
///
/// # Safety
///
/// `task` must be null or point at a live task, and the caller must hold no
/// locks.
pub(crate) unsafe fn priority(
    task: *mut Task,
    priority: c_int,
    change_threads: bool,
) -> Result<(), Error> {
    if task.is_null() || invalid_pri(priority) {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*task).lock.lock();
        if (*task).max_priority > priority {
            (*task).lock.unlock();
            return Err(Error::NoAccess);
        }
        (*task).priority = priority;

        let mut result = Ok(());
        if change_threads {
            let list = addr_of_mut!((*task).thread_list);
            let mut cursor = (*list).cursor_front();
            while let Some(thread) = cursor.current_ptr() {
                cursor.move_next();
                let thread = thread.as_ptr();
                if Thread::priority(thread, priority, false).is_err() {
                    result = Err(Error::Failure);
                }
            }
        }
        (*task).lock.unlock();
        result
    }
}

/// Sets `task`'s name.
///
/// # Safety
///
/// `task` must be null or point at a live task.
pub(crate) unsafe fn set_name(
    task: *mut Task,
    name: &[u8],
) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        let dst = core::slice::from_raw_parts_mut(
            addr_of_mut!((*task).name).cast::<u8>(),
            TASK_NAME_SIZE,
        );
        dst.fill(0);
        let copy = name.len().min(TASK_NAME_SIZE - 1);
        dst[..copy].copy_from_slice(&name[..copy]);
    }
    Ok(())
}

/// Marks `task` essential or not.
///
/// # Safety
///
/// `task` must be null or point at a live task.
pub(crate) unsafe fn set_essential(
    task: *mut Task,
    essential: bool,
) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe { (*task).set_essential(essential) };
    Ok(())
}

/// Walks every processor set's tasks and lets the machine layer release what
/// it can.
///
/// # Safety
///
/// The collector calls this with nothing locked.
unsafe fn collect_scan() {
    let mut prev_task: *mut Task = null_mut();
    let mut prev_pset: *mut ProcessorSet = null_mut();

    // SAFETY: the walk keeps a reference on both the set and the task between
    // iterations.
    unsafe {
        let mut all_psets = processor::ALL_PSETS.lock();
        let mut pset_entry = all_psets.list().cursor_front().current_ptr();
        while let Some(pset) = pset_entry {
            let pset = pset.as_ptr();
            (*pset).lock.lock();

            let mut task_entry = (*pset).tasks.cursor_front().current_ptr();
            while let Some(task) = task_entry {
                let task = task.as_ptr();
                reference(task);
                (*pset).reference();
                (*pset).lock.unlock();

                all_psets.unlocked(|| {
                    (*task).machine.collect();
                    pmap_collect(NonNull::new(
                        (*(*task).map.cast::<VmMap>()).pmap,
                    ));

                    if !prev_task.is_null() {
                        deallocate(prev_task);
                    }
                    prev_task = task;

                    if !prev_pset.is_null() {
                        (*prev_pset).deallocate();
                    }
                    prev_pset = pset;
                });

                (*pset).lock.lock();
                // `task` is referenced, so it stays linked.
                task_entry = next_task(pset, task);
            }
            (*pset).lock.unlock();
            // `pset` is still linked: the walk either kept the list's lock
            // or holds a reference on the set.
            let mut cursor = all_psets
                .list_pinned()
                .cursor_mut_from_ptr(NonNull::new_unchecked(pset));
            cursor.move_next();
            pset_entry = cursor.current_ptr();
        }
        drop(all_psets);

        if !prev_task.is_null() {
            deallocate(prev_task);
        }
        if !prev_pset.is_null() {
            (*prev_pset).deallocate();
        }
    }
}

/// Runs the collector, when it is allowed and its last run is long enough ago.
///
/// # Safety
///
/// The pageout daemon calls this with nothing locked, as the C did.
pub(crate) unsafe fn consider_collect() {
    // The C's `hz / 1` and the usual arithmetic conversions reinterpret the
    // signed tick rate as unsigned; `hz` is positive and set before the
    // pageout daemon can run.
    let hz_rate = machine::CLOCK_HZ as c_uint;
    let mut max_rate = TASK_COLLECT_MAX_RATE.load(Ordering::Relaxed);
    if max_rate == 0 {
        max_rate = hz_rate;
        TASK_COLLECT_MAX_RATE.store(max_rate, Ordering::Relaxed);
    }

    let last_tick = TASK_COLLECT_LAST_TICK.load(Ordering::Relaxed);
    let deadline = last_tick.wrapping_add(max_rate / hz_rate);
    if TASK_COLLECT_ALLOWED.load(Ordering::Relaxed) != 0
        && sched_tick() > deadline
    {
        TASK_COLLECT_LAST_TICK.store(sched_tick(), Ordering::Relaxed);
        unsafe { collect_scan() };
    }
}

/// Sets `thread`'s maximum priority, and lowers its priority to it when
/// `set_priority` is set.
///
/// # Safety
///
/// `thread` must point at a live thread, and the caller must hold the task
/// lock the C held.
unsafe fn override_max_priority(
    thread: *mut Thread,
    max_priority: c_int,
    set_priority: bool,
) {
    // SAFETY: the thread lock is taken under `splsched()`.
    let s = unsafe { spl::splsched() };
    unsafe {
        (*thread).lock.lock();

        (*thread).max_priority = max_priority;
        let pset = (*thread).processor_set;
        if (*pset).max_priority > max_priority {
            (*thread).max_priority = (*pset).max_priority;
        }
        if (*thread).max_priority > (*thread).priority || set_priority {
            (*thread).priority = (*thread).max_priority;
        }

        compute_priority(thread, c_int::from(true));

        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// The kernel-object type of `port` when it is a host or privileged host port,
/// `IKOT_NONE` otherwise.
///
/// # Safety
///
/// `port` must be null, `IP_DEAD` or a live port.
unsafe fn extract_host_type(port: *mut c_void) -> c_uint {
    if port.is_null() || port.addr() == IP_DEAD {
        return IKOT_NONE;
    }

    // SAFETY: the checks above rule out null and dead, so the pointer is live.
    let port = unsafe { IpcPort::from_raw(port) };
    // SAFETY: the port is live; the lock is held over the fields the C read.
    let ikot = unsafe {
        port.lock();
        let ikot = if port.is_active() {
            port.kotype()
        } else {
            IKOT_NONE
        };
        port.unlock();
        ikot
    };

    if ikot == IKOT_HOST || ikot == IKOT_HOST_PRIV {
        ikot
    } else {
        IKOT_NONE
    }
}

/// Sets `task`'s maximum priority with the privilege the host port `host`
/// carries, and its threads' when `change_threads` is set.
///
/// # Safety
///
/// `host` must be the port MIG converted from the request, `task` must be
/// null or point at a live task, and the caller must hold no locks.
pub(crate) unsafe fn max_priority(
    host: *mut c_void,
    task: *mut Task,
    max_priority: c_int,
    set_priority: bool,
    change_threads: bool,
) -> Result<(), Error> {
    let ikot_host = unsafe { extract_host_type(host) };

    if ikot_host == IKOT_NONE || task.is_null() || invalid_pri(max_priority) {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*task).lock.lock();

        if max_priority < (*task).max_priority && ikot_host != IKOT_HOST_PRIV {
            (*task).lock.unlock();
            return Err(Error::NoAccess);
        }

        (*task).max_priority = max_priority;
        if max_priority > (*task).priority || set_priority {
            (*task).priority = max_priority;
        }

        if change_threads {
            let list = addr_of_mut!((*task).thread_list);
            let mut cursor = (*list).cursor_front();
            while let Some(thread) = cursor.current_ptr() {
                cursor.move_next();
                let thread = thread.as_ptr();
                override_max_priority(thread, max_priority, set_priority);
            }
        }

        (*task).lock.unlock();
    }

    Ok(())
}
