// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_tt.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The task- and thread-related IPC operations, which `kern/ipc_tt.c` used to
//! define and `kern/ipc_tt.h` declares.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::per_cpu;
use crate::ipc::ipc_port;
use crate::ipc::ipc_space;
use crate::ipc::ipc_thread::ipc_thread_links_init;
use crate::ipc::{IpcPort, IpcSpace};
use crate::kern::debug::kpanic;
use crate::kern::slab::{kalloc, kfree};
use crate::kern::task::{self, TASK_PORT_REGISTER_MAX, Task, current_task};
use crate::kern::thread::{IpcKmsgQueue, Thread};
use crate::kern::types::KernError;
use crate::vm::vm_map::VmMap;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};

/// `IKOT_THREAD` and `IKOT_TASK` of <`kern/ipc_kobject.h`>.
const IKOT_THREAD: c_uint = 1;
const IKOT_TASK: c_uint = 2;
/// `IKOT_NONE` of <`kern/ipc_kobject.h>`: the type of a port bound to no kernel
/// object.
const IKOT_NONE: c_uint = 0;
/// `IKO_NULL` of <`kern/ipc_kobject.h>`: the value that clears a port's
/// `ip_kobject`.
const IKO_NULL: VmOffset = 0;

/// `TASK_KERNEL_PORT`, `TASK_EXCEPTION_PORT` and `TASK_BOOTSTRAP_PORT` of
/// <`mach/task_special_ports.h>`: the `which` values `task_*_special_port()`
/// accepts.
const TASK_KERNEL_PORT: c_int = 1;
const TASK_EXCEPTION_PORT: c_int = 3;
const TASK_BOOTSTRAP_PORT: c_int = 4;

/// `THREAD_KERNEL_PORT` and `THREAD_EXCEPTION_PORT` of
/// <`mach/thread_special_ports.h`>.
const THREAD_KERNEL_PORT: c_int = 1;
const THREAD_EXCEPTION_PORT: c_int = 3;

/// `MACH_PORT_NULL` of <mach/port.h>.
const MACH_PORT_NULL: c_uint = 0;

/// The `which` domain of `task_get_special_port()` and
/// `task_set_special_port()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskSpecialPort {
    /// `TASK_KERNEL_PORT`.
    Kernel,
    /// `TASK_EXCEPTION_PORT`.
    Exception,
    /// `TASK_BOOTSTRAP_PORT`.
    Bootstrap,
}

impl TaskSpecialPort {
    /// The port a C `which` names, or `None` for anything else.
    pub(crate) const fn from_int(which: c_int) -> Option<Self> {
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
pub(crate) enum ThreadSpecialPort {
    /// `THREAD_KERNEL_PORT`.
    Kernel,
    /// `THREAD_EXCEPTION_PORT`.
    Exception,
}

impl ThreadSpecialPort {
    /// The port a C `which` names, or `None` for anything else.
    pub(crate) const fn from_int(which: c_int) -> Option<Self> {
        match which {
            THREAD_KERNEL_PORT => Some(Self::Kernel),
            THREAD_EXCEPTION_PORT => Some(Self::Exception),
            _ => None,
        }
    }
}

/// `ipc_space_create()` of <`ipc/ipc_space.h`>.
fn create_space() -> Result<*mut c_void, KernError> {
    Ok(ipc_space::create()?.as_ptr())
}

/// The C `panic()` of `ipc_task_init()` and `ipc_thread_init()`.
fn init_panic(fun: &'static str) -> ! {
    kpanic!(fun, "{}", fun)
}

/// The `if (IP_VALID(port)) ipc_port_release_send(port);` the C repeats.
///
/// # Safety
///
/// A non-null, non-dead `port` must hold one send right.
unsafe fn release_send_if_valid(port: *mut c_void) {
    if let Some(port) = IpcPort::valid(port) {
        unsafe { ipc_port::release_send(port) };
    }
}

/// `ipc_task_init()` in C.
///
/// # Safety
///
/// `task` must be a fresh task whose IPC fields this call is the first to
/// write, and a non-null `parent` a live task whose own
/// `ipc_task_init()` already ran; the caller must hold no locks, as the
/// allocation may block.
pub(crate) unsafe fn ipc_task_init(
    task: *mut Task,
    parent: Option<NonNull<Task>>,
) {
    let Ok(space) = create_space() else {
        init_panic("ipc_task_init")
    };

    // SAFETY: the kernel's space is live for the life of the kernel; this
    // is the C's `ipc_port_alloc_kernel()`.
    let kport = unsafe { ipc_port::alloc_special(ipc_space::kernel()) };
    let Some(kport) = kport else {
        init_panic("ipc_task_init")
    };

    unsafe {
        (*task).itk_lock_data.init();
        (*task).itk_self = kport.as_ptr();
        (*task).itk_sself = ipc_port::make_send(kport).as_ptr();
        (*task).itk_space = space;

        match parent {
            None => {
                (*task).itk_exception = ptr::null_mut();
                (*task).itk_bootstrap = ptr::null_mut();
                (*task).itk_registered =
                    [ptr::null_mut(); TASK_PORT_REGISTER_MAX];
            }
            Some(parent) => {
                (*parent.as_ptr()).itk_lock_data.lock();
                for (slot, parent_port) in (*task)
                    .itk_registered
                    .iter_mut()
                    .zip((*parent.as_ptr()).itk_registered.iter())
                {
                    *slot = ipc_port::copy_send(*parent_port);
                }
                (*task).itk_exception =
                    ipc_port::copy_send((*parent.as_ptr()).itk_exception);
                (*task).itk_bootstrap =
                    ipc_port::copy_send((*parent.as_ptr()).itk_bootstrap);
                (*parent.as_ptr()).itk_lock_data.unlock();
            }
        }
    }
}

/// `ipc_task_enable()` in C.
///
/// # Safety
///
/// `task` must point at a live task whose IPC state is initialized and not
/// terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_task_enable(task: *mut Task) {
    unsafe {
        (*task).itk_lock_data.lock();
        let kport = (*task).itk_self;
        if !kport.is_null() {
            crate::kern::ipc_kobject::set(kport, task.addr(), IKOT_TASK);
        }
        (*task).itk_lock_data.unlock();
    }
}

/// `ipc_task_disable()` in C.
///
/// # Safety
///
/// `task` must point at a live task whose IPC state is initialized and not
/// terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_task_disable(task: *mut Task) {
    unsafe {
        (*task).itk_lock_data.lock();
        let kport = (*task).itk_self;
        if !kport.is_null() {
            crate::kern::ipc_kobject::set(kport, IKO_NULL, IKOT_NONE);
        }
        (*task).itk_lock_data.unlock();
    }
}

/// `ipc_task_terminate()` in C.
///
/// # Safety
///
/// `task` must be a live, suspended task, or the current thread's own task,
/// and the caller must hold no locks.
pub(crate) unsafe fn ipc_task_terminate(task: *mut Task) {
    let kport = unsafe {
        (*task).itk_lock_data.lock();
        let kport = (*task).itk_self;
        if kport.is_null() {
            (*task).itk_lock_data.unlock();
            return;
        }
        (*task).itk_self = ptr::null_mut();
        (*task).itk_lock_data.unlock();
        kport
    };

    unsafe {
        release_send_if_valid((*task).itk_sself);
        release_send_if_valid((*task).itk_exception);
        release_send_if_valid((*task).itk_bootstrap);
        for port in &(*task).itk_registered {
            release_send_if_valid(*port);
        }
        ipc_space::destroy(IpcSpace::from_raw((*task).itk_space));
        ipc_port::dealloc_special(IpcPort::from_raw(kport));
    }
}

/// `ipc_thread_init()` in C.
///
/// # Safety
///
/// `thread` must be a fresh thread whose IPC fields this call is the first to
/// write, and the caller must hold no locks: the allocation may block.
pub(crate) unsafe fn ipc_thread_init(thread: *mut Thread) {
    // SAFETY: the kernel's space is live for the life of the kernel; this
    // is the C's `ipc_port_alloc_kernel()`.
    let kport = unsafe { ipc_port::alloc_special(ipc_space::kernel()) };
    let Some(kport) = kport else {
        init_panic("ipc_thread_init")
    };

    unsafe {
        ipc_thread_links_init(thread.cast());
        (*thread).ith_messages = IpcKmsgQueue {
            base: ptr::null_mut(),
        };
        (*thread).ith_lock_data.init();
        (*thread).ith_self = kport.as_ptr();
        (*thread).ith_sself = ipc_port::make_send(kport).as_ptr();
        (*thread).ith_exception = ptr::null_mut();
        (*thread).ith_mig_reply = MACH_PORT_NULL;
        (*thread).ith_rpc_reply = ptr::null_mut();
    }
}

/// `ipc_thread_enable()` in C.
///
/// # Safety
///
/// `thread` must point at a live thread whose IPC state is initialized and
/// not terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_thread_enable(thread: *mut Thread) {
    unsafe {
        (*thread).ith_lock_data.lock();
        let kport = (*thread).ith_self;
        if !kport.is_null() {
            crate::kern::ipc_kobject::set(kport, thread.addr(), IKOT_THREAD);
        }
        (*thread).ith_lock_data.unlock();
    }
}

/// `ipc_thread_disable()` in C.
///
/// # Safety
///
/// `thread` must point at a live thread whose IPC state is initialized and
/// not terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_thread_disable(thread: *mut Thread) {
    unsafe {
        (*thread).ith_lock_data.lock();
        let kport = (*thread).ith_self;
        if !kport.is_null() {
            crate::kern::ipc_kobject::set(kport, IKO_NULL, IKOT_NONE);
        }
        (*thread).ith_lock_data.unlock();
    }
}

/// `ipc_thread_terminate()` in C.
///
/// # Safety
///
/// `thread` must be a live, suspended thread, or the current thread, and the
/// caller must hold no locks.
pub(crate) unsafe fn ipc_thread_terminate(thread: *mut Thread) {
    let kport = unsafe {
        (*thread).ith_lock_data.lock();
        let kport = (*thread).ith_self;
        if kport.is_null() {
            (*thread).ith_lock_data.unlock();
            return;
        }
        (*thread).ith_self = ptr::null_mut();
        (*thread).ith_lock_data.unlock();
        kport
    };

    unsafe {
        release_send_if_valid((*thread).ith_sself);
        release_send_if_valid((*thread).ith_exception);
        ipc_port::dealloc_special(IpcPort::from_raw(kport));
    }
}

/// `retrieve_task_self_fast()` in C.
///
/// # Safety
///
/// `task` must be a live task, and the caller must hold no locks.
pub(crate) unsafe fn retrieve_task_self_fast(
    task: *mut Task,
) -> Option<IpcPort> {
    unsafe {
        (*task).itk_lock_data.lock();

        let sself = (*task).itk_sself;
        let port = if ptr::eq(sself, (*task).itk_self) {
            // No interposing: the two fields name the same live port.
            let Some(port) = IpcPort::valid(sself) else {
                (*task).itk_lock_data.unlock();
                return None;
            };
            port.lock();
            port.increment_references();
            port.increment_srights();
            port.unlock();
            Some(port)
        } else {
            IpcPort::new(ipc_port::copy_send(sself))
        };

        (*task).itk_lock_data.unlock();
        port
    }
}

/// `retrieve_thread_self_fast()` in C.
///
/// # Safety
///
/// `thread` must be a live thread, and the caller must hold no locks.
pub(crate) unsafe fn retrieve_thread_self_fast(
    thread: *mut Thread,
) -> Option<IpcPort> {
    unsafe {
        (*thread).ith_lock_data.lock();

        let sself = (*thread).ith_sself;
        let port = if ptr::eq(sself, (*thread).ith_self) {
            // No interposing: the two fields name the same live port.
            let Some(port) = IpcPort::valid(sself) else {
                (*thread).ith_lock_data.unlock();
                return None;
            };
            port.lock();
            port.increment_references();
            port.increment_srights();
            port.unlock();
            Some(port)
        } else {
            IpcPort::new(ipc_port::copy_send(sself))
        };

        (*thread).ith_lock_data.unlock();
        port
    }
}

/// `mach_task_self()` in C, the mach trap.
///
/// # Safety
///
/// Must be called from a thread context: the current task and its space are
/// live, and nothing may be locked.
pub(crate) unsafe fn mach_task_self() -> c_uint {
    let task = unsafe { current_task() };
    let sright = unsafe { retrieve_task_self_fast(task) };

    // SAFETY: the current task's space is live, and `copyout_send` handles
    // a null or dead send right itself.
    unsafe {
        ipc_port::copyout_send(
            sright.map_or(ptr::null_mut(), IpcPort::as_ptr),
            IpcSpace::from_raw((*task).itk_space),
        )
    }
}

/// `mach_task_self()` of <`mach/mach_traps.h>`: the `mach_task_self` trap
/// entry.
///
/// # Safety
///
/// Must be called from a thread context, with nothing locked.
pub(crate) unsafe extern "C" fn mach_task_self_entry() -> c_uint {
    unsafe { mach_task_self() }
}

/// `mach_thread_self()` in C, the mach trap.
///
/// # Safety
///
/// Must be called from a thread context: the current thread, its task and
/// that task's space are live, and nothing may be locked.
pub(crate) unsafe fn mach_thread_self() -> c_uint {
    let thread = per_cpu::thread();
    let task = unsafe { (*thread).task };
    let sright = unsafe { retrieve_thread_self_fast(thread) };

    // SAFETY: the task's space is live, and `copyout_send` handles a null or
    // dead send right itself.
    unsafe {
        ipc_port::copyout_send(
            sright.map_or(ptr::null_mut(), IpcPort::as_ptr),
            IpcSpace::from_raw((*task).itk_space),
        )
    }
}

/// `mach_thread_self()` of <`mach/mach_traps.h>`: the `mach_thread_self` trap
/// entry.
///
/// # Safety
///
/// Must be called from a thread context, with nothing locked.
pub(crate) unsafe extern "C" fn mach_thread_self_entry() -> c_uint {
    unsafe { mach_thread_self() }
}

/// `mach_reply_port()` in C, the mach trap.
///
/// # Safety
///
/// Must be called from a thread context: the current task and its space are
/// live, and nothing may be locked.
pub(crate) unsafe fn mach_reply_port() -> c_uint {
    let task = unsafe { current_task() };
    let Some(space) = IpcSpace::new(unsafe { (*task).itk_space }) else {
        return MACH_PORT_NULL;
    };

    // SAFETY: the space is live, as `ipc_port_alloc` needs.
    match ipc_port::alloc(space) {
        Ok((name, port)) => {
            // SAFETY: `ipc_port_alloc` returns the port live and locked, and
            // the C's `ip_unlock` released it.
            unsafe { port.unlock() };
            name
        }
        Err(_) => MACH_PORT_NULL,
    }
}

/// `mach_reply_port()` of <`mach/mach_traps.h>`: the `mach_reply_port` trap
/// entry.
///
/// # Safety
///
/// Must be called from a thread context, with nothing locked.
pub(crate) unsafe extern "C" fn mach_reply_port_entry() -> c_uint {
    unsafe { mach_reply_port() }
}

/// The `whichp` the C `switch` selected.
///
/// # Safety
///
/// `task` must be live and its IPC lock held.
unsafe fn task_port_field(
    task: *mut Task,
    which: TaskSpecialPort,
) -> *mut *mut c_void {
    unsafe {
        match which {
            TaskSpecialPort::Kernel => ptr::addr_of_mut!((*task).itk_sself),
            TaskSpecialPort::Exception => {
                ptr::addr_of_mut!((*task).itk_exception)
            }
            TaskSpecialPort::Bootstrap => {
                ptr::addr_of_mut!((*task).itk_bootstrap)
            }
        }
    }
}

/// The `whichp` the C `switch` selected.
///
/// # Safety
///
/// `thread` must be live and its IPC lock held.
unsafe fn thread_port_field(
    thread: *mut Thread,
    which: ThreadSpecialPort,
) -> *mut *mut c_void {
    unsafe {
        match which {
            ThreadSpecialPort::Kernel => {
                ptr::addr_of_mut!((*thread).ith_sself)
            }
            ThreadSpecialPort::Exception => {
                ptr::addr_of_mut!((*thread).ith_exception)
            }
        }
    }
}

/// `task_get_special_port()` in C.
///
/// # Safety
///
/// `task` must be null or a live task, and the caller must hold no locks.
pub(crate) unsafe fn task_get_special_port(
    task: *mut Task,
    which: TaskSpecialPort,
) -> Result<Option<IpcPort>, KernError> {
    if task.is_null() {
        return Err(KernError::InvalidArgument);
    }

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            return Err(KernError::Failure);
        }

        let port =
            IpcPort::new(ipc_port::copy_send(*task_port_field(task, which)));
        (*task).itk_lock_data.unlock();
        Ok(port)
    }
}

/// `task_set_special_port()` in C.
///
/// # Safety
///
/// `task` must be null or a live task, `port` must be a naked send right or
/// `IP_NULL`, and the caller must hold no locks; on success the right is
/// consumed.
pub(crate) unsafe fn task_set_special_port(
    task: *mut Task,
    which: TaskSpecialPort,
    port: *mut c_void,
) -> Result<(), KernError> {
    if task.is_null() {
        return Err(KernError::InvalidArgument);
    }

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            return Err(KernError::Failure);
        }

        let whichp = task_port_field(task, which);
        let old = *whichp;
        *whichp = port;
        (*task).itk_lock_data.unlock();

        release_send_if_valid(old);
    }
    Ok(())
}

/// `thread_get_special_port()` in C.
///
/// # Safety
///
/// `thread` must be null or a live thread, and the caller must hold no locks.
pub(crate) unsafe fn thread_get_special_port(
    thread: *mut Thread,
    which: ThreadSpecialPort,
) -> Result<Option<IpcPort>, KernError> {
    if thread.is_null() {
        return Err(KernError::InvalidArgument);
    }

    unsafe {
        (*thread).ith_lock_data.lock();
        if (*thread).ith_self.is_null() {
            (*thread).ith_lock_data.unlock();
            return Err(KernError::Failure);
        }

        let port = IpcPort::new(ipc_port::copy_send(*thread_port_field(
            thread, which,
        )));
        (*thread).ith_lock_data.unlock();
        Ok(port)
    }
}

/// `thread_set_special_port()` in C.
///
/// # Safety
///
/// `thread` must be null or a live thread, `port` must be a naked send right
/// or `IP_NULL`, and the caller must hold no locks; on success the right is
/// consumed.
pub(crate) unsafe fn thread_set_special_port(
    thread: *mut Thread,
    which: ThreadSpecialPort,
    port: *mut c_void,
) -> Result<(), KernError> {
    if thread.is_null() {
        return Err(KernError::InvalidArgument);
    }

    unsafe {
        (*thread).ith_lock_data.lock();
        if (*thread).ith_self.is_null() {
            (*thread).ith_lock_data.unlock();
            return Err(KernError::Failure);
        }

        let whichp = thread_port_field(thread, which);
        let old = *whichp;
        *whichp = port;
        (*thread).ith_lock_data.unlock();

        release_send_if_valid(old);
    }
    Ok(())
}

/// `mach_ports_register()` in C.
///
/// # Safety
///
/// `task` must be null or a live task; `ports` holds naked send rights the
/// caller gives up on success, and the caller must hold no locks.
pub(crate) unsafe fn ports_register(
    task: *mut Task,
    ports: &[VmOffset],
) -> Result<(), KernError> {
    if task.is_null() || ports.len() > TASK_PORT_REGISTER_MAX {
        return Err(KernError::InvalidArgument);
    }

    let mut new_ports = [ptr::null_mut(); TASK_PORT_REGISTER_MAX];
    for (slot, port) in new_ports.iter_mut().zip(ports.iter()) {
        *slot = with_exposed_provenance_mut(*port);
    }

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            return Err(KernError::InvalidArgument);
        }

        for (slot, new) in
            (*task).itk_registered.iter_mut().zip(new_ports.iter_mut())
        {
            core::mem::swap(slot, new);
        }
        (*task).itk_lock_data.unlock();
    }

    // SAFETY: every valid entry is a naked send right the C released after
    // the unlock.
    unsafe {
        for port in new_ports {
            release_send_if_valid(port);
        }
    }
    Ok(())
}

/// `mach_ports_lookup()` in C.
///
/// # Safety
///
/// `task` must be null or a live task, and the caller must hold no locks: the
/// routine allocates.
pub(crate) unsafe fn ports_lookup(
    task: *mut Task,
) -> Result<(NonNull<VmOffset>, c_uint), KernError> {
    if task.is_null() {
        return Err(KernError::InvalidArgument);
    }

    let size = TASK_PORT_REGISTER_MAX * size_of::<VmOffset>();
    // SAFETY: `kalloc_init()` ran during the boot this kernel call follows.
    let Some(memory) = kalloc(size) else {
        return Err(KernError::ResourceShortage);
    };

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            kfree(memory, size);
            return Err(KernError::InvalidArgument);
        }

        let ports = memory.as_ptr().cast::<VmOffset>();
        for (i, port) in (*task).itk_registered.iter().enumerate() {
            let clone = ipc_port::copy_send(*port);
            ptr::write(ports.add(i), clone.addr());
        }
        (*task).itk_lock_data.unlock();
    }

    // SAFETY: `memory` points at the live slots just filled.
    let ports = unsafe { NonNull::new_unchecked(memory.as_ptr().cast()) };
    // `TASK_PORT_REGISTER_MAX` is four, so the narrowing cannot lose a bit.
    Ok((ports, TASK_PORT_REGISTER_MAX as c_uint))
}

/// `convert_port_to_task()` in C.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub(crate) unsafe fn convert_port_to_task(
    port: *mut c_void,
) -> Option<NonNull<Task>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and the reference is the one the C took.
    unsafe {
        port.lock();
        let task = match NonNull::new(port.kobject().cast::<Task>()) {
            Some(task) if port.is_active() && port.kotype() == IKOT_TASK => {
                task::reference(task.as_ptr());
                Some(task)
            }
            _ => None,
        };
        port.unlock();
        task
    }
}

/// `convert_port_to_space()` in C.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub(crate) unsafe fn convert_port_to_space(
    port: *mut c_void,
) -> Option<IpcSpace> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and the reference is the one the C took.
    unsafe {
        port.lock();
        let space = if port.is_active() && port.kotype() == IKOT_TASK {
            let task = port.kobject().cast::<Task>();
            NonNull::new((*task).itk_space).map(|found| {
                let space = IpcSpace::from_raw(found.as_ptr());
                ipc_space::reference(space);
                space
            })
        } else {
            None
        };
        port.unlock();
        space
    }
}

/// `convert_port_to_map()` in C.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub(crate) unsafe fn convert_port_to_map(
    port: *mut c_void,
) -> Option<NonNull<VmMap>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and a live task's map is set.
    unsafe {
        port.lock();
        let map = if port.is_active() && port.kotype() == IKOT_TASK {
            let task = port.kobject().cast::<Task>();
            NonNull::new((*task).map.cast::<VmMap>())
        } else {
            None
        };
        if let Some(map) = map {
            VmMap::reference(map);
        }
        port.unlock();
        map
    }
}

/// `convert_port_to_thread()` in C.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub(crate) unsafe fn convert_port_to_thread(
    port: *mut c_void,
) -> Option<NonNull<Thread>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and the reference is the one the C took.
    unsafe {
        port.lock();
        let thread = match NonNull::new(port.kobject().cast::<Thread>()) {
            Some(thread)
                if port.is_active() && port.kotype() == IKOT_THREAD =>
            {
                Thread::reference(thread.as_ptr());
                Some(thread)
            }
            _ => None,
        };
        port.unlock();
        thread
    }
}

/// `convert_task_to_port()` in C.
///
/// # Safety
///
/// `task` must be a live task the caller holds a reference to; the routine
/// consumes it and may deallocate the task.
pub(crate) unsafe fn convert_task_to_port(task: *mut Task) -> Option<IpcPort> {
    let port = unsafe {
        (*task).itk_lock_data.lock();
        let port = if (*task).itk_self.is_null() {
            None
        } else {
            IpcPort::new(
                ipc_port::make_send(IpcPort::from_raw((*task).itk_self))
                    .as_ptr(),
            )
        };
        (*task).itk_lock_data.unlock();
        port
    };

    unsafe { task::deallocate(task) };
    port
}

/// `convert_thread_to_port()` in C.
///
/// # Safety
///
/// `thread` must be a live thread the caller holds a reference to; the
/// routine consumes it and may deallocate the thread.
pub(crate) unsafe fn convert_thread_to_port(
    thread: *mut Thread,
) -> Option<IpcPort> {
    let port = unsafe {
        (*thread).ith_lock_data.lock();
        let port = if (*thread).ith_self.is_null() {
            None
        } else {
            IpcPort::new(
                ipc_port::make_send(IpcPort::from_raw((*thread).ith_self))
                    .as_ptr(),
            )
        };
        (*thread).ith_lock_data.unlock();
        port
    };

    unsafe { Thread::deallocate(thread) };
    port
}

/// `space_deallocate()` in C: the `is_release()` of a space ref a
/// [`convert_port_to_space()`] produced.
///
/// # Safety
///
/// A non-null `space` must be a live space the caller holds a reference to.
pub(crate) unsafe fn space_deallocate(space: *mut c_void) {
    if let Some(space) = IpcSpace::new(space) {
        unsafe { ipc_space::release(space) };
    }
}
