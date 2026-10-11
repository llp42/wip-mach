// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The task- and thread-related IPC operations.

use crate::error::Error;
use crate::platform::Platform;
use crate::task;
use crate::task::{Task, current_task};
use crate::thread::Thread;
use crate::types::{TaskSpecialPort, ThreadSpecialPort};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use core::ptr::{NonNull, with_exposed_provenance_mut};
use mach_ipc::ipc_kmsg::IpcKmsgQueue;
use mach_ipc::ipc_thread::ipc_thread_links_init;
use mach_ipc::{IpcPort, IpcSpace, ipc_port, ipc_space};
use mach_task::task::TASK_PORT_REGISTER_MAX;
use mach_vm::param::VmOffset;
use mach_vm::vm_map::VmMap;

/// The kernel-object types of a thread port and a task port.
pub(crate) const IKOT_THREAD: c_uint = 1;
const IKOT_TASK: c_uint = 2;
/// The type of a port bound to no kernel object.
const IKOT_NONE: c_uint = 0;
/// The value that clears a port's kernel object.
const IKO_NULL: VmOffset = 0;

/// `TASK_KERNEL_PORT`, `TASK_EXCEPTION_PORT` and `TASK_BOOTSTRAP_PORT`: the
/// `which` values the task special-port calls accept.
pub(crate) const TASK_KERNEL_PORT: c_int = 1;
pub(crate) const TASK_EXCEPTION_PORT: c_int = 3;
pub(crate) const TASK_BOOTSTRAP_PORT: c_int = 4;

/// `THREAD_KERNEL_PORT` and `THREAD_EXCEPTION_PORT`: the `which` values the
/// thread special-port calls accept.
pub(crate) const THREAD_KERNEL_PORT: c_int = 1;
pub(crate) const THREAD_EXCEPTION_PORT: c_int = 3;

/// The null port name.
const MACH_PORT_NULL: c_uint = 0;

/// Creates an IPC space for a new task.
fn create_space<P: Platform>() -> Result<*mut c_void, Error> {
    Ok(ipc_space::create::<P>()?.as_ptr())
}

/// The C `panic()` of `ipc_task_init()` and `ipc_thread_init()`.
fn init_panic(fun: &'static str) -> ! {
    panic!("{fun}")
}

/// Releases the send right `port` when it is neither null nor dead.
///
/// # Safety
///
/// A non-null, non-dead `port` must hold one send right.
unsafe fn release_send_if_valid<P: Platform>(port: *mut c_void) {
    if let Some(port) = IpcPort::valid(port) {
        unsafe { ipc_port::release_send::<P>(port) };
    }
}

/// Gives `task` its IPC space and kernel port, and inherits the special ports
/// of `parent`.
///
/// # Safety
///
/// `task` must be a fresh task whose IPC fields this call is the first to
/// write, and a non-null `parent` a live task whose own
/// `ipc_task_init()` already ran; the caller must hold no locks, as the
/// allocation may block.
pub(crate) unsafe fn ipc_task_init<P: Platform>(
    task: *mut Task<P>,
    parent: Option<NonNull<Task<P>>>,
) {
    let Ok(space) = create_space::<P>() else {
        init_panic("ipc_task_init")
    };

    // SAFETY: the kernel's space is live for the life of the kernel, so its
    // special ports can be allocated in it.
    let kport = unsafe { ipc_port::alloc_special::<P>(ipc_space::kernel()) };
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

/// Names `task` in its kernel port, so the port translates to it.
///
/// # Safety
///
/// `task` must point at a live task whose IPC state is initialized and not
/// terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_task_enable<P: Platform>(task: *mut Task<P>) {
    unsafe {
        (*task).itk_lock_data.lock();
        let kport = (*task).itk_self;
        if !kport.is_null() {
            P::kobject_set(kport, task.addr(), IKOT_TASK);
        }
        (*task).itk_lock_data.unlock();
    }
}

/// Clears `task` from its kernel port, so the port translates to nothing.
///
/// # Safety
///
/// `task` must point at a live task whose IPC state is initialized and not
/// terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_task_disable<P: Platform>(task: *mut Task<P>) {
    unsafe {
        (*task).itk_lock_data.lock();
        let kport = (*task).itk_self;
        if !kport.is_null() {
            P::kobject_set(kport, IKO_NULL, IKOT_NONE);
        }
        (*task).itk_lock_data.unlock();
    }
}

/// Releases `task`'s special ports and destroys its kernel port.
///
/// # Safety
///
/// `task` must be a live, suspended task, or the current thread's own task,
/// and the caller must hold no locks.
pub(crate) unsafe fn ipc_task_terminate<P: Platform>(task: *mut Task<P>) {
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
        release_send_if_valid::<P>((*task).itk_sself);
        release_send_if_valid::<P>((*task).itk_exception);
        release_send_if_valid::<P>((*task).itk_bootstrap);
        for port in &(*task).itk_registered {
            release_send_if_valid::<P>(*port);
        }
        ipc_space::destroy::<P>(IpcSpace::from_raw((*task).itk_space));
        ipc_port::dealloc_special::<P>(IpcPort::from_raw(kport));
    }
}

/// Gives `thread` its kernel port.
///
/// # Safety
///
/// `thread` must be a fresh thread whose IPC fields this call is the first to
/// write, and the caller must hold no locks: the allocation may block.
pub(crate) unsafe fn ipc_thread_init<P: Platform>(thread: *mut Thread<P>) {
    // SAFETY: the kernel's space is live for the life of the kernel, so its
    // special ports can be allocated in it.
    let kport = unsafe { ipc_port::alloc_special::<P>(ipc_space::kernel()) };
    let Some(kport) = kport else {
        init_panic("ipc_thread_init")
    };

    unsafe {
        ipc_thread_links_init::<P>(thread.cast());
        (*thread).ipc.messages = IpcKmsgQueue {
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

/// Names `thread` in its kernel port, so the port translates to it.
///
/// # Safety
///
/// `thread` must point at a live thread whose IPC state is initialized and
/// not terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_thread_enable<P: Platform>(thread: *mut Thread<P>) {
    unsafe {
        (*thread).ith_lock_data.lock();
        let kport = (*thread).ith_self;
        if !kport.is_null() {
            P::kobject_set(kport, thread.addr(), IKOT_THREAD);
        }
        (*thread).ith_lock_data.unlock();
    }
}

/// Clears `thread` from its kernel port, so the port translates to nothing.
///
/// # Safety
///
/// `thread` must point at a live thread whose IPC state is initialized and
/// not terminated, and the caller must hold no locks.
pub(crate) unsafe fn ipc_thread_disable<P: Platform>(thread: *mut Thread<P>) {
    unsafe {
        (*thread).ith_lock_data.lock();
        let kport = (*thread).ith_self;
        if !kport.is_null() {
            P::kobject_set(kport, IKO_NULL, IKOT_NONE);
        }
        (*thread).ith_lock_data.unlock();
    }
}

/// Releases `thread`'s special ports and destroys its kernel port.
///
/// # Safety
///
/// `thread` must be a live, suspended thread, or the current thread, and the
/// caller must hold no locks.
pub(crate) unsafe fn ipc_thread_terminate<P: Platform>(
    thread: *mut Thread<P>,
) {
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
        release_send_if_valid::<P>((*thread).ith_sself);
        release_send_if_valid::<P>((*thread).ith_exception);
        ipc_port::dealloc_special::<P>(IpcPort::from_raw(kport));
    }
}

/// A send right for `task`'s self port, made directly on the port when nothing
/// interposes on it.
///
/// # Safety
///
/// `task` must be a live task, and the caller must hold no locks.
pub unsafe fn retrieve_task_self_fast<P: Platform>(
    task: *mut Task<P>,
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

/// A send right for `thread`'s self port, made directly on the port when
/// nothing interposes on it.
///
/// # Safety
///
/// `thread` must be a live thread, and the caller must hold no locks.
pub unsafe fn retrieve_thread_self_fast<P: Platform>(
    thread: *mut Thread<P>,
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

/// Returns the name of the caller's task port in its own space.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn mach_task_self<P: Platform>() -> c_uint {
    let task = current_task::<P>().as_ptr();
    let sright = unsafe { retrieve_task_self_fast(task) };

    // SAFETY: the current task's space is live, and `copyout_send` handles
    // a null or dead send right itself.
    unsafe {
        ipc_port::copyout_send::<P>(
            sright.map_or(ptr::null_mut(), IpcPort::as_ptr),
            IpcSpace::from_raw((*task).itk_space),
        )
    }
}

/// The `mach_task_self` trap entry.
///
/// # Safety
///
/// Must be called with nothing locked.
#[must_use]
pub unsafe extern "C" fn mach_task_self_entry<P: Platform>() -> c_uint {
    unsafe { mach_task_self::<P>() }
}

/// Returns the name of the caller's thread port in its task's space.
///
/// # Safety
///
/// Must be called from a thread context: the current thread, its task and
/// that task's space are live, and nothing may be locked.
pub(crate) unsafe fn mach_thread_self<P: Platform>() -> c_uint {
    let thread = P::cpu_thread();
    let task = unsafe { (*thread).task };
    let sright = unsafe { retrieve_thread_self_fast(thread) };

    // SAFETY: the task's space is live, and `copyout_send` handles a null or
    // dead send right itself.
    unsafe {
        ipc_port::copyout_send::<P>(
            sright.map_or(ptr::null_mut(), IpcPort::as_ptr),
            IpcSpace::from_raw((*task).itk_space),
        )
    }
}

/// The `mach_thread_self` trap entry.
///
/// # Safety
///
/// Must be called from a thread context, with nothing locked.
#[must_use]
pub unsafe extern "C" fn mach_thread_self_entry<P: Platform>() -> c_uint {
    unsafe { mach_thread_self::<P>() }
}

/// Allocates a reply port in the caller's space and returns its name.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn mach_reply_port<P: Platform>() -> c_uint {
    let task = current_task::<P>().as_ptr();
    let Some(space) = IpcSpace::new(unsafe { (*task).itk_space }) else {
        return MACH_PORT_NULL;
    };

    // SAFETY: the space is live, as `ipc_port::alloc` needs.
    match ipc_port::alloc::<P>(space) {
        Ok((name, port)) => {
            // SAFETY: `ipc_port::alloc` returns the port live and locked, and
            // only the unlock is left.
            unsafe { port.unlock() };
            name
        }
        Err(_) => MACH_PORT_NULL,
    }
}

/// The `mach_reply_port` trap entry.
///
/// # Safety
///
/// Must be called with nothing locked.
#[must_use]
pub unsafe extern "C" fn mach_reply_port_entry<P: Platform>() -> c_uint {
    unsafe { mach_reply_port::<P>() }
}

/// The `whichp` the C `switch` selected.
///
/// # Safety
///
/// `task` must be live and its IPC lock held.
unsafe fn task_port_field<P: Platform>(
    task: *mut Task<P>,
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
unsafe fn thread_port_field<P: Platform>(
    thread: *mut Thread<P>,
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

/// A send right for `task`'s special port `which`.
///
/// # Safety
///
/// `task` must be null or a live task, and the caller must hold no locks.
pub unsafe fn task_get_special_port<P: Platform>(
    task: *mut Task<P>,
    which: TaskSpecialPort,
) -> Result<Option<IpcPort>, Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            return Err(Error::Failure);
        }

        let port =
            IpcPort::new(ipc_port::copy_send(*task_port_field(task, which)));
        (*task).itk_lock_data.unlock();
        Ok(port)
    }
}

/// Sets `task`'s special port `which` to `port`, releasing the previous one.
///
/// # Safety
///
/// `task` must be null or a live task, `port` must be a naked send right or
/// `IP_NULL`, and the caller must hold no locks; on success the right is
/// consumed.
pub unsafe fn task_set_special_port<P: Platform>(
    task: *mut Task<P>,
    which: TaskSpecialPort,
    port: *mut c_void,
) -> Result<(), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            return Err(Error::Failure);
        }

        let whichp = task_port_field(task, which);
        let old = *whichp;
        *whichp = port;
        (*task).itk_lock_data.unlock();

        release_send_if_valid::<P>(old);
    }
    Ok(())
}

/// A send right for `thread`'s special port `which`.
///
/// # Safety
///
/// `thread` must be null or a live thread, and the caller must hold no locks.
pub unsafe fn thread_get_special_port<P: Platform>(
    thread: *mut Thread<P>,
    which: ThreadSpecialPort,
) -> Result<Option<IpcPort>, Error> {
    if thread.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*thread).ith_lock_data.lock();
        if (*thread).ith_self.is_null() {
            (*thread).ith_lock_data.unlock();
            return Err(Error::Failure);
        }

        let port = IpcPort::new(ipc_port::copy_send(*thread_port_field(
            thread, which,
        )));
        (*thread).ith_lock_data.unlock();
        Ok(port)
    }
}

/// Sets `thread`'s special port `which` to `port`, releasing the previous one.
///
/// # Safety
///
/// `thread` must be null or a live thread, `port` must be a naked send right
/// or `IP_NULL`, and the caller must hold no locks; on success the right is
/// consumed.
pub unsafe fn thread_set_special_port<P: Platform>(
    thread: *mut Thread<P>,
    which: ThreadSpecialPort,
    port: *mut c_void,
) -> Result<(), Error> {
    if thread.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*thread).ith_lock_data.lock();
        if (*thread).ith_self.is_null() {
            (*thread).ith_lock_data.unlock();
            return Err(Error::Failure);
        }

        let whichp = thread_port_field(thread, which);
        let old = *whichp;
        *whichp = port;
        (*thread).ith_lock_data.unlock();

        release_send_if_valid::<P>(old);
    }
    Ok(())
}

/// Registers up to `TASK_PORT_REGISTER_MAX` ports with `task`, for its
/// children to look up.
///
/// # Safety
///
/// `task` must be null or a live task; `ports` holds naked send rights the
/// caller gives up on success, and the caller must hold no locks.
pub unsafe fn ports_register<P: Platform>(
    task: *mut Task<P>,
    ports: &[VmOffset],
) -> Result<(), Error> {
    if task.is_null() || ports.len() > TASK_PORT_REGISTER_MAX {
        return Err(Error::InvalidArgument);
    }

    let mut new_ports = [ptr::null_mut(); TASK_PORT_REGISTER_MAX];
    for (slot, port) in new_ports.iter_mut().zip(ports.iter()) {
        *slot = with_exposed_provenance_mut(*port);
    }

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            return Err(Error::InvalidArgument);
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
            release_send_if_valid::<P>(port);
        }
    }
    Ok(())
}

/// Send rights for the ports registered with `task`.
///
/// # Safety
///
/// `task` must be null or a live task, and the caller must hold no locks: the
/// routine allocates.
pub unsafe fn ports_lookup<P: Platform>(
    task: *mut Task<P>,
) -> Result<(NonNull<VmOffset>, c_uint), Error> {
    if task.is_null() {
        return Err(Error::InvalidArgument);
    }

    let size = TASK_PORT_REGISTER_MAX * size_of::<VmOffset>();
    // SAFETY: `kalloc_init()` ran during the boot this kernel call follows.
    let Some(memory) = P::kalloc(size) else {
        return Err(Error::ResourceShortage);
    };

    unsafe {
        (*task).itk_lock_data.lock();
        if (*task).itk_self.is_null() {
            (*task).itk_lock_data.unlock();
            P::kfree(memory, size);
            return Err(Error::InvalidArgument);
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

/// The task `port` names, with a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub unsafe fn convert_port_to_task<P: Platform>(
    port: *mut c_void,
) -> Option<NonNull<Task<P>>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and the reference is the one the C took.
    unsafe {
        port.lock();
        let task = match NonNull::new(port.kobject().cast::<Task<P>>()) {
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

/// The IPC space of the task `port` names, with a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub unsafe fn convert_port_to_space<P: Platform>(
    port: *mut c_void,
) -> Option<IpcSpace> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and the reference is the one the C took.
    unsafe {
        port.lock();
        let space = if port.is_active() && port.kotype() == IKOT_TASK {
            let task = port.kobject().cast::<Task<P>>();
            NonNull::new((*task).itk_space).map(|found| {
                let space = IpcSpace::from_raw(found.as_ptr());
                ipc_space::reference::<P>(space);
                space
            })
        } else {
            None
        };
        port.unlock();
        space
    }
}

/// The address map of the task `port` names, with a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub unsafe fn convert_port_to_map<P: Platform>(
    port: *mut c_void,
) -> Option<NonNull<VmMap<P>>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and a live task's map is set.
    unsafe {
        port.lock();
        let map = if port.is_active() && port.kotype() == IKOT_TASK {
            let task = port.kobject().cast::<Task<P>>();
            NonNull::new((*task).map.cast::<VmMap<P>>())
        } else {
            None
        };
        if let Some(map) = map {
            VmMap::<P>::reference(map);
        }
        port.unlock();
        map
    }
}

/// The thread `port` names, with a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port.
pub unsafe fn convert_port_to_thread<P: Platform>(
    port: *mut c_void,
) -> Option<NonNull<Thread<P>>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port; the lock covers the
    // kobject fields, and the reference is the one the C took.
    unsafe {
        port.lock();
        let thread = match NonNull::new(port.kobject().cast::<Thread<P>>()) {
            Some(thread)
                if port.is_active() && port.kotype() == IKOT_THREAD =>
            {
                Thread::<P>::reference(thread.as_ptr());
                Some(thread)
            }
            _ => None,
        };
        port.unlock();
        thread
    }
}

/// A send right for `task`'s port, consuming the caller's task reference.
///
/// # Safety
///
/// `task` must be a live task the caller holds a reference to; the routine
/// consumes it and may deallocate the task.
pub unsafe fn convert_task_to_port<P: Platform>(
    task: *mut Task<P>,
) -> Option<IpcPort> {
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

/// A send right for `thread`'s port, consuming the caller's thread reference.
///
/// # Safety
///
/// `thread` must be a live thread the caller holds a reference to; the
/// routine consumes it and may deallocate the thread.
pub unsafe fn convert_thread_to_port<P: Platform>(
    thread: *mut Thread<P>,
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

    unsafe { Thread::<P>::deallocate(thread) };
    port
}

/// Drops the space reference a [`convert_port_to_space()`] produced.
///
/// # Safety
///
/// A non-null `space` must be a live space the caller holds a reference to.
pub unsafe fn space_deallocate<P: Platform>(space: *mut c_void) {
    if let Some(space) = IpcSpace::new(space) {
        unsafe { ipc_space::release::<P>(space) };
    }
}

/// Destroy the kernel-RPC reply port `thread` holds, if it holds one.
///
/// # Safety
///
/// `thread` must point at a live thread, and nothing may be locked, as the C
/// documented.
pub(crate) unsafe fn abort_rpc<P: Platform>(thread: *mut Thread<P>) {
    let reply = unsafe {
        (*thread).ith_lock_data.lock();
        let reply = if (*thread).ith_self.is_null() {
            ptr::null_mut()
        } else {
            let reply = (*thread).ith_rpc_reply;
            (*thread).ith_rpc_reply = ptr::null_mut();
            reply
        };
        (*thread).ith_lock_data.unlock();
        reply
    };

    if !reply.is_null() {
        // SAFETY: `reply` was the thread's live reply port and the thread no
        // longer holds it, so this call owns the reference.
        unsafe {
            ipc_port::dealloc_special::<P>(IpcPort::from_raw(reply));
        };
    }
}
