// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The translation of a caller's port names into the tasks, threads,
//! maps, spaces and devices the traps act on.

use crate::platform::Platform;
use core::ffi::{c_uint, c_void};
use core::ptr::{self, NonNull};
use mach_device::dev_lookup;
use mach_device::ds_routines::device_reference;
use mach_ipc::types::PortType;
use mach_ipc::{IpcPort, IpcSpace};
use mach_ipc::{ipc_object, ipc_port, ipc_space};
use mach_thread::ipc_tt;
use mach_thread::task::{self, Task};
use mach_thread::thread::Thread;
use mach_vm::vm_map::VmMap;

/// The null port name a reply carries.
pub(crate) const MACH_PORT_NULL: c_uint = 0;

/// The space of the running task.
pub(crate) fn current_space<P: Platform>() -> IpcSpace {
    // SAFETY: the running thread's task is live. Task creation sets its
    // `itk_space` to a fresh, non-null space before the task has a thread,
    // and nothing writes the field again.
    unsafe {
        IpcSpace::from_raw((*task::current_task::<P>().as_ptr()).itk_space)
    }
}

/// The null port name.
pub(crate) const MACH_PORT_NAME_NULL: c_uint = 0;

/// The dead port name.
pub(crate) const MACH_PORT_NAME_DEAD: c_uint = c_uint::MAX;

/// The dead port value: the all-ones word.
pub(crate) const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// The receive-right disposition.
pub(crate) const MACH_MSG_TYPE_PORT_RECEIVE: c_uint = 16;

/// `MACH_MSG_TYPE_PORT_SEND`, the wire alias of `MACH_MSG_TYPE_MOVE_SEND`.
pub(crate) const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;

/// The disposition that copies a send right.
pub(crate) const MACH_MSG_TYPE_COPY_SEND: c_uint = 19;

/// The disposition that makes a send-once right.
pub(crate) const MACH_MSG_TYPE_MAKE_SEND_ONCE: c_uint = 21;

/// The kernel-object type of a thread port.
pub(crate) const IKOT_THREAD: c_uint = 1;

/// The kernel-object type of a task port.
pub(crate) const IKOT_TASK: c_uint = 2;

/// The kernel-object type of a device port.
pub(crate) const IKOT_DEVICE: c_uint = 10;

/// The port an invalid name stands for.  A valid name is impossible at every
/// call site and halts the kernel.
pub(crate) fn invalid_name_to_port(name: c_uint) -> *mut c_void {
    match name {
        MACH_PORT_NAME_NULL => ptr::null_mut(),
        MACH_PORT_NAME_DEAD => IO_DEAD,
        _ => {
            panic!("invalid_name_to_port() called with a valid port")
        }
    }
}

/// Whether `object` is neither null nor dead.
pub(crate) fn io_valid(object: *mut c_void) -> bool {
    !object.is_null() && object != IO_DEAD
}

/// One send right to `name` from the current space, or `None` when the copyin
/// failed: the slow path of the name translations.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn copyin_send<P: Platform>(
    name: c_uint,
) -> Option<*mut c_void> {
    unsafe {
        ipc_object::copyin::<P>(
            current_space::<P>(),
            name,
            MACH_MSG_TYPE_COPY_SEND,
        )
    }
    .ok()
}

/// Release the send right a slow path copied in, when it is a live port.
///
/// # Safety
///
/// `object` must be an object [`copyin_send()`] returned.
pub(crate) unsafe fn release_send<P: Platform>(object: *mut c_void) {
    if let Some(port) = IpcPort::valid(object) {
        unsafe { ipc_port::release_send::<P>(port) };
    }
}

/// `name` looked up as a bare send right in the current space, with the port
/// locked, or `None` for the slow path.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn fast_send_right_lookup<P: Platform>(
    name: c_uint,
) -> Option<IpcPort> {
    let space = current_space::<P>();

    unsafe {
        space.lock_read::<P>();
        let found = space.entry_lookup::<P>(name);
        let Some(entry) = found else {
            space.unlock_read::<P>();
            return None;
        };
        if (*entry).bits().type_ != PortType::SEND {
            space.unlock_read::<P>();
            return None;
        }

        let port = IpcPort::from_raw((*entry).object());
        port.lock();
        space.unlock_read::<P>();
        Some(port)
    }
}

/// The device the send right `name` names, with a reference, or `None`.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn port_name_to_device<P: Platform>(
    name: c_uint,
) -> Option<NonNull<c_void>> {
    if let Some(port) = unsafe { fast_send_right_lookup::<P>(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is live, and the reference is the one the C took before
        // unlocking.
        return unsafe {
            let device = match NonNull::new(port.kobject()) {
                Some(device)
                    if port.is_active() && port.kotype() == IKOT_DEVICE =>
                {
                    device_reference(device);
                    Some(device)
                }
                _ => None,
            };
            port.unlock();
            device
        };
    }

    let object = (unsafe { copyin_send::<P>(name) })?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let device = unsafe {
        NonNull::new(dev_lookup::port_lookup(object).cast::<c_void>())
    };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send::<P>(object) };
    device
}

/// The thread the send right `name` names, with a reference, or `None`.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn port_name_to_thread<P: Platform>(
    name: c_uint,
) -> Option<NonNull<Thread<P>>> {
    if let Some(port) = unsafe { fast_send_right_lookup::<P>(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live thread, and `Thread::reference()` takes the
        // reference the C took before unlocking.
        return unsafe {
            let thread = match NonNull::new(port.kobject().cast::<Thread<P>>())
            {
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
        };
    }

    let object = unsafe { copyin_send::<P>(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let thread = unsafe { ipc_tt::convert_port_to_thread(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send::<P>(object) };
    thread
}

/// The task the send right `name` names, with a reference, or `None`.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn port_name_to_task<P: Platform>(
    name: c_uint,
) -> Option<NonNull<Task<P>>> {
    if let Some(port) = unsafe { fast_send_right_lookup::<P>(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live task, and `task::reference()` takes the reference
        // the C took before unlocking.
        return unsafe {
            let task = match NonNull::new(port.kobject().cast::<Task<P>>()) {
                Some(task)
                    if port.is_active() && port.kotype() == IKOT_TASK =>
                {
                    task::reference(task.as_ptr());
                    Some(task)
                }
                _ => None,
            };
            port.unlock();
            task
        };
    }

    let object = unsafe { copyin_send::<P>(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let task = unsafe { ipc_tt::convert_port_to_task(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send::<P>(object) };
    task
}

/// The address map of the task the send right `name` names, with a reference,
/// or `None`.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn port_name_to_map<P: Platform>(
    name: c_uint,
) -> Option<NonNull<VmMap<P>>> {
    if let Some(port) = unsafe { fast_send_right_lookup::<P>(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live task whose map is live, and `VmMap::reference()`
        // takes the reference the C took before unlocking.
        return unsafe {
            let map = match NonNull::new(port.kobject().cast::<Task<P>>()) {
                Some(task)
                    if port.is_active() && port.kotype() == IKOT_TASK =>
                {
                    let map = NonNull::new((*task.as_ptr()).map.cast());
                    if let Some(map) = map {
                        VmMap::<P>::reference(map);
                    }
                    map
                }
                _ => None,
            };
            port.unlock();
            map
        };
    }

    let object = unsafe { copyin_send::<P>(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let map = unsafe { ipc_tt::convert_port_to_map(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send::<P>(object) };
    map
}

/// The IPC space of the task the send right `name` names, with a reference, or
/// `None`.
///
/// # Safety
///
/// Must be called with nothing locked.
pub(crate) unsafe fn port_name_to_space<P: Platform>(
    name: c_uint,
) -> Option<IpcSpace> {
    if let Some(port) = unsafe { fast_send_right_lookup::<P>(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live task whose space is live, and
        // `ipc_space::reference()` takes the reference the C took before
        // unlocking.
        return unsafe {
            let space = match NonNull::new(port.kobject().cast::<Task<P>>()) {
                Some(task)
                    if port.is_active() && port.kotype() == IKOT_TASK =>
                {
                    let space = IpcSpace::new((*task.as_ptr()).itk_space);
                    if let Some(space) = space {
                        ipc_space::reference::<P>(space);
                    }
                    space
                }
                _ => None,
            };
            port.unlock();
            space
        };
    }

    let object = unsafe { copyin_send::<P>(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let space = unsafe { ipc_tt::convert_port_to_space::<P>(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send::<P>(object) };
    space
}

/// Whether `name` is neither null nor dead.
pub(crate) const fn mach_port_name_valid(name: c_uint) -> bool {
    name != MACH_PORT_NAME_NULL && name != MACH_PORT_NAME_DEAD
}

/// Whether `name` is a port-right type.
pub(crate) const fn mach_msg_type_port_any(name: c_uint) -> bool {
    MACH_MSG_TYPE_PORT_RECEIVE <= name && name <= MACH_MSG_TYPE_MAKE_SEND_ONCE
}
