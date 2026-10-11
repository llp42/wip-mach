// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The traps that stand in for RPCs: each acts on the object a port name
//! denotes, or answers that the name is no kernel object, and the user
//! stub then sends the RPC as a message.

use crate::error::Error;
use crate::name::{
    MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_PORT_SEND, MACH_PORT_NULL,
    current_space, invalid_name_to_port, io_valid, mach_msg_type_port_any,
    mach_port_name_valid, port_name_to_device, port_name_to_map,
    port_name_to_space, port_name_to_task, port_name_to_thread, release_send,
};
use crate::platform::Platform;
use crate::types::VmMapRequest;
use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::mem::size_of;
use core::ptr::{self};
use mach_device::ds_routines::{
    device_deallocate, ds_device_write_trap, ds_device_writev_trap,
};
use mach_device::r#return::Reply;
use mach_ipc::IpcPort;
use mach_ipc::error::Error as IpcError;
use mach_ipc::ipc_kmsg;
use mach_ipc::{ipc_object, ipc_space};
use mach_thread::error::Error as TaskError;
use mach_thread::ipc_tt;
use mach_thread::syscall_subr;
use mach_thread::task::{self};
use mach_thread::thread::Thread;
use mach_thread::types::MapSource;
use mach_thread::types::TaskSpecialPort;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::types::{VmInherit, VmProt};
use mach_vm::vm_map::VmMap;
use mach_vm::vm_user;

/// The `vm_map` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 64 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub unsafe fn syscall_vm_map<P: Platform>(
    request: &VmMapRequest,
) -> Result<(), Error> {
    let Some(map) = (unsafe { port_name_to_map(request.target_map) }) else {
        return Err(Error::NotKernelObject);
    };

    let port = if mach_port_name_valid(request.memory_object) {
        let space = current_space::<P>();
        match unsafe {
            ipc_object::copyin::<P>(
                space,
                request.memory_object,
                MACH_MSG_TYPE_COPY_SEND,
            )
        } {
            Ok(object) => object,
            Err(error) => {
                VmMap::<P>::deallocate(map);
                return Err(error.into());
            }
        }
    } else {
        invalid_name_to_port(request.memory_object)
    };

    let mut addr: VmOffset = 0;
    // The C ignored the copyin result and handed `vm_map()` whatever the
    // stack held when it failed; zero is the deterministic stand-in.
    unsafe {
        let _ = P::copyin_into(request.address.cast(), &mut addr);
    }

    // SAFETY: the map is live and unlocked, `port` is the right the copyin
    // produced or an invalid-name sentinel, and the caller permits the
    // mapping.
    let result = unsafe {
        vm_user::map(
            &mut *map.as_ptr(),
            &mut vm_user::MapRequest {
                address: &mut addr,
                size: request.size,
                mask: request.mask,
                anywhere: request.anywhere != 0,
                memory_object: port,
                offset: request.offset,
                copy: request.copy != 0,
                cur_protection: VmProt::from_bits_retain(
                    request.cur_protection,
                ),
                max_protection: VmProt::from_bits_retain(
                    request.max_protection,
                ),
                inheritance: VmInherit::from_bits(request.inheritance),
            },
        )
    };
    if result.is_ok() {
        // SAFETY: `vm_map()` wrote the mapped address into `addr`, and the
        // caller promises the user address is writable.
        unsafe {
            let _ = P::copyout(
                ptr::addr_of!(addr).cast(),
                request.address.cast(),
                size_of::<VmOffset>(),
            );
        }
    }

    // SAFETY: `port` is the right the copyin produced, when it did.
    unsafe { release_send::<P>(port) };
    VmMap::<P>::deallocate(map);

    result.map_err(Error::Vm)
}

/// The `vm_allocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 65 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub unsafe fn syscall_vm_allocate<P: Platform>(
    target_map: c_uint,
    address: *mut VmOffset,
    size: VmSize,
    anywhere: c_int,
) -> Result<(), Error> {
    let Some(map) = (unsafe { port_name_to_map(target_map) }) else {
        return Err(Error::NotKernelObject);
    };

    let mut addr: VmOffset = 0;
    unsafe {
        let _ = P::copyin_into(address.cast(), &mut addr);
    }

    // SAFETY: the map is live and unlocked, and the caller holds no locks.
    let result = unsafe {
        vm_user::allocate(&mut *map.as_ptr(), &mut addr, size, anywhere != 0)
    };
    if result.is_ok() {
        // SAFETY: the allocation wrote the address into `addr`, and the
        // caller promises the user address is writable.
        unsafe {
            let _ = P::copyout(
                ptr::addr_of!(addr).cast(),
                address.cast(),
                size_of::<VmOffset>(),
            );
        }
    }
    VmMap::<P>::deallocate(map);

    result.map_err(Error::from)
}

/// The `vm_deallocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 66 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_vm_deallocate<P: Platform>(
    target_map: c_uint,
    start: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    let Some(map) = (unsafe { port_name_to_map(target_map) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the map is live and unlocked, and the caller holds no locks.
    let result =
        unsafe { vm_user::deallocate(&mut *map.as_ptr(), start, size) };
    VmMap::<P>::deallocate(map);

    result.map_err(Error::from)
}

/// The `task_create` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 68 with user arguments: `child_task` must name user
/// storage of one name in the current map, and the caller must hold no locks.
pub unsafe fn syscall_task_create<P: Platform>(
    parent_task: c_uint,
    inherit_memory: c_int,
    child_task: *mut c_uint,
) -> Result<(), Error> {
    let Some(parent) = (unsafe { port_name_to_task::<P>(parent_task) }) else {
        return Err(Error::NotKernelObject);
    };

    let source = if inherit_memory != 0 {
        MapSource::Inherit
    } else {
        MapSource::Fresh
    };
    // SAFETY: the parent is live and the caller holds no locks.
    let created = unsafe { task::create_kernel_task(Some(parent), source) };

    if let Ok(child) = created {
        // SAFETY: the C's `convert_task_to_port()` consumes the child
        // reference even when the task has no self port.
        let object = unsafe { ipc_tt::convert_task_to_port(child) }
            .map_or(ptr::null_mut(), IpcPort::as_ptr);

        let space = current_space::<P>();
        // SAFETY: the object is the send right the conversion produced or the
        // null it left behind; the copyout inserts the name into the current
        // space and always returns one.
        let (_, name) = unsafe {
            ipc_kmsg::copyout_object::<P>(
                space,
                object,
                MACH_MSG_TYPE_PORT_SEND,
            )
        };

        unsafe {
            let _ = P::copyout(
                ptr::addr_of!(name).cast(),
                child_task.cast(),
                size_of::<c_uint>(),
            );
        }
    }

    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(parent.as_ptr()) };

    created.map(|_| ()).map_err(Error::from)
}

/// The `task_terminate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 69 with a user argument, and the caller must hold no
/// locks.
pub unsafe fn syscall_task_terminate<P: Platform>(
    task_name: c_uint,
) -> Result<(), Error> {
    let Some(task) = (unsafe { port_name_to_task::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the task is live and the caller holds no locks.
    let result = unsafe { task::terminate(task.as_ptr()) };
    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(task.as_ptr()) };

    result.map_err(Error::from)
}

/// The `task_suspend` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 70 with a user argument, and the caller must hold no
/// locks.
pub unsafe fn syscall_task_suspend<P: Platform>(
    task_name: c_uint,
) -> Result<(), Error> {
    let Some(task) = (unsafe { port_name_to_task::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the task is live and the caller holds no locks.
    let result = unsafe { task::suspend(task.as_ptr()) };
    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(task.as_ptr()) };

    result.map_err(Error::from)
}

/// The `task_set_special_port` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 71 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_task_set_special_port<P: Platform>(
    task_name: c_uint,
    which_port: c_int,
    port_name: c_uint,
) -> Result<(), Error> {
    let Some(target) = (unsafe { port_name_to_task::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    let port = if mach_port_name_valid(port_name) {
        let space = current_space::<P>();
        match unsafe {
            ipc_object::copyin::<P>(space, port_name, MACH_MSG_TYPE_COPY_SEND)
        } {
            Ok(object) => object,
            Err(error) => {
                // SAFETY: the reference `port_name_to_task()` took is the one
                // released here.
                unsafe { task::deallocate(target.as_ptr()) };
                return Err(error.into());
            }
        }
    } else {
        invalid_name_to_port(port_name)
    };

    let result = TaskSpecialPort::from_int(which_port).map_or(
        Err(Error::Task(TaskError::InvalidArgument)),
        |which| {
            // SAFETY: the task is live and owns the right on success; the
            // caller holds no locks.
            unsafe {
                ipc_tt::task_set_special_port(target.as_ptr(), which, port)
            }
            .map_err(Error::from)
        },
    );
    if result.is_err() {
        // SAFETY: the failed call left the right to this call.
        unsafe { release_send::<P>(port) };
    }
    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(target.as_ptr()) };

    result
}

/// The `mach_port_allocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 72 with user arguments: `namep` must name user storage of
/// one name in the current map, and the caller must hold no locks.
pub unsafe fn syscall_mach_port_allocate<P: Platform>(
    task_name: c_uint,
    right: c_uint,
    namep: *mut c_uint,
) -> Result<(), Error> {
    let Some(space) = (unsafe { port_name_to_space::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the space is live and unlocked, and the caller holds no locks.
    let result =
        unsafe { mach_ipc::mach_port::allocate::<P>(Some(space), right) };
    if let Ok(name) = result {
        unsafe {
            let _ = P::copyout(
                ptr::addr_of!(name).cast(),
                namep.cast(),
                size_of::<c_uint>(),
            );
        }
    }
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release::<P>(space) };

    result.map(|_| ()).map_err(Error::from)
}

/// The `mach_port_allocate_name` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 75 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_mach_port_allocate_name<P: Platform>(
    task_name: c_uint,
    right: c_uint,
    name: c_uint,
) -> Result<(), Error> {
    let Some(space) = (unsafe { port_name_to_space::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the space is live and unlocked, and the caller holds no locks.
    let result = unsafe {
        mach_ipc::mach_port::allocate_name::<P>(Some(space), right, name)
    };
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release::<P>(space) };

    result.map_err(Error::from)
}

/// The `mach_port_deallocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 73 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_mach_port_deallocate<P: Platform>(
    task_name: c_uint,
    name: c_uint,
) -> Result<(), Error> {
    let Some(space) = (unsafe { port_name_to_space::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the space is live and unlocked, and the caller holds no locks.
    let result =
        unsafe { mach_ipc::mach_port::deallocate::<P>(Some(space), name) };
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release::<P>(space) };

    result.map_err(Error::from)
}

/// The `mach_port_insert_right` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 74 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_mach_port_insert_right<P: Platform>(
    task_name: c_uint,
    name: c_uint,
    right: c_uint,
    right_type: c_uint,
) -> Result<(), Error> {
    let Some(space) = (unsafe { port_name_to_space::<P>(task_name) }) else {
        return Err(Error::NotKernelObject);
    };

    if !mach_msg_type_port_any(right_type) {
        // SAFETY: the reference `port_name_to_space()` took is the one
        // released here.
        unsafe { ipc_space::release::<P>(space) };
        return Err(Error::Ipc(IpcError::InvalidValue));
    }

    let object = if mach_port_name_valid(right) {
        let current = current_space::<P>();
        match unsafe { ipc_object::copyin::<P>(current, right, right_type) } {
            Ok(object) => object,
            Err(error) => {
                // SAFETY: the reference `port_name_to_space()` took is the
                // one released here.
                unsafe { ipc_space::release::<P>(space) };
                return Err(error.into());
            }
        }
    } else {
        invalid_name_to_port(right)
    };
    let newtype = ipc_object::copyin_type(right_type);

    // SAFETY: the space is live and unlocked, `object` is the naked right,
    // and the caller holds no locks.
    let result = unsafe {
        mach_ipc::mach_port::insert_right::<P>(
            Some(space),
            name,
            object,
            newtype,
        )
    };
    if result.is_err() && io_valid(object) {
        // SAFETY: the failed insert left the right to this call, and
        // destroying it consumes it.
        unsafe { ipc_object::destroy_object::<P>(object, newtype) };
    }
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release::<P>(space) };

    result.map_err(Error::from)
}

/// The `thread_depress_abort` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 76 with a user argument, and the caller must hold no
/// locks.
pub unsafe fn syscall_thread_depress_abort<P: Platform>(
    thread_name: c_uint,
) -> Result<(), Error> {
    let Some(thread) = (unsafe { port_name_to_thread(thread_name) }) else {
        return Err(Error::NotKernelObject);
    };

    // SAFETY: the thread is live, and the routine takes its own locks.
    let result = unsafe { syscall_subr::depress_abort(thread.as_ptr()) };
    // SAFETY: the reference `port_name_to_thread()` took is the one released
    // here.
    unsafe { Thread::<P>::deallocate(thread.as_ptr()) };

    result.map_err(Error::from)
}

/// The `device_write_request` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 40 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_device_write_request<P: Platform>(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: VmOffset,
    data_count: VmSize,
) -> Result<Reply, Error> {
    let Some(device) = (unsafe { port_name_to_device::<P>(device_name) })
    else {
        return Err(Error::Ipc(IpcError::InvalidCapability));
    };

    if reply_name != MACH_PORT_NULL {
        // SAFETY: the reference `port_name_to_device()` took is the one
        // released here.
        unsafe { device_deallocate(device) };
        return Err(Error::Ipc(IpcError::InvalidRight));
    }

    // SAFETY: the device is live and its reference is held, and the trap does
    // the I/O.  `VmOffset` and `VmSize` are pointer-sized, as `c_ulong` is.
    let result = unsafe {
        ds_device_write_trap(
            device,
            mode,
            recnum,
            data as c_ulong,
            data_count as c_ulong,
        )
    };
    // SAFETY: the reference `port_name_to_device()` took is the one released
    // here.
    unsafe { device_deallocate(device) };
    result.map_err(Error::Device)
}

/// The `device_writev_request` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 39 with user arguments, and the caller must hold no locks.
pub unsafe fn syscall_device_writev_request<P: Platform>(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut c_void,
    iocount: VmSize,
) -> Result<Reply, Error> {
    let Some(device) = (unsafe { port_name_to_device::<P>(device_name) })
    else {
        return Err(Error::Ipc(IpcError::InvalidCapability));
    };

    if reply_name != MACH_PORT_NULL {
        // SAFETY: the reference `port_name_to_device()` took is the one
        // released here.
        unsafe { device_deallocate(device) };
        return Err(Error::Ipc(IpcError::InvalidRight));
    }

    // SAFETY: the device is live and its reference is held, and the trap does
    // the I/O.  `VmSize` is pointer-sized, as `c_ulong` is, and the iovec is
    // the user array the trap reads through its typed pointer.
    let result = unsafe {
        ds_device_writev_trap(
            device,
            mode,
            recnum,
            iovec.cast(),
            iocount as c_ulong,
        )
    };
    // SAFETY: the reference `port_name_to_device()` took is the one released
    // here.
    unsafe { device_deallocate(device) };
    result.map_err(Error::Device)
}
