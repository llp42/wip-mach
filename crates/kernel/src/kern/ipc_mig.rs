// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_mig.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The MIG support entry points and the kernel-side RPC traps.
//!
//! The symbols the generated code calls are in [`crate::mig::runtime`]; this
//! module holds the routines themselves.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::user_access;
use crate::device::dev_lookup;
use crate::device::ds_routines::{
    device_deallocate, device_reference, ds_device_write_trap,
    ds_device_writev_trap,
};
use crate::device::r#return::Reply;
use crate::ipc::error::Error as IpcError;
use crate::ipc::error::SendError;
use crate::ipc::ipc_kmsg;
use crate::ipc::ipc_mqueue;
use crate::ipc::{IpcPort, IpcSpace, MachMsgHeader};
use crate::ipc::{ipc_object, ipc_port, ipc_space};
use crate::kern::debug::kpanic;
use crate::kern::error::{Error, RpcError};
use crate::kern::ipc_tt::{self, TaskSpecialPort};
use crate::kern::syscall_subr;
use crate::kern::task::{self, MapSource, Task};
use crate::kern::thread::Thread;
use crate::mig::code::{KERN_SUCCESS, io_return, kern_return};
use crate::vm::types::{VmInherit, VmProt};
use crate::vm::vm_map::VmMap;
use crate::vm::vm_user;
use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// No port name.
const MACH_PORT_NULL: c_uint = 0;
/// The `natural_t` words the C scratch array of `thread_set_self_state()`
/// held.
const MAX_SELF_STATE: usize = 150;

/// The null port name.
const MACH_PORT_NAME_NULL: c_uint = 0;
/// The dead port name.
const MACH_PORT_NAME_DEAD: c_uint = c_uint::MAX;
/// The dead port value: the all-ones word.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// The receive-right disposition.
const MACH_MSG_TYPE_PORT_RECEIVE: c_uint = 16;
/// `MACH_MSG_TYPE_PORT_SEND`, the wire alias of `MACH_MSG_TYPE_MOVE_SEND`.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;
/// The disposition that copies a send right.
const MACH_MSG_TYPE_COPY_SEND: c_uint = 19;
/// The disposition that makes a send-once right.
const MACH_MSG_TYPE_MAKE_SEND_ONCE: c_uint = 21;
/// The kernel's send option that ignores the queue limit, as the unsigned
/// message-queue option word takes it.
const MACH_SEND_ALWAYS: c_uint = 0x0001_0000;
/// No timeout.
const MACH_MSG_TIMEOUT_NONE: c_uint = 0;
/// The capability-type field.
const IE_BITS_TYPE_MASK: u32 = 0x001f_0000;
/// The type bit of a send right.
const MACH_PORT_TYPE_SEND: u32 = 1 << 16;
/// The kernel-object type of a thread port.
const IKOT_THREAD: c_uint = 1;
/// The kernel-object type of a task port.
const IKOT_TASK: c_uint = 2;
/// The kernel-object type of a device port.
const IKOT_DEVICE: c_uint = 10;

/// The running task's IPC space.
///
/// # Safety
///
/// Must be called from a thread context: the running task is live and its
/// space is not null.
pub(crate) unsafe fn current_space() -> IpcSpace {
    unsafe { IpcSpace::from_raw((*task::current_task()).itk_space) }
}

/// The running task's address space.
///
/// # Safety
///
/// Must be called from a thread context: the running task is live and its map
/// is not null.
pub(crate) unsafe fn current_map() -> *mut VmMap {
    unsafe { (*task::current_task()).map.cast() }
}

/// The port an invalid name stands for.  A valid name is impossible at every
/// call site and halts the kernel.
fn invalid_name_to_port(name: c_uint) -> *mut c_void {
    match name {
        MACH_PORT_NAME_NULL => ptr::null_mut(),
        MACH_PORT_NAME_DEAD => IO_DEAD,
        _ => {
            kpanic!(
                "invalid_name_to_port",
                "invalid_name_to_port() called with a valid port"
            )
        }
    }
}

/// Whether `name` is neither null nor dead.
const fn mach_port_name_valid(name: c_uint) -> bool {
    name != MACH_PORT_NAME_NULL && name != MACH_PORT_NAME_DEAD
}

/// Whether `name` is a port-right type.
const fn mach_msg_type_port_any(name: c_uint) -> bool {
    MACH_MSG_TYPE_PORT_RECEIVE <= name && name <= MACH_MSG_TYPE_MAKE_SEND_ONCE
}

/// Whether `object` is neither null nor dead.
fn io_valid(object: *mut c_void) -> bool {
    !object.is_null() && object != IO_DEAD
}

/// Destroy the kernel-RPC reply port `thread` holds, if it holds one.
///
/// # Safety
///
/// `thread` must point at a live thread, and nothing may be locked, as the C
/// documented.
pub(crate) unsafe fn abort_rpc(thread: *mut Thread) {
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
        unsafe { ipc_port::dealloc_special(IpcPort::from_raw(reply)) };
    }
}

/// Copy the user's state words into `scratch`, reporting how many were copied.
///
/// # Safety
///
/// A `count` in range requires `new_state` to be readable for that many
/// `natural_t` words; a fault is what `copyin()` reports.
unsafe fn copy_self_state(
    new_state: *mut c_uint,
    count: c_uint,
    scratch: &mut [c_uint; MAX_SELF_STATE],
) -> Option<usize> {
    let words = usize::try_from(count).ok()?;
    if words == 0 || words > MAX_SELF_STATE {
        return None;
    }

    let faulted = unsafe {
        user_access::copyin(
            new_state.cast(),
            scratch.as_mut_ptr().cast(),
            words * size_of::<c_uint>(),
        )
    };
    if faulted.is_err() { None } else { Some(words) }
}

/// Set the current thread's machine state from a user buffer.
///
/// # Safety
///
/// Reached as trap -77 with a user `new_state`; a fault is what `copyin()`
/// reports.
pub(crate) unsafe fn set_self_state(
    flavor: c_int,
    new_state: *mut c_uint,
    count: c_uint,
) -> Result<(), Error> {
    let mut scratch = [0; MAX_SELF_STATE];

    let Some(words) =
        (unsafe { copy_self_state(new_state, count, &mut scratch) })
    else {
        return Err(Error::InvalidArgument);
    };

    let thread = per_cpu::thread();
    // SAFETY: `thread` is the running thread.
    unsafe {
        crate::arch::x86_64::pcb::thread_set_syscall_return(
            thread,
            KERN_SUCCESS,
        );
        let result = crate::arch::x86_64::pcb::thread_setstatus(
            thread,
            flavor,
            scratch.as_mut_ptr(),
            // `words` is at most `MAX_SELF_STATE`, so the narrowing cannot
            // lose anything.
            words as c_uint,
        );
        if result.is_ok() {
            crate::arch::x86_64::locore::thread_exception_return();
        }
        result.map_err(Error::Machine)
    }
}

/// The `thread_set_self_state` trap entry, trap -77.
///
/// # Safety
///
/// Reached as trap -77: a non-null `new_state` must be readable for
/// `new_state_count` `natural_t` words, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn thread_set_self_state(
    flavor: c_int,
    new_state: *mut c_uint,
    new_state_count: c_uint,
) -> c_int {
    kern_return(unsafe { set_self_state(flavor, new_state, new_state_count) })
}

/// One send right to `name` from the current space, or `None` when the copyin
/// failed: the slow path of the name translations.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn copyin_send(name: c_uint) -> Option<*mut c_void> {
    unsafe {
        ipc_object::copyin(current_space(), name, MACH_MSG_TYPE_COPY_SEND)
    }
    .ok()
}

/// Release the send right a slow path copied in, when it is a live port.
///
/// # Safety
///
/// `object` must be an object [`copyin_send()`] returned.
unsafe fn release_send(object: *mut c_void) {
    if let Some(port) = IpcPort::valid(object) {
        unsafe { ipc_port::release_send(port) };
    }
}

/// `name` looked up as a bare send right in the current space, with the port
/// locked, or `None` for the slow path.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn fast_send_right_lookup(name: c_uint) -> Option<IpcPort> {
    let space = unsafe { current_space() };

    unsafe {
        space.lock_read();
        let found = space.entry_lookup(name);
        let Some(entry) = found else {
            space.lock_done();
            return None;
        };
        if (*entry).bits() & IE_BITS_TYPE_MASK != MACH_PORT_TYPE_SEND {
            space.lock_done();
            return None;
        }

        let port = IpcPort::from_raw((*entry).object());
        port.lock();
        space.lock_done();
        Some(port)
    }
}

/// The device the send right `name` names, with a reference, or `None`.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn port_name_to_device(name: c_uint) -> Option<NonNull<c_void>> {
    if let Some(port) = unsafe { fast_send_right_lookup(name) } {
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

    let object = (unsafe { copyin_send(name) })?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let device = unsafe {
        NonNull::new(dev_lookup::port_lookup(object).cast::<c_void>())
    };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send(object) };
    device
}

/// The thread the send right `name` names, with a reference, or `None`.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn port_name_to_thread(name: c_uint) -> Option<NonNull<Thread>> {
    if let Some(port) = unsafe { fast_send_right_lookup(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live thread, and `Thread::reference()` takes the
        // reference the C took before unlocking.
        return unsafe {
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
        };
    }

    let object = unsafe { copyin_send(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let thread = unsafe { ipc_tt::convert_port_to_thread(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send(object) };
    thread
}

/// The task the send right `name` names, with a reference, or `None`.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn port_name_to_task(name: c_uint) -> Option<NonNull<Task>> {
    if let Some(port) = unsafe { fast_send_right_lookup(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live task, and `task::reference()` takes the reference
        // the C took before unlocking.
        return unsafe {
            let task = match NonNull::new(port.kobject().cast::<Task>()) {
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

    let object = unsafe { copyin_send(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let task = unsafe { ipc_tt::convert_port_to_task(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send(object) };
    task
}

/// The address map of the task the send right `name` names, with a reference,
/// or `None`.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn port_name_to_map(name: c_uint) -> Option<NonNull<VmMap>> {
    if let Some(port) = unsafe { fast_send_right_lookup(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live task whose map is live, and `VmMap::reference()`
        // takes the reference the C took before unlocking.
        return unsafe {
            let map = match NonNull::new(port.kobject().cast::<Task>()) {
                Some(task)
                    if port.is_active() && port.kotype() == IKOT_TASK =>
                {
                    let map = NonNull::new((*task.as_ptr()).map.cast());
                    if let Some(map) = map {
                        VmMap::reference(map);
                    }
                    map
                }
                _ => None,
            };
            port.unlock();
            map
        };
    }

    let object = unsafe { copyin_send(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let map = unsafe { ipc_tt::convert_port_to_map(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send(object) };
    map
}

/// The IPC space of the task the send right `name` names, with a reference, or
/// `None`.
///
/// # Safety
///
/// Must be called from a thread context with nothing locked.
unsafe fn port_name_to_space(name: c_uint) -> Option<IpcSpace> {
    if let Some(port) = unsafe { fast_send_right_lookup(name) } {
        // SAFETY: the lookup returned the live, locked port; a matching
        // kobject is a live task whose space is live, and
        // `ipc_space::reference()` takes the reference the C took before
        // unlocking.
        return unsafe {
            let space = match NonNull::new(port.kobject().cast::<Task>()) {
                Some(task)
                    if port.is_active() && port.kotype() == IKOT_TASK =>
                {
                    let space = IpcSpace::new((*task.as_ptr()).itk_space);
                    if let Some(space) = space {
                        ipc_space::reference(space);
                    }
                    space
                }
                _ => None,
            };
            port.unlock();
            space
        };
    }

    let object = unsafe { copyin_send(name) }?;
    // SAFETY: the copyin returned one live reference to the object the name
    // denoted.
    let space = unsafe { ipc_tt::convert_port_to_space(object) };
    // SAFETY: the reference the copyin returned is the one this releases.
    unsafe { release_send(object) };
    space
}

/// Sends a message the kernel built, of `send_size` bytes at `msg`.
///
/// # Safety
///
/// `msg` must point at a readable kernel message of `send_size` bytes, and
/// the caller must hold no locks.
pub(crate) unsafe fn mach_msg_send_from_kernel(
    msg: *mut c_void,
    send_size: c_uint,
) -> Result<(), SendError> {
    let remote = unsafe { (*msg.cast::<MachMsgHeader>()).remote() };
    // `MACH_PORT_VALID()` over the kernel header's pointer-wide field.
    if remote == 0 || remote == usize::MAX {
        return Err(SendError::InvalidDest);
    }

    let Ok(kmsg) = (unsafe { ipc_kmsg::get_from_kernel(msg, send_size) })
    else {
        kpanic!("mach_msg_send_from_kernel", "mach_msg_send_from_kernel")
    };

    // SAFETY: the message is live and this call owns it.
    unsafe { ipc_kmsg::copyin_from_kernel(kmsg) };
    // SAFETY: the message is live and holds the send right the send consumes;
    // the result is discarded.
    let _ = unsafe {
        ipc_mqueue::send(
            kmsg.as_ptr(),
            MACH_SEND_ALWAYS,
            MACH_MSG_TIMEOUT_NONE,
        )
    };
    Ok(())
}

/// The arguments of `syscall_vm_map()`, which the trap passes as eleven
/// words.
pub(crate) struct VmMapRequest {
    pub(crate) target_map: c_uint,
    pub(crate) address: *mut VmOffset,
    pub(crate) size: VmSize,
    pub(crate) mask: VmOffset,
    pub(crate) anywhere: c_int,
    pub(crate) memory_object: c_uint,
    pub(crate) offset: VmOffset,
    pub(crate) copy: c_int,
    pub(crate) cur_protection: c_int,
    pub(crate) max_protection: c_int,
    pub(crate) inheritance: c_int,
}

/// The `vm_map` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 64 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub(crate) unsafe fn syscall_vm_map(
    request: &VmMapRequest,
) -> Result<(), RpcError> {
    let Some(map) = (unsafe { port_name_to_map(request.target_map) }) else {
        return Err(RpcError::NotKernelObject);
    };

    let port = if mach_port_name_valid(request.memory_object) {
        let space = unsafe { current_space() };
        match unsafe {
            ipc_object::copyin(
                space,
                request.memory_object,
                MACH_MSG_TYPE_COPY_SEND,
            )
        } {
            Ok(object) => object,
            Err(error) => {
                VmMap::deallocate(map);
                return Err(error.into());
            }
        }
    } else {
        invalid_name_to_port(request.memory_object)
    };

    let mut addr = 0;
    // The C ignored the copyin result and handed `vm_map()` whatever the
    // stack held when it failed; zero is the deterministic stand-in.
    unsafe {
        let _ = user_access::copyin(
            request.address.cast(),
            ptr::addr_of_mut!(addr).cast(),
            size_of::<VmOffset>(),
        );
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
                cur_protection: VmProt::from_bits(request.cur_protection),
                max_protection: VmProt::from_bits(request.max_protection),
                inheritance: VmInherit::from_bits(request.inheritance),
            },
        )
    };
    if result.is_ok() {
        // SAFETY: `vm_map()` wrote the mapped address into `addr`, and the
        // caller promises the user address is writable.
        unsafe {
            let _ = user_access::copyout(
                ptr::addr_of!(addr).cast(),
                request.address.cast(),
                size_of::<VmOffset>(),
            );
        }
    }

    // SAFETY: `port` is the right the copyin produced, when it did.
    unsafe { release_send(port) };
    VmMap::deallocate(map);

    result.map_err(RpcError::Vm)
}

/// The `syscall_vm_map` trap entry, trap 64.
///
/// # Safety
///
/// Reached as trap 64 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_vm_map_entry(
    target_map: c_uint,
    address: *mut VmOffset,
    size: VmSize,
    mask: VmOffset,
    anywhere: c_int,
    memory_object: c_uint,
    offset: VmOffset,
    copy: c_int,
    cur_protection: c_int,
    max_protection: c_int,
    inheritance: c_int,
) -> c_int {
    let request = VmMapRequest {
        target_map,
        address,
        size,
        mask,
        anywhere,
        memory_object,
        offset,
        copy,
        cur_protection,
        max_protection,
        inheritance,
    };

    kern_return(unsafe { syscall_vm_map(&request) })
}

/// The `vm_allocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 65 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub(crate) unsafe fn syscall_vm_allocate(
    target_map: c_uint,
    address: *mut VmOffset,
    size: VmSize,
    anywhere: c_int,
) -> Result<(), RpcError> {
    let Some(map) = (unsafe { port_name_to_map(target_map) }) else {
        return Err(RpcError::NotKernelObject);
    };

    let mut addr = 0;
    unsafe {
        let _ = user_access::copyin(
            address.cast(),
            ptr::addr_of_mut!(addr).cast(),
            size_of::<VmOffset>(),
        );
    }

    // SAFETY: the map is live and unlocked, and the caller holds no locks.
    let result = unsafe {
        vm_user::allocate(&mut *map.as_ptr(), &mut addr, size, anywhere != 0)
    };
    if result.is_ok() {
        // SAFETY: the allocation wrote the address into `addr`, and the
        // caller promises the user address is writable.
        unsafe {
            let _ = user_access::copyout(
                ptr::addr_of!(addr).cast(),
                address.cast(),
                size_of::<VmOffset>(),
            );
        }
    }
    VmMap::deallocate(map);

    result.map_err(RpcError::from)
}

/// The `syscall_vm_allocate` trap entry, trap 65.
///
/// # Safety
///
/// Reached as trap 65 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_vm_allocate_entry(
    target_map: c_uint,
    address: *mut VmOffset,
    size: VmSize,
    anywhere: c_int,
) -> c_int {
    kern_return(unsafe {
        syscall_vm_allocate(target_map, address, size, anywhere)
    })
}

/// The `vm_deallocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 66 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_vm_deallocate(
    target_map: c_uint,
    start: VmOffset,
    size: VmSize,
) -> Result<(), RpcError> {
    let Some(map) = (unsafe { port_name_to_map(target_map) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the map is live and unlocked, and the caller holds no locks.
    let result =
        unsafe { vm_user::deallocate(&mut *map.as_ptr(), start, size) };
    VmMap::deallocate(map);

    result.map_err(RpcError::from)
}

/// The `syscall_vm_deallocate` trap entry, trap 66.
///
/// # Safety
///
/// Reached as trap 66 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_vm_deallocate_entry(
    target_map: c_uint,
    start: VmOffset,
    size: VmSize,
) -> c_int {
    kern_return(unsafe { syscall_vm_deallocate(target_map, start, size) })
}

/// The `task_create` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 68 with user arguments: `child_task` must name user
/// storage of one name in the current map, and the caller must hold no locks.
pub(crate) unsafe fn syscall_task_create(
    parent_task: c_uint,
    inherit_memory: c_int,
    child_task: *mut c_uint,
) -> Result<(), RpcError> {
    let Some(parent) = (unsafe { port_name_to_task(parent_task) }) else {
        return Err(RpcError::NotKernelObject);
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

        // SAFETY: the object is the send right the conversion produced or the
        // null it left behind; the copyout inserts the name into the current
        // space and always returns one.
        let (_, name) = unsafe {
            let space = current_space();
            ipc_kmsg::copyout_object(space, object, MACH_MSG_TYPE_PORT_SEND)
        };

        unsafe {
            let _ = user_access::copyout(
                ptr::addr_of!(name).cast(),
                child_task.cast(),
                size_of::<c_uint>(),
            );
        }
    }

    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(parent.as_ptr()) };

    created.map(|_| ()).map_err(RpcError::from)
}

/// The `syscall_task_create` trap entry, trap 68.
///
/// # Safety
///
/// Reached as trap 68 with user arguments: `child_task` must name user
/// storage of one name in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_task_create_entry(
    parent_task: c_uint,
    inherit_memory: c_int,
    child_task: *mut c_uint,
) -> c_int {
    kern_return(unsafe {
        syscall_task_create(parent_task, inherit_memory, child_task)
    })
}

/// The `task_terminate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 69 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe fn syscall_task_terminate(
    task_name: c_uint,
) -> Result<(), RpcError> {
    let Some(task) = (unsafe { port_name_to_task(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the task is live and the caller holds no locks.
    let result = unsafe { task::terminate(task.as_ptr()) };
    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(task.as_ptr()) };

    result.map_err(RpcError::from)
}

/// The `syscall_task_terminate` trap entry, trap 69.
///
/// # Safety
///
/// Reached as trap 69 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe extern "C" fn syscall_task_terminate_entry(
    task: c_uint,
) -> c_int {
    kern_return(unsafe { syscall_task_terminate(task) })
}

/// The `task_suspend` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 70 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe fn syscall_task_suspend(
    task_name: c_uint,
) -> Result<(), RpcError> {
    let Some(task) = (unsafe { port_name_to_task(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the task is live and the caller holds no locks.
    let result = unsafe { task::suspend(task.as_ptr()) };
    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(task.as_ptr()) };

    result.map_err(RpcError::from)
}

/// The `syscall_task_suspend` trap entry, trap 70.
///
/// # Safety
///
/// Reached as trap 70 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe extern "C" fn syscall_task_suspend_entry(
    task: c_uint,
) -> c_int {
    kern_return(unsafe { syscall_task_suspend(task) })
}

/// The `task_set_special_port` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 71 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_task_set_special_port(
    task_name: c_uint,
    which_port: c_int,
    port_name: c_uint,
) -> Result<(), RpcError> {
    let Some(target) = (unsafe { port_name_to_task(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    let port = if mach_port_name_valid(port_name) {
        let space = unsafe { current_space() };
        match unsafe {
            ipc_object::copyin(space, port_name, MACH_MSG_TYPE_COPY_SEND)
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
        Err(Error::InvalidArgument),
        |which| {
            // SAFETY: the task is live and owns the right on success; the
            // caller holds no locks.
            unsafe {
                ipc_tt::task_set_special_port(target.as_ptr(), which, port)
            }
        },
    );
    if result.is_err() {
        // SAFETY: the failed call left the right to this call.
        unsafe { release_send(port) };
    }
    // SAFETY: the reference `port_name_to_task()` took is the one released
    // here.
    unsafe { task::deallocate(target.as_ptr()) };

    result.map_err(RpcError::from)
}

/// The `syscall_task_set_special_port` trap entry, trap 71.
///
/// # Safety
///
/// Reached as trap 71 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_task_set_special_port_entry(
    task: c_uint,
    which_port: c_int,
    port_name: c_uint,
) -> c_int {
    kern_return(unsafe {
        syscall_task_set_special_port(task, which_port, port_name)
    })
}

/// The `mach_port_allocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 72 with user arguments: `namep` must name user storage of
/// one name in the current map, and the caller must hold no locks.
pub(crate) unsafe fn syscall_mach_port_allocate(
    task_name: c_uint,
    right: c_uint,
    namep: *mut c_uint,
) -> Result<(), RpcError> {
    let Some(space) = (unsafe { port_name_to_space(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the space is live and unlocked, and the caller holds no locks.
    let result =
        unsafe { crate::ipc::mach_port::allocate(Some(space), right) };
    if let Ok(name) = result {
        unsafe {
            let _ = user_access::copyout(
                ptr::addr_of!(name).cast(),
                namep.cast(),
                size_of::<c_uint>(),
            );
        }
    }
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release(space) };

    result.map(|_| ()).map_err(RpcError::from)
}

/// The `syscall_mach_port_allocate` trap entry, trap 72.
///
/// # Safety
///
/// Reached as trap 72 with user arguments: `namep` must name user storage of
/// one name in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_allocate_entry(
    task: c_uint,
    right: c_uint,
    namep: *mut c_uint,
) -> c_int {
    kern_return(unsafe { syscall_mach_port_allocate(task, right, namep) })
}

/// The `mach_port_allocate_name` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 75 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_mach_port_allocate_name(
    task_name: c_uint,
    right: c_uint,
    name: c_uint,
) -> Result<(), RpcError> {
    let Some(space) = (unsafe { port_name_to_space(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the space is live and unlocked, and the caller holds no locks.
    let result = unsafe {
        crate::ipc::mach_port::allocate_name(Some(space), right, name)
    };
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release(space) };

    result.map_err(RpcError::from)
}

/// The `syscall_mach_port_allocate_name` trap entry, trap 75.
///
/// # Safety
///
/// Reached as trap 75 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_allocate_name_entry(
    task: c_uint,
    right: c_uint,
    name: c_uint,
) -> c_int {
    kern_return(unsafe { syscall_mach_port_allocate_name(task, right, name) })
}

/// The `mach_port_deallocate` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 73 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_mach_port_deallocate(
    task_name: c_uint,
    name: c_uint,
) -> Result<(), RpcError> {
    let Some(space) = (unsafe { port_name_to_space(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the space is live and unlocked, and the caller holds no locks.
    let result =
        unsafe { crate::ipc::mach_port::deallocate(Some(space), name) };
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release(space) };

    result.map_err(RpcError::from)
}

/// The `syscall_mach_port_deallocate` trap entry, trap 73.
///
/// # Safety
///
/// Reached as trap 73 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_deallocate_entry(
    task: c_uint,
    name: c_uint,
) -> c_int {
    kern_return(unsafe { syscall_mach_port_deallocate(task, name) })
}

/// The `mach_port_insert_right` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 74 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_mach_port_insert_right(
    task_name: c_uint,
    name: c_uint,
    right: c_uint,
    right_type: c_uint,
) -> Result<(), RpcError> {
    let Some(space) = (unsafe { port_name_to_space(task_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    if !mach_msg_type_port_any(right_type) {
        // SAFETY: the reference `port_name_to_space()` took is the one
        // released here.
        unsafe { ipc_space::release(space) };
        return Err(RpcError::Ipc(IpcError::InvalidValue));
    }

    let object = if mach_port_name_valid(right) {
        let current = unsafe { current_space() };
        match unsafe { ipc_object::copyin(current, right, right_type) } {
            Ok(object) => object,
            Err(error) => {
                // SAFETY: the reference `port_name_to_space()` took is the
                // one released here.
                unsafe { ipc_space::release(space) };
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
        crate::ipc::mach_port::insert_right(Some(space), name, object, newtype)
    };
    if result.is_err() && io_valid(object) {
        // SAFETY: the failed insert left the right to this call, and
        // destroying it consumes it.
        unsafe { ipc_object::destroy_object(object, newtype) };
    }
    // SAFETY: the reference `port_name_to_space()` took is the one released
    // here.
    unsafe { ipc_space::release(space) };

    result.map_err(RpcError::from)
}

/// The `syscall_mach_port_insert_right` trap entry, trap 74.
///
/// # Safety
///
/// Reached as trap 74 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_insert_right_entry(
    task: c_uint,
    name: c_uint,
    right: c_uint,
    right_type: c_uint,
) -> c_int {
    kern_return(unsafe {
        syscall_mach_port_insert_right(task, name, right, right_type)
    })
}

/// The `thread_depress_abort` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 76 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe fn syscall_thread_depress_abort(
    thread_name: c_uint,
) -> Result<(), RpcError> {
    let Some(thread) = (unsafe { port_name_to_thread(thread_name) }) else {
        return Err(RpcError::NotKernelObject);
    };

    // SAFETY: the thread is live, and the routine takes its own locks.
    let result = unsafe { syscall_subr::depress_abort(thread.as_ptr()) };
    // SAFETY: the reference `port_name_to_thread()` took is the one released
    // here.
    unsafe { Thread::deallocate(thread.as_ptr()) };

    result.map_err(RpcError::Kern)
}

/// The `syscall_thread_depress_abort` trap entry, trap 76.
///
/// # Safety
///
/// Reached as trap 76 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe extern "C" fn syscall_thread_depress_abort_entry(
    thread: c_uint,
) -> c_int {
    kern_return(unsafe { syscall_thread_depress_abort(thread) })
}

/// The `device_write_request` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 40 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_device_write_request(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: VmOffset,
    data_count: VmSize,
) -> Result<Reply, RpcError> {
    let Some(device) = (unsafe { port_name_to_device(device_name) }) else {
        return Err(RpcError::Ipc(IpcError::InvalidCapability));
    };

    if reply_name != MACH_PORT_NULL {
        // SAFETY: the reference `port_name_to_device()` took is the one
        // released here.
        unsafe { device_deallocate(device) };
        return Err(RpcError::Ipc(IpcError::InvalidRight));
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
    result.map_err(RpcError::Device)
}

/// The `syscall_device_write_request` trap entry, trap 40.
///
/// # Safety
///
/// Reached as trap 40 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_device_write_request_entry(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: VmOffset,
    data_count: VmSize,
) -> c_int {
    match unsafe {
        syscall_device_write_request(
            device_name,
            reply_name,
            mode,
            recnum,
            data,
            data_count,
        )
    } {
        Ok(reply) => io_return(Ok(reply)),
        Err(error) => c_int::from(error),
    }
}

/// The `device_writev_request` call as a trap, on port names.
///
/// # Safety
///
/// Reached as trap 39 with user arguments, and the caller must hold no locks.
pub(crate) unsafe fn syscall_device_writev_request(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut c_void,
    iocount: VmSize,
) -> Result<Reply, RpcError> {
    let Some(device) = (unsafe { port_name_to_device(device_name) }) else {
        return Err(RpcError::Ipc(IpcError::InvalidCapability));
    };

    if reply_name != MACH_PORT_NULL {
        // SAFETY: the reference `port_name_to_device()` took is the one
        // released here.
        unsafe { device_deallocate(device) };
        return Err(RpcError::Ipc(IpcError::InvalidRight));
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
    result.map_err(RpcError::Device)
}

/// The `syscall_device_writev_request` trap entry, trap 39.
///
/// # Safety
///
/// Reached as trap 39 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_device_writev_request_entry(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut c_void,
    iocount: VmSize,
) -> c_int {
    match unsafe {
        syscall_device_writev_request(
            device_name,
            reply_name,
            mode,
            recnum,
            iovec,
            iocount,
        )
    } {
        Ok(reply) => io_return(Ok(reply)),
        Err(error) => c_int::from(error),
    }
}
