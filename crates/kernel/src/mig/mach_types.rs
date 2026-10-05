// SPDX-License-Identifier: CMU-Mach AND GPL-2.0-or-later
// SPDX-FileCopyrightText: 1994-1987 Carnegie Mellon University
// SPDX-FileCopyrightText: 1993,1994 The University of Utah and the Computer Systems Laboratory (CSL)
// SPDX-FileCopyrightText: 2012 Free Software Foundation
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: include/mach/gnumach.defs, include/mach/mach.defs,
//   kern/ipc_host.c, kern/ipc_tt.c, kern/processor.c, kern/processor.h,
//   kern/task.c, kern/task.h, kern/thread.c, kern/thread.h, vm/vm_map.c,
//   vm/vm_map.h, vm/vm_object.c and vm/vm_object.h

//! The translations and destructors <`mach/mach_types.defs`> names.
//!
//! The generated server stubs turn each port argument into the kernel
//! object it names on the way in, turn each object back into a port on the
//! way out, and drop the reference the translation took.

use crate::ipc::{IpcPort, IpcSpace};
use crate::kern::host::Host;
use crate::kern::processor::{Processor, ProcessorSet};
use crate::kern::task::{self, Task};
use crate::kern::thread::Thread;
use crate::kern::{ipc_host, ipc_tt};
use crate::vm::types::VmObject;
use crate::vm::vm_map::VmMap;
use crate::vm::vm_object;
use core::ffi::c_void;
use core::ptr::{self, NonNull};

/// `convert_port_to_task()`: the task `port` names, with a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_task(port: *mut c_void) -> *mut Task {
    unsafe { ipc_tt::convert_port_to_task(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `convert_port_to_space()`: the IPC space of the task `port` names, with
/// a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_space(
    port: *mut c_void,
) -> *mut c_void {
    unsafe { ipc_tt::convert_port_to_space(port) }
        .map_or(ptr::null_mut(), IpcSpace::as_ptr)
}

/// `convert_port_to_map()`: the address map of the task `port` names, with
/// a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_map(port: *mut c_void) -> *mut VmMap {
    unsafe { ipc_tt::convert_port_to_map(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `convert_port_to_thread()`: the thread `port` names, with a reference.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_thread(
    port: *mut c_void,
) -> *mut Thread {
    unsafe { ipc_tt::convert_port_to_thread(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `convert_task_to_port()`: a send right for `task`'s port.
///
/// # Safety
///
/// `task` must be a live task the caller holds a reference to; the routine
/// consumes the reference and may deallocate the task.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_task_to_port(task: *mut Task) -> *mut c_void {
    unsafe { ipc_tt::convert_task_to_port(task) }
        .map_or(ptr::null_mut(), IpcPort::as_ptr)
}

/// `convert_thread_to_port()`: a send right for `thread`'s port.
///
/// # Safety
///
/// `thread` must be a live thread the caller holds a reference to; the
/// routine consumes the reference and may deallocate the thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_thread_to_port(
    thread: *mut Thread,
) -> *mut c_void {
    unsafe { ipc_tt::convert_thread_to_port(thread) }
        .map_or(ptr::null_mut(), IpcPort::as_ptr)
}

/// `convert_port_to_host()`: the host that `port`, a host or privileged
/// host port, names, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_host(port: *mut c_void) -> *mut Host {
    unsafe { ipc_host::port_to_host(port) }
}

/// `convert_port_to_host_priv()`: the host that `port`, a privileged host
/// port, names, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_host_priv(
    port: *mut c_void,
) -> *mut Host {
    unsafe { ipc_host::port_to_host_priv(port) }
}

/// `convert_host_to_port()`: a send right for `host`'s name port.
///
/// # Safety
///
/// `host` must point at a live [`Host`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_host_to_port(host: *mut Host) -> *mut c_void {
    unsafe { ipc_host::host_to_port(host) }
}

/// `convert_port_to_processor()`: the processor that `port`, a processor
/// port, names, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_processor(
    port: *mut c_void,
) -> *mut Processor {
    unsafe { ipc_host::port_to_processor(port) }
}

/// `convert_port_to_processor_name()`: the processor that `port`, a
/// processor or processor-name port, names, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_processor_name(
    port: *mut c_void,
) -> *mut Processor {
    unsafe { ipc_host::port_to_processor_name(port) }
}

/// `convert_port_to_pset()`: the processor set that `port`, a set port,
/// names, with one more reference, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_pset(
    port: *mut c_void,
) -> *mut ProcessorSet {
    unsafe { ipc_host::port_to_pset(port) }
}

/// `convert_port_to_pset_name()`: the processor set that `port`, a set or
/// set-name port, names, with one more reference, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_pset_name(
    port: *mut c_void,
) -> *mut ProcessorSet {
    unsafe { ipc_host::port_to_pset_name(port) }
}

/// `convert_pset_to_port()`: a send right for `pset`'s port.
///
/// # Safety
///
/// `pset` must point at a live, referenced [`ProcessorSet`]; the call
/// consumes the reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_pset_to_port(
    pset: *mut ProcessorSet,
) -> *mut c_void {
    unsafe { ipc_host::pset_to_port(pset) }
}

/// `convert_pset_name_to_port()`: a send right for `pset`'s name port.
///
/// # Safety
///
/// `pset` must point at a live, referenced [`ProcessorSet`]; the call
/// consumes the reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_pset_name_to_port(
    pset: *mut ProcessorSet,
) -> *mut c_void {
    unsafe { ipc_host::pset_name_to_port(pset) }
}

/// `vm_object_lookup()`: the memory object `port` controls, with a
/// reference.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_lookup(port: *mut c_void) -> *mut VmObject {
    unsafe { vm_object::lookup(port) }.map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `vm_object_lookup_name()`: the memory object `port` names, with a
/// reference.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_lookup_name(
    port: *mut c_void,
) -> *mut VmObject {
    unsafe { vm_object::lookup_name(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `task_deallocate()`: drop a task reference.
///
/// # Safety
///
/// `task` must be null or a live task the caller holds a reference to, and
/// the caller must hold no locks: the cleanup may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_deallocate(task: *mut c_void) {
    unsafe { task::deallocate(task.cast()) };
}

/// `thread_deallocate()`: drop a thread reference.
///
/// # Safety
///
/// `thread` must be null or a live thread the caller holds a reference to,
/// and the caller must hold no locks: the teardown may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_deallocate(thread: *mut Thread) {
    unsafe { Thread::deallocate(thread) };
}

/// `space_deallocate()`: drop the space reference
/// [`convert_port_to_space`] took.
///
/// # Safety
///
/// A non-null `space` must be a live space the caller holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn space_deallocate(space: *mut c_void) {
    unsafe { ipc_tt::space_deallocate(space) };
}

/// `pset_deallocate()`: drop a processor-set reference.
///
/// # Safety
///
/// `pset` must be null or point at a live [`ProcessorSet`] that the caller
/// holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pset_deallocate(pset: *mut ProcessorSet) {
    let Some(pset) = NonNull::new(pset) else {
        return;
    };

    unsafe { (*pset.as_ptr()).deallocate() };
}

/// `vm_map_deallocate()`: drop a map reference.
///
/// # Safety
///
/// A non-null `map` must point at a valid map, and the caller must hold a
/// reference to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_map_deallocate(map: *mut VmMap) {
    if let Some(map) = NonNull::new(map) {
        VmMap::deallocate(map);
    }
}

/// `vm_object_deallocate()`: drop a memory-object reference.
///
/// # Safety
///
/// `object` must be null or a live object the caller holds a reference to,
/// and no lock of the caller's may be held.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_deallocate(object: *mut VmObject) {
    unsafe { vm_object::deallocate(object) };
}
