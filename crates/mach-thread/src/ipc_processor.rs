// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The processor and processor-set ports.

use crate::error::Error;
use crate::platform::Platform;
use crate::processor;
use crate::processor::Processor;
use crate::processor_set::ProcessorSet;
use core::ffi::{c_uint, c_void};
use core::ptr;
use core::ptr::NonNull;
use mach_ipc::{IpcPort, ipc_port, ipc_space};
use mach_vm::param::VmOffset;

/// `IKOT_PROCESSOR`: the object type of a processor's control port.
const IKOT_PROCESSOR: c_uint = 5;
/// `IKOT_PSET`: the object type of a processor set's control port.
const IKOT_PSET: c_uint = 6;
/// `IKOT_PSET_NAME`: the object type of a set's name port.
const IKOT_PSET_NAME: c_uint = 7;
/// `IKOT_PROCESSOR_NAME`: the object type of a processor's name port.
const IKOT_PROCESSOR_NAME: c_uint = 29;
/// `IKOT_NONE`: the type of a port bound to no kernel object.
const IKOT_NONE: c_uint = 0;
/// The value that clears a port's kernel object.
const IKO_NULL: VmOffset = 0;

/// Allocate a special port in the kernel's IPC space, halting when the
/// allocator fails as the C callers did.
fn alloc_kernel_port<P: Platform>(function: &'static str) -> NonNull<c_void> {
    // SAFETY: the kernel's space is live from `ipc_init()` on, and the
    // allocator takes its own locks.
    let port = unsafe { ipc_port::alloc_special::<P>(ipc_space::kernel()) };
    let Some(port) = port else {
        panic!("{function}")
    };
    // SAFETY: `IpcPort` always holds a non-null pointer.
    unsafe { NonNull::new_unchecked(port.as_ptr()) }
}

/// Makes the processor's control and name ports.
pub fn processor_init<P: Platform>(processor: &mut Processor<P>) {
    let port = alloc_kernel_port::<P>("ipc_processor_init");
    processor.processor_self = port.as_ptr();
    // SAFETY: `port` is the special port just allocated and nothing else can
    // reach it yet; `processor` is the live object the C bound.
    unsafe {
        P::kobject_set(
            port.as_ptr(),
            ptr::from_mut(processor).addr(),
            IKOT_PROCESSOR,
        );
    }

    let port = alloc_kernel_port::<P>("ipc_processor_init");
    processor.processor_name_self = port.as_ptr();
    // SAFETY: `port` is the special port just allocated and nothing else can
    // reach it yet; `processor` is the live object the C bound; for
    // the second, name port.
    unsafe {
        P::kobject_set(
            port.as_ptr(),
            ptr::from_mut(processor).addr(),
            IKOT_PROCESSOR_NAME,
        );
    }
}

/// Makes the set's control and name ports.
pub fn pset_init<P: Platform>(pset: &mut ProcessorSet<P>) {
    let port = alloc_kernel_port::<P>("ipc_pset_init");
    pset.pset_self = port.as_ptr();

    let port = alloc_kernel_port::<P>("ipc_pset_init");
    pset.pset_name_self = port.as_ptr();
}

/// Names the set in its ports, so they translate to it.
pub fn pset_enable<P: Platform>(pset: &mut ProcessorSet<P>) {
    pset.lock.lock();
    if pset.active != 0 {
        let pset_addr = ptr::from_mut(pset).addr();
        // SAFETY: the set lock is held, so the two port fields are the ports
        // `pset_init()` allocated and nothing is deallocating them.
        unsafe {
            P::kobject_set(pset.pset_self, pset_addr, IKOT_PSET);
            P::kobject_set(pset.pset_name_self, pset_addr, IKOT_PSET_NAME);
        }
        pset.ref_lock.lock();
        pset.ref_count = pset.ref_count.wrapping_add(2);
        pset.ref_lock.unlock();
    }
    pset.lock.unlock();
}

/// Clears the set from its ports, so they translate to nothing.
pub(crate) fn pset_disable<P: Platform>(pset: &mut ProcessorSet<P>) {
    // SAFETY: the caller holds the set lock and a reference, as the C
    // required, so the two port fields are live.
    unsafe {
        P::kobject_set(pset.pset_self, IKO_NULL, IKOT_NONE);
        P::kobject_set(pset.pset_name_self, IKO_NULL, IKOT_NONE);
    }
    pset.ref_count = pset.ref_count.wrapping_sub(2);
}

/// Destroys the set's ports.
pub(crate) fn pset_terminate<P: Platform>(pset: &mut ProcessorSet<P>) {
    // SAFETY: the set is dead, so nothing else may use the two ports, which
    // are live special-space ports.
    unsafe {
        ipc_port::dealloc_special::<P>(IpcPort::from_raw(pset.pset_self));
        ipc_port::dealloc_special::<P>(IpcPort::from_raw(pset.pset_name_self));
    }
}

/// The processor that `port`, a processor port, names, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub unsafe fn port_to_processor<P: Platform>(
    port: *mut c_void,
) -> *mut Processor<P> {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let processor = if port.is_active() && port.kotype() == IKOT_PROCESSOR
        {
            port.kobject().cast::<Processor<P>>()
        } else {
            ptr::null_mut()
        };
        port.unlock();
        processor
    }
}

/// The processor that `port`, a processor or processor-name port, names, or
/// null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub unsafe fn port_to_processor_name<P: Platform>(
    port: *mut c_void,
) -> *mut Processor<P> {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let processor = if port.is_active()
            && (port.kotype() == IKOT_PROCESSOR
                || port.kotype() == IKOT_PROCESSOR_NAME)
        {
            port.kobject().cast::<Processor<P>>()
        } else {
            ptr::null_mut()
        };
        port.unlock();
        processor
    }
}

/// The set that `port`, a set port, names, with one more reference, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub unsafe fn port_to_pset<P: Platform>(
    port: *mut c_void,
) -> *mut ProcessorSet<P> {
    unsafe { port_to_pset_kind(port, IKOT_PSET) }
}

/// The set that `port`, a set or set-name port, names, with one more
/// reference, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub unsafe fn port_to_pset_name<P: Platform>(
    port: *mut c_void,
) -> *mut ProcessorSet<P> {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let pset = if port.is_active()
            && (port.kotype() == IKOT_PSET || port.kotype() == IKOT_PSET_NAME)
        {
            let pset = port.kobject().cast::<ProcessorSet<P>>();
            (*pset).reference();
            pset
        } else {
            ptr::null_mut()
        };
        port.unlock();
        pset
    }
}

/// The shared body of `convert_port_to_pset()`: check the set's object type
/// and take a reference.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
unsafe fn port_to_pset_kind<P: Platform>(
    port: *mut c_void,
    kotype: c_uint,
) -> *mut ProcessorSet<P> {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let pset = if port.is_active() && port.kotype() == kotype {
            let pset = port.kobject().cast::<ProcessorSet<P>>();
            (*pset).reference();
            pset
        } else {
            ptr::null_mut()
        };
        port.unlock();
        pset
    }
}

/// A naked send right for the processor's control port.
///
/// # Safety
///
/// `processor` must be non-null and point at a live [`Processor`].
pub unsafe fn processor_to_port<P: Platform>(
    processor: *mut Processor<P>,
) -> *mut c_void {
    let port = unsafe { (*processor).processor_self };
    IpcPort::valid(port).map_or(port, |port| {
        // SAFETY: the port is live and active from `processor_init` on.
        unsafe { ipc_port::make_send(port) }.as_ptr()
    })
}

/// A naked send right for the processor's name port.
///
/// # Safety
///
/// `processor` must be non-null and point at a live [`Processor`].
pub unsafe fn processor_name_to_port<P: Platform>(
    processor: *mut Processor<P>,
) -> *mut c_void {
    let port = unsafe { (*processor).processor_name_self };
    IpcPort::valid(port)
        .map_or(port, |port| unsafe { ipc_port::make_send(port) }.as_ptr())
}

/// Consumes the caller's set reference and returns a naked send right, or null
/// when the set is dead.
///
/// # Safety
///
/// `pset` must be non-null and point at a live, referenced
/// [`ProcessorSet`]; the call consumes that one reference.
pub unsafe fn pset_to_port<P: Platform>(
    pset: *mut ProcessorSet<P>,
) -> *mut c_void {
    let pset = unsafe { &mut *pset };
    pset.lock.lock();
    let port = if pset.active != 0 {
        IpcPort::valid(pset.pset_self).map_or(ptr::null_mut(), |port| {
            // SAFETY: an active set's port is live from `pset_init()` on.
            unsafe { ipc_port::make_send(port) }.as_ptr()
        })
    } else {
        ptr::null_mut()
    };
    pset.lock.unlock();

    pset.deallocate();
    port
}

/// Consumes the caller's set reference and returns its name port as a naked
/// send right, or null when the set is dead.
///
/// # Safety
///
/// `pset` must be non-null and point at a live, referenced
/// [`ProcessorSet`]; the call consumes that one reference.
pub unsafe fn pset_name_to_port<P: Platform>(
    pset: *mut ProcessorSet<P>,
) -> *mut c_void {
    let pset = unsafe { &mut *pset };
    pset.lock.lock();
    let port = if pset.active != 0 {
        IpcPort::valid(pset.pset_name_self).map_or(ptr::null_mut(), |port| {
            // SAFETY: an active set's name port is live from `pset_init()`
            // on.
            unsafe { ipc_port::make_send(port) }.as_ptr()
        })
    } else {
        ptr::null_mut()
    };
    pset.lock.unlock();

    pset.deallocate();
    port
}

/// The default set with one more reference.
///
/// # Safety
///
/// Must be called only after the processor bootstrap has built the default
/// processor set, that is once IPC is up; `host` is only null-checked, never
/// dereferenced.
pub unsafe fn set_default<P: Platform>(
    host: *mut c_void,
) -> Result<*mut ProcessorSet<P>, Error> {
    if host.is_null() {
        return Err(Error::InvalidArgument);
    }

    let pset = processor::default_pset();
    // SAFETY: the global is live from boot, and the entry is reached only once
    // IPC is up.
    unsafe { (*pset).reference() };
    Ok(pset)
}
