// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_host.c:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The host, processor and processor-set ports.

use crate::arch::types::VmOffset;
use crate::ipc::{IpcPort, IpcSpace, ipc_port, ipc_space};
use crate::kern::debug::kpanic;
use crate::kern::error::Error;
use crate::kern::host::{self, Host};
use crate::kern::ipc_kobject::set;
use crate::kern::processor::{self, Processor, ProcessorSet};
use crate::kern::task::current_task;
use core::ffi::{c_uint, c_void};
use core::ptr;
use core::ptr::NonNull;

/// The object type of the host port.
const IKOT_HOST: c_uint = 3;
/// `IKOT_HOST_PRIV`: the object type of the host privilege port.
const IKOT_HOST_PRIV: c_uint = 4;
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
/// The null port name.
const MACH_PORT_NULL: c_uint = 0;

/// Allocate a special port in the kernel's IPC space, halting when the
/// allocator fails as the C callers did.
fn alloc_kernel_port(function: &'static str) -> NonNull<c_void> {
    // SAFETY: the kernel's space is live from `ipc_init()` on, and the
    // allocator takes its own locks.
    let port = unsafe { ipc_port::alloc_special(ipc_space::kernel()) };
    let Some(port) = port else {
        kpanic!(function, "{}", function)
    };
    // SAFETY: `IpcPort` always holds a non-null pointer.
    unsafe { NonNull::new_unchecked(port.as_ptr()) }
}

/// Makes the two host ports, the default set's two ports, and the boot
/// processor's two ports.
///
/// # Safety
///
/// Must run once during boot, after the processor bootstrap has built the
/// default set and the boot processor, and before anything else can reach the
/// host, set, or processor ports.
pub(crate) unsafe fn init() {
    let port = alloc_kernel_port("ipc_host_init");
    // SAFETY: `realhost` is the one host object, and the freshly allocated
    // port can be bound to it before anything else can reach it.
    unsafe {
        set(port.as_ptr(), host::realhost().addr(), IKOT_HOST);
        (*host::realhost()).host_self = port.as_ptr();
    }

    let port = alloc_kernel_port("ipc_host_init");
    unsafe {
        set(port.as_ptr(), host::realhost().addr(), IKOT_HOST_PRIV);
        (*host::realhost()).host_priv_self = port.as_ptr();
    }

    let pset = processor::default_pset();
    // SAFETY: the default set is the global the processor bootstrap
    // initialized during the boot, the boot processor its record, and their
    // port fields are still null, so no other thread can be looking at them.
    unsafe {
        pset_init(&mut *pset);
        pset_enable(&mut *pset);
        processor_init(&mut *processor::boot_processor());
    }
}

/// A send right for the caller's own host port.
///
/// # Safety
///
/// Must run on the current thread's own context after `init()` has built
/// the host port: `current_task()` requires a live current thread, and that
/// task's IPC space must already be set.
pub(crate) unsafe fn mach_host_self() -> c_uint {
    // SAFETY: `realhost` is the live host object.
    let host_self = unsafe { (*host::realhost()).host_self };
    let Some(port) = IpcPort::valid(host_self) else {
        return MACH_PORT_NULL;
    };

    // SAFETY: the host port is live and active from `init` on.
    let sright = unsafe { ipc_port::make_send(port) };
    // SAFETY: the running task is live, and its space is set before any IPC
    // call the task can make; the `current_space()` macro.
    let space = unsafe { IpcSpace::from_raw((*current_task()).itk_space) };
    // SAFETY: the right is live and belongs to this task's space; the
    // successful copyout consumes it.
    unsafe { ipc_port::copyout_send(sright.as_ptr(), space) }
}

/// The `mach_host_self` trap entry.
///
/// # Safety
///
/// Runs on the caller's own thread once [`init`] has built the host port.
pub(crate) unsafe extern "C" fn mach_host_self_entry() -> c_uint {
    unsafe { mach_host_self() }
}

/// Makes the processor's control and name ports.
pub(crate) fn processor_init(processor: &mut Processor) {
    let port = alloc_kernel_port("ipc_processor_init");
    processor.processor_self = port.as_ptr();
    // SAFETY: `port` is the special port just allocated and nothing else can
    // reach it yet; `processor` is the live object the C bound.
    unsafe {
        set(
            port.as_ptr(),
            ptr::from_mut(processor).addr(),
            IKOT_PROCESSOR,
        );
    }

    let port = alloc_kernel_port("ipc_processor_init");
    processor.processor_name_self = port.as_ptr();
    // SAFETY: `port` is the special port just allocated and nothing else can
    // reach it yet; `processor` is the live object the C bound; for
    // the second, name port.
    unsafe {
        set(
            port.as_ptr(),
            ptr::from_mut(processor).addr(),
            IKOT_PROCESSOR_NAME,
        );
    }
}

/// Makes the set's control and name ports.
pub(crate) fn pset_init(pset: &mut ProcessorSet) {
    let port = alloc_kernel_port("ipc_pset_init");
    pset.pset_self = port.as_ptr();

    let port = alloc_kernel_port("ipc_pset_init");
    pset.pset_name_self = port.as_ptr();
}

/// Names the set in its ports, so they translate to it.
pub(crate) fn pset_enable(pset: &mut ProcessorSet) {
    pset.lock.lock();
    if pset.active != 0 {
        let pset_addr = ptr::from_mut(pset).addr();
        // SAFETY: the set lock is held, so the two port fields are the ports
        // `pset_init()` allocated and nothing is deallocating them.
        unsafe {
            set(pset.pset_self, pset_addr, IKOT_PSET);
            set(pset.pset_name_self, pset_addr, IKOT_PSET_NAME);
        }
        pset.ref_lock.lock();
        pset.ref_count = pset.ref_count.wrapping_add(2);
        pset.ref_lock.unlock();
    }
    pset.lock.unlock();
}

/// Clears the set from its ports, so they translate to nothing.
pub(crate) fn pset_disable(pset: &mut ProcessorSet) {
    // SAFETY: the caller holds the set lock and a reference, as the C
    // required, so the two port fields are live.
    unsafe {
        set(pset.pset_self, IKO_NULL, IKOT_NONE);
        set(pset.pset_name_self, IKO_NULL, IKOT_NONE);
    }
    pset.ref_count = pset.ref_count.wrapping_sub(2);
}

/// Destroys the set's ports.
pub(crate) fn pset_terminate(pset: &mut ProcessorSet) {
    // SAFETY: the set is dead, so nothing else may use the two ports, which
    // are live special-space ports.
    unsafe {
        ipc_port::dealloc_special(IpcPort::from_raw(pset.pset_self));
        ipc_port::dealloc_special(IpcPort::from_raw(pset.pset_name_self));
    }
}

/// The host that `port`, a host or privileged host port, names, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub(crate) unsafe fn port_to_host(port: *mut c_void) -> *mut Host {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let host = if port.is_active()
            && (port.kotype() == IKOT_HOST || port.kotype() == IKOT_HOST_PRIV)
        {
            port.kobject().cast::<Host>()
        } else {
            ptr::null_mut()
        };
        port.unlock();
        host
    }
}

/// The host that `port`, a privileged host port, names, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub(crate) unsafe fn port_to_host_priv(port: *mut c_void) -> *mut Host {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let host = if port.is_active() && port.kotype() == IKOT_HOST_PRIV {
            port.kobject().cast::<Host>()
        } else {
            ptr::null_mut()
        };
        port.unlock();
        host
    }
}

/// The processor that `port`, a processor port, names, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub(crate) unsafe fn port_to_processor(port: *mut c_void) -> *mut Processor {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let processor = if port.is_active() && port.kotype() == IKOT_PROCESSOR
        {
            port.kobject().cast::<Processor>()
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
pub(crate) unsafe fn port_to_processor_name(
    port: *mut c_void,
) -> *mut Processor {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let processor = if port.is_active()
            && (port.kotype() == IKOT_PROCESSOR
                || port.kotype() == IKOT_PROCESSOR_NAME)
        {
            port.kobject().cast::<Processor>()
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
pub(crate) unsafe fn port_to_pset(port: *mut c_void) -> *mut ProcessorSet {
    unsafe { port_to_pset_kind(port, IKOT_PSET) }
}

/// The set that `port`, a set or set-name port, names, with one more
/// reference, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub(crate) unsafe fn port_to_pset_name(
    port: *mut c_void,
) -> *mut ProcessorSet {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let pset = if port.is_active()
            && (port.kotype() == IKOT_PSET || port.kotype() == IKOT_PSET_NAME)
        {
            let pset = port.kobject().cast::<ProcessorSet>();
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
unsafe fn port_to_pset_kind(
    port: *mut c_void,
    kotype: c_uint,
) -> *mut ProcessorSet {
    let Some(port) = IpcPort::valid(port) else {
        return ptr::null_mut();
    };

    unsafe {
        port.lock();
        let pset = if port.is_active() && port.kotype() == kotype {
            let pset = port.kobject().cast::<ProcessorSet>();
            (*pset).reference();
            pset
        } else {
            ptr::null_mut()
        };
        port.unlock();
        pset
    }
}

/// A naked send right, or the invalid pointer unchanged.
///
/// # Safety
///
/// `host` must be non-null and point at a live [`Host`].
pub(crate) unsafe fn host_to_port(host: *mut Host) -> *mut c_void {
    let port = unsafe { (*host).host_self };
    IpcPort::valid(port).map_or(port, |port| {
        // SAFETY: the host port is live and active from `init` on.
        unsafe { ipc_port::make_send(port) }.as_ptr()
    })
}

/// A naked send right for the processor's control port.
///
/// # Safety
///
/// `processor` must be non-null and point at a live [`Processor`].
pub(crate) unsafe fn processor_to_port(
    processor: *mut Processor,
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
pub(crate) unsafe fn processor_name_to_port(
    processor: *mut Processor,
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
pub(crate) unsafe fn pset_to_port(pset: *mut ProcessorSet) -> *mut c_void {
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
pub(crate) unsafe fn pset_name_to_port(
    pset: *mut ProcessorSet,
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
pub(crate) unsafe fn set_default(
    host: *mut c_void,
) -> Result<*mut ProcessorSet, Error> {
    if host.is_null() {
        return Err(Error::InvalidArgument);
    }

    let pset = processor::default_pset();
    // SAFETY: the global is live from boot, and the entry is reached only once
    // IPC is up.
    unsafe { (*pset).reference() };
    Ok(pset)
}
