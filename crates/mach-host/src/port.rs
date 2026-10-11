// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The host ports.

use crate::host::{self, Host};
use crate::platform::Platform;
use core::ffi::{c_uint, c_void};
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use mach_ipc::{IpcPort, IpcSpace, ipc_port, ipc_space};
use mach_thread::ipc_processor::{processor_init, pset_enable, pset_init};
use mach_thread::processor::{self};
use mach_thread::task::current_task;

/// The object type of the host port.
const IKOT_HOST: c_uint = 3;
/// `IKOT_HOST_PRIV`: the object type of the host privilege port.
const IKOT_HOST_PRIV: c_uint = 4;
/// The null port name.
const MACH_PORT_NULL: c_uint = 0;

/// Allocate a special port in the kernel's IPC space, halting when the
/// allocator fails as the C callers did.
fn alloc_kernel_port<P: Platform>(function: &'static str) -> NonNull<c_void> {
    // SAFETY: the kernel's space is live from `ipc_init()` on, and the
    // allocator takes its own locks.
    let port = unsafe { ipc_port::alloc_special::<P>(ipc_space::kernel()) };
    let Some(port) = port else {
        panic!("{}", function)
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
pub unsafe fn init<P: Platform>() {
    let port = alloc_kernel_port::<P>("ipc_host_init");
    // SAFETY: `realhost` is the one host object, and the freshly allocated
    // port can be bound to it before anything else can reach it.
    unsafe {
        P::kobject_set(
            port.as_ptr(),
            host::realhost().expose_provenance(),
            IKOT_HOST,
        );
        (*host::realhost())
            .host_self
            .store(port.as_ptr(), Ordering::Release);
    }

    let port = alloc_kernel_port::<P>("ipc_host_init");
    unsafe {
        P::kobject_set(
            port.as_ptr(),
            host::realhost().expose_provenance(),
            IKOT_HOST_PRIV,
        );
        (*host::realhost())
            .host_priv_self
            .store(port.as_ptr(), Ordering::Release);
    }

    let pset = processor::default_pset::<P>();
    // SAFETY: the default set is the global the processor bootstrap
    // initialized during the boot, the boot processor its record, and their
    // port fields are still null, so no other thread can be looking at them.
    unsafe {
        pset_init(&mut *pset);
        pset_enable(&mut *pset);
        processor_init(&mut *processor::boot_processor::<P>());
    }
}

/// A send right for the caller's own host port.
///
/// # Safety
///
/// Must run after `init()` has built the host port.
pub(crate) unsafe fn mach_host_self<P: Platform>() -> c_uint {
    let host_self = host::host_self();
    let Some(port) = IpcPort::valid(host_self) else {
        return MACH_PORT_NULL;
    };

    // SAFETY: the host port is live and active from `init` on.
    let sright = unsafe { ipc_port::make_send(port) };
    // SAFETY: the running thread's task is live. Task creation sets its
    // `itk_space` to a fresh, non-null space before the task has a thread,
    // and nothing writes the field again.
    let space = unsafe {
        IpcSpace::from_raw((*current_task::<P>().as_ptr()).itk_space)
    };
    // SAFETY: the right is live and belongs to this task's space; the
    // successful copyout consumes it.
    unsafe { ipc_port::copyout_send::<P>(sright.as_ptr(), space) }
}

/// The `mach_host_self` trap entry.
///
/// # Safety
///
/// Runs once [`init`] has built the host port.
#[must_use]
pub unsafe extern "C" fn mach_host_self_entry<P: Platform>() -> c_uint {
    unsafe { mach_host_self::<P>() }
}

/// The host that `port`, a host or privileged host port, names, or null.
///
/// # Safety
///
/// `port` must be null or a live port pointer that [`IpcPort::valid()`]
/// accepts.
pub unsafe fn port_to_host(port: *mut c_void) -> *mut Host {
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
pub unsafe fn port_to_host_priv(port: *mut c_void) -> *mut Host {
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

/// A naked send right, or the invalid pointer unchanged.
///
/// # Safety
///
/// `host` must be non-null and point at a live [`Host`].
pub unsafe fn host_to_port(host: *mut Host) -> *mut c_void {
    let port = unsafe { (*host).host_self.load(Ordering::Acquire) };
    IpcPort::valid(port).map_or(port, |port| {
        // SAFETY: the host port is live and active from `init` on.
        unsafe { ipc_port::make_send(port) }.as_ptr()
    })
}
