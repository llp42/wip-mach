// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from vm/memory_object_proxy.c and vm/memory_object_proxy.h:
//   Copyright (C) 2005, 2011 Free Software Foundation, Inc.
//   Written by Marcus Brinkmann.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Proxy memory objects, which `vm/memory_object_proxy.c` used to define and
//! `vm/memory_object_proxy.h` declares.
//!
//! A proxy is a kernel port that holds one reference to a real memory object
//! and restricts what a mapping made through it may access: the mapping takes
//! the intersection of the requested protections and the proxy's maximum, and
//! its range must fit inside the proxy's `[start, start + len)`.  The proxy
//! itself is never reference-counted; the caller holds the reference to the
//! port while it looks the proxy up.

use crate::arch::types::{VmOffset, VmSize};
use crate::ipc::{IpcPort, IpcSpace, MachMsgHeader, ipc_port, ipc_space};
use crate::kern::console::kprint;
use crate::kern::ipc_kobject::set;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::vm::error::Error;
use crate::vm::types::VmProt;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull, addr_of_mut, with_exposed_provenance_mut};

/// `MACH_NOTIFY_NO_SENDERS` of <mach/notify.h>.
const MACH_NOTIFY_NO_SENDERS: c_int = 0o106;
/// `IKOT_PAGER_PROXY` of <`kern/ipc_kobject.h`>.
const IKOT_PAGER_PROXY: c_uint = 27;

/// `struct memory_object_proxy`: one proxy's state, reached only through the
/// two kernel ports that name it.
struct MemoryObjectProxy {
    /// The port handed to users, whose kobject is this record.
    port: IpcPort,
    /// The real memory object the proxy holds a reference to.
    object: *mut c_void,
    /// The port the no-senders request is registered on.
    notify: IpcPort,
    /// The most a mapping through this proxy may request.
    max_protection: VmProt,
    /// The offset of the proxy's window in the real object.
    start: VmOffset,
    /// The size of the proxy's window.
    len: VmSize,
}

/// `memory_object_proxy_cache` of `memory_object_proxy.c`: the proxy record's
/// slab cache.
static mut MEMORY_OBJECT_PROXY_CACHE: KmemCache = KmemCache::zeroed();

/// `kmem_cache_alloc(&memory_object_proxy_cache, 0)` of the C.
fn cache_alloc() -> Option<NonNull<MemoryObjectProxy>> {
    // SAFETY: the caller runs after `memory_object_proxy_init()`, so the cache
    // is live, and the cache's lock serializes the call.
    let buf = unsafe { (*addr_of_mut!(MEMORY_OBJECT_PROXY_CACHE)).alloc() }?;
    Some(buf.cast::<MemoryObjectProxy>())
}

/// `kmem_cache_free(&memory_object_proxy_cache, proxy)` of the C.
///
/// # Safety
///
/// `proxy` must be a dead record that came from [`cache_alloc()`] and has no
/// other holder.
unsafe fn cache_free(proxy: NonNull<MemoryObjectProxy>) {
    unsafe {
        (*addr_of_mut!(MEMORY_OBJECT_PROXY_CACHE))
            .free(NonNull::new_unchecked(proxy.as_ptr().cast::<u8>()));
    };
}

/// `memory_object_proxy_init()` in C.
pub(crate) fn init() {
    // SAFETY: the call runs once in the bootstrap sequence, after the slab
    // package is up and before any proxy is allocated.
    unsafe {
        (*addr_of_mut!(MEMORY_OBJECT_PROXY_CACHE)).init(
            b"memory_object_proxy",
            size_of::<MemoryObjectProxy>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}

/// `memory_object_proxy_port_lookup()` in C: the proxy a live port of type
/// `IKOT_PAGER_PROXY` names.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port.
unsafe fn port_lookup(
    port: *mut c_void,
) -> Option<NonNull<MemoryObjectProxy>> {
    let port = IpcPort::valid(port)?;

    // SAFETY: `valid()` established the live port, and this call does not
    // already hold its lock.
    unsafe { port.lock() };
    let proxy = if
    // SAFETY: the port is live and locked above.
    unsafe { port.is_active() }
        // SAFETY: the port is live and locked above.
        && unsafe { port.kotype() } == IKOT_PAGER_PROXY
    {
        // SAFETY: a live proxy port's kobject is the live record.
        NonNull::new(unsafe { port.kobject() }.cast::<MemoryObjectProxy>())
    } else {
        None
    };
    // SAFETY: the port is live and was locked above.
    unsafe { port.unlock() };

    proxy
}

/// `memory_object_proxy_notify()` in C: process a no-senders notification for
/// a proxy port.
///
/// # Safety
///
/// `msg` must point at a readable `mach_msg_header_t`.
pub(crate) unsafe fn notify(msg: *mut MachMsgHeader) -> bool {
    let header = unsafe { &*msg };

    if header.id() != MACH_NOTIFY_NO_SENDERS {
        kprint!(
            "memory_object_proxy_notify: strange notification {}\n",
            header.id(),
        );
        return false;
    }

    // SAFETY: the no-senders notification names a live remote port.
    let remote = with_exposed_provenance_mut::<c_void>(header.remote());
    let Some(port) = IpcPort::valid(remote) else {
        return false;
    };
    // SAFETY: `valid()` established the live port.
    let Some(proxy) =
        (unsafe { NonNull::new(port.kobject().cast::<MemoryObjectProxy>()) })
    else {
        return false;
    };
    // SAFETY: the record is the kobject of a live proxy port.
    let proxy_record = unsafe { proxy.as_ref() };

    if port.as_ptr() != proxy_record.notify.as_ptr() {
        return false;
    }

    // SAFETY: the record holds one send right to the object; the notification
    // is its last user.
    unsafe { ipc_port::release_send(IpcPort::from_raw(proxy_record.object)) };
    // SAFETY: both ports are live, and the record is dead once the two
    // deallocations complete.
    unsafe {
        set(proxy_record.port.as_ptr(), 0, 0);
        ipc_port::dealloc_special(proxy_record.port);
        set(proxy_record.notify.as_ptr(), 0, 0);
        ipc_port::dealloc_special(proxy_record.notify);
    }
    // SAFETY: the record is dead and owned by this call.
    unsafe { cache_free(proxy) };

    true
}

/// The real target a proxy chain names, as
/// `memory_object_proxy_lookup()` reports it.
pub(crate) struct ProxyTarget {
    /// The real memory object, or an invalid port.
    pub(crate) object: *mut c_void,
    /// The first proxy's maximum protection.
    pub(crate) max_protection: VmProt,
    /// The accumulated offset into the real object.
    pub(crate) start: VmOffset,
    /// The accumulated window size.
    pub(crate) len: VmSize,
}

/// `memory_object_proxy_lookup()` in C: follow the chain of proxies to the
/// real memory object and its protection window.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port, and the caller must
/// hold the reference the C required for the duration of the call.
pub(crate) unsafe fn lookup(port: *mut c_void) -> Result<ProxyTarget, Error> {
    let Some(mut proxy) = (unsafe { port_lookup(port) }) else {
        return Err(Error::InvalidArgument);
    };
    // SAFETY: `port_lookup` returned a live record.
    let max_protection = unsafe { proxy.as_ref() }.max_protection;

    let mut start: VmOffset = 0;
    let mut len: VmSize = VmSize::MAX;
    let object = loop {
        // SAFETY: the record is live; the caller's port reference keeps it
        // from being freed.
        let record = unsafe { proxy.as_ref() };
        let object = record.object;

        if record.len <= start {
            len = 0;
        } else {
            len = len.min(record.len - start);
        }
        start = start.wrapping_add(record.start);

        // SAFETY: the real object may be any port value, and `port_lookup`
        // rejects an invalid one.
        match unsafe { port_lookup(record.object) } {
            Some(next) => proxy = next,
            None => break object,
        }
    };

    Ok(ProxyTarget {
        object,
        max_protection,
        start,
        len,
    })
}

/// `memory_object_create_proxy()` in C: create a proxy for
/// `[start, start + len)` of `objects[0]`.
///
/// # Safety
///
/// `objects`, `offsets`, `starts` and `lens` must each be readable for their
/// own length, and the caller must hold no lock.
pub(crate) unsafe fn create_proxy(
    space: Option<IpcSpace>,
    max_protection: VmProt,
    objects: &[*mut c_void],
    offsets: &[VmOffset],
    starts: &[VmOffset],
    lens: &[VmSize],
) -> Result<IpcPort, Error> {
    if space.is_none() {
        return Err(Error::InvalidTask);
    }

    if offsets.len() != objects.len()
        || starts.len() != objects.len()
        || lens.len() != objects.len()
    {
        return Err(Error::InvalidArgument);
    }

    if objects.len() != 1 {
        return Err(Error::InvalidArgument);
    }

    if IpcPort::valid(objects[0]).is_none() {
        return Err(Error::InvalidName);
    }

    if offsets[0] != 0 {
        return Err(Error::InvalidArgument);
    }

    if starts[0].wrapping_add(lens[0]) < starts[0] {
        return Err(Error::InvalidArgument);
    }

    let Some(proxy) = cache_alloc() else {
        return Err(Error::ResourceShortage);
    };

    // SAFETY: `ipc_port_alloc_kernel` is the special-space allocator, and the
    // port cache is up once proxies are created.
    let Some(port) = (unsafe { ipc_port::alloc_special(ipc_space::kernel()) })
    else {
        // SAFETY: the record came from the cache and was never published.
        unsafe { cache_free(proxy) };
        return Err(Error::ResourceShortage);
    };
    // SAFETY: the port is fresh and unpublished.
    unsafe {
        set(
            port.as_ptr(),
            proxy.as_ptr().expose_provenance(),
            IKOT_PAGER_PROXY,
        );
    };

    // SAFETY: `ipc_port_alloc_kernel` is the special-space allocator, and
    // the port cache is up once proxies are created.
    let Some(notify) =
        (unsafe { ipc_port::alloc_special(ipc_space::kernel()) })
    else {
        // SAFETY: the port is live and publishes the record; the record is
        // not yet reachable through any user right.
        unsafe {
            set(port.as_ptr(), 0, 0);
            ipc_port::dealloc_special(port);
            cache_free(proxy);
        }
        return Err(Error::ResourceShortage);
    };
    // SAFETY: the port is fresh and unpublished.
    unsafe {
        set(
            notify.as_ptr(),
            proxy.as_ptr().expose_provenance(),
            IKOT_PAGER_PROXY,
        );
    };

    // SAFETY: `notify` is live and active, and no lock is held.
    let sonce = unsafe { ipc_port::make_sonce(notify) };
    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { port.lock() };
    // SAFETY: the port is live, active and locked; the call consumes the
    // send-once right and the previous request value, which the C dropped.
    let _ = unsafe { ipc_port::nsrequest(port, 1, Some(sonce.as_non_null())) };

    let record = MemoryObjectProxy {
        port,
        object: objects[0],
        notify,
        max_protection,
        start: starts[0],
        len: lens[0],
    };
    // SAFETY: the record is owned by this call and unshared.
    unsafe { ptr::write(proxy.as_ptr(), record) };

    // SAFETY: the port is live and active, and no lock is held.
    Ok(unsafe { ipc_port::make_send(port) })
}
