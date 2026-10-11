// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Proxy memory objects.
//!
//! A proxy is a kernel port that holds one reference to a real memory object
//! and restricts what a mapping made through it may access: the mapping takes
//! the intersection of the requested protections and the proxy's maximum, and
//! its range must fit inside the proxy's `[start, start + len)`.  The proxy
//! itself is never reference-counted; the caller holds the reference to the
//! port while it looks the proxy up.

use crate::error::Error;
use crate::param::{VmOffset, VmSize};
use crate::platform::{CacheFlags, Platform, Port, VmCache};
use crate::types::VmProt;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// The message id of a no-senders notification.
const MACH_NOTIFY_NO_SENDERS: c_int = 0o106;
/// The kernel-object type of a proxy port.
const IKOT_PAGER_PROXY: c_uint = 27;

/// One proxy's state, reached only through the two kernel ports that name it.
struct MemoryObjectProxy {
    /// The port handed to users, whose kobject is this record.
    port: Port,
    /// The real memory object the proxy holds a reference to.
    object: *mut c_void,
    /// The port the no-senders request is registered on.
    notify: Port,
    /// The most a mapping through this proxy may request.
    max_protection: VmProt,
    /// The offset of the proxy's window in the real object.
    start: VmOffset,
    /// The size of the proxy's window.
    len: VmSize,
}

/// Allocates a proxy record, or `None` when the cache is out of memory.
fn cache_alloc<P: Platform>() -> Option<NonNull<MemoryObjectProxy>> {
    // SAFETY: the caller runs after `init()`, so the cache is live, and the
    // cache's lock serializes the call.
    let buf = unsafe { P::cache_alloc(VmCache::Proxy) }?;
    Some(buf.cast::<MemoryObjectProxy>())
}

/// Returns `proxy` to the cache.
///
/// # Safety
///
/// `proxy` must be a dead record that came from [`cache_alloc()`] and has no
/// other holder.
unsafe fn cache_free<P: Platform>(proxy: NonNull<MemoryObjectProxy>) {
    unsafe {
        P::cache_free(
            VmCache::Proxy,
            NonNull::new_unchecked(proxy.as_ptr().cast::<u8>()),
        );
    };
}

/// Sets up the cache of proxy records.
pub(crate) fn init<P: Platform>() {
    // SAFETY: the call runs once in the bootstrap sequence, after the slab
    // package is up and before any proxy is allocated.
    unsafe {
        P::cache_init(
            VmCache::Proxy,
            b"memory_object_proxy",
            size_of::<MemoryObjectProxy>(),
            CacheFlags::empty(),
        );
    }
}

/// The proxy a live port of type `IKOT_PAGER_PROXY` names.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port.
unsafe fn port_lookup<P: Platform>(
    port: *mut c_void,
) -> Option<NonNull<MemoryObjectProxy>> {
    let port = Port::valid(port)?;

    // SAFETY: `valid()` established the live port, and this call does not
    // already hold its lock.
    unsafe { P::port_lock(port) };
    let proxy = if
    // SAFETY: the port is live and locked above.
    unsafe { P::port_is_active(port) }
        // SAFETY: the port is live and locked above.
        && unsafe { P::port_kotype(port) } == IKOT_PAGER_PROXY
    {
        // SAFETY: a live proxy port's kobject is the live record.
        NonNull::new(
            unsafe { P::port_kobject(port) }.cast::<MemoryObjectProxy>(),
        )
    } else {
        None
    };
    // SAFETY: the port is live and was locked above.
    unsafe { P::port_unlock(port) };

    proxy
}

/// Processes notification `id` sent to the proxy port `remote`.
///
/// # Safety
///
/// `remote` must be the port the notification names, live or invalid.
pub unsafe fn notify<P: Platform>(id: c_int, remote: *mut c_void) -> bool {
    if id != MACH_NOTIFY_NO_SENDERS {
        P::print(format_args!(
            "memory_object_proxy_notify: strange notification {id}\n"
        ));
        return false;
    }

    let Some(port) = Port::valid(remote) else {
        return false;
    };
    // SAFETY: `valid()` established the live port.
    let Some(proxy) = (unsafe {
        NonNull::new(P::port_kobject(port).cast::<MemoryObjectProxy>())
    }) else {
        return false;
    };
    // SAFETY: the record is the kobject of a live proxy port.
    let proxy_record = unsafe { proxy.as_ref() };

    if port.as_ptr() != proxy_record.notify.as_ptr() {
        return false;
    }

    // SAFETY: the record holds one send right to the object; the notification
    // is its last user.
    unsafe { P::port_release_send(Port::from_raw(proxy_record.object)) };
    // SAFETY: both ports are live, and the record is dead once the two
    // deallocations complete.
    unsafe {
        P::kobject_set(proxy_record.port.as_ptr(), 0, 0);
        P::port_dealloc(proxy_record.port);
        P::kobject_set(proxy_record.notify.as_ptr(), 0, 0);
        P::port_dealloc(proxy_record.notify);
    }
    // SAFETY: the record is dead and owned by this call.
    unsafe { cache_free::<P>(proxy) };

    true
}

/// The real target a proxy chain names, as [`lookup()`] reports it.
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

/// Follows the chain of proxies to the real memory object and its protection
/// window.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port, and the caller must
/// hold the reference the C required for the duration of the call.
pub(crate) unsafe fn lookup<P: Platform>(
    port: *mut c_void,
) -> Result<ProxyTarget, Error> {
    let Some(mut proxy) = (unsafe { port_lookup::<P>(port) }) else {
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
        match unsafe { port_lookup::<P>(record.object) } {
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

/// Creates a proxy for `[start, start + len)` of `objects[0]`.
///
/// # Safety
///
/// `objects`, `offsets`, `starts` and `lens` must each be readable for their
/// own length, and the caller must hold no lock.  `space` is the caller's
/// IPC space, `None` for a task without one.
pub unsafe fn create_proxy<P: Platform>(
    space: Option<NonNull<c_void>>,
    max_protection: VmProt,
    objects: &[*mut c_void],
    offsets: &[VmOffset],
    starts: &[VmOffset],
    lens: &[VmSize],
) -> Result<Port, Error> {
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

    if Port::valid(objects[0]).is_none() {
        return Err(Error::InvalidName);
    }

    if offsets[0] != 0 {
        return Err(Error::InvalidArgument);
    }

    if starts[0].wrapping_add(lens[0]) < starts[0] {
        return Err(Error::InvalidArgument);
    }

    let Some(proxy) = cache_alloc::<P>() else {
        return Err(Error::ResourceShortage);
    };

    // SAFETY: `alloc_special` in the kernel space is the kernel-port
    // allocator, and the port cache is up once proxies are created.
    let Some(port) = (unsafe { P::port_alloc() }) else {
        // SAFETY: the record came from the cache and was never published.
        unsafe { cache_free::<P>(proxy) };
        return Err(Error::ResourceShortage);
    };
    // SAFETY: the port is fresh and unpublished.
    unsafe {
        P::kobject_set(
            port.as_ptr(),
            proxy.as_ptr().expose_provenance(),
            IKOT_PAGER_PROXY,
        );
    };

    // SAFETY: `alloc_special` in the kernel space is the kernel-port
    // allocator, and the port cache is up once proxies are created.
    let Some(notify) = (unsafe { P::port_alloc() }) else {
        // SAFETY: the port is live and publishes the record; the record is
        // not yet reachable through any user right.
        unsafe {
            P::kobject_set(port.as_ptr(), 0, 0);
            P::port_dealloc(port);
            cache_free::<P>(proxy);
        }
        return Err(Error::ResourceShortage);
    };
    // SAFETY: the port is fresh and unpublished.
    unsafe {
        P::kobject_set(
            notify.as_ptr(),
            proxy.as_ptr().expose_provenance(),
            IKOT_PAGER_PROXY,
        );
    };

    // SAFETY: `notify` is live and active, and no lock is held.
    let sonce = unsafe { P::port_make_sonce(notify) };
    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { P::port_lock(port) };
    // SAFETY: the port is live, active and locked; the call consumes the
    // send-once right and the previous request value, which the C dropped.
    let _ = unsafe { P::port_nsrequest(port, 1, Some(sonce.as_non_null())) };

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
    Ok(unsafe { P::port_make_send(port) })
}
