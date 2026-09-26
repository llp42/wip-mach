// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_port.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The port manipulation routines, which `ipc/ipc_port.c` used to define and
//! `ipc/ipc_port.h` declares.

use crate::ipc::ipc_kmsg::{self, MsgReturn};
use crate::ipc::ipc_mqueue;
use crate::ipc::ipc_notify;
use crate::ipc::ipc_object;
use crate::ipc::ipc_pset;
use crate::ipc::ipc_table::{self, IPC_PORT_REQUEST_SIZE, IpcTableSize};
use crate::ipc::ipc_target;
use crate::ipc::ipc_thread;
use crate::ipc::{
    IOT_PORT, IpcMqueue, IpcPort, IpcPortRequest, IpcSpace, IpcTarget,
};
use crate::kern::debug::kpanic;
use crate::kern::ipc_sched;
use crate::kern::lock::SimpleLock;
use crate::kern::thread::Thread;
use crate::kern::types::KernError;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicU32, Ordering};

/// `ipc_port_timestamp_lock_data` of `ipc/ipc_port.c`: serializes the counter's
/// read and post-increment.
static TIMESTAMP_LOCK: SimpleLock = SimpleLock::new();

/// `ipc_bootstrap()` writes the initial zero before any other thread can reach
/// it; after that every access is a `Relaxed` read or write under
/// [`TIMESTAMP_LOCK`], whose acquire and release order the counter against
/// other callers.
static TIMESTAMP_DATA: AtomicU32 = AtomicU32::new(0);

/// `ipc_port_multiple_lock_data` of `ipc/ipc_port.c`: the lock that grants the
/// holder the privilege to lock several ports at once.
static MULTIPLE_LOCK: SimpleLock = SimpleLock::new();

/// `IOT_PORT` as the `io_bits` object-type field spells it; it is also the
/// index of the port cache.
const IOT_PORT_TYPE: c_uint = 0;
/// `IO_BITS_ACTIVE` of <`ipc/ipc_object.h`>.
const IO_BITS_ACTIVE: c_uint = 0x8000_0000;
/// `MACH_PORT_TYPE_RECEIVE` of <mach/port.h>: `1 << (right + 16)` for the
/// receive right.
const MACH_PORT_TYPE_RECEIVE: c_uint = 1 << 17;
/// `MACH_PORT_QLIMIT_DEFAULT` of <mach/port.h>.
const MACH_PORT_QLIMIT_DEFAULT: c_uint = 5;
/// `MACH_PORT_NULL` and `MACH_PORT_NULL` of <mach/port.h>.
const MACH_PORT_NULL: c_uint = 0;
/// `MACH_PORT_NAME_DEAD` of <mach/port.h>.
const MACH_PORT_NAME_DEAD: c_uint = c_uint::MAX;
/// `MACH_MSG_TYPE_PORT_SEND` of <mach/message.h>, an alias of
/// `MACH_MSG_TYPE_MOVE_SEND`.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;
/// `MACH_MSG_SUCCESS` of <mach/message.h>.
const MACH_MSG_SUCCESS: c_int = 0;
/// `IKOT_NONE` of <`kern/ipc_kobject.h>`: the type of a port bound to no kernel
/// object.
const IKOT_NONE: c_uint = 0;
/// `IP_DEAD` of <`ipc/ipc_port.h`>, the port image of `IO_DEAD`.
const IP_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// `ipc_port_timestamp()` in C.
pub(crate) fn timestamp() -> c_uint {
    TIMESTAMP_LOCK.lock();

    let timestamp = TIMESTAMP_DATA.load(Ordering::Relaxed);
    TIMESTAMP_DATA.store(timestamp.wrapping_add(1), Ordering::Relaxed);

    TIMESTAMP_LOCK.unlock();

    timestamp
}

/// The `simple_lock_init()` calls `ipc_bootstrap()` makes on this file's
/// statics.
pub(crate) fn init_static_locks() {
    MULTIPLE_LOCK.init();
    TIMESTAMP_LOCK.init();
}

/// `ipc_port_alloc()` in C.
pub(crate) fn alloc(space: IpcSpace) -> Result<(c_uint, IpcPort), KernError> {
    // SAFETY: the caller promises a live space; a successful allocation
    // returns the object locked, which `init` needs and keeps.
    let (name, port) = unsafe {
        ipc_object::alloc(space, IOT_PORT_TYPE, MACH_PORT_TYPE_RECEIVE, 0)
    }?;

    // SAFETY: a successful allocation returned a live object.
    let port = IpcPort(unsafe { NonNull::new_unchecked(port) });

    // SAFETY: the object is live and locked, and `init` initializes its
    // fields in place without unlocking; the caller keeps the unlock.
    unsafe { init(port, space.as_ptr(), name) };

    Ok((name, port))
}

/// `ipc_port_alloc_name()` in C.
pub(crate) fn alloc_name(
    space: IpcSpace,
    name: c_uint,
) -> Result<IpcPort, KernError> {
    // SAFETY: the caller promises a live space; a successful allocation
    // returns the object locked, which `init` needs and keeps.
    let port = unsafe {
        ipc_object::alloc_name(
            space,
            IOT_PORT_TYPE,
            MACH_PORT_TYPE_RECEIVE,
            0,
            name,
        )
    }?;

    // SAFETY: a successful allocation returned a live object.
    let port = IpcPort(unsafe { NonNull::new_unchecked(port) });

    // SAFETY: the object is live and locked, and `init` initializes its
    // fields in place without unlocking; the caller keeps the unlock.
    unsafe { init(port, space.as_ptr(), name) };

    Ok(port)
}

/// `it_dnrequests_alloc()` of <`ipc/ipc_table.h`>.
fn dnrequests_alloc(its: *mut IpcTableSize) -> Option<*mut IpcPortRequest> {
    // SAFETY: the caller promises `its` points at a live size record.  The C
    // widens `its_size` to the `vm_size_t` the multiplication runs in.
    let size = unsafe { (*its).its_size as usize } * IPC_PORT_REQUEST_SIZE;
    // SAFETY: `kalloc_init()` ran before any port exists.
    let table = unsafe { ipc_table::ipc_table_alloc(size) };
    NonNull::new(with_exposed_provenance_mut::<IpcPortRequest>(table))
        .map(NonNull::as_ptr)
}

/// `it_dnrequests_free()` of <`ipc/ipc_table.h`>.
///
/// # Safety
///
/// `its` must be the size record the table was allocated with, and `table`
/// must be that allocation with nothing referencing it.
unsafe fn dnrequests_free(its: *mut IpcTableSize, table: *mut IpcPortRequest) {
    let size = unsafe { (*its).its_size as usize } * IPC_PORT_REQUEST_SIZE;
    unsafe { ipc_table::ipc_table_free(size, table.addr()) };
}

/// `ipc_port_dnrequest()` in C.
///
/// # Safety
///
/// `port` must be live and locked, and `soright` must be `IP_NULL` or a live
/// send-once right the table takes ownership of.
pub(crate) unsafe fn dnrequest(
    port: IpcPort,
    name: c_uint,
    soright: NonNull<c_void>,
) -> Result<c_uint, KernError> {
    let table = unsafe { port.dnrequests() };
    let Some(table) = NonNull::new(table) else {
        return Err(KernError::NoSpace);
    };

    // SAFETY: a non-null dnrequests table is live, and element zero holds its
    // free-list head.
    let index = unsafe { (*table.as_ptr()).next() };
    if index == 0 {
        return Err(KernError::NoSpace);
    }

    // SAFETY: the free list only names free elements of the table, so `index`
    // is live, and the caller holds the port lock that serializes the table.
    unsafe {
        let request = table.as_ptr().add(index as usize);
        (*table.as_ptr()).set_next((*request).next());
        (*request).set_name(name);
        (*request).set_soright(soright.as_ptr());
    }

    Ok(index)
}

/// `ipc_port_dngrow()` in C.
///
/// # Safety
///
/// `port` must be live and locked on entry and unlocked on return, and the
/// caller must hold a reference.
pub(crate) unsafe fn dngrow(port: IpcPort) -> Result<(), KernError> {
    let old = unsafe { port.dnrequests() };
    // SAFETY: `ipc_table_dnrequests` is the table `ipc_table_init()` built,
    // whose last entry is the zero terminator.  `ipr_size + 1` is the next
    // entry when the port already has a table.
    let its = unsafe {
        if old.is_null() {
            ipc_table::IPC_TABLE_DNREQUESTS
        } else {
            (*old).size().add(1)
        }
    };
    let size = unsafe { (*its).its_size };

    unsafe {
        port.increment_references();
        port.unlock();
    }

    if size == 0 {
        // SAFETY: the port is live and unlocked; this consumes the reference
        // taken above.
        unsafe { port.release() };
        return Err(KernError::ResourceShortage);
    }
    let Some(new) = dnrequests_alloc(its) else {
        unsafe { port.release() };
        return Err(KernError::ResourceShortage);
    };

    unsafe {
        port.lock();
        port.decrement_references();
    }

    // SAFETY: the port is live and locked; the fields are the C's.
    let unchanged = unsafe {
        port.is_active()
            && ptr::eq(port.dnrequests(), old)
            && (old.is_null() || (*old).size().add(1) == its)
    };

    if unchanged {
        // SAFETY: the new table is a fresh allocation of `its->its_size`
        // elements; the caller holds the port lock and nobody else can see
        // it.
        unsafe {
            let (osize, mut free) = if old.is_null() {
                (1, 0)
            } else {
                let oits = (*old).size();
                let osize = (*oits).its_size;
                let free = (*old).next();
                ptr::copy_nonoverlapping(
                    old.add(1),
                    new.add(1),
                    osize.wrapping_sub(1) as usize,
                );
                (osize, free)
            };

            let nsize = (*its).its_size;
            for i in osize..nsize {
                let request = new.add(i as usize);
                (*request).set_name(MACH_PORT_NULL);
                (*request).set_next(free);
                free = i;
            }

            (*new).set_next(free);
            (*new).set_size(its);
            port.set_dnrequests(new);
            port.unlock();
        }

        if !old.is_null() {
            // SAFETY: the detached table is no longer reachable.
            unsafe {
                let oits = (*old).size();
                dnrequests_free(oits, old);
            }
        }
    } else {
        // SAFETY: the port is live and locked; the C's check-unlock.
        unsafe { port.check_unlock() };
        // SAFETY: the new table is unused.
        unsafe { dnrequests_free(its, new) };
    }

    Ok(())
}

/// `ipc_port_dncancel()` in C.  Its `name` argument is unused.
///
/// # Safety
///
/// `port` must be live and locked, with a live dnrequests table, and `index`
/// must name a live request in it.
pub(crate) unsafe fn dncancel(port: IpcPort, index: c_uint) -> *mut c_void {
    unsafe {
        let table = port.dnrequests();
        let request = table.add(index as usize);
        let soright = (*request).soright();

        (*request).set_name(MACH_PORT_NULL);
        (*request).set_next((*table).next());
        (*table).set_next(index);

        soright
    }
}

/// `ipc_port_dnrename()` of <`ipc/ipc_port.h>`: rename the dead-name request a
/// table index holds.
///
/// # Safety
///
/// `port` must be live and locked, with a live dnrequests table, and `index`
/// must name a live request in it.
pub(crate) unsafe fn dnrename(port: IpcPort, index: c_uint, name: c_uint) {
    unsafe {
        let table = port.dnrequests();
        let request = table.add(index as usize);
        (*request).set_name(name);
    }
}

/// `ipc_port_pdrequest()` in C: installs `notify`, consuming its reference,
/// and returns the previous request with its own reference.
///
/// # Safety
///
/// `port` must be live, active, and locked; `notify` must be `IP_NULL` or a
/// live send-once right.
pub(crate) unsafe fn pdrequest(
    port: IpcPort,
    notify: Option<NonNull<c_void>>,
) -> Option<NonNull<c_void>> {
    unsafe {
        let previous = port.pdrequest();
        port.set_pdrequest(notify);
        port.unlock();
        previous
    }
}

/// `ipc_port_nsrequest()` in C: installs `notify`, consuming its reference,
/// and returns the previous request with its own reference.
///
/// # Safety
///
/// `port` must be live, active, and locked; `notify` must be `IP_NULL` or a
/// live send-once right.
pub(crate) unsafe fn nsrequest(
    port: IpcPort,
    sync: c_uint,
    notify: Option<NonNull<c_void>>,
) -> Option<NonNull<c_void>> {
    unsafe {
        let previous = port.nsrequest();
        let mscount = port.mscount();

        match notify {
            Some(notify) if port.srights() == 0 && sync <= mscount => {
                port.set_nsrequest(None);
                port.unlock();
                ipc_notify::no_senders(notify, mscount);
            }
            _ => {
                port.set_nsrequest(notify);
                port.unlock();
            }
        }

        previous
    }
}

/// `ipc_port_set_qlimit()` in C.
///
/// # Safety
///
/// `port` must be live, active, and locked.
pub(crate) unsafe fn set_qlimit(port: IpcPort, qlimit: c_uint) {
    let old = unsafe { port.qlimit() };

    if qlimit > old {
        // The C's subtraction is unsigned and `qlimit > old` makes it exact.
        let wakeup = qlimit - old;

        for _ in 0..wakeup {
            // SAFETY: the port is live and locked, so its blocked queue is
            // live and serialized.
            let sender =
                unsafe { ipc_thread::ipc_thread_dequeue(port.blocked()) };
            if sender.is_null() {
                break;
            }

            let sender = sender.cast::<Thread>();
            // SAFETY: the queue holds live threads.
            unsafe {
                (*sender).ith_state = MACH_MSG_SUCCESS;
            }
            // SAFETY: the sender is live and not locked.
            unsafe { ipc_sched::thread_go(sender) };
        }
    }

    unsafe { port.set_qlimit(qlimit) };
}

/// `ipc_port_lock_mqueue()` in C: locks and returns the message queue the
/// port is using, which may be in the port or in its port set.
///
/// # Safety
///
/// `port` must be live, active, and locked.  The port set's lock and message
/// queue locks may be taken.
pub(crate) unsafe fn lock_mqueue(port: IpcPort) -> *mut IpcMqueue {
    let pset = unsafe { port.pset() };
    if !pset.is_null() {
        let target = pset.cast::<IpcTarget>();

        // SAFETY: a non-null `ip_pset` names a live port set.
        unsafe {
            (*target).lock();
            if (*target).is_active() {
                let mqueue = (*target).messages();
                (*mqueue).lock();
                (*target).unlock();
                return mqueue;
            }

            ipc_pset::remove(target, port);
            IpcTarget::check_unlock(target);
        }
    }

    let mqueue = unsafe { port.messages() };
    unsafe { (*mqueue).lock() };
    mqueue
}

/// `ipc_port_set_seqno()` in C.
///
/// # Safety
///
/// `port` must be live, active, and locked; the message queue lock may be
/// taken.
pub(crate) unsafe fn set_seqno(port: IpcPort, seqno: c_uint) {
    let mqueue = unsafe { lock_mqueue(port) };

    // SAFETY: the mqueue belongs to the port and is locked.
    unsafe {
        port.set_seqno(seqno);
        (*mqueue).unlock();
    }
}

/// `ipc_port_set_protected_payload()` in C.
///
/// # Safety
///
/// `port` must be live, active, and locked; the message queue lock may be
/// taken.
pub(crate) unsafe fn set_protected_payload(port: IpcPort, payload: usize) {
    let mqueue = unsafe { lock_mqueue(port) };

    // SAFETY: the mqueue belongs to the port and is locked.
    unsafe {
        port.set_protected_payload(payload);
        port.set_protected_flag();
        (*mqueue).unlock();
    }
}

/// `ipc_port_clear_protected_payload()` in C.
///
/// # Safety
///
/// `port` must be live, active, and locked; the message queue lock may be
/// taken.
pub(crate) unsafe fn clear_protected_payload(port: IpcPort) {
    let mqueue = unsafe { lock_mqueue(port) };

    // SAFETY: the mqueue belongs to the port and is locked.
    unsafe {
        port.clear_protected_flag();
        (*mqueue).unlock();
    }
}

/// `ipc_port_clear_receiver()` in C.
///
/// # Safety
///
/// `port` must be live, active, and locked; port set and message queue locks
/// may be taken.
pub(crate) unsafe fn clear_receiver(port: IpcPort) {
    let pset = unsafe { port.pset() };
    if pset.is_null() {
        let mqueue = unsafe { port.messages() };
        unsafe {
            (*mqueue).lock();
            ipc_mqueue::changed(mqueue, MsgReturn::RCV_PORT_DIED);
            (*mqueue).unlock();
        }
    } else {
        let target = pset.cast::<IpcTarget>();

        // SAFETY: a non-null `ip_pset` names a live port set.
        unsafe {
            (*target).lock();
            ipc_pset::remove(target, port);
            IpcTarget::check_unlock(target);
        }
    }

    // SAFETY: the port is live and locked.
    unsafe {
        port.set_mscount(0);
        let mqueue = port.messages();
        (*mqueue).lock();
        port.set_seqno(0);
        (*mqueue).unlock();
    }
}

/// `ipc_port_init()` in C.
///
/// # Safety
///
/// `port` must be a fresh, locked port this call initializes, and `space`
/// must be the live space that will hold it.
pub(crate) unsafe fn init(port: IpcPort, space: *mut c_void, name: c_uint) {
    unsafe {
        let record = port.record();
        ipc_target::init(ptr::addr_of_mut!((*record).target), name);

        port.set_receiver(space);
        port.set_mscount(0);
        port.set_srights(0);
        port.set_sorights(0);
        port.set_nsrequest(None);
        port.set_pdrequest(None);
        port.set_dnrequests(ptr::null_mut());
        port.set_pset(ptr::null_mut());
        port.set_cur_target(ptr::addr_of_mut!((*record).target));
        port.set_seqno(0);
        port.set_msgcount(0);
        port.set_qlimit(MACH_PORT_QLIMIT_DEFAULT);
        port.clear_protected_flag();
        port.set_protected_payload(0);

        ipc_mqueue::init(port.messages());
        ipc_thread::ipc_thread_queue_init(port.blocked());
    }
}

/// `ipc_port_destroy()` in C.
///
/// # Safety
///
/// `port` must be live, active, and locked, and the caller's reference is
/// consumed; on return the port is destroyed.
pub(crate) unsafe fn destroy(port: IpcPort) {
    unsafe {
        let pdrequest = port.pdrequest();
        if let Some(pdrequest) = pdrequest {
            port.set_pdrequest(None);
            port.set_receiver_name(MACH_PORT_NULL);
            port.set_destination(ptr::null_mut());
            port.clear_protected_flag();
            port.unlock();

            if !check_circularity(port, pdrequest.as_ptr()) {
                ipc_notify::port_destroyed(pdrequest.as_ptr(), port.as_ptr());
                return;
            }

            release_sonce(IpcPort::from_raw(pdrequest.as_ptr()));
            port.lock();
        }

        loop {
            // SAFETY: the port is live and locked, which serializes its
            // blocked queue.
            let sender = ipc_thread::ipc_thread_dequeue(port.blocked());
            if sender.is_null() {
                break;
            }

            let sender = sender.cast::<Thread>();
            // SAFETY: the queue holds live threads.
            (*sender).ith_state = MACH_MSG_SUCCESS;
            // SAFETY: the sender is live and not locked.
            ipc_sched::thread_go(sender);
        }

        port.clear_active();
        port.set_timestamp(timestamp());
        port.unlock();

        if let Some(nsrequest) = port.nsrequest() {
            ipc_notify::send_once(nsrequest);
        }

        let mqueue = port.messages();
        (*mqueue).lock();
        loop {
            let kmsg = ipc_kmsg::dequeue((*mqueue).messages().cast());
            let Some(kmsg) = kmsg else {
                break;
            };

            (*mqueue).unlock();

            port.release();
            // The destination right was just released, so clearing the field
            // keeps the destroy from consuming it twice.
            kmsg.clear_remote();
            ipc_kmsg::destroy(kmsg);

            (*mqueue).lock();
        }
        (*mqueue).unlock();

        let dnrequests = port.dnrequests();
        if !dnrequests.is_null() {
            let its = (*dnrequests).size();
            let size = (*its).its_size;

            for index in 1..size {
                let request = dnrequests.add(index as usize);
                let name = (*request).name();
                if name == MACH_PORT_NULL {
                    continue;
                }

                ipc_notify::dead_name((*request).soright(), name);
            }

            dnrequests_free(its, dnrequests);
        }

        if port.kotype() != IKOT_NONE {
            crate::kern::ipc_kobject::destroy(port.as_ptr());
        }

        let record = port.record();
        ipc_target::ipc_target_terminate(
            ptr::addr_of_mut!((*record).target).cast(),
        );

        port.release();
    }
}

/// `ipc_port_check_circularity()` in C.
///
/// # Safety
///
/// `port` and `dest` must be live ports and no port locks may be held.
pub(crate) unsafe fn check_circularity(
    port: IpcPort,
    dest: *mut c_void,
) -> bool {
    if ptr::eq(port.as_ptr(), dest) {
        return true;
    }

    let dest_port = unsafe { IpcPort::from_raw(dest) };
    let mut base = dest_port;

    let fast = unsafe {
        port.lock();
        let fast = if dest_port.try_lock() {
            let in_transit = dest_port.is_active()
                && dest_port.receiver_name() == MACH_PORT_NULL
                && !dest_port.destination().is_null();
            if in_transit {
                dest_port.unlock();
                false
            } else {
                true
            }
        } else {
            false
        };
        if !fast {
            port.unlock();
        }
        fast
    };

    if !fast {
        MULTIPLE_LOCK.lock();

        loop {
            let current = base;
            // SAFETY: the chain starts at the live destination and every
            // hop is a live destination port.
            unsafe {
                current.lock();
                if !current.is_active()
                    || current.receiver_name() != MACH_PORT_NULL
                    || current.destination().is_null()
                {
                    break;
                }
                base = IpcPort::from_raw(current.destination());
            }
        }

        if port == base {
            MULTIPLE_LOCK.unlock();

            let mut node = dest;
            while !node.is_null() {
                // SAFETY: the chain is locked end to end.
                let current = unsafe { IpcPort::from_raw(node) };
                // SAFETY: the chain is locked end to end.
                let next = unsafe { current.destination() };
                // SAFETY: the chain is locked end to end.
                unsafe { current.unlock() };
                node = next;
            }
            return true;
        }

        unsafe { port.lock() };
        MULTIPLE_LOCK.unlock();
    }

    // SAFETY: `port` and the chain from `dest` to `base` are locked, and the
    // C's reference and relink happen under those locks.
    unsafe {
        dest_port.increment_references();
        port.set_destination(dest);

        let mut node = port;
        while node != base {
            let next = node.destination();
            node.unlock();
            // SAFETY: the nodes between `port` and `base` are in transit,
            // so their destinations are live ports.
            node = IpcPort::from_raw(next);
        }
        base.unlock();
    }

    false
}

/// `ipc_port_lookup_notify()` in C.
///
/// # Safety
///
/// `space` must be live, active, and locked, as `ipc_entry_lookup()` needs.
pub(crate) unsafe fn lookup_notify(
    space: IpcSpace,
    name: c_uint,
) -> Option<IpcPort> {
    let entry = unsafe { space.entry_lookup(name) }?;

    // SAFETY: a found entry is live and its bits name the rights it holds.
    if unsafe { (*entry).bits } & MACH_PORT_TYPE_RECEIVE == 0 {
        return None;
    }

    // SAFETY: an entry holding receive rights has a live port object.
    let port = unsafe { IpcPort::from_raw((*entry).object) };

    unsafe {
        port.lock();
        port.increment_references();
        port.increment_sorights();
        port.unlock();
    }

    Some(port)
}

/// `ipc_port_make_send()` in C.
///
/// # Safety
///
/// `port` must be live and active, and no lock may be held.
pub(crate) unsafe fn make_send(port: IpcPort) -> IpcPort {
    unsafe {
        port.lock();
        port.increment_mscount();
        port.increment_srights();
        port.increment_references();
        port.unlock();
    }

    port
}

/// `ipc_port_copy_send()` in C: `IP_NULL` maps to `IP_NULL`, `IP_DEAD` and a
/// dead port to `IP_DEAD`, and a live port to itself plus a reference.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD`, or a live port, and no lock may be
/// held.
pub(crate) unsafe fn copy_send(port: *mut c_void) -> *mut c_void {
    let Some(live) = IpcPort::valid(port) else {
        return port;
    };

    // SAFETY: `valid()` established the live port.
    unsafe {
        live.lock();
        let sright = if live.is_active() {
            live.increment_references();
            live.increment_srights();
            live.as_ptr()
        } else {
            IP_DEAD
        };
        live.unlock();
        sright
    }
}

/// `ipc_port_copyout_send()` in C.
///
/// # Safety
///
/// `space` must be a live space, and nothing may be locked.
pub(crate) unsafe fn copyout_send(
    sright: *mut c_void,
    space: IpcSpace,
) -> c_uint {
    IpcPort::valid(sright).map_or_else(
        || {
            // SAFETY: the C's `invalid_port_to_name()` only accepts a null
            // or dead port and halts otherwise.
            unsafe { invalid_port_to_name(sright) }
        },
        |sright| {
            match unsafe {
                ipc_object::copyout(
                    space,
                    sright.as_ptr(),
                    MACH_MSG_TYPE_PORT_SEND,
                    true,
                )
            } {
                Ok(name) => name,
                Err(error) => {
                    // SAFETY: the failed copyout leaves the C owning the
                    // right, which it released.
                    unsafe { release_send(sright) };

                    if error == KernError::InvalidCapability {
                        MACH_PORT_NAME_DEAD
                    } else {
                        MACH_PORT_NULL
                    }
                }
            }
        },
    )
}

/// `invalid_name_to_port()` of <ipc/port.h>.
///
/// # Panics
///
/// Halts through [`kpanic!`] when `name` is a valid port name, as the C
/// `panic()` did.
///
/// # Safety
///
/// `name` must be `MACH_PORT_NAME_NULL` or `MACH_PORT_NAME_DEAD`, never a
/// name that indexes a live entry.
pub(crate) unsafe fn invalid_name_to_port(name: c_uint) -> *mut c_void {
    match name {
        MACH_PORT_NULL => ptr::null_mut(),
        MACH_PORT_NAME_DEAD => IP_DEAD,
        _ => kpanic!(
            "invalid_name_to_port",
            "invalid_name_to_port() called with a valid port"
        ),
    }
}

/// `invalid_port_to_name()` of <ipc/port.h>.
///
/// # Panics
///
/// Halts through [`kpanic!`] when `port` is a valid name, as the C
/// `panic()` did.
///
/// # Safety
///
/// `port` must be null or `IP_DEAD`, never a live port.
pub(crate) unsafe fn invalid_port_to_name(port: *mut c_void) -> c_uint {
    match port.addr() {
        0 => MACH_PORT_NULL,
        usize::MAX => MACH_PORT_NAME_DEAD,
        _ => kpanic!(
            "invalid_port_to_name",
            "invalid_port_to_name() called with a valid name"
        ),
    }
}

/// `ipc_port_release_send()` in C.  Consumes a reference.
///
/// # Safety
///
/// `port` must be a live port holding one send right, and nothing may be
/// locked.
pub(crate) unsafe fn release_send(port: IpcPort) {
    unsafe {
        port.lock();
        port.decrement_references();

        if !port.is_active() {
            port.check_unlock();
            return;
        }

        let mut nsrequest = None;
        let mut mscount = 0;

        port.decrement_srights();
        if port.srights() == 0 {
            nsrequest = port.nsrequest();
            if nsrequest.is_some() {
                port.set_nsrequest(None);
                mscount = port.mscount();
            }
        }

        port.unlock();

        if let Some(nsrequest) = nsrequest {
            ipc_notify::no_senders(nsrequest, mscount);
        }
    }
}

/// `ipc_port_make_sonce()` in C.
///
/// # Safety
///
/// `port` must be live and active, and no lock may be held.
pub(crate) unsafe fn make_sonce(port: IpcPort) -> IpcPort {
    unsafe {
        port.lock();
        port.increment_sorights();
        port.increment_references();
        port.unlock();
    }

    port
}

/// `ipc_port_release_sonce()` in C.  Consumes a reference.
///
/// # Safety
///
/// `port` must be a live port holding one send-once right, and nothing may be
/// locked.
pub(crate) unsafe fn release_sonce(port: IpcPort) {
    unsafe {
        port.lock();
        port.decrement_sorights();
        port.decrement_references();

        if !port.is_active() {
            port.check_unlock();
            return;
        }

        port.unlock();
    }
}

/// `ipc_port_release_receive()` in C.  Consumes a reference and destroys the
/// port.
///
/// # Safety
///
/// `port` must be a live receive right in limbo or in transit, and nothing
/// may be locked.
pub(crate) unsafe fn release_receive(port: IpcPort) {
    let destination = unsafe {
        port.lock();
        let destination = port.destination();
        destroy(port);
        destination
    };

    if let Some(destination) = IpcPort::valid(destination) {
        // SAFETY: the destination is a live port holding a reference.
        unsafe { destination.release() };
    }
}

/// `ipc_port_alloc_special()` in C.
///
/// # Safety
///
/// `space` must be a live space, and `io_alloc()`'s cache must be
/// initialized.
pub(crate) unsafe fn alloc_special(space: IpcSpace) -> Option<IpcPort> {
    let object = unsafe {
        (*ptr::addr_of_mut!(ipc_object::IPC_OBJECT_CACHES))
            .get_mut(IOT_PORT)?
            .alloc()?
    };
    // SAFETY: the cache's buffers are `struct ipc_port` sized, as its init
    // recorded from the C size.
    let port = IpcPort(unsafe {
        NonNull::new_unchecked(object.as_ptr().cast::<c_void>())
    });

    unsafe {
        port.init_lock();
        port.set_references(1);
        port.set_bits(IO_BITS_ACTIVE | (IOT_PORT_TYPE << 16));

        // The C cast the port's address to the name, a deliberate truncation
        // on the 64-bit kernel.
        init(port, space.as_ptr(), port.as_ptr().addr() as c_uint);
    }

    Some(port)
}

/// `ipc_port_dealloc_special()` in C.  Consumes one reference and destroys
/// the port.
///
/// # Safety
///
/// `port` must be a live port in a special space, and `space` must be that
/// live space.
pub(crate) unsafe fn dealloc_special(port: IpcPort) {
    unsafe {
        port.lock();
        port.set_receiver_name(MACH_PORT_NULL);
        port.set_receiver(ptr::null_mut());

        clear_receiver(port);
        destroy(port);
    }
}
