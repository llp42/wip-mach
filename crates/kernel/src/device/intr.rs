// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from device/intr.c:
//   Copyright (c) 2010, 2011, 2016, 2019 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt device, which `device/intr.c` used to define and
//! <device/intr.h> declares.
//!
//! The registration list and the delivery thread are here; the `irqdev` and
//! `user_intr_t` records belong to <device/intr.h> and are mirrored by
//! [`crate::arch::x86_64::irq`].

use crate::arch::x86_64::io_req::DevT;
use crate::arch::x86_64::ioapic::{self, InterruptHandler};
use crate::arch::x86_64::irq::{self, IrqDev, UserIntr, UserIntrQueue};
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::platform::MachPlatform;
use crate::config::NINTR;
use crate::device::r#return::DeviceError;
use crate::ipc::ipc_kmsg;
use crate::ipc::ipc_mqueue;
use crate::ipc::ipc_port;
use crate::ipc::{IpcPort, MachMsgHeader, MachMsgType};
use crate::kern::console::{CStrArg, kprint};
use crate::kern::kheap::Kalloc;
use crate::kern::machine::CLOCK_HZ;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, clear_wait, thread_block,
    thread_set_timeout, thread_wakeup_prim,
};
use crate::kern::slab::kalloc;
use crate::kern::task::current_task;
use collections::simple_queue;
use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::mem::{offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use kmem::KBox;
use lock::IrqSpinLock;

/// `IRQGETPICMODE` of <`device/irq_status.h`>.
const IRQGETPICMODE: c_uint = 0;

/// `SA_SHIRQ` of `device/intr.c`.
const SA_SHIRQ: c_ulong = 0x0400_0000;

/// `MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND, 0)` of <mach/message.h>.
const MACH_MSGH_BITS_PORT_SEND: u32 = 17;

/// `MACH_MSG_TYPE_INTEGER_32` of <mach/message.h>.
const MACH_MSG_TYPE_INTEGER_32: u32 = 2;

/// `DEVICE_INTR_NOTIFY` of <device/notify.h>.
const DEVICE_INTR_NOTIFY: c_int = 100;

/// `DEVICE_NOTIFY_MSGH_SEQNO` of <device/intr.h>.
const DEVICE_NOTIFY_MSGH_SEQNO: u32 = 0;

/// The `mach_msg_type_t` initializer of `deliver_intr()`.
const INTR_TYPE: MachMsgType =
    MachMsgType::new(MACH_MSG_TYPE_INTEGER_32 | (32 << 8) | (1 << 29), 1);

/// `device_intr_notification_t` of <device/notify.h>: the message a delivery
/// port receives, laid over the `struct ipc_kmsg` header.
#[repr(C)]
#[allow(missing_docs)]
struct DeviceIntrNotification {
    intr_header: MachMsgHeader,
    intr_type: MachMsgType,
    id: c_int,
}

const _: () = {
    assert!(size_of::<DeviceIntrNotification>() == 48);
    assert!(align_of::<DeviceIntrNotification>() == 8);
    assert!(offset_of!(DeviceIntrNotification, intr_header) == 0);
    assert!(offset_of!(DeviceIntrNotification, intr_type) == 32);
    assert!(offset_of!(DeviceIntrNotification, id) == 40);
};

/// `struct intr_list` of `device/intr.c`: one shared-IRQ registration.
#[repr(C)]
#[allow(missing_docs)]
struct IntrList {
    user_intr: *mut UserIntr,
    flags: c_ulong,
    next: *mut Self,
}

/// `user_intr_handlers[]` of `device/intr.c`: one list per interrupt.
static mut USER_INTR_HANDLERS: [*mut IntrList; NINTR] =
    [ptr::null_mut(); NINTR];

/// `main_intr_queue` of <device/intr.h>, the queue `irqtab` points at.
pub static mut MAIN_INTR_QUEUE: UserIntrQueue = UserIntrQueue::new();

/// The main interrupt queue head.
///
/// # Safety
///
/// The caller must hold `INTR_LOCK` for as long as it uses the queue.
unsafe fn main_intr_queue() -> Pin<&'static mut UserIntrQueue> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the queue.
    unsafe { Pin::new_unchecked(&mut *ptr::addr_of_mut!(MAIN_INTR_QUEUE)) }
}

/// The entry after `entry` in the main interrupt queue, or the first entry
/// for `None`.
///
/// # Safety
///
/// The caller must hold `INTR_LOCK`, and `entry` must be `None` or on the
/// queue.
unsafe fn next_intr(
    entry: Option<NonNull<UserIntr>>,
) -> Option<NonNull<UserIntr>> {
    // SAFETY: the lock is held.
    let mut head = unsafe { main_intr_queue() };
    let Some(entry) = entry else {
        return head.cursor_front().current_ptr();
    };
    // SAFETY: `entry` is on the queue.
    let mut cursor = unsafe { head.as_mut().cursor_mut_from_ptr(entry) };
    cursor.move_next();
    cursor.current_ptr()
}

/// The queue of `dev`'s registrations.
///
/// # Safety
///
/// `dev` must be the live `irqtab`, whose `intr_queue` is an initialized queue
/// that never moves, and the caller must hold `INTR_LOCK` for as long as it
/// uses the queue.
unsafe fn dev_intr_queue<'a>(dev: *mut IrqDev) -> Pin<&'a mut UserIntrQueue> {
    // SAFETY: the caller promises the queue is live, stays in place and is
    // unshared.
    unsafe { Pin::new_unchecked(&mut *(*dev).intr_queue) }
}

/// `intr_lock` of `device/intr.c`, around the queue and the handler lists.
/// An irq spin lock, since the shared vector handler takes it.
static INTR_LOCK: IrqSpinLock<(), MachPlatform> = IrqSpinLock::new(());

/// `e->dst_port` lost its last reference, or is unusable.
///
/// # Safety
///
/// `port` must be `MACH_PORT_NULL` or a live port, as the registration's own
/// reference keeps it until the entry is removed.
unsafe fn references_dead(port: *mut c_void) -> bool {
    IpcPort::valid(port).is_none_or(|port| {
        // SAFETY: `valid()` established the live port.
        (unsafe { port.references() }) == 1
    })
}

/// Release the registration's reference on `port`.
///
/// # Safety
///
/// `port` must be `MACH_PORT_NULL` or a live port, as [`references_dead()`].
unsafe fn release_port(port: *mut c_void) {
    if let Some(port) = IpcPort::valid(port) {
        // SAFETY: `valid()` established the live port, which holds the
        // registration's reference.
        unsafe { port.release() };
    }
}

/// `irqtab.irq[id]`, or [`None`] outside the table.
///
/// # Safety
///
/// `dev` must be the live `irqtab`.
unsafe fn irq_of(dev: *mut IrqDev, id: c_int) -> Option<c_uint> {
    let index = usize::try_from(id).ok()?;
    unsafe { (*dev).irq.get(index).copied() }
}

/// The event the interrupt thread waits and wakes on: the C's
/// `(event_t) &intr_thread`.
fn intr_event() -> *mut c_void {
    intr_thread as *const () as *mut c_void
}

/// Whether the line's handler is `wanted`, compared by address.
fn is_handler(
    current: InterruptHandler,
    wanted: unsafe extern "C" fn(c_int),
) -> bool {
    current.is_some_and(|current| ptr::fn_addr_eq(current, wanted))
}

/// Wake the interrupt thread, as the C's `thread_wakeup()` did.
fn wake_intr_thread() {
    // SAFETY: the event is this module's; a non-interruptible wait is woken
    // normally.
    unsafe { thread_wakeup_prim(intr_event(), 0, THREAD_AWAKENED) };
}

/// `search_intr()` of `device/intr.c`.
///
/// # Safety
///
/// `dev` must be the live `irqtab`, whose `intr_queue` is an initialized
/// queue of [`UserIntr`] entries with the chain as their first field.
unsafe fn search_intr(
    dev: *mut IrqDev,
    dst_port: *mut c_void,
) -> Option<NonNull<UserIntr>> {
    // SAFETY: the caller holds the lock.
    let queue = unsafe { dev_intr_queue(dev) };
    let mut cursor = queue.cursor_front();
    while let Some(e) = cursor.current() {
        if e.dst_port == dst_port {
            return cursor.current_ptr();
        }
        cursor.move_next();
    }
    None
}

/// `queue_intr()` of `device/intr.c`: account a delivery and wake the
/// interrupt thread.
///
/// # Safety
///
/// `dev` must be the live `irqtab`, `id` inside its `irq` table, and `e` the
/// live registration the line belongs to.
unsafe fn queue_intr(dev: *mut IrqDev, id: c_int, e: *mut UserIntr) {
    unsafe {
        if let Some(irq) = irq_of(dev, id) {
            irq::__disable_irq(irq);
        }
        (*e).n_unacked += 1;
        (*e).interrupts += 1;
        (*dev).tot_num_intr += 1;
    }
    wake_intr_thread();
}

/// `deliver_user_intr()` of `device/intr.c`.
///
/// # Safety
///
/// `dev` must be the live `irqtab`, `id` inside its `irq` table, and `e` the
/// live registration for that line.
pub(crate) unsafe fn deliver_user_intr(
    dev: *mut IrqDev,
    id: c_int,
    e: *mut UserIntr,
) -> bool {
    if unsafe { references_dead((*e).dst_port) } {
        wake_intr_thread();
        false
    } else {
        unsafe { queue_intr(dev, id, e) };
        true
    }
}

/// `insert_intr_entry()` of `device/intr.c`.
///
/// # Safety
///
/// `dev` must be the live `irqtab` with an initialized `intr_queue`, and
/// `dst_port` a port the caller keeps alive.
pub(crate) unsafe fn insert_intr_entry(
    dev: *mut IrqDev,
    id: c_int,
    dst_port: *mut c_void,
) -> Option<NonNull<UserIntr>> {
    let new = KBox::try_new(
        UserIntr {
            chain: simple_queue::Link::new(),
            interrupts: 0,
            n_unacked: 0,
            dst_port,
            id,
        },
        Kalloc,
    )
    .ok()?;

    let guard = INTR_LOCK.lock();
    let found = unsafe { search_intr(dev, dst_port) }.is_some();
    let result = if found {
        kprint!(
            "the interrupt entry for irq[{}] and port {:x} has already been inserted\n",
            id,
            dst_port.expose_provenance(),
        );
        None
    } else {
        // The queue keeps the entry for good: the delivery thread unlinks a
        // dead one but never frees it, as the C did not.
        let new = NonNull::from(KBox::leak(new));
        kprint!(
            "irq handler [{}]: new delivery port {:x} entry {:x} for {}\n",
            id,
            dst_port.expose_provenance(),
            new.as_ptr().expose_provenance(),
            // SAFETY: the current task is live and its name is
            // NUL-terminated.
            unsafe { CStrArg::from_ptr((*current_task()).name.as_ptr()) },
        );
        // SAFETY: the lock is held, and the entry is unlinked and leaked, so it
        // stays live and in place.
        unsafe { dev_intr_queue(dev).push_back_ptr(new) };
        Some(new)
    };
    drop(guard);

    // A duplicate's unused entry drops on return, after the lock.
    result
}

/// `user_irq_handler()` of `device/intr.c`: the vector a shared line points
/// at.
unsafe extern "C" fn user_irq_handler(id: c_int) {
    let guard = INTR_LOCK.lock();

    let index = usize::try_from(id).ok().filter(|index| *index < NINTR);
    // SAFETY: the lock is held, and `index` keeps the table access inside
    // `NINTR` exactly as the C's `user_intr_handlers[id]` assumed.
    if let Some(index) = index {
        // SAFETY: a listed node is this module's live `IntrList`.
        unsafe {
            let head = ptr::addr_of_mut!(USER_INTR_HANDLERS[index]);
            let mut prev = head;
            let mut handler = *head;
            while !handler.is_null() {
                let e = (*handler).user_intr;
                if !deliver_user_intr(ptr::addr_of_mut!(irq::IRQTAB), id, e) {
                    *prev = (*handler).next;
                }
                prev = ptr::addr_of_mut!((*handler).next);
                handler = (*handler).next;
            }
        }
    }

    drop(guard);
}

/// `install_user_intr_handler()` of `device/intr.c`.
///
/// # Safety
///
/// `dev` must be the live `irqtab`, `id` inside its `irq` table, and
/// `user_intr` the live entry [`insert_intr_entry()`] returned.
pub(crate) unsafe fn install_user_intr_handler(
    dev: *mut IrqDev,
    id: c_int,
    mut flags: c_ulong,
    user_intr: *mut UserIntr,
) -> Result<(), DeviceError> {
    flags |= SA_SHIRQ;

    let irq = unsafe { irq_of(dev, id) };
    let Some(irq) = irq.and_then(|irq| c_int::try_from(irq).ok()) else {
        return Err(DeviceError::InvalidOperation);
    };

    let handler = irq::handler(irq);
    if !is_handler(handler, user_irq_handler)
        && !is_handler(handler, ioapic::intnull)
    {
        kprint!("You can't have this interrupt {}:{}\n", id, irq);
        return Err(DeviceError::AlreadyOpen);
    }

    let index = usize::try_from(id).ok().filter(|index| *index < NINTR);
    let Some(index) = index else {
        return Err(DeviceError::InvalidOperation);
    };
    // SAFETY: `index` is inside the handlers table, and a non-null head
    // points at a live node.
    let old = unsafe { *ptr::addr_of!(USER_INTR_HANDLERS[index]) };
    if !old.is_null() {
        // SAFETY: a non-null head points at a live node.
        if unsafe { (*old).flags & flags & SA_SHIRQ } == 0 {
            kprint!("Cannot share irq\n");
            return Err(DeviceError::AlreadyOpen);
        }
    }

    // SAFETY: `kalloc()` returns fresh storage for the size asked, or
    // nothing.
    let Some(new) = kalloc(size_of::<IntrList>()) else {
        return Err(DeviceError::NoMemory);
    };
    let new = new.as_ptr().cast::<IntrList>();
    // SAFETY: `new` is fresh, unshared storage.
    unsafe {
        (*new).user_intr = user_intr;
        (*new).flags = flags;
    }

    let guard = INTR_LOCK.lock();
    // SAFETY: the lock is held, `new` is unlinked, and `index` is inside the
    // handlers table.
    unsafe {
        let head = ptr::addr_of_mut!(USER_INTR_HANDLERS[index]);
        (*new).next = *head;
        *head = new;
    }
    irq::set_handler(irq, Some(user_irq_handler));
    irq::set_unit(irq, irq);
    ioapic::unmask(irq);
    drop(guard);

    Ok(())
}

/// `deliver_intr()` of `device/intr.c`: send the notification message.
///
/// # Safety
///
/// `dst_port` must be a live port, and that port must be the send right the
/// caller holds.
unsafe fn deliver_intr(id: c_int, dst_port: NonNull<c_void>) -> bool {
    // SAFETY: the message size fits the notification record, and a `None`
    // means no buffer.
    let Some(kmsg) =
        (unsafe { ipc_kmsg::alloc(size_of::<DeviceIntrNotification>()) })
    else {
        return false;
    };

    // SAFETY: the fresh message's header is the notification record.
    let n = unsafe { kmsg.header().cast::<DeviceIntrNotification>() };
    let size = u32::try_from(size_of::<DeviceIntrNotification>()).unwrap_or(0);
    // SAFETY: `kmsg` is live and this call owns it until the send below.
    unsafe {
        (*n).intr_header.set_bits(MACH_MSGH_BITS_PORT_SEND);
        (*n).intr_header.set_size(size);
        (*n).intr_header.set_seqno(DEVICE_NOTIFY_MSGH_SEQNO);
        (*n).intr_header.set_local(0);
        (*n).intr_header.set_remote(0);
        (*n).intr_header.set_id(DEVICE_INTR_NOTIFY);
        (*n).intr_type = INTR_TYPE;
        (*n).id = id;
        (*n).intr_header.set_remote(dst_port.as_ptr().addr());
    }

    unsafe { ipc_port::copy_send(dst_port.as_ptr()) };
    // SAFETY: `kmsg` is a live message this call owns and the remote port
    // holds the reference `copy_send()` just made.
    let _ = unsafe { ipc_mqueue::send_always(kmsg.as_ptr()) };
    true
}

/// `intr_thread()` of `device/intr.c`: deliver the queued user interrupts.
///
/// # Safety
///
/// Started once, as the `intr` kernel thread, after the device layer and the
/// interrupt tables exist.
pub(crate) unsafe fn intr_thread() {
    // SAFETY: the current thread is the one `kernel_thread()` started for
    // this routine.
    unsafe { (*per_cpu::thread()).vm_privilege = 1 };

    loop {
        // SAFETY: this is the interrupt thread; the event is the one every
        // wakeup names, and `hz` is the kernel's tick rate.
        unsafe {
            assert_wait(NonNull::new(intr_event()), 0);
            thread_set_timeout(CLOCK_HZ);
        }
        let mut guard = INTR_LOCK.lock();

        loop {
            let mut deleted = ptr::null_mut::<UserIntr>();
            // SAFETY: the lock is held, and every entry is a live registration
            // that only this thread unlinks. The walk keeps pointers, not a
            // cursor, because the lock is dropped mid-walk and another CPU
            // may queue an entry.
            let mut next = unsafe { next_intr(None) };
            while let Some(e) = next {
                // SAFETY: the lock is held and `e` is on the queue.
                next = unsafe { next_intr(Some(e)) };
                let e = e.as_ptr();
                // SAFETY: `e` is the entry the queue links point at.
                let dst_port = unsafe { (*e).dst_port };
                // SAFETY: the lock is held; the port field is a registration
                // slot.
                if unsafe { references_dead(dst_port) } {
                    // SAFETY: the current thread is the one waiting above.
                    unsafe { clear_wait(per_cpu::thread(), 0, 0) };
                    deleted = e;
                    break;
                }

                // SAFETY: `e` is the entry the queue links point at.
                if unsafe { (*e).interrupts } != 0 {
                    // SAFETY: the current thread is the one waiting above.
                    unsafe { clear_wait(per_cpu::thread(), 0, 0) };
                    // SAFETY: `e` is live; the lock is still held, and
                    // `irqtab` is the live table.
                    let id = unsafe {
                        let id = (*e).id;
                        (*e).interrupts -= 1;
                        (*ptr::addr_of_mut!(irq::IRQTAB)).tot_num_intr -= 1;
                        id
                    };
                    // SAFETY: `references_dead()` returned false, so the
                    // registration's port is live and non-null; the entry
                    // and its port are live, and the C made the same drop
                    // of the lock before sending.
                    guard.unlocked(|| unsafe {
                        deliver_intr(id, NonNull::new_unchecked(dst_port));
                    });
                }
            }

            if !deleted.is_null() {
                // SAFETY: `deleted` is linked in the queue and the lock is
                // held.
                unsafe {
                    let _ = main_intr_queue().remove_ptr(deleted.cast_const());
                    kprint!(
                        "irq handler [{}]: release a dead delivery port {:x} entry {:x}\n",
                        (*deleted).id,
                        (*deleted).dst_port.expose_provenance(),
                        deleted.expose_provenance(),
                    );
                    release_port((*deleted).dst_port);
                    (*deleted).dst_port = ptr::null_mut();

                    if (*deleted).n_unacked != 0 {
                        kprint!(
                            "irq handler [{}]: still {} unacked irqs in entry {:x}\n",
                            (*deleted).id,
                            (*deleted).n_unacked,
                            deleted.expose_provenance(),
                        );
                    }
                    while (*deleted).n_unacked != 0 {
                        if let Some(irq) = irq_of(
                            ptr::addr_of_mut!(irq::IRQTAB),
                            (*deleted).id,
                        ) {
                            irq::__enable_irq(irq);
                        }
                        (*deleted).n_unacked -= 1;
                    }

                    let tot = ptr::addr_of_mut!(irq::IRQTAB);
                    (*tot).tot_num_intr -= (*deleted).interrupts;
                    (*deleted).interrupts = 0;
                }
            }

            // SAFETY: `irqtab` is the live table, and the lock is held.
            let pending =
                unsafe { (*ptr::addr_of!(irq::IRQTAB)).tot_num_intr };
            if deleted.is_null() && pending == 0 {
                break;
            }
        }

        drop(guard);
        // SAFETY: this thread is the one that waited above; the null
        // continuation resumes it at the top of the loop.
        unsafe { thread_block(None) };
    }
}

/// Enable the line registration `id` names, outside the lock, as
/// `irq_acknowledge()` did.
pub(crate) fn enable_line(id: c_int) {
    // SAFETY: `irqtab` is the live table, and `id` came from a registration.
    if let Some(irq) = unsafe { irq_of(ptr::addr_of_mut!(irq::IRQTAB), id) } {
        irq::__enable_irq(irq);
    }
}

/// `irq_acknowledge()` of `device/intr.c`: account a userland acknowledgement
/// and report the line to enable.
///
/// # Errors
///
/// Returns [`DeviceError::InvalidArgument`] when no registration names the
/// port, and [`DeviceError::InvalidOperation`] when it has nothing left to
/// acknowledge.
///
/// # Safety
///
/// `receive_port` must be the port named by a live registration.
pub(crate) unsafe fn irq_acknowledge(
    receive_port: *mut c_void,
) -> Result<c_int, DeviceError> {
    let guard = INTR_LOCK.lock();
    let entry =
        unsafe { search_intr(ptr::addr_of_mut!(irq::IRQTAB), receive_port) };
    let result = entry.map_or_else(
        || {
            kprint!("didn't find user intr for interrupt !?\n");
            Err(DeviceError::InvalidArgument)
        },
        |e| {
            // SAFETY: `e` is live under the lock.
            if unsafe { (*e.as_ptr()).n_unacked } == 0 {
                Err(DeviceError::InvalidOperation)
            } else {
                // SAFETY: the count is nonzero, as the branch checked.
                unsafe { (*e.as_ptr()).n_unacked -= 1 };
                // SAFETY: `e` is live under the lock.
                Ok(unsafe { (*e.as_ptr()).id })
            }
        },
    );
    drop(guard);
    result
}

/// The status reply for `flavor`, or [`None`] for a flavor the device does
/// not serve.
pub(crate) const fn getstat(flavor: c_uint) -> Option<(c_int, u32)> {
    match flavor {
        IRQGETPICMODE => Some((ioapic::PIC_MODE, 1)),
        _ => None,
    }
}

/// `irqgetstat()` in C.
///
/// # Safety
///
/// For `IRQGETPICMODE`, the only flavor the C served, `data` must be writable
/// for one integer and `count` must be writable; the C wrote both and read
/// neither.
pub(crate) unsafe fn irqgetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut c_uint,
) -> Result<(), DeviceError> {
    match getstat(flavor) {
        Some((mode, n)) => {
            unsafe {
                *data = mode;
                *count = n;
            }
            Ok(())
        }
        None => Err(DeviceError::InvalidOperation),
    }
}

/// `intr_thread()` in C: the interrupt service thread.
///
/// # Safety
///
/// Started once, as the `intr` kernel thread, after the device layer and the
/// interrupt tables exist.
pub(crate) unsafe extern "C" fn intr_thread_entry() {
    unsafe { intr_thread() }
}
