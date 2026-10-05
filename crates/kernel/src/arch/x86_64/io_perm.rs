// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/io_perm.c and i386/i386/io_perm.h:
//   Copyright (C) 2002, 2007 Free Software Foundation, Inc.
//   Copyright (c) 1993,1992,1991,1990 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The I/O permission objects: device ports that each enable a range of I/O
//! ports in a task's bitmap.

use crate::arch::x86_64::error::Error;
use crate::arch::x86_64::machine_task::{IOPB_BYTES, IOPB_CACHE};
use crate::arch::x86_64::pcb;
use crate::device::dev_lookup;
use crate::device::ds_routines::{Device, DeviceEmulationOps};
use crate::ipc::{IpcPort, MachMsgHeader, ipc_port, ipc_space};
use crate::kern::ipc_kobject::set;
use crate::kern::slab;
use crate::kern::task::{self, Task};
use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

/// The first PCI configuration address.
const PCI_CFG1_START: u16 = 0xcf8;
/// The last PCI configuration address.
const PCI_CFG1_END: u16 = 0xcff;
/// No kernel object.
const IKO_NULL: usize = 0;
/// A port bound to no kernel object.
const IKOT_NONE: u32 = 0;
/// A port bound to a device.
const IKOT_DEVICE: u32 = 10;

/// The device, port and range of one I/O-permission object.
#[repr(C)]
#[allow(missing_docs)]
pub struct IoPerm {
    pub device: Device,
    pub port: *mut c_void,
    pub from: u16,
    pub to: u16,
}

const _: () = {
    assert!(size_of::<IoPerm>() == 32);
    assert!(align_of::<IoPerm>() == 8);
    assert!(offset_of!(IoPerm, device) == 0);
    assert!(offset_of!(IoPerm, port) == 16);
    assert!(offset_of!(IoPerm, from) == 24);
    assert!(offset_of!(IoPerm, to) == 26);
};

/// Whether a live object holds the PCI configuration range.
///
/// The C read and wrote this flag without a lock; `Relaxed` keeps the
/// accesses defined, and a lost race would lose no more than the C's.
static TAKEN_PCI_CFG: AtomicBool = AtomicBool::new(false);

/// The emulation ops of an I/O-permission device, which only handle
/// no-senders.
static IO_PERM_DEVICE_EMULATION_OPS: DeviceEmulationOps = DeviceEmulationOps {
    reference: None,
    dealloc: None,
    dev_to_port: None,
    open: None,
    close: None,
    write: None,
    write_inband: None,
    read: None,
    read_inband: None,
    set_status: None,
    get_status: None,
    set_filter: None,
    map: None,
    no_senders: Some(no_senders),
    write_trap: None,
    writev_trap: None,
};

/// Whether `from..=to` overlaps the PCI configuration range.
const fn contains_pci_cfg(from: u16, to: u16) -> bool {
    from <= PCI_CFG1_END && to >= PCI_CFG1_START
}

/// A permission bitmap: one bit per I/O port, set when the port is disabled.
type IoBitmap = [u8; IOPB_BYTES];

/// Sets every bit, so no port is enabled.
fn bitmap_init(iopb: &mut IoBitmap) {
    iopb.fill(0xff);
}

/// Enables `from..=to`.
fn bitmap_set(iopb: &mut IoBitmap, from: u16, to: u16) {
    for port in from..=to {
        iopb[usize::from(port) >> 3] &= !(1u8 << (port & 0x7));
    }
}

/// Disables `from..=to`.
fn bitmap_clear(iopb: &mut IoBitmap, from: u16, to: u16) {
    for port in from..=to {
        iopb[usize::from(port) >> 3] |= 1u8 << (port & 0x7);
    }
}

/// A send right for `io_perm`'s port, or null.
///
/// # Safety
///
/// A non-null `io_perm` must point at a live [`IoPerm`].
pub(crate) unsafe fn convert_io_perm_to_port(
    io_perm: Option<NonNull<IoPerm>>,
) -> *mut c_void {
    let Some(io_perm) = io_perm else {
        return ptr::null_mut();
    };
    let io_perm = io_perm.as_ptr();

    unsafe { ipc_port::make_send(IpcPort::from_raw((*io_perm).port)) }.as_ptr()
}

/// The I/O-permission object `port` names, or null.
///
/// # Safety
///
/// `port` must be null or a live port; the returned pointer is null when the
/// port names no device.
pub(crate) unsafe fn convert_port_to_io_perm(
    port: *mut c_void,
) -> *mut IoPerm {
    let device = unsafe { dev_lookup::port_lookup(port) };
    if device.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: a successful lookup returned a live device.
    unsafe { (*device).emul_data.cast::<IoPerm>() }
}

/// Releases the PCI configuration range when `io_perm` held it.
///
/// # Safety
///
/// `io_perm` must point at a live [`IoPerm`].
pub(crate) unsafe fn deallocate(io_perm: *mut IoPerm) {
    let (from, to) = unsafe { ((*io_perm).from, (*io_perm).to) };
    if contains_pci_cfg(from, to) {
        TAKEN_PCI_CFG.store(false, Ordering::Relaxed);
    }
}

/// Frees the object when its port loses its last sender.
///
/// # Safety
///
/// The caller must pass a live no-senders notification, as the emulation's
/// `no_senders` hook receives.
unsafe fn no_senders(notification: *mut c_void) {
    // The notification begins with the message header the C read; no other
    // field is touched.
    let header = notification.cast::<MachMsgHeader>();

    let port = ptr::with_exposed_provenance_mut::<c_void>(unsafe {
        (*header).remote()
    });
    // SAFETY: the port is this object's, so the lookup finds the device it
    // was bound to when the object was created.
    let io_perm = unsafe { convert_port_to_io_perm(port) };

    unsafe {
        set((*io_perm).port, IKO_NULL, IKOT_NONE);
        ipc_port::dealloc_special(IpcPort::from_raw((*io_perm).port));
        slab::kfree(
            NonNull::new_unchecked(io_perm.cast::<u8>()),
            size_of::<IoPerm>(),
        );
    }
}

/// Creates an object for the ports `from..=to`, for the master device port.
///
/// # Safety
///
/// `master_port` must be null or a live port, and `new` writable storage for
/// one pointer, written only on success.
pub(crate) unsafe fn create(
    master_port: *mut c_void,
    from: u16,
    to: u16,
    new: *mut *mut IoPerm,
) -> Result<(), Error> {
    if master_port != crate::device::device_init::master_device_port() {
        return Err(Error::InvalidArgument);
    }

    if from > to {
        return Err(Error::InvalidArgument);
    }

    if TAKEN_PCI_CFG.load(Ordering::Relaxed) && contains_pci_cfg(from, to) {
        return Err(Error::PortsTaken);
    }

    let Some(allocation) = slab::kalloc(size_of::<IoPerm>()) else {
        return Err(Error::ResourceShortage);
    };
    let io_perm = allocation.as_ptr().cast::<IoPerm>();

    // SAFETY: `ipc_space::kernel()` is the live kernel space, and the port
    // cache was initialized at IPC bootstrap.
    let Some(port) = (unsafe { ipc_port::alloc_special(ipc_space::kernel()) })
    else {
        // SAFETY: the allocation is fresh and nothing else can see it.
        unsafe { slab::kfree(allocation, size_of::<IoPerm>()) };
        return Err(Error::ResourceShortage);
    };

    // SAFETY: the allocation is a fresh `IoPerm` image nothing else can see,
    // and `port` is a live receive right.
    unsafe {
        (*io_perm).device.emul_ops =
            (&raw const IO_PERM_DEVICE_EMULATION_OPS).cast_mut();
        (*io_perm).device.emul_data = io_perm.cast::<c_void>();
        (*io_perm).port = port.as_ptr();
        (*io_perm).from = from;
        (*io_perm).to = to;
    }

    // SAFETY: the port is live and this object's, and the kobject it stores is
    // the embedded device, as the C registered it.
    unsafe {
        set(
            port.as_ptr(),
            (&raw mut (*io_perm).device).addr(),
            IKOT_DEVICE,
        );
    }

    // SAFETY: the port is live, so the send-once right exists; `nsrequest()`
    // consumes it and releases the lock `lock()` took.
    unsafe {
        let notify = ipc_port::make_sonce(port);
        port.lock();
        let _previous =
            ipc_port::nsrequest(port, 1, Some(notify.as_non_null()));
    }

    unsafe { new.write(io_perm) };

    if contains_pci_cfg(from, to) {
        TAKEN_PCI_CFG.store(true, Ordering::Relaxed);
    }

    Ok(())
}

/// Whether `modify()` grants or withdraws a port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    Grant,
    Withdraw,
}

/// Enables or disables the range of `io_perm` in `target_task`'s bitmap.
///
/// # Safety
///
/// `target_task` must be a live task, and `io_perm` a live [`IoPerm`].
pub(crate) unsafe fn modify(
    target_task: NonNull<Task>,
    io_perm: NonNull<IoPerm>,
    access: Access,
) -> Result<(), Error> {
    let (from, to) =
        unsafe { ((*io_perm.as_ptr()).from, (*io_perm.as_ptr()).to) };
    let machine = unsafe { &raw mut (*target_task.as_ptr()).machine };

    // SAFETY: the live task's machine part carries the bitmap lock.
    unsafe { (*machine).iopb_lock.lock() };
    // SAFETY: the lock taken above guards the field.
    let mut iopb = unsafe { (*machine).iopb };
    // The C kept the size in an `io_port_t`; every writer keeps the field
    // below `IOPB_BYTES`, so the conversion is exact.
    let mut iopb_size =
        // SAFETY: the lock taken above guards the field.
        u16::try_from(unsafe { (*machine).iopb_size }).unwrap_or(0);

    if access == Access::Withdraw && iopb_size == 0 {
        // SAFETY: this call took the lock above.
        unsafe { (*machine).iopb_lock.unlock() };
        return Ok(());
    }

    if iopb.is_null() {
        // SAFETY: this call took the lock above.
        unsafe { (*machine).iopb_lock.unlock() };

        let cache = &raw mut IOPB_CACHE;
        // SAFETY: the cache is initialized before any task runs, and its own
        // lock serializes the allocation.
        let allocated = unsafe { (*cache).alloc() };
        // SAFETY: this call took the lock above; it was free while this
        // thread was allocating.
        unsafe { (*machine).iopb_lock.lock() };

        // SAFETY: the lock is held, so the field is stable.
        if !unsafe { (*machine).iopb }.is_null() {
            if let Some(fresh) = allocated {
                // SAFETY: the allocation came from this cache and nothing
                // else uses it.
                unsafe { (*cache).free(fresh) };
            }
            // SAFETY: the lock is held, so the field is stable.
            iopb = unsafe { (*machine).iopb };
            iopb_size =
                // SAFETY: the lock is held, so the field is stable.
                u16::try_from(unsafe { (*machine).iopb_size }).unwrap_or(0);
        } else if let Some(fresh) = allocated {
            // SAFETY: the cache's buffers are `IOPB_BYTES` long.
            unsafe {
                (*machine).iopb = fresh.as_ptr();
                bitmap_init(&mut *fresh.as_ptr().cast::<IoBitmap>());
            }
            iopb = fresh.as_ptr();
        } else {
            // SAFETY: this call took the lock above.
            unsafe { (*machine).iopb_lock.unlock() };
            return Err(Error::ResourceShortage);
        }
    }

    // SAFETY: `iopb` is non-null here, and the cache's buffers are
    // `IOPB_BYTES` long.
    let bitmap = unsafe { &mut *iopb.cast::<IoBitmap>() };

    match access {
        Access::Grant => {
            bitmap_set(bitmap, from, to);
            let needed = (to >> 3) + 1;
            if needed > iopb_size {
                // SAFETY: the task is live, as the lock above established.
                unsafe { (*machine).iopb_size = c_int::from(needed) };
                iopb_size = needed;
            }
        }
        Access::Withdraw => {
            if (from >> 3) + 1 > iopb_size {
                // SAFETY: this call took the lock above.
                unsafe { (*machine).iopb_lock.unlock() };
                return Ok(());
            }

            bitmap_clear(bitmap, from, to);
            while 0 < iopb_size && bitmap[usize::from(iopb_size) - 1] == 0xff {
                iopb_size -= 1;
            }
            // SAFETY: the task is live, as the lock above established.
            unsafe { (*machine).iopb_size = c_int::from(iopb_size) };
        }
    }

    // The C warned that no other CPU running a thread of the task is told of
    // the bitmap change; that gap remains.  The running CPU updates its own
    // TSS, and a context switch to another CPU's thread refreshes that one.
    if target_task == task::current_task() {
        // SAFETY: the lock is held, `iopb` is the non-null bitmap the block
        // above established, and `iopb_size` is the byte count
        // `update_ktss_iopb()` copies.
        unsafe {
            pcb::update_ktss_iopb(
                Some(NonNull::new_unchecked(iopb)),
                iopb_size,
            );
        };
    }

    // SAFETY: this call took the lock above.
    unsafe { (*machine).iopb_lock.unlock() };
    Ok(())
}
