// SPDX-License-Identifier: CMU-Mach
// Derived from kern/host.c:
//   Copyright (c) 1993,1992,1991,1990,1989,1988 Carnegie Mellon
//   University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The cores of `kern/host.c`, mirroring <kern/host.h>.

use crate::arch::types::VmOffset;
use crate::kern::debug::kpanic;
use crate::kern::ipc_host::pset_name_to_port;
use crate::kern::machine;
use crate::kern::processor::{self, ProcessorSet, PsetList, processor_at};
use crate::kern::slab::{kalloc, kfree};
use crate::kern::smp::CpuId;
use crate::kern::types::KernError;
use core::ffi::{c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull};

/// `struct host` of <kern/host.h>, the host object MIG hands the host
/// routines.
#[repr(C)]
#[allow(missing_docs)]
pub struct Host {
    pub host_self: *mut c_void,
    pub host_priv_self: *mut c_void,
}

/// `realhost` of kern/host.c: the one host object, and the C symbol the
/// bootstrap and server paths still name.
pub(crate) static mut REALHOST: Host = Host {
    host_self: ptr::null_mut(),
    host_priv_self: ptr::null_mut(),
};

/// `&realhost`, which the C passes to `ipc_kobject_set()`.
pub(crate) fn realhost() -> *mut Host {
    ptr::addr_of_mut!(REALHOST)
}

/// The host's self port, live from the host initialization on.
#[must_use]
pub(crate) fn host_self() -> *mut c_void {
    // SAFETY: the host object is initialized before any caller.
    unsafe { (*realhost()).host_self }
}

/// The host's privileged self port, live from the host initialization on.
#[must_use]
pub(crate) fn host_priv_self() -> *mut c_void {
    // SAFETY: the host object is initialized before any caller.
    unsafe { (*realhost()).host_priv_self }
}

/// The body of `host_processor_set_priv()` in kern/host.c: a live host and a
/// live name set give back the same set with one more reference.
pub(crate) fn processor_set_priv(
    host: Option<NonNull<Host>>,
    name: Option<&mut ProcessorSet>,
) -> Result<NonNull<ProcessorSet>, KernError> {
    match (host, name) {
        (Some(_), Some(set)) => {
            set.reference();
            Ok(NonNull::from(set))
        }
        _ => Err(KernError::InvalidArgument),
    }
}

/// The body of `processor_set_processors()` in kern/host.c: allocate the array
/// MIG sends back, walk the set's processor queue and convert each processor
/// to its name port.
pub(crate) fn processor_ports(
    pset: &mut ProcessorSet,
) -> Result<(NonNull<VmOffset>, c_uint), KernError> {
    pset.lock.lock();

    // The C read the `int` count into an `unsigned int`; the field is
    // maintained as the number of processors, so it is small and never
    // negative.
    let count = pset.processor_count as c_uint;
    // A `c_uint` count fits a `VmSize` on x86_64, so the widening cannot
    // lose a bit.
    let count_slots = count as usize;
    let size = count_slots * size_of::<VmOffset>();

    // `kalloc_init()` ran during the boot this MIG entry follows, and the
    // size is the C expression's.
    let Some(ports) = kalloc(size).map(NonNull::cast::<*mut c_void>) else {
        pset.lock.unlock();
        return Err(KernError::ResourceShortage);
    };
    let list = ptr::addr_of_mut!(pset.processors);
    // SAFETY: the set lock is held, so the queue links are stable and every
    // entry is a live processor.
    let mut cursor = unsafe { (*list).cursor_front() };
    let mut i = 0;
    // SAFETY: the set lock is held, so the queue links are stable.
    unsafe {
        while i < count_slots {
            let Some(processor) = cursor.current_ptr() else {
                break;
            };
            cursor.move_next();
            let processor = processor.as_ptr();
            // SAFETY: `processor` is a live queue member, so it is a live
            // processor whose name port `ipc_processor_init()` built, and `i`
            // is below `count`, inside the allocation.
            ports
                .add(i)
                .write(crate::kern::ipc_host::processor_name_to_port(
                    processor,
                ));
            i += 1;
        }
    }

    pset.lock.unlock();
    Ok((ports.cast::<VmOffset>(), count))
}

/// The body of `host_processors()` in kern/host.c: the control port of every
/// CPU the machine reports.
pub(crate) fn processors(
    host: Option<NonNull<Host>>,
) -> Result<(NonNull<VmOffset>, c_uint), KernError> {
    if host.is_none() {
        return Err(KernError::InvalidArgument);
    }

    let mut count: c_uint = 0;
    for cpu in CpuId::all() {
        // SAFETY: the slot is `cpu`'s own `machine_slot`, which the probe
        // filled and the machine never frees.
        if unsafe { (*machine::slot(cpu)).is_cpu } != 0 {
            count += 1;
        }
    }

    if count == 0 {
        kpanic!("host_processors", "host_processors")
    }

    // The C count holds at most `MAX_NCPUS` slots, so the widening cannot
    // lose a bit.
    let slots = count as usize;
    let size = slots * size_of::<VmOffset>();

    // `kalloc_init()` ran during the boot this MIG entry follows.
    let Some(ports) = kalloc(size).map(NonNull::cast::<VmOffset>) else {
        return Err(KernError::ResourceShortage);
    };

    let mut slot = 0;
    for cpu in CpuId::all() {
        // SAFETY: the slot is `cpu`'s own `machine_slot`, which the probe
        // filled and the machine never frees.
        if unsafe { (*machine::slot(cpu)).is_cpu } == 0 {
            continue;
        }

        let processor = processor_at(cpu).as_ptr();
        // SAFETY: `slot` is below `count`, the allocation's length; the C
        // stored the processors and converted them in a second pass, and
        // converting each as it is stored leaves the same array.
        unsafe {
            ports.add(slot).write(
                crate::kern::ipc_host::processor_to_port(processor).addr(),
            );
        }
        slot += 1;
    }

    Ok((ports, count))
}

/// The body of `host_processor_sets()` in kern/host.c: the name port of
/// every set on the host, in the array MIG sends back.
///
/// # Safety
///
/// `host`, when [`Some`], must be a live host reference, as the MIG stub
/// that converted the request port promises.
pub(crate) unsafe fn processor_sets(
    host: Option<&Host>,
) -> Result<(*mut *mut c_void, c_uint), KernError> {
    if host.is_none() {
        return Err(KernError::InvalidArgument);
    }

    let lock = processor::all_psets_lock();
    let mut size: usize = 0;
    let mut addr: *mut u8 = ptr::null_mut();
    let actual;
    let size_needed;

    loop {
        // SAFETY: the lock guards `all_psets`.
        unsafe { (*lock).lock() };
        // SAFETY: the lock is held.
        let count = unsafe { *processor::all_psets_count() };
        // The count is the number of live sets, never negative.
        let count = count as usize;
        let needed = count.wrapping_mul(size_of::<usize>());
        if needed <= size {
            actual = count;
            size_needed = needed;
            break;
        }

        // SAFETY: the lock taken above.
        unsafe { (*lock).unlock() };
        if let Some(old) = NonNull::new(addr) {
            // SAFETY: `addr` came from `kalloc(size)`.
            unsafe { kfree(old, size) };
        }
        size = needed;
        let Some(buffer) = kalloc(size) else {
            return Err(KernError::ResourceShortage);
        };
        addr = buffer.as_ptr();
    }

    let psets = addr.cast::<*mut c_void>();
    // SAFETY: the lock is held, the list was initialized by
    // `processor_set_create()`, and every link is a live set.
    let list = unsafe { processor::all_psets() };
    let mut cursor = list.cursor_front();
    for i in 0..actual {
        let Some(pset) = cursor.current_ptr() else {
            break;
        };
        cursor.move_next();
        let pset = pset.as_ptr();
        // SAFETY: `pset` is a live set in the locked list.
        unsafe {
            (*pset).reference();
            // SAFETY: `i` is below `actual`, the allocation's slot count.
            psets.add(i).write(pset.cast());
        }
    }
    // SAFETY: the lock taken above.
    unsafe { (*lock).unlock() };

    let mut psets = psets;
    if size_needed < size {
        let Some(buffer) = kalloc(size_needed) else {
            for i in 0..actual {
                // SAFETY: every slot below `actual` holds a referenced set.
                let pset = unsafe { psets.add(i).read() };
                // SAFETY: the reference came from the loop above.
                unsafe { (*pset.cast::<ProcessorSet>()).deallocate() };
            }
            // SAFETY: `addr` came from `kalloc(size)`.
            unsafe { kfree(NonNull::new_unchecked(addr), size) };
            return Err(KernError::ResourceShortage);
        };
        let newaddr = buffer.as_ptr();

        // SAFETY: `size_needed <= size`, and both regions are live
        // allocations.
        unsafe {
            ptr::copy_nonoverlapping(addr, newaddr, size_needed);
            kfree(NonNull::new_unchecked(addr), size);
        }
        psets = newaddr.cast::<*mut c_void>();
    }

    for i in 0..actual {
        // SAFETY: every slot below `actual` holds a referenced set, which
        // `pset_name_to_port()` consumes.
        let pset = unsafe { psets.add(i).read() };
        // SAFETY: the set is referenced and live.
        let port = unsafe { pset_name_to_port(pset.cast::<ProcessorSet>()) };
        // SAFETY: the slot is writable.
        unsafe { psets.add(i).write(port) };
    }

    Ok((psets, actual as c_uint))
}

/// The C `struct host` is two pointers, in the order `Host` mirrors.
const _: () = {
    const PTR: usize = size_of::<*mut c_void>();
    assert!(size_of::<Host>() == 2 * PTR);
    assert!(align_of::<Host>() == align_of::<*mut c_void>());
    assert!(offset_of!(Host, host_self) == 0);
    assert!(offset_of!(Host, host_priv_self) == PTR);
};

// The `all_psets` head is two words.
const _: () = assert!(size_of::<PsetList>() == 2 * size_of::<*mut c_void>());
