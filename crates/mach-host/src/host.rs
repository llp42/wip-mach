// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The host object and the host calls' cores.

use crate::error::Error;
use crate::machine;
use crate::platform::Platform;
use core::ffi::{c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};
use mach_thread::ipc_processor;
use mach_thread::ipc_processor::pset_name_to_port;
use mach_thread::processor::processor_at;
use mach_thread::processor_set::ProcessorSet;
use mach_thread::smp::CpuId;
use mach_vm::param::VmOffset;

/// The host object MIG hands the host routines.
///
/// The ports are stored once, by the host initialization, and read by any
/// CPU after it: Release and Acquire, so a reader sees the port it names.
#[repr(C)]
#[allow(missing_docs)]
pub struct Host {
    pub host_self: AtomicPtr<c_void>,
    pub host_priv_self: AtomicPtr<c_void>,
}

/// The one host object.
static REALHOST: Host = Host {
    host_self: AtomicPtr::new(ptr::null_mut()),
    host_priv_self: AtomicPtr::new(ptr::null_mut()),
};

/// The address of the one host object, which the host ports name.
#[must_use]
pub const fn realhost() -> *mut Host {
    ptr::from_ref(&REALHOST).cast_mut()
}

/// The host's self port, live from the host initialization on.
#[must_use]
pub fn host_self() -> *mut c_void {
    REALHOST.host_self.load(Ordering::Acquire)
}

/// The host's privileged self port, live from the host initialization on.
#[must_use]
pub fn host_priv_self() -> *mut c_void {
    REALHOST.host_priv_self.load(Ordering::Acquire)
}

/// A live host and a live name set give back the same set with one more
/// reference.
pub fn processor_set_priv<P: Platform>(
    host: Option<NonNull<Host>>,
    name: Option<&mut ProcessorSet<P>>,
) -> Result<NonNull<ProcessorSet<P>>, Error> {
    match (host, name) {
        (Some(_), Some(set)) => {
            set.reference();
            Ok(NonNull::from(set))
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Allocates the array the reply carries, walks the set's processor queue and
/// converts each processor to its name port.
pub fn processor_ports<P: Platform>(
    pset: &mut ProcessorSet<P>,
) -> Result<(NonNull<VmOffset>, c_uint), Error> {
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
    let Some(ports) = P::kalloc(size).map(NonNull::cast::<*mut c_void>) else {
        pset.lock.unlock();
        return Err(Error::ResourceShortage);
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
            // processor whose name port `ipc_processor::processor_init` built, and
            // `i` is below `count`, inside the allocation.
            ports
                .add(i)
                .write(ipc_processor::processor_name_to_port(processor));
            i += 1;
        }
    }

    pset.lock.unlock();
    Ok((ports.cast::<VmOffset>(), count))
}

/// The control port of every CPU the machine reports.
///
/// # Panics
///
/// When the machine reports no CPU: the boot CPU is always one.
pub fn processors<P: Platform>(
    host: Option<NonNull<Host>>,
) -> Result<(NonNull<VmOffset>, c_uint), Error> {
    if host.is_none() {
        return Err(Error::InvalidArgument);
    }

    let mut count: c_uint = 0;
    for cpu in CpuId::all() {
        if machine::slot(cpu).is_cpu.load(Ordering::Relaxed) != 0 {
            count += 1;
        }
    }

    assert!(count != 0, "host_processors");

    // The C count holds at most `MAX_NCPUS` slots, so the widening cannot
    // lose a bit.
    let slots = count as usize;
    let size = slots * size_of::<VmOffset>();

    // `kalloc_init()` ran during the boot this MIG entry follows.
    let Some(ports) = P::kalloc(size).map(NonNull::cast::<VmOffset>) else {
        return Err(Error::ResourceShortage);
    };

    let mut slot = 0;
    for cpu in CpuId::all() {
        if machine::slot(cpu).is_cpu.load(Ordering::Relaxed) == 0 {
            continue;
        }

        let processor = processor_at::<P>(cpu).as_ptr();
        // SAFETY: `slot` is below `count`, the allocation's length; the C
        // stored the processors and converted them in a second pass, and
        // converting each as it is stored leaves the same array.
        unsafe {
            ports
                .add(slot)
                .write(ipc_processor::processor_to_port(processor).addr());
        }
        slot += 1;
    }

    Ok((ports, count))
}

/// The name port of every set on the host, in the array the reply carries.
///
/// # Safety
///
/// `host`, when [`Some`], must be a live host reference, as the MIG stub
/// that converted the request port promises.
pub unsafe fn processor_sets<P: Platform>(
    host: Option<&Host>,
) -> Result<(*mut *mut c_void, c_uint), Error> {
    if host.is_none() {
        return Err(Error::InvalidArgument);
    }

    let mut size: usize = 0;
    let mut addr: *mut u8 = ptr::null_mut();
    let actual;
    let size_needed;

    let all_psets = loop {
        let all_psets = P::task_state().all_psets.lock();
        let count = all_psets.count as usize;
        let needed = count.wrapping_mul(size_of::<usize>());
        if needed <= size {
            actual = count;
            size_needed = needed;
            break all_psets;
        }

        drop(all_psets);
        if let Some(old) = NonNull::new(addr) {
            // SAFETY: `addr` came from `P::kalloc(size)`.
            unsafe { P::kfree(old, size) };
        }
        size = needed;
        let Some(buffer) = P::kalloc(size) else {
            return Err(Error::ResourceShortage);
        };
        addr = buffer.as_ptr();
    };

    let psets = addr.cast::<*mut c_void>();
    let mut cursor = all_psets.list().cursor_front();
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
    drop(all_psets);

    let mut psets = psets;
    if size_needed < size {
        let Some(buffer) = P::kalloc(size_needed) else {
            for i in 0..actual {
                // SAFETY: every slot below `actual` holds a referenced set.
                let pset = unsafe { psets.add(i).read() };
                // SAFETY: the reference came from the loop above.
                unsafe {
                    (*pset.cast::<ProcessorSet<P>>()).deallocate();
                };
            }
            // SAFETY: `addr` came from `P::kalloc(size)`.
            unsafe { P::kfree(NonNull::new_unchecked(addr), size) };
            return Err(Error::ResourceShortage);
        };
        let newaddr = buffer.as_ptr();

        // SAFETY: `size_needed <= size`, and both regions are live
        // allocations.
        unsafe {
            ptr::copy_nonoverlapping(addr, newaddr, size_needed);
            P::kfree(NonNull::new_unchecked(addr), size);
        }
        psets = newaddr.cast::<*mut c_void>();
    }

    for i in 0..actual {
        // SAFETY: every slot below `actual` holds a referenced set, which
        // `pset_name_to_port()` consumes.
        let pset = unsafe { psets.add(i).read() };
        // SAFETY: the set is referenced and live.
        let port =
            unsafe { pset_name_to_port(pset.cast::<ProcessorSet<P>>()) };
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
