// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_debug.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// Derived from mach_debug/vm_info.h and mach_debug/hash_info.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The VM debugging calls, which `vm/vm_debug.c` used to define, and the
//! `mach_debug/vm_info.h` records they fill.

use crate::arch::types::{RpcPhysAddr, VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::pmap::pmap_is_modified;
use crate::arch::x86_64::pmap::pmap_is_referenced;
use crate::ipc::ipc_init;
use crate::ipc::{HashInfoBucket, IpcPort, ipc_port};
use crate::kern::debug::kpanic;
use crate::kern::host::Host;
use crate::vm::error::Error;
use crate::vm::types::{VmObject, VmPage};
use crate::vm::vm_kern::{kmem_alloc, kmem_alloc_pageable, kmem_free};
use crate::vm::vm_map::{VmMap, round_page};
use crate::vm::vm_resident;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{NonNull, addr_of_mut, null_mut, with_exposed_provenance_mut};

/// `VOI_STATE_*` of <`mach_debug/vm_info.h>`: the object-state bits.
const VOI_STATE_PAGER_CREATED: c_uint = 0x0000_0001;
const VOI_STATE_PAGER_INITIALIZED: c_uint = 0x0000_0002;
const VOI_STATE_PAGER_READY: c_uint = 0x0000_0004;
const VOI_STATE_CAN_PERSIST: c_uint = 0x0000_0008;
const VOI_STATE_INTERNAL: c_uint = 0x0000_0010;
const VOI_STATE_TEMPORARY: c_uint = 0x0000_0020;
const VOI_STATE_ALIVE: c_uint = 0x0000_0040;
const VOI_STATE_LOCK_IN_PROGRESS: c_uint = 0x0000_0080;
const VOI_STATE_LOCK_RESTART: c_uint = 0x0000_0100;

/// `VPI_STATE_*` of <`mach_debug/vm_info.h>`: the page-state bits.
const VPI_STATE_BUSY: c_uint = 0x0000_0001;
const VPI_STATE_WANTED: c_uint = 0x0000_0002;
const VPI_STATE_TABLED: c_uint = 0x0000_0004;
const VPI_STATE_FICTITIOUS: c_uint = 0x0000_0008;
const VPI_STATE_PRIVATE: c_uint = 0x0000_0010;
const VPI_STATE_ABSENT: c_uint = 0x0000_0020;
const VPI_STATE_ERROR: c_uint = 0x0000_0040;
const VPI_STATE_DIRTY: c_uint = 0x0000_0080;
const VPI_STATE_PRECIOUS: c_uint = 0x0000_0100;
const VPI_STATE_OVERWRITING: c_uint = 0x0000_0200;
const VPI_STATE_INACTIVE: c_uint = 0x0000_0400;
const VPI_STATE_ACTIVE: c_uint = 0x0000_0800;
const VPI_STATE_LAUNDRY: c_uint = 0x0000_1000;
const VPI_STATE_FREE: c_uint = 0x0000_2000;
const VPI_STATE_REFERENCE: c_uint = 0x0000_4000;

/// `VPI_STATE_NODATA`: the bits that mean the page holds no data to inspect.
const VPI_STATE_NODATA: c_uint = VPI_STATE_BUSY
    | VPI_STATE_FICTITIOUS
    | VPI_STATE_PRIVATE
    | VPI_STATE_ABSENT;

/// `vm_region_info_t` of <`mach_debug/vm_info.h`>.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmRegionInfo {
    pub vri_start: VmOffset,
    pub vri_end: VmOffset,
    pub vri_protection: c_int,
    pub vri_max_protection: c_int,
    pub vri_inheritance: c_int,
    pub vri_wired_count: c_uint,
    pub vri_user_wired_count: c_uint,
    pub vri_object: VmOffset,
    pub vri_offset: VmOffset,
    pub vri_needs_copy: c_int,
    pub vri_sharing: c_uint,
}

const _: () = {
    assert!(size_of::<VmRegionInfo>() == 64);
    assert!(align_of::<VmRegionInfo>() == 8);
    assert!(offset_of!(VmRegionInfo, vri_start) == 0);
    assert!(offset_of!(VmRegionInfo, vri_end) == 8);
    assert!(offset_of!(VmRegionInfo, vri_protection) == 16);
    assert!(offset_of!(VmRegionInfo, vri_max_protection) == 20);
    assert!(offset_of!(VmRegionInfo, vri_inheritance) == 24);
    assert!(offset_of!(VmRegionInfo, vri_wired_count) == 28);
    assert!(offset_of!(VmRegionInfo, vri_user_wired_count) == 32);
    assert!(offset_of!(VmRegionInfo, vri_object) == 40);
    assert!(offset_of!(VmRegionInfo, vri_offset) == 48);
    assert!(offset_of!(VmRegionInfo, vri_needs_copy) == 56);
    assert!(offset_of!(VmRegionInfo, vri_sharing) == 60);
};

/// `vm_object_info_t` of <`mach_debug/vm_info.h`>.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmObjectInfo {
    pub voi_object: VmOffset,
    pub voi_pagesize: VmSize,
    pub voi_size: VmSize,
    pub voi_ref_count: c_uint,
    pub voi_resident_page_count: c_uint,
    pub voi_absent_count: c_uint,
    pub voi_copy: VmOffset,
    pub voi_shadow: VmOffset,
    pub voi_shadow_offset: VmOffset,
    pub voi_paging_offset: VmOffset,
    pub voi_copy_strategy: c_int,
    pub voi_last_alloc: VmOffset,
    pub voi_paging_in_progress: c_uint,
    pub voi_state: c_uint,
}

const _: () = {
    assert!(size_of::<VmObjectInfo>() == 96);
    assert!(align_of::<VmObjectInfo>() == 8);
    assert!(offset_of!(VmObjectInfo, voi_object) == 0);
    assert!(offset_of!(VmObjectInfo, voi_pagesize) == 8);
    assert!(offset_of!(VmObjectInfo, voi_size) == 16);
    assert!(offset_of!(VmObjectInfo, voi_ref_count) == 24);
    assert!(offset_of!(VmObjectInfo, voi_resident_page_count) == 28);
    assert!(offset_of!(VmObjectInfo, voi_absent_count) == 32);
    assert!(offset_of!(VmObjectInfo, voi_copy) == 40);
    assert!(offset_of!(VmObjectInfo, voi_shadow) == 48);
    assert!(offset_of!(VmObjectInfo, voi_shadow_offset) == 56);
    assert!(offset_of!(VmObjectInfo, voi_paging_offset) == 64);
    assert!(offset_of!(VmObjectInfo, voi_copy_strategy) == 72);
    assert!(offset_of!(VmObjectInfo, voi_last_alloc) == 80);
    assert!(offset_of!(VmObjectInfo, voi_paging_in_progress) == 88);
    assert!(offset_of!(VmObjectInfo, voi_state) == 92);
};

/// `vm_page_info_t` of <`mach_debug/vm_info.h>`: the object-local record, whose
/// physical address is a `vm_offset_t`.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmPageInfo {
    pub vpi_offset: VmOffset,
    pub vpi_phys_addr: VmOffset,
    pub vpi_wire_count: c_uint,
    pub vpi_page_lock: c_int,
    pub vpi_unlock_request: c_int,
    pub vpi_state: c_uint,
}

const _: () = {
    assert!(size_of::<VmPageInfo>() == 32);
    assert!(align_of::<VmPageInfo>() == 8);
    assert!(offset_of!(VmPageInfo, vpi_offset) == 0);
    assert!(offset_of!(VmPageInfo, vpi_phys_addr) == 8);
    assert!(offset_of!(VmPageInfo, vpi_wire_count) == 16);
    assert!(offset_of!(VmPageInfo, vpi_page_lock) == 20);
    assert!(offset_of!(VmPageInfo, vpi_unlock_request) == 24);
    assert!(offset_of!(VmPageInfo, vpi_state) == 28);
};

/// `vm_page_phys_info_t` of <`mach_debug/vm_info.h>`: the interface record,
/// whose physical address is the 64-bit `rpc_phys_addr_t`.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmPagePhysInfo {
    pub vpi_offset: VmOffset,
    pub vpi_phys_addr: RpcPhysAddr,
    pub vpi_wire_count: c_uint,
    pub vpi_page_lock: c_int,
    pub vpi_unlock_request: c_int,
    pub vpi_state: c_uint,
}

const _: () = {
    assert!(size_of::<VmPagePhysInfo>() == 32);
    assert!(align_of::<VmPagePhysInfo>() == 8);
    assert!(offset_of!(VmPagePhysInfo, vpi_offset) == 0);
    assert!(offset_of!(VmPagePhysInfo, vpi_phys_addr) == 8);
    assert!(offset_of!(VmPagePhysInfo, vpi_wire_count) == 16);
    assert!(offset_of!(VmPagePhysInfo, vpi_page_lock) == 20);
    assert!(offset_of!(VmPagePhysInfo, vpi_unlock_request) == 24);
    assert!(offset_of!(VmPagePhysInfo, vpi_state) == 28);
};

/// A table count as an index; the widening is lossless.
const fn as_index(count: c_uint) -> usize {
    count as usize
}

/// `panic()` of `vm_debug.c`; the C called it with the routine name as both
/// tags.
fn die(message: &'static str) -> ! {
    kpanic!("_mach_vm_object_pages", "{}", message)
}

/// `vm_object_real_name()` in C: a send right for the object's name port, or
/// `IP_NULL` when the object or its name port is null.
///
/// # Safety
///
/// `object` must be null or a live object; nothing may be locked.
unsafe fn object_real_name(object: *mut VmObject) -> *mut c_void {
    let Some(object) = NonNull::new(object) else {
        return null_mut();
    };

    unsafe {
        (*object.as_ptr()).lock.lock();
        let name = (*object.as_ptr()).pager_name;
        let port = if name.is_null() {
            null_mut()
        } else {
            ipc_port::make_send(IpcPort::from_raw(name)).as_ptr()
        };
        (*object.as_ptr()).lock.unlock();
        port
    }
}

/// `mach_vm_region_info()` in C: the region containing or following
/// `address`, and a send right for its object's name port.
///
/// # Safety
///
/// `map` must be null or a live, unlocked map, and the caller must permit
/// taking the map's read lock.
pub(crate) unsafe fn region_info(
    map: *mut VmMap,
    address: VmOffset,
) -> Result<(VmRegionInfo, *mut c_void), Error> {
    if map.is_null() {
        return Err(Error::InvalidTask);
    }
    let map = unsafe { NonNull::new_unchecked(map) };
    let mut address = address;
    let mut cmap = map;

    // SAFETY: the map is live and unlocked.
    unsafe { (*map.as_ptr()).lock.read() };

    let entry = loop {
        // SAFETY: `cmap` is live and read-locked.
        let (found, entry) = unsafe { (*cmap.as_ptr()).lookup_entry(address) };
        let entry = if found {
            entry
        } else {
            // SAFETY: `entry` came from the locked map; its next link is the
            // sentinel or a live entry.
            let next = unsafe { (*entry.as_ptr()).links.next }
                .unwrap_or_else(|| unsafe { (*cmap.as_ptr()).to_entry() });
            // SAFETY: `cmap` is live and read-locked.
            if next == unsafe { (*cmap.as_ptr()).to_entry() } {
                if map == cmap {
                    // SAFETY: the read lock was taken above.
                    unsafe { (*cmap.as_ptr()).lock.done() };
                    return Err(Error::NoSpace);
                }

                // Back out to the top-level map and skip this submap.
                // SAFETY: `cmap` is live and read-locked.
                address = unsafe { (*cmap.as_ptr()).hdr.links.end };
                // SAFETY: the read lock was taken above.
                unsafe { (*cmap.as_ptr()).lock.done() };
                cmap = map;
                // SAFETY: the top-level map is live and unlocked again.
                unsafe { (*map.as_ptr()).lock.read() };
                continue;
            }
            next
        };

        // SAFETY: `entry` is a live entry of the read-locked map.
        if unsafe { (*entry.as_ptr()).is_sub_map() } {
            // SAFETY: a submap entry names a live map.
            let nmap = unsafe { (*entry.as_ptr()).object.sub_map };
            // SAFETY: the submap entry names a live map.
            let nmap = unsafe { NonNull::new_unchecked(nmap) };
            // SAFETY: the submap is live and unlocked.
            unsafe { (*nmap.as_ptr()).lock.read() };
            // SAFETY: `cmap` was read-locked.
            unsafe { (*cmap.as_ptr()).lock.done() };
            cmap = nmap;
            continue;
        }

        break entry;
    };

    // SAFETY: `entry` is a live entry of the read-locked `cmap`.
    let entry = unsafe { &*entry.as_ptr() };
    // SAFETY: `entry` is a live entry of the read-locked map.
    let object = unsafe { entry.object.vm_object };
    let info = VmRegionInfo {
        vri_start: entry.links.start,
        vri_end: entry.links.end,
        vri_protection: entry.protection.bits(),
        vri_max_protection: entry.max_protection.bits(),
        vri_inheritance: entry.inheritance.bits(),
        vri_wired_count: c_uint::from(entry.wired_count != 0),
        vri_user_wired_count: c_uint::from(entry.wired_count != 0),
        vri_object: object.expose_provenance(),
        vri_offset: entry.offset,
        vri_needs_copy: c_int::from(entry.needs_copy()),
        vri_sharing: c_uint::from(entry.is_shared()),
    };
    // SAFETY: the object is live or null; the C takes its lock here while the
    // map read lock is still held.
    let port = unsafe { object_real_name(object) };
    // SAFETY: `cmap` was read-locked, as above.
    unsafe { (*cmap.as_ptr()).lock.done() };

    Ok((info, port))
}

/// `mach_vm_object_info()` in C: the object's record and send rights for its
/// shadow and copy objects' name ports.
///
/// # Safety
///
/// `object` must be null or a live object; nothing may be locked.
pub(crate) unsafe fn object_info(
    object: *mut VmObject,
) -> Result<(VmObjectInfo, *mut c_void, *mut c_void), Error> {
    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };
    let object = object.as_ptr();

    // Because of lock-ordering considerations, the copy object's name port
    // is fetched here rather than through `object_real_name()`.
    let copy;
    loop {
        unsafe { (*object).lock.lock() };
        let mut this_copy = null_mut();
        // SAFETY: the object is live and its lock is held.
        let copy_object = unsafe { (*object).copy };
        if !copy_object.is_null() {
            // SAFETY: the object lock is held and the copy object is live.
            if !unsafe { (*copy_object).lock.try_lock() } {
                // SAFETY: the object lock was taken above.
                unsafe { (*object).lock.unlock() };
                crate::arch::x86_64::mp_desc::simple_lock_pause();
                continue;
            }

            // SAFETY: the copy object is locked.
            if !unsafe { (*copy_object).pager_name.is_null() } {
                // SAFETY: a non-null pager name is a live port.
                this_copy = unsafe {
                    ipc_port::make_send(IpcPort::from_raw(
                        (*copy_object).pager_name,
                    ))
                }
                .as_ptr();
            }
            // SAFETY: the copy object was locked above.
            unsafe { (*copy_object).lock.unlock() };
        }
        copy = this_copy;
        break;
    }

    // SAFETY: the object lock is held and the shadow is live or null.
    let shadow = unsafe { object_real_name((*object).shadow) };

    // SAFETY: the object lock is held.
    let info = unsafe {
        let mut state = 0;
        if (*object).is_pager_created() {
            state |= VOI_STATE_PAGER_CREATED;
        }
        if (*object).is_pager_initialized() {
            state |= VOI_STATE_PAGER_INITIALIZED;
        }
        if (*object).is_pager_ready() {
            state |= VOI_STATE_PAGER_READY;
        }
        if (*object).can_persist() {
            state |= VOI_STATE_CAN_PERSIST;
        }
        if (*object).is_internal() {
            state |= VOI_STATE_INTERNAL;
        }
        if (*object).is_temporary() {
            state |= VOI_STATE_TEMPORARY;
        }
        if (*object).is_alive() {
            state |= VOI_STATE_ALIVE;
        }
        if (*object).is_lock_in_progress() {
            state |= VOI_STATE_LOCK_IN_PROGRESS;
        }
        if (*object).is_lock_restart() {
            state |= VOI_STATE_LOCK_RESTART;
        }

        VmObjectInfo {
            voi_object: object.expose_provenance(),
            voi_pagesize: PAGE_SIZE,
            voi_size: (*object).size,
            // The C assigned the two counts to `unsigned int` fields; those
            // many references or pages cannot exist.
            voi_ref_count: (*object).ref_count as c_uint,
            voi_resident_page_count: (*object).resident_page_count as c_uint,
            voi_absent_count: (*object).absent_count,
            voi_copy: (*object).copy.expose_provenance(),
            voi_shadow: (*object).shadow.expose_provenance(),
            voi_shadow_offset: (*object).shadow_offset,
            voi_paging_offset: (*object).paging_offset,
            voi_copy_strategy: (*object).copy_strategy,
            voi_last_alloc: (*object).last_alloc,
            voi_paging_in_progress: (*object).paging_in_progress(),
            voi_state: state,
        }
    };

    // SAFETY: the object lock was taken above.
    unsafe { (*object).lock.unlock() };

    Ok((info, shadow, copy))
}

/// The record `mach_vm_object_pages*()` fills for one resident page.
trait PageRecord {
    /// `sizeof` the record.
    const SIZE: usize;

    /// The record for one page and its computed state bits.
    fn new(page: &VmPage, state: c_uint) -> Self;
}

impl PageRecord for VmPageInfo {
    const SIZE: usize = size_of::<Self>();

    fn new(page: &VmPage, state: c_uint) -> Self {
        // The C's cast to `rpc_vm_offset_t` widens, so its overflow warning
        // is dead.
        Self {
            vpi_offset: page.offset,
            vpi_phys_addr: page.phys_addr,
            vpi_wire_count: page.wire_count(),
            vpi_page_lock: page.page_lock().bits(),
            vpi_unlock_request: page.unlock_request().bits(),
            vpi_state: state,
        }
    }
}

impl PageRecord for VmPagePhysInfo {
    const SIZE: usize = size_of::<Self>();

    fn new(page: &VmPage, state: c_uint) -> Self {
        Self {
            vpi_offset: page.offset,
            vpi_phys_addr: RpcPhysAddr::from_vm_offset(page.phys_addr),
            vpi_wire_count: page.wire_count(),
            vpi_page_lock: page.page_lock().bits(),
            vpi_unlock_request: page.unlock_request().bits(),
            vpi_state: state,
        }
    }
}

/// The state bits `_mach_vm_object_pages()` computes for one page, including
/// the two `pmap_is_*()` probes.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
unsafe fn page_state(page: *mut VmPage) -> c_uint {
    unsafe {
        let page_ref = &mut *page;
        let mut state = 0;
        if page_ref.is_busy() {
            state |= VPI_STATE_BUSY;
        }
        if page_ref.is_wanted() {
            state |= VPI_STATE_WANTED;
        }
        if page_ref.is_tabled() {
            state |= VPI_STATE_TABLED;
        }
        if page_ref.is_fictitious() {
            state |= VPI_STATE_FICTITIOUS;
        }
        if page_ref.is_private() {
            state |= VPI_STATE_PRIVATE;
        }
        if page_ref.is_absent() {
            state |= VPI_STATE_ABSENT;
        }
        if page_ref.is_error() {
            state |= VPI_STATE_ERROR;
        }
        if page_ref.is_dirty() {
            state |= VPI_STATE_DIRTY;
        }
        if page_ref.is_precious() {
            state |= VPI_STATE_PRECIOUS;
        }
        if page_ref.is_overwriting() {
            state |= VPI_STATE_OVERWRITING;
        }

        if state & (VPI_STATE_NODATA | VPI_STATE_DIRTY) == 0
            && pmap_is_modified(page_ref.phys_addr) != 0
        {
            state |= VPI_STATE_DIRTY;
            page_ref.set_dirty(true);
        }

        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock();
        if page_ref.is_inactive() {
            state |= VPI_STATE_INACTIVE;
        }
        if page_ref.is_active() {
            state |= VPI_STATE_ACTIVE;
        }
        if page_ref.is_laundry() {
            state |= VPI_STATE_LAUNDRY;
        }
        if page_ref.is_free() {
            state |= VPI_STATE_FREE;
        }
        if page_ref.is_reference() {
            state |= VPI_STATE_REFERENCE;
        }

        if state & (VPI_STATE_NODATA | VPI_STATE_REFERENCE) == 0
            && pmap_is_referenced(page_ref.phys_addr) != 0
        {
            state |= VPI_STATE_REFERENCE;
            page_ref.set_reference(true);
        }
        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();

        state
    }
}

/// `_mach_vm_object_pages()` in C, generic over the record the caller asked
/// for.
///
/// # Safety
///
/// `object` must be null or a live object, `pagesp` must be writable storage
/// for one array pointer and `countp` for one count; the caller permits an
/// allocation and a kernel-map copy.
unsafe fn object_pages<R: PageRecord>(
    object: *mut VmObject,
    pagesp: *mut *mut c_void,
    countp: *mut c_uint,
) -> Result<(), Error> {
    if object.is_null() {
        return Err(Error::InvalidArgument);
    }

    let map = ipc_init::ipc_kernel_map();
    // SAFETY: the kernel map is live once VM is up.
    let map = unsafe { NonNull::new_unchecked(map) };

    let initial = unsafe { *pagesp };
    let initial = initial.cast::<u8>();
    let mut pages = initial;
    let mut potential = unsafe { *countp };
    let mut addr: VmOffset = 0;
    let mut size: VmSize = 0;

    let actual = loop {
        unsafe { (*object).lock.lock() };
        // The C assigned the unsigned long count to an unsigned int; that
        // many resident pages cannot exist.
        // SAFETY: the object is live and its lock is held.
        let actual = unsafe { (*object).resident_page_count } as c_uint;
        if actual <= potential {
            break actual;
        }
        // SAFETY: the object was locked above.
        unsafe { (*object).lock.unlock() };

        if pages != initial {
            // SAFETY: the region came from the kernel-map allocation below.
            let _ = unsafe { kmem_free(&mut *map.as_ptr(), addr, size) };
        }

        size = round_page(as_index(actual) * R::SIZE);
        // SAFETY: the kernel map is live, nothing is locked, and the caller
        // permits the allocation.
        addr = kmem_alloc(map, size)?;
        pages = with_exposed_provenance_mut(addr);
        potential = (size / R::SIZE) as c_uint;
    };

    let mut count: c_uint = 0;
    // SAFETY: the object is live and its lock is held.
    let head = unsafe { addr_of_mut!((*object).memq) };
    // SAFETY: the object is locked, so its page list is stable.
    let mut cursor = unsafe { (*head).cursor_front() };
    while let Some(e) = cursor.current_ptr() {
        cursor.move_next();
        let page = e.as_ptr();
        // SAFETY: the page is live while the object lock is held.
        let state = unsafe { page_state(page) };
        // The loop stops at `actual` records, the count the allocation above
        // sized `pages` for.
        // SAFETY: `count` stays below `potential`, the record count.
        let dst = unsafe { pages.add(as_index(count) * R::SIZE).cast::<R>() };
        // SAFETY: `dst` is inside the `potential`-record buffer, and the page
        // is live.
        unsafe { dst.write(R::new(&*page, state)) };
        count += 1;
    }

    // SAFETY: the object is live and its lock is held.
    if unsafe { (*object).resident_page_count != as_index(count) } {
        // The C `panic()` does not return.
        die("mach_vm_object_pages");
    }
    // SAFETY: the object was locked above.
    unsafe { (*object).lock.unlock() };

    if pages == initial {
        // The data fit in-line; nothing to deallocate.
        unsafe { *countp = actual };
    } else if actual == 0 {
        // SAFETY: the region came from the kernel-map allocation above.
        let _ = unsafe { kmem_free(&mut *map.as_ptr(), addr, size) };
        unsafe { *countp = 0 };
    } else {
        let size_used = as_index(actual) * R::SIZE;
        let rsize_used = round_page(size_used);

        // `kmem_alloc` does not zero memory.
        if rsize_used != size {
            // SAFETY: the tail of the region came from the same allocation.
            let _ = unsafe {
                kmem_free(
                    &mut *map.as_ptr(),
                    addr + rsize_used,
                    size - rsize_used,
                )
            };
        }
        if size_used != rsize_used {
            // SAFETY: the region is `rsize_used` bytes long, as above.
            unsafe {
                core::ptr::write_bytes(
                    with_exposed_provenance_mut::<u8>(addr + size_used),
                    0,
                    rsize_used - size_used,
                );
            };
        }

        // SAFETY: the region is live in the kernel map, the map is unlocked,
        // and the caller permits the copy.
        if let Ok(copy) =
            unsafe { (*map.as_ptr()).copyin(addr, rsize_used, true) }
        {
            unsafe { *pagesp = copy.as_ptr().cast() };
        }
        unsafe { *countp = actual };
    }

    Ok(())
}

/// `mach_vm_object_pages()` in C.
///
/// # Safety
///
/// Same contract as [`object_pages()`].
pub(crate) unsafe fn object_pages_info(
    object: *mut VmObject,
    pagesp: *mut *mut c_void,
    countp: *mut c_uint,
) -> Result<(), Error> {
    unsafe { object_pages::<VmPageInfo>(object, pagesp, countp) }
}

/// `mach_vm_object_pages_phys()` in C.
///
/// # Safety
///
/// Same contract as [`object_pages()`].
pub(crate) unsafe fn object_pages_phys(
    object: *mut VmObject,
    pagesp: *mut *mut c_void,
    countp: *mut c_uint,
) -> Result<(), Error> {
    unsafe { object_pages::<VmPagePhysInfo>(object, pagesp, countp) }
}

/// `host_virtual_physical_table_info()` in C.
///
/// # Safety
///
/// `host` must be null or the live host pointer the generated server
/// converted the request port into; `infop` and `countp` must be writable
/// storage, and the caller permits an allocation and a kernel-map copy.
pub(crate) unsafe fn virtual_physical_table_info(
    host: Option<NonNull<Host>>,
    infop: *mut *mut HashInfoBucket,
    countp: *mut c_uint,
) -> Result<(), Error> {
    if host.is_none() {
        return Err(Error::InvalidHost);
    }

    let initial = unsafe { *infop };
    let mut info = initial;
    let mut potential = unsafe { *countp };
    let mut addr: VmOffset = 0;
    let mut size: VmSize = 0;

    let map = ipc_init::ipc_kernel_map();

    let actual = loop {
        // SAFETY: `info` holds `potential` writable records, and nothing is
        // locked.
        let actual = unsafe { vm_resident::info(info, potential) };
        if actual <= potential {
            break actual;
        }

        if info != initial {
            // SAFETY: `info` came from the kernel-map allocation below.
            let _ = unsafe { kmem_free(&mut *map, addr, size) };
        }

        size = round_page(as_index(actual) * size_of::<HashInfoBucket>());
        // SAFETY: the kernel map is live, nothing is locked, and the caller
        // permits the allocation.
        addr = unsafe { kmem_alloc_pageable(&mut *map, size) }?;
        info = with_exposed_provenance_mut(addr);
        potential = (size / size_of::<HashInfoBucket>()) as c_uint;
    };

    if info == initial {
        // The data fit in-line; nothing to deallocate.
        unsafe { *countp = actual };
        return Ok(());
    }

    if actual == 0 {
        // SAFETY: the region came from the kernel-map allocation above.
        let _ = unsafe { kmem_free(&mut *map, addr, size) };
        unsafe { *countp = 0 };
        return Ok(());
    }

    let used = round_page(as_index(actual) * size_of::<HashInfoBucket>());
    if used != size {
        // SAFETY: the tail of the region came from the same allocation.
        let _ = unsafe { kmem_free(&mut *map, addr + used, size - used) };
    }

    // SAFETY: the region is live in the kernel map, the map is unlocked, and
    // the caller permits the copy.
    if let Ok(copy) = unsafe { (*map).copyin(addr, used, true) } {
        unsafe { *infop = copy.as_ptr().cast() };
    }
    unsafe { *countp = actual };

    Ok(())
}
