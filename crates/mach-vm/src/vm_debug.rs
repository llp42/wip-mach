// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The VM debugging calls, and the `mach_debug` interface records they fill.

use crate::error::Error;
use crate::param::PAGE_SIZE;
use crate::param::{RpcPhysAddr, VmOffset, VmSize};
use crate::platform::{Platform, Port};
use crate::types::HashInfoBucket;
use crate::types::{ObjectInfoState, PageInfoState};
use crate::types::{VmObject, VmPage};
use crate::vm_kern::{kmem_alloc, kmem_alloc_pageable, kmem_free};
use crate::vm_map::{VmMap, round_page};
use crate::vm_resident;
use crate::vm_resident::VM_PAGE_QUEUE_LOCK;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{NonNull, addr_of_mut, null_mut, with_exposed_provenance_mut};
use lock::lock_api::RawMutex as _;
use zerocopy::{Immutable, IntoBytes};

/// `vm_region_info_t`: the record `mach_vm_region_info()` fills for one map
/// entry.
#[repr(C)]
#[allow(missing_docs)]
#[derive(IntoBytes, Immutable)]
pub struct VmRegionInfo {
    pub vri_start: VmOffset,
    pub vri_end: VmOffset,
    pub vri_protection: c_int,
    pub vri_max_protection: c_int,
    pub vri_inheritance: c_int,
    pub vri_wired_count: c_uint,
    pub vri_user_wired_count: c_uint,
    /// The C compiler's alignment hole, kept zero so no stale kernel byte
    /// reaches a task.
    padding: c_uint,
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

/// `vm_object_info_t`: the record `mach_vm_object_info()` fills for one
/// object.
#[repr(C)]
#[allow(missing_docs)]
#[derive(IntoBytes, Immutable)]
pub struct VmObjectInfo {
    pub voi_object: VmOffset,
    pub voi_pagesize: VmSize,
    pub voi_size: VmSize,
    pub voi_ref_count: c_uint,
    pub voi_resident_page_count: c_uint,
    pub voi_absent_count: c_uint,
    /// The C compiler's alignment hole, kept zero so no stale kernel byte
    /// reaches a task.
    padding0: c_uint,
    pub voi_copy: VmOffset,
    pub voi_shadow: VmOffset,
    pub voi_shadow_offset: VmOffset,
    pub voi_paging_offset: VmOffset,
    pub voi_copy_strategy: c_int,
    /// The C compiler's alignment hole, kept zero so no stale kernel byte
    /// reaches a task.
    padding1: c_int,
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

/// `vm_page_info_t`: the object-local page record, whose physical address is a
/// `vm_offset_t`.
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

/// `vm_page_phys_info_t`: the interface page record, whose physical address is
/// the 64-bit `rpc_phys_addr_t`.
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

/// Halts the kernel with `message`, under the `mach_vm_object_pages` tag.
fn die(message: &'static str) -> ! {
    panic!("{message}")
}

/// A send right for the object's name port, or null when the object or its
/// name port is null.
///
/// # Safety
///
/// `object` must be null or a live object; nothing may be locked.
unsafe fn object_real_name<P: Platform>(object: *mut VmObject) -> *mut c_void {
    let Some(object) = NonNull::new(object) else {
        return null_mut();
    };

    unsafe {
        (*object.as_ptr()).lock.lock();
        let name = (*object.as_ptr()).pager_name;
        let port = if name.is_null() {
            null_mut()
        } else {
            P::port_make_send(Port::from_raw(name)).as_ptr()
        };
        (*object.as_ptr()).lock.unlock();
        port
    }
}

/// The region containing or following `address`, and a send right for its
/// object's name port.
///
/// # Safety
///
/// `map` must be null or a live, unlocked map, and the caller must permit
/// taking the map's read lock.
pub unsafe fn region_info<P: Platform>(
    map: *mut VmMap<P>,
    address: VmOffset,
) -> Result<(VmRegionInfo, *mut c_void), Error> {
    if map.is_null() {
        return Err(Error::InvalidTask);
    }
    let map = unsafe { NonNull::new_unchecked(map) };
    let mut address = address;
    let mut cmap = map;

    // SAFETY: the map is live and unlocked.
    unsafe { (*map.as_ptr()).lock.lock() };

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
                    unsafe { (*cmap.as_ptr()).lock.unlock() };
                    return Err(Error::NoSpace);
                }

                // Back out to the top-level map and skip this submap.
                // SAFETY: `cmap` is live and read-locked.
                address = unsafe { (*cmap.as_ptr()).hdr.links.end };
                // SAFETY: the read lock was taken above.
                unsafe { (*cmap.as_ptr()).lock.unlock() };
                cmap = map;
                // SAFETY: the top-level map is live and unlocked again.
                unsafe { (*map.as_ptr()).lock.lock() };
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
            // The parent is released before the submap is locked: a
            // submap lives as long as the kernel, so the parent's lock
            // need not keep it, and holding both would order the map
            // classes against the slab's.
            // SAFETY: `cmap` was locked above.
            unsafe { (*cmap.as_ptr()).lock.unlock() };
            // SAFETY: the submap is live and unlocked.
            unsafe { (*nmap.as_ptr()).lock.lock() };
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
        padding: 0,
        vri_object: object.expose_provenance(),
        vri_offset: entry.offset,
        vri_needs_copy: c_int::from(entry.needs_copy()),
        vri_sharing: c_uint::from(entry.is_shared()),
    };
    // SAFETY: the object is live or null; the C takes its lock here while the
    // map read lock is still held.
    let port = unsafe { object_real_name::<P>(object) };
    // SAFETY: `cmap` was read-locked, as above.
    unsafe { (*cmap.as_ptr()).lock.unlock() };

    Ok((info, port))
}

/// The object's record and send rights for its shadow and copy objects' name
/// ports.
///
/// # Safety
///
/// `object` must be null or a live object; nothing may be locked.
pub unsafe fn object_info<P: Platform>(
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
                P::lock_pause();
                continue;
            }

            // SAFETY: the copy object is locked.
            if !unsafe { (*copy_object).pager_name.is_null() } {
                // SAFETY: a non-null pager name is a live port.
                this_copy = unsafe {
                    P::port_make_send(Port::from_raw(
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
    let shadow = unsafe { object_real_name::<P>((*object).shadow) };

    // SAFETY: the object lock is held.
    let info = unsafe {
        let mut state = ObjectInfoState::empty();
        if (*object).is_pager_created() {
            state |= ObjectInfoState::PAGER_CREATED;
        }
        if (*object).is_pager_initialized() {
            state |= ObjectInfoState::PAGER_INITIALIZED;
        }
        if (*object).is_pager_ready() {
            state |= ObjectInfoState::PAGER_READY;
        }
        if (*object).can_persist() {
            state |= ObjectInfoState::CAN_PERSIST;
        }
        if (*object).is_internal() {
            state |= ObjectInfoState::INTERNAL;
        }
        if (*object).is_temporary() {
            state |= ObjectInfoState::TEMPORARY;
        }
        if (*object).is_alive() {
            state |= ObjectInfoState::ALIVE;
        }
        if (*object).is_lock_in_progress() {
            state |= ObjectInfoState::LOCK_IN_PROGRESS;
        }
        if (*object).is_lock_restart() {
            state |= ObjectInfoState::LOCK_RESTART;
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
            padding0: 0,
            voi_copy: (*object).copy.expose_provenance(),
            voi_shadow: (*object).shadow.expose_provenance(),
            voi_shadow_offset: (*object).shadow_offset,
            voi_paging_offset: (*object).paging_offset,
            voi_copy_strategy: (*object).copy_strategy,
            padding1: 0,
            voi_last_alloc: (*object).last_alloc,
            voi_paging_in_progress: (*object).paging_in_progress(),
            voi_state: state.bits(),
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

/// The state bits [`object_pages`] reports for one page, including the two
/// `pmap_is_*()` probes.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
unsafe fn page_state<P: Platform>(page: *mut VmPage) -> c_uint {
    unsafe {
        let page_ref = &mut *page;
        let mut state = PageInfoState::empty();
        if page_ref.is_busy() {
            state |= PageInfoState::BUSY;
        }
        if page_ref.is_wanted() {
            state |= PageInfoState::WANTED;
        }
        if page_ref.is_tabled() {
            state |= PageInfoState::TABLED;
        }
        if page_ref.is_fictitious() {
            state |= PageInfoState::FICTITIOUS;
        }
        if page_ref.is_private() {
            state |= PageInfoState::PRIVATE;
        }
        if page_ref.is_absent() {
            state |= PageInfoState::ABSENT;
        }
        if page_ref.is_error() {
            state |= PageInfoState::ERROR;
        }
        if page_ref.is_dirty() {
            state |= PageInfoState::DIRTY;
        }
        if page_ref.is_precious() {
            state |= PageInfoState::PRECIOUS;
        }
        if page_ref.is_overwriting() {
            state |= PageInfoState::OVERWRITING;
        }

        if !state.intersects(PageInfoState::NODATA | PageInfoState::DIRTY)
            && P::pmap_is_modified(page_ref.phys_addr)
        {
            state |= PageInfoState::DIRTY;
            page_ref.set_dirty(true);
        }

        VM_PAGE_QUEUE_LOCK.lock();
        if page_ref.is_inactive() {
            state |= PageInfoState::INACTIVE;
        }
        if page_ref.is_active() {
            state |= PageInfoState::ACTIVE;
        }
        if page_ref.is_laundry() {
            state |= PageInfoState::LAUNDRY;
        }
        if page_ref.is_free() {
            state |= PageInfoState::FREE;
        }
        if page_ref.is_reference() {
            state |= PageInfoState::REFERENCE;
        }

        if !state.intersects(PageInfoState::NODATA | PageInfoState::REFERENCE)
            && P::pmap_is_referenced(page_ref.phys_addr)
        {
            state |= PageInfoState::REFERENCE;
            page_ref.set_reference(true);
        }
        VM_PAGE_QUEUE_LOCK.unlock();

        state.bits()
    }
}

/// The page records of `object`, of the record type `R` the caller asked for.
///
/// # Safety
///
/// `object` must be null or a live object, `pagesp` must be writable storage
/// for one array pointer and `countp` for one count; the caller permits an
/// allocation and a kernel-map copy.
unsafe fn object_pages<R: PageRecord, P: Platform>(
    object: *mut VmObject,
    pagesp: *mut *mut c_void,
    countp: *mut c_uint,
) -> Result<(), Error> {
    if object.is_null() {
        return Err(Error::InvalidArgument);
    }

    let map = P::state().ipc_kernel_map();
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
        let state = unsafe { page_state::<P>(page) };
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

/// The object-local page records `mach_vm_object_pages()` reports.
///
/// # Safety
///
/// Same contract as `object_pages()`.
pub unsafe fn object_pages_info<P: Platform>(
    object: *mut VmObject,
    pagesp: *mut *mut c_void,
    countp: *mut c_uint,
) -> Result<(), Error> {
    unsafe { object_pages::<VmPageInfo, P>(object, pagesp, countp) }
}

/// The physical page records `mach_vm_object_pages_phys()` reports.
///
/// # Safety
///
/// Same contract as `object_pages()`.
pub unsafe fn object_pages_phys<P: Platform>(
    object: *mut VmObject,
    pagesp: *mut *mut c_void,
    countp: *mut c_uint,
) -> Result<(), Error> {
    unsafe { object_pages::<VmPagePhysInfo, P>(object, pagesp, countp) }
}

/// The bucket occupancy of the virtual-to-physical page table, as
/// `host_virtual_physical_table_info()` reports it.
///
/// # Safety
///
/// `infop` and `countp` must be writable storage, and the caller permits an
/// allocation and a kernel-map copy.
pub unsafe fn virtual_physical_table_info<P: Platform>(
    infop: *mut *mut HashInfoBucket,
    countp: *mut c_uint,
) -> Result<(), Error> {
    let initial = unsafe { *infop };
    let mut info = initial;
    let mut potential = unsafe { *countp };
    let mut addr: VmOffset = 0;
    let mut size: VmSize = 0;

    let map = P::state().ipc_kernel_map();

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
