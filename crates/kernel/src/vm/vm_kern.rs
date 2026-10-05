// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_kern.c and vm/vm_kern.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Kernel memory management.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::pmap::kernel_pmap_ptr;
use crate::arch::x86_64::pmap::pmap_enter;
use crate::arch::x86_64::pmap::pmap_map_bd;
use crate::arch::x86_64::pmap::pmap_pageable;
use crate::arch::x86_64::pmap::pmap_reference;
use crate::arch::x86_64::pmap::pmap_remove;
use crate::arch::x86_64::pmap::pmap_unmap_bd;
use crate::arch::x86_64::user_access::{self, UserFault};
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::slab::slab_collect;
use crate::kern::task::current_task;
use crate::vm::error::Error;
use crate::vm::types::{Pmap, VmInherit, VmObject, VmProt};
use crate::vm::vm_map::{
    EnterRequest, Projection, VmMap, round_page, trunc_page,
};
use crate::vm::vm_object::KERNEL_OBJECT;
use crate::vm::vm_object::VM_SUBMAP_OBJECT;
use crate::vm::vm_object::{self, allocate, deallocate, reference};
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm::{vm_page, vm_resident};
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use lock::RawMutex;

/// The allocation flag that lets the page come from high physical memory.
const VM_PAGE_HIGHMEM: c_uint = 0x08;

/// The lowest kernel virtual address, where the kernel map begins. A
/// `KERNEL_OBJECT` offset is linear in the kernel virtual address, so a kernel
/// mapping is stored at `addr - VM_MIN_KERNEL_ADDRESS`, and `phystokv()` adds
/// it back.
pub(crate) const VM_MIN_KERNEL_ADDRESS: VmOffset = 0xffff_ffff_8000_0000;

/// The storage of the boot kernel map.
static mut KERNEL_MAP_STORE: VmMap = VmMap::zeroed();

/// The kernel map `kmem_init()` builds.
pub static mut KERNEL_MAP: *mut VmMap = &raw mut KERNEL_MAP_STORE;

/// Unmaps every projected buffer of `map`.
pub(crate) fn projected_buffer_collect(
    map: NonNull<VmMap>,
) -> Result<(), Error> {
    // SAFETY: `kernel_map` is the boot kernel map storage.
    if map.as_ptr() == unsafe { KERNEL_MAP } {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the caller promises a live map, and the sentinel is the header's
    // links as `to_entry()` computes them.
    let sentinel = unsafe { (*map.as_ptr()).to_entry() };
    // SAFETY: the header's `next` is the sentinel or a live entry.
    let mut entry =
        unsafe { (*map.as_ptr()).hdr.links.next.unwrap_or(sentinel) };

    while entry != sentinel {
        // SAFETY: `entry` is the sentinel or a live entry of the map; the
        // caller promises the chain stays stable except for the deallocation
        // below.
        let (next, start, end, projected) = unsafe {
            let entry = &*entry.as_ptr();
            (
                entry.links.next.unwrap_or(sentinel),
                entry.links.start,
                entry.links.end,
                !entry.projected_on.is_null(),
            )
        };
        if projected {
            // `start` and `end` were read from the live entry before the
            // call, which may delete it.
            let _ = projected_buffer_deallocate(map, start, end);
        }
        entry = next;
    }

    Ok(())
}

/// Whether a projected buffer overlaps `start..end`.
pub(crate) fn projected_buffer_in_range(
    map: &VmMap,
    start: VmOffset,
    end: VmOffset,
) -> bool {
    // SAFETY: `kernel_map` is the boot kernel map storage.
    if ptr::from_ref(map).cast_mut() == unsafe { KERNEL_MAP } {
        return false;
    }

    let sentinel = map.to_entry();
    let (found, entry) = map.lookup_entry(start);
    let mut entry = if found {
        entry
    } else {
        // SAFETY: `lookup_entry` returned the sentinel or a live entry, so
        // its `next` is the sentinel or a live entry.
        unsafe { (*entry.as_ptr()).links.next.unwrap_or(sentinel) }
    };

    while entry != sentinel
        // SAFETY: `entry` is the sentinel or a live entry, as above.
        && unsafe { (*entry.as_ptr()).projected_on.is_null() }
        // SAFETY: `entry` is the sentinel or a live entry, as above.
        && unsafe { (*entry.as_ptr()).links.start } <= end
    {
        // SAFETY: `entry` is the sentinel or a live entry, as above.
        entry = unsafe { (*entry.as_ptr()).links.next.unwrap_or(sentinel) };
    }

    // SAFETY: the short-circuit proves `entry` is a live map entry.
    entry != sentinel && unsafe { (*entry.as_ptr()).links.start } <= end
}

/// Reserves kernel virtual space and wires memory for it.
pub(crate) fn kmem_alloc_wired_flags(
    map: NonNull<VmMap>,
    size: VmSize,
    flags: c_uint,
) -> Result<VmOffset, Error> {
    let addr = kmem_valloc(map, size)?;

    let offset = addr.wrapping_sub(VM_MIN_KERNEL_ADDRESS);
    // SAFETY: `KERNEL_OBJECT` is the boot object every kernel mapping maps,
    // and `addr..addr + size` is the region `kmem_valloc` just reserved.
    unsafe {
        alloc_pages(
            KERNEL_OBJECT,
            offset,
            addr,
            addr.wrapping_add(size),
            VmProt::READ | VmProt::WRITE,
            flags,
        );
    };

    Ok(addr)
}

/// Like [`kmem_alloc_wired_flags`], with the pages allowed to come from high
/// memory.
pub(crate) fn kmem_alloc_wired(
    map: NonNull<VmMap>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    kmem_alloc_wired_flags(map, size, VM_PAGE_HIGHMEM)
}

/// Maps a physical table at a kernel address with the physical address's
/// in-page offset.
///
/// No memory backs the range: its page-table entries name `phys_address`
/// directly, and [`kmem_unmap_aligned_table`] takes it back.
pub(crate) fn kmem_map_aligned_table(
    map: NonNull<VmMap>,
    phys_address: VmOffset,
    size: VmSize,
    mode: c_int,
) -> Option<NonNull<c_void>> {
    let into_page = phys_address % PAGE_SIZE;
    let nearest_page = phys_address.wrapping_sub(into_page);
    let size = round_page(size.wrapping_add(into_page));

    // SAFETY: the callers pass the live kernel map, unlocked.
    let virt_addr =
        kmem_alloc_pageable(unsafe { &mut *map.as_ptr() }, size).ok()?;

    // SAFETY: `virt_addr` is the free range just reserved, and
    // `nearest_page..nearest_page + size` is the physical range it stands for.
    unsafe {
        pmap_map_bd(
            virt_addr,
            nearest_page,
            nearest_page.wrapping_add(size),
            VmProt::from_bits(mode),
        )
    };

    // SAFETY: the C casts the integer address back to a pointer, and
    // `virt_addr + into_page` is inside the mapping just made.
    Some(unsafe {
        NonNull::new_unchecked(with_exposed_provenance_mut::<c_void>(
            virt_addr.wrapping_add(into_page),
        ))
    })
}

/// Takes back a range [`kmem_map_aligned_table`] mapped, given the address
/// it returned and the size it was asked for.
///
/// # Safety
///
/// `addr..addr + size` must be a range `kmem_map_aligned_table` mapped
/// into `map`, which nothing uses afterwards.
pub(crate) unsafe fn kmem_unmap_aligned_table(
    map: &mut VmMap,
    addr: VmOffset,
    size: VmSize,
) {
    let start = trunc_page(addr);
    let end = round_page(addr.wrapping_add(size));
    unsafe { pmap_unmap_bd(start, end) };
    let _ = kmem_free(map, start, end.wrapping_sub(start));
}

/// Reserves pageable space in the kernel map.
pub(crate) fn kmem_alloc_pageable(
    map: &mut VmMap,
    size: VmSize,
) -> Result<VmOffset, Error> {
    let mut addr = map.hdr.links.start;

    let entered = map.enter(EnterRequest {
        address: &mut addr,
        size: round_page(size),
        mask: 0,
        anywhere: true,
        object: ptr::null_mut(),
        offset: 0,
        needs_copy: false,
        cur_protection: VmProt::READ | VmProt::WRITE,
        max_protection: VmProt::ALL,
        inheritance: VmInherit::COPY,
    });

    match entered {
        Ok(()) => Ok(addr),
        Err(error) => {
            // The C `printf_once` guards a diagnostic; a relaxed flag is
            // enough because the worst case is printing it twice.
            static PRINTED: AtomicBool = AtomicBool::new(false);
            if !PRINTED.swap(true, Ordering::Relaxed) {
                // SAFETY: `map.name` is the map's NUL-terminated name.
                let name = unsafe { CStrArg::from_ptr(map.name) };
                kprint!(
                    "no more room for kmem_alloc_pageable in {:x} ({})\n",
                    ptr::from_ref(map).expose_provenance(),
                    name,
                );
            }
            Err(error)
        }
    }
}

/// Releases a region a `kmem_alloc*` call made.
pub(crate) fn kmem_free(
    map: &mut VmMap,
    addr: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    map.remove(trunc_page(addr), round_page(addr.wrapping_add(size)))
}

/// Builds `map` as a submap of `parent`.
pub(crate) fn kmem_submap(
    map: &mut VmMap,
    parent: NonNull<VmMap>,
    size: VmSize,
) -> Result<(VmOffset, VmOffset), Error> {
    let size = round_page(size);

    // SAFETY: `VM_SUBMAP_OBJECT` is the boot placeholder and is live for the
    // life of the kernel.
    let object = unsafe { VM_SUBMAP_OBJECT };
    // SAFETY: the parent's new entry holds the reference taken here, as the C
    // does before `vm_map_enter`.
    unsafe { reference(object) };

    // SAFETY: the caller promises a valid, unlocked parent map.
    let parent = unsafe { &mut *parent.as_ptr() };
    let mut addr = parent.hdr.links.start;
    parent.enter(EnterRequest {
        address: &mut addr,
        size,
        mask: 0,
        anywhere: true,
        object,
        offset: 0,
        needs_copy: false,
        cur_protection: VmProt::READ | VmProt::WRITE,
        max_protection: VmProt::ALL,
        inheritance: VmInherit::COPY,
    })?;

    let pmap = parent.pmap;
    // SAFETY: the parent owns a reference to `pmap`, and the submap must hold
    // its own.
    unsafe { pmap_reference(NonNull::new(pmap)) };
    VmMap::setup(map, pmap, addr, addr.wrapping_add(size));
    // Submaps get a lock class of their own: one may be held while the slab
    // locks the kernel map.
    map.lock = RawMutex::new();

    // The caller promises the parent is a live map and `map` the storage just
    // set up, which is what `submap()` requires.
    parent.submap(addr, addr.wrapping_add(size), ptr::from_mut(map))?;

    Ok((addr, addr.wrapping_add(size)))
}

/// Initializes the kernel map's address range.
pub(crate) fn kmem_init(
    map: NonNull<VmMap>,
    pmap: *mut Pmap,
    start: VmOffset,
    end: VmOffset,
) -> Result<(), Error> {
    // SAFETY: the caller passes the kernel's own map storage before anything
    // else uses it, and `pmap` is the boot pmap.
    unsafe {
        VmMap::setup(&mut *map.as_ptr(), pmap, VM_MIN_KERNEL_ADDRESS, end);
        // The kernel map's lock gets a class of its own: a user map or a
        // submap may be held while the slab locks it.
        (*map.as_ptr()).lock = RawMutex::new();
    };

    if start == VM_MIN_KERNEL_ADDRESS {
        return Ok(());
    }

    let mut addr = VM_MIN_KERNEL_ADDRESS;
    // SAFETY: the map was just set up and is unlocked.
    unsafe {
        (*map.as_ptr()).enter(EnterRequest {
            address: &mut addr,
            size: start.wrapping_sub(VM_MIN_KERNEL_ADDRESS),
            mask: 0,
            anywhere: true,
            object: ptr::null_mut(),
            offset: 0,
            needs_copy: false,
            cur_protection: VmProt::READ | VmProt::WRITE,
            max_protection: VmProt::ALL,
            inheritance: VmInherit::COPY,
        })
    }
}

/// Drops the I/O mapping of `addr..addr + size` from `map` and from its
/// physical map.
pub(crate) fn kmem_io_map_deallocate(
    map: &mut VmMap,
    addr: VmOffset,
    size: VmSize,
) {
    let end = addr.wrapping_add(size);
    // SAFETY: the caller promises the range belongs to this map, whose pmap
    // is live.
    unsafe { pmap_remove(NonNull::new(map.pmap), addr, end) };
    let _ = map.remove(addr, end);
}

/// `kernel_map` as the non-null map the boot path built.
fn kernel_map_non_null() -> NonNull<VmMap> {
    // SAFETY: the boot map storage is a live `VmMap` from the first call
    // onwards; `kmem_init()` is what fills its range.
    unsafe { NonNull::new_unchecked(ptr::addr_of_mut!(KERNEL_MAP_STORE)) }
}

/// Unmaps a projected buffer from `map`, and from the kernel map when it was
/// the last non-persistent use.
pub(crate) fn projected_buffer_deallocate(
    map: NonNull<VmMap>,
    start: VmOffset,
    end: VmOffset,
) -> Result<(), Error> {
    let kernel = kernel_map_non_null();
    if map == kernel {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the caller promises a valid map; the write lock serializes the
    // entry surgery below.
    VmMap::lock(map);
    // SAFETY: the map is live and locked; the entry points into it.
    let (found, entry) = unsafe { (*map.as_ptr()).lookup_entry(start) };
    // SAFETY: `lookup_entry()` returned a live entry, found or sentinel.
    let projected = unsafe { (*entry.as_ptr()).projected_on };
    if !found
        // SAFETY: `entry` is the live entry `lookup_entry()` returned.
        || end > unsafe { (*entry.as_ptr()).links.end }
        || projected.is_null()
    {
        VmMap::unlock(map);
        return Err(Error::InvalidArgument);
    }
    // SAFETY: the check above read the non-null kernel entry.
    let k_entry = unsafe { NonNull::new_unchecked(projected) };

    // SAFETY: `entry` is a live entry of the locked map, and the clips split
    // it only when the range lies strictly inside.
    unsafe {
        if (*entry.as_ptr()).links.start < start {
            (*map.as_ptr()).hdr.clip_start(entry, start, true);
        }
        if (*entry.as_ptr()).links.end > end {
            (*map.as_ptr()).hdr.clip_end(entry, end, true);
        }
        if (*map.as_ptr()).first_free == entry.as_ptr() {
            (*map.as_ptr()).first_free = (*entry.as_ptr())
                .links
                .prev
                .map_or(ptr::null_mut(), NonNull::as_ptr);
        }
        (*entry.as_ptr()).projected_on = ptr::null_mut();
        (*entry.as_ptr()).wired_count = 0;
        (*map.as_ptr()).entry_delete(entry);
    }
    VmMap::unlock(map);

    // SAFETY: the boot map is live; the write lock serializes the kernel
    // entry surgery.
    VmMap::lock(kernel);
    // SAFETY: `k_entry` is the live kernel entry the user entry pointed at.
    let non_persistent = unsafe { (*k_entry.as_ptr()).projection() }
        == Projection::NonPersistent;
    // SAFETY: `k_entry` is the live kernel entry and the boot map is locked.
    let last_reference = unsafe {
        !(*k_entry.as_ptr()).object.vm_object.is_null()
            && (*(*k_entry.as_ptr()).object.vm_object).ref_count == 1
    };
    if non_persistent && last_reference {
        // SAFETY: `k_entry` is linked in the locked boot map.
        unsafe {
            if (*kernel.as_ptr()).first_free == k_entry.as_ptr() {
                (*kernel.as_ptr()).first_free = (*k_entry.as_ptr())
                    .links
                    .prev
                    .map_or(ptr::null_mut(), NonNull::as_ptr);
            }
            (*k_entry.as_ptr()).projected_on = ptr::null_mut();
            (*kernel.as_ptr()).entry_delete(k_entry);
        }
    }
    VmMap::unlock(kernel);
    Ok(())
}

/// Allocates wired-down memory in a kernel map or submap, not zeroed.
pub(crate) fn kmem_alloc(
    map: NonNull<VmMap>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    let size = round_page(size);
    // SAFETY: the object allocator halts the kernel rather than fail.
    let object = unsafe { allocate(size) }.as_ptr();

    let mut attempts = 0;
    loop {
        // SAFETY: the caller promises a valid map; the write lock serializes
        // the entry search.
        VmMap::lock(map);
        // SAFETY: the map is live and write-locked above, so the search is
        // exclusive.
        let found = unsafe {
            VmMap::find_entry(
                &mut *map.as_ptr(),
                size,
                0,
                None,
                VmProt::READ | VmProt::WRITE,
                VmProt::ALL,
            )
        };
        match found {
            Ok((addr, entry)) => {
                // SAFETY: `entry` is the new entry of the locked map, and the
                // reference it takes is the allocator's.
                unsafe {
                    (*entry.as_ptr()).object.vm_object = object;
                    (*entry.as_ptr()).offset = 0;
                }
                VmMap::unlock(map);
                // SAFETY: `object` owns the range `addr..addr + size` the
                // entry just took.
                unsafe {
                    alloc_pages(
                        object,
                        0,
                        addr,
                        addr.wrapping_add(size),
                        VmProt::READ | VmProt::WRITE,
                        VM_PAGE_HIGHMEM,
                    );
                };
                return Ok(addr);
            }
            Err(error) => {
                // The C `printf_once` guards a diagnostic; a relaxed flag is
                // enough because the worst case is printing it twice.
                static PRINTED: AtomicBool = AtomicBool::new(false);
                VmMap::unlock(map);
                if attempts == 0 {
                    attempts += 1;
                    slab_collect();
                    continue;
                }
                if !PRINTED.swap(true, Ordering::Relaxed) {
                    // SAFETY: `map.name` is the map's NUL-terminated name.
                    let name =
                        unsafe { CStrArg::from_ptr((*map.as_ptr()).name) };
                    kprint!(
                        "no more room for kmem_alloc in {:x} ({})\n",
                        map.as_ptr().expose_provenance(),
                        name,
                    );
                }
                // SAFETY: the entry search failed, so the allocator's
                // reference is the only one.
                unsafe { deallocate(object) };
                return Err(error);
            }
        }
    }
}

/// Reserves addressing space in a kernel map or submap without mapping
/// anything.
pub(crate) fn kmem_valloc(
    map: NonNull<VmMap>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    let size = round_page(size);
    // SAFETY: `KERNEL_OBJECT` is the boot object of every kernel mapping.
    let object = unsafe { KERNEL_OBJECT };

    let mut attempts = 0;
    loop {
        // SAFETY: the caller promises a valid map; the write lock serializes
        // the entry search.
        VmMap::lock(map);
        // SAFETY: the map is live and write-locked above, so the search is
        // exclusive.
        let found = unsafe {
            VmMap::find_entry(
                &mut *map.as_ptr(),
                size,
                0,
                NonNull::new(object),
                VmProt::READ | VmProt::WRITE,
                VmProt::ALL,
            )
        };
        match found {
            Ok((addr, entry)) => {
                let offset = addr.wrapping_sub(VM_MIN_KERNEL_ADDRESS);
                // SAFETY: `entry` is the new or extended entry of the locked
                // map; only a fresh entry needs the object reference.
                unsafe {
                    if (*entry.as_ptr()).object.vm_object.is_null() {
                        reference(object);
                        (*entry.as_ptr()).object.vm_object = object;
                        (*entry.as_ptr()).offset = offset;
                    }
                }
                VmMap::unlock(map);
                return Ok(addr);
            }
            Err(error) => {
                // The C `printf_once` guards a diagnostic; a relaxed flag is
                // enough because the worst case is printing it twice.
                static PRINTED: AtomicBool = AtomicBool::new(false);
                VmMap::unlock(map);
                if attempts == 0 {
                    attempts += 1;
                    slab_collect();
                    continue;
                }
                if !PRINTED.swap(true, Ordering::Relaxed) {
                    // SAFETY: `map.name` is the map's NUL-terminated name.
                    let name =
                        unsafe { CStrArg::from_ptr((*map.as_ptr()).name) };
                    kprint!(
                        "no more room for kmem_valloc in {:x} ({})\n",
                        map.as_ptr().expose_provenance(),
                        name,
                    );
                }
                return Err(error);
            }
        }
    }
}

/// Like [`kmem_valloc`], with an aligned address and the pages wired in.
///
/// # Panics
///
/// The caller must pass a power-of-two `size`; anything else halts the
/// kernel, as the C `panic("kmem_alloc_aligned")` did.
pub(crate) fn kmem_alloc_aligned(
    map: NonNull<VmMap>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    if size & size.wrapping_sub(1) != 0 {
        kpanic!("kmem_alloc_aligned", "kmem_alloc_aligned");
    }

    let size = round_page(size);
    // SAFETY: `KERNEL_OBJECT` is the boot object of every kernel mapping.
    let object = unsafe { KERNEL_OBJECT };

    let mut attempts = 0;
    loop {
        // SAFETY: the caller promises a valid map; the write lock serializes
        // the entry search.
        VmMap::lock(map);
        // SAFETY: the map is live and write-locked above, so the search is
        // exclusive.
        let found = unsafe {
            VmMap::find_entry(
                &mut *map.as_ptr(),
                size,
                size.wrapping_sub(1),
                NonNull::new(object),
                VmProt::READ | VmProt::WRITE,
                VmProt::ALL,
            )
        };
        match found {
            Ok((addr, entry)) => {
                let offset = addr.wrapping_sub(VM_MIN_KERNEL_ADDRESS);
                // SAFETY: `entry` is the new or extended entry of the locked
                // map; only a fresh entry needs the object reference.
                unsafe {
                    if (*entry.as_ptr()).object.vm_object.is_null() {
                        reference(object);
                        (*entry.as_ptr()).object.vm_object = object;
                        (*entry.as_ptr()).offset = offset;
                    }
                }
                VmMap::unlock(map);
                // SAFETY: `object` owns the range `addr..addr + size` the
                // entry just took.
                unsafe {
                    alloc_pages(
                        object,
                        offset,
                        addr,
                        addr.wrapping_add(size),
                        VmProt::READ | VmProt::WRITE,
                        VM_PAGE_HIGHMEM,
                    );
                };
                return Ok(addr);
            }
            Err(error) => {
                // The C `printf_once` guards a diagnostic; a relaxed flag is
                // enough because the worst case is printing it twice.
                static PRINTED: AtomicBool = AtomicBool::new(false);
                VmMap::unlock(map);
                if attempts == 0 {
                    attempts += 1;
                    slab_collect();
                    continue;
                }
                if !PRINTED.swap(true, Ordering::Relaxed) {
                    // SAFETY: `map.name` is the map's NUL-terminated name.
                    let name =
                        unsafe { CStrArg::from_ptr((*map.as_ptr()).name) };
                    kprint!(
                        "no more room for kmem_alloc_aligned in {:x} ({})\n",
                        map.as_ptr().expose_provenance(),
                        name,
                    );
                }
                return Err(error);
            }
        }
    }
}

/// Allocates wired pages of `object` in `start..end`.
///
/// # Safety
///
/// `object` must be a live object mapped into the kernel map, and its lock
/// must not be held.
pub(crate) unsafe fn alloc_pages(
    object: *mut VmObject,
    mut offset: VmOffset,
    mut start: VmOffset,
    end: VmOffset,
    protection: VmProt,
    flags: c_uint,
) {
    pmap_pageable(kernel_pmap_ptr(), start, end, c_int::from(false));

    while start < end {
        let object_ref = unsafe { NonNull::new_unchecked(object) };
        // SAFETY: the object lock guards the page tables this walk reads.
        unsafe { (*object).lock.lock() };

        let mem = loop {
            // SAFETY: the object lock is held, as `alloc_flags` requires.
            if let Some(page) =
                // SAFETY: the object lock is held, as `alloc_flags` requires.
                unsafe {
                    vm_resident::alloc_flags(object_ref, offset, flags)
                }
            {
                break page;
            }
            // SAFETY: the C drops the object lock before waiting for a page.
            unsafe {
                (*object).lock.unlock();
                vm_page::wait(None);
                (*object).lock.lock();
            }
        };

        // SAFETY: the page-queues lock is the live lock and the object lock
        // is held.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_page::wire(mem);
            VM_PAGE_QUEUE_LOCK.unlock();
        }
        // SAFETY: the page is wired; the C unlocks the object before entering
        // the mapping.
        unsafe { (*object).lock.unlock() };

        // SAFETY: `kernel_pmap_ptr()` is the boot pmap, and the page's
        // physical address is live; the page's lock bits are masked out of the
        // protection.
        unsafe {
            pmap_enter(
                NonNull::new(kernel_pmap_ptr()),
                start,
                (*mem.as_ptr()).phys_addr,
                (protection & !(*mem.as_ptr()).page_lock()).bits(),
                c_int::from(true),
            );
        };

        // SAFETY: the object lock guards the page's busy state.
        unsafe {
            (*object).lock.lock();
            vm_object::page_wakeup_done(mem.as_ptr());
            (*object).lock.unlock();
        }

        start = start.wrapping_add(PAGE_SIZE);
        offset = offset.wrapping_add(PAGE_SIZE);
    }
}

/// Copies bytes in from a kernel map or from the current user map.
///
/// # Safety
///
/// `fromaddr` must be readable and `toaddr` writable for `length` bytes, as
/// the C `copyin` required.
pub(crate) unsafe fn copyinmap(
    map: &VmMap,
    fromaddr: *const c_char,
    toaddr: *mut c_char,
    length: c_int,
) -> Result<(), UserFault> {
    // SAFETY: `kernel_pmap_ptr()` is the boot pmap.
    if map.pmap == kernel_pmap_ptr() {
        unsafe {
            ptr::copy_nonoverlapping(
                fromaddr,
                toaddr,
                usize::try_from(length).unwrap_or(0),
            );
        };
        return Ok(());
    }

    // SAFETY: `current_task()` is the running task, whose map is live.
    let current_map = unsafe { (*current_task()).map };
    if current_map == ptr::from_ref(map).cast_mut().cast::<c_void>() {
        // SAFETY: `copyin` is the real asm routine, and the C's `int`
        // argument converts to its `size_t` parameter.
        return unsafe {
            user_access::copyin(
                fromaddr.cast::<c_void>(),
                toaddr.cast::<c_void>(),
                length as usize,
            )
        };
    }

    Err(UserFault)
}

/// Copies bytes out into a kernel map or into the current user map.
///
/// # Safety
///
/// `fromaddr` must be readable and `toaddr` writable for `length` bytes, as
/// the C `copyout` required.
pub(crate) unsafe fn copyoutmap(
    map: &VmMap,
    fromaddr: *const c_char,
    toaddr: *mut c_char,
    length: c_int,
) -> Result<(), UserFault> {
    // SAFETY: `kernel_pmap_ptr()` is the boot pmap.
    if map.pmap == kernel_pmap_ptr() {
        unsafe {
            ptr::copy_nonoverlapping(
                fromaddr,
                toaddr,
                usize::try_from(length).unwrap_or(0),
            );
        };
        return Ok(());
    }

    // SAFETY: `current_task()` is the running task, whose map is live.
    let current_map = unsafe { (*current_task()).map };
    if current_map == ptr::from_ref(map).cast_mut().cast::<c_void>() {
        // SAFETY: `user_access::copyout` is the real routine, and the
        // C's `int` argument converts to its `size_t` parameter.
        return unsafe {
            user_access::copyout(
                fromaddr.cast::<c_void>(),
                toaddr.cast::<c_void>(),
                length as usize,
            )
        };
    }

    Err(UserFault)
}
