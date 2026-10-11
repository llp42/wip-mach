// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Kernel memory management.

use crate::cstr::CStrArg;
use crate::error::Error;
use crate::param::PAGE_SIZE;
use crate::param::{VM_MIN_KERNEL_ADDRESS, VmOffset, VmSize};
use crate::platform::{Platform, UserFault};
use crate::types::PageSelect;
use crate::types::{VmInherit, VmObject, VmProt};
use crate::vm_map::{EnterRequest, Projection, VmMap, round_page, trunc_page};
use crate::vm_object::{self, allocate, deallocate, reference};
use crate::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::{vm_page, vm_resident};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use lock::RawMutex;

/// Unmaps every projected buffer of `map`.
pub(crate) fn projected_buffer_collect<P: Platform>(
    map: NonNull<VmMap<P>>,
) -> Result<(), Error> {
    // SAFETY: `kernel_map` is the boot kernel map storage.
    if map.as_ptr() == P::state().kernel_map() {
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
pub(crate) fn projected_buffer_in_range<P: Platform>(
    map: &VmMap<P>,
    start: VmOffset,
    end: VmOffset,
) -> bool {
    // SAFETY: `kernel_map` is the boot kernel map storage.
    if ptr::from_ref(map).cast_mut() == P::state().kernel_map() {
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
pub(crate) fn kmem_alloc_wired_flags<P: Platform>(
    map: NonNull<VmMap<P>>,
    size: VmSize,
    flags: PageSelect,
) -> Result<VmOffset, Error> {
    let addr = kmem_valloc(map, size)?;

    let offset = addr.wrapping_sub(VM_MIN_KERNEL_ADDRESS);
    // SAFETY: `kernel_object()` is the boot object every kernel mapping maps,
    // and `addr..addr + size` is the region `kmem_valloc` just reserved.
    unsafe {
        alloc_pages::<P>(
            vm_object::kernel_object(),
            offset,
            addr,
            addr.wrapping_add(size),
            VmProt::READ | VmProt::WRITE,
            flags,
        );
    };

    Ok(addr)
}

/// Like `kmem_alloc_wired_flags()`, with the pages allowed to come from high
/// memory.
pub fn kmem_alloc_wired<P: Platform>(
    map: NonNull<VmMap<P>>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    kmem_alloc_wired_flags(map, size, PageSelect::HIGHMEM)
}

/// Maps a physical table at a kernel address with the physical address's
/// in-page offset.
///
/// No memory backs the range: its page-table entries name `phys_address`
/// directly, and [`kmem_unmap_aligned_table`] takes it back.
#[must_use]
pub fn kmem_map_aligned_table<P: Platform>(
    map: NonNull<VmMap<P>>,
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
        P::pmap_map_bd(
            virt_addr,
            nearest_page,
            nearest_page.wrapping_add(size),
            VmProt::from_bits_retain(mode),
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
pub unsafe fn kmem_unmap_aligned_table<P: Platform>(
    map: &mut VmMap<P>,
    addr: VmOffset,
    size: VmSize,
) {
    let start = trunc_page(addr);
    let end = round_page(addr.wrapping_add(size));
    unsafe { P::pmap_unmap_bd(start, end) };
    let _ = kmem_free(map, start, end.wrapping_sub(start));
}

/// Reserves pageable space in the kernel map.
pub fn kmem_alloc_pageable<P: Platform>(
    map: &mut VmMap<P>,
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
                P::print(format_args!(
                    "no more room for kmem_alloc_pageable in {:x} ({})\n",
                    ptr::from_ref(map).expose_provenance(),
                    name,
                ));
            }
            Err(error)
        }
    }
}

/// Releases a region a `kmem_alloc*` call made.
pub fn kmem_free<P: Platform>(
    map: &mut VmMap<P>,
    addr: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    map.remove(trunc_page(addr), round_page(addr.wrapping_add(size)))
}

/// Builds `map` as a submap of `parent`.
pub fn kmem_submap<P: Platform>(
    map: &mut VmMap<P>,
    parent: NonNull<VmMap<P>>,
    size: VmSize,
) -> Result<(VmOffset, VmOffset), Error> {
    let size = round_page(size);

    let object = vm_object::vm_submap_object();
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
    unsafe { P::pmap_reference(NonNull::new(pmap)) };
    VmMap::<P>::setup(map, pmap, addr, addr.wrapping_add(size));
    // Submaps get a lock name of their own: one may be held while the slab
    // locks the kernel map.
    map.lock = RawMutex::named("submap");

    // The caller promises the parent is a live map and `map` the storage just
    // set up, which is what `submap()` requires.
    parent.submap(addr, addr.wrapping_add(size), ptr::from_mut(map))?;

    Ok((addr, addr.wrapping_add(size)))
}

/// Initializes the kernel map's address range.
pub(crate) fn kmem_init<P: Platform>(
    map: NonNull<VmMap<P>>,
    pmap: *mut P::Pmap,
    start: VmOffset,
    end: VmOffset,
) -> Result<(), Error> {
    // SAFETY: the caller passes the kernel's own map storage before anything
    // else uses it, and `pmap` is the boot pmap.
    unsafe {
        VmMap::<P>::setup(
            &mut *map.as_ptr(),
            pmap,
            VM_MIN_KERNEL_ADDRESS,
            end,
        );
        // The kernel map's lock gets a name of its own: a user map or a
        // submap may be held while the slab locks it.
        (*map.as_ptr()).lock = RawMutex::named("kernel map");
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
pub fn kmem_io_map_deallocate<P: Platform>(
    map: &mut VmMap<P>,
    addr: VmOffset,
    size: VmSize,
) {
    let end = addr.wrapping_add(size);
    // SAFETY: the caller promises the range belongs to this map, whose pmap
    // is live.
    unsafe { P::pmap_remove(NonNull::new(map.pmap), addr, end) };
    let _ = map.remove(addr, end);
}

/// `kernel_map` as the non-null map the boot path built.
fn kernel_map_non_null<P: Platform>() -> NonNull<VmMap<P>> {
    // SAFETY: the boot map storage is a live `VmMap` from the first call
    // onwards; `kmem_init()` is what fills its range.
    unsafe { NonNull::new_unchecked(P::state().kernel_map()) }
}

/// Unmaps a projected buffer from `map`, and from the kernel map when it was
/// the last non-persistent use.
pub(crate) fn projected_buffer_deallocate<P: Platform>(
    map: NonNull<VmMap<P>>,
    start: VmOffset,
    end: VmOffset,
) -> Result<(), Error> {
    let kernel = kernel_map_non_null();
    if map == kernel {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the caller promises a valid map; the write lock serializes the
    // entry surgery below.
    VmMap::<P>::lock(map);
    // SAFETY: the map is live and locked; the entry points into it.
    let (found, entry) = unsafe { (*map.as_ptr()).lookup_entry(start) };
    // SAFETY: `lookup_entry()` returned a live entry, found or sentinel.
    let projected = unsafe { (*entry.as_ptr()).projected_on };
    if !found
        // SAFETY: `entry` is the live entry `lookup_entry()` returned.
        || end > unsafe { (*entry.as_ptr()).links.end }
        || projected.is_null()
    {
        VmMap::<P>::unlock(map);
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
    VmMap::<P>::unlock(map);

    // SAFETY: the boot map is live; the write lock serializes the kernel
    // entry surgery.
    VmMap::<P>::lock(kernel);
    // SAFETY: `k_entry` is the live kernel entry the user entry pointed at.
    let non_persistent = unsafe { (*k_entry.as_ptr()).projection() }
        == Projection::<P>::NonPersistent;
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
    VmMap::<P>::unlock(kernel);
    Ok(())
}

/// Allocates wired-down memory in a kernel map or submap, not zeroed.
pub fn kmem_alloc<P: Platform>(
    map: NonNull<VmMap<P>>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    let size = round_page(size);
    // SAFETY: the object allocator halts the kernel rather than fail.
    let object = unsafe { allocate::<P>(size) }.as_ptr();

    let mut attempts = 0;
    loop {
        // SAFETY: the caller promises a valid map; the write lock serializes
        // the entry search.
        VmMap::<P>::lock(map);
        // SAFETY: the map is live and write-locked above, so the search is
        // exclusive.
        let found = unsafe {
            VmMap::<P>::find_entry(
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
                VmMap::<P>::unlock(map);
                // SAFETY: `object` owns the range `addr..addr + size` the
                // entry just took.
                unsafe {
                    alloc_pages::<P>(
                        object,
                        0,
                        addr,
                        addr.wrapping_add(size),
                        VmProt::READ | VmProt::WRITE,
                        PageSelect::HIGHMEM,
                    );
                };
                return Ok(addr);
            }
            Err(error) => {
                // The C `printf_once` guards a diagnostic; a relaxed flag is
                // enough because the worst case is printing it twice.
                static PRINTED: AtomicBool = AtomicBool::new(false);
                VmMap::<P>::unlock(map);
                if attempts == 0 {
                    attempts += 1;
                    P::slab_collect();
                    continue;
                }
                if !PRINTED.swap(true, Ordering::Relaxed) {
                    // SAFETY: `map.name` is the map's NUL-terminated name.
                    let name =
                        unsafe { CStrArg::from_ptr((*map.as_ptr()).name) };
                    P::print(format_args!(
                        "no more room for kmem_alloc in {:x} ({})\n",
                        map.as_ptr().expose_provenance(),
                        name,
                    ));
                }
                // SAFETY: the entry search failed, so the allocator's
                // reference is the only one.
                unsafe { deallocate::<P>(object) };
                return Err(error);
            }
        }
    }
}

/// Reserves addressing space in a kernel map or submap without mapping
/// anything.
pub(crate) fn kmem_valloc<P: Platform>(
    map: NonNull<VmMap<P>>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    let size = round_page(size);
    let object = vm_object::kernel_object();

    let mut attempts = 0;
    loop {
        // SAFETY: the caller promises a valid map; the write lock serializes
        // the entry search.
        VmMap::<P>::lock(map);
        // SAFETY: the map is live and write-locked above, so the search is
        // exclusive.
        let found = unsafe {
            VmMap::<P>::find_entry(
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
                VmMap::<P>::unlock(map);
                return Ok(addr);
            }
            Err(error) => {
                // The C `printf_once` guards a diagnostic; a relaxed flag is
                // enough because the worst case is printing it twice.
                static PRINTED: AtomicBool = AtomicBool::new(false);
                VmMap::<P>::unlock(map);
                if attempts == 0 {
                    attempts += 1;
                    P::slab_collect();
                    continue;
                }
                if !PRINTED.swap(true, Ordering::Relaxed) {
                    // SAFETY: `map.name` is the map's NUL-terminated name.
                    let name =
                        unsafe { CStrArg::from_ptr((*map.as_ptr()).name) };
                    P::print(format_args!(
                        "no more room for kmem_valloc in {:x} ({})\n",
                        map.as_ptr().expose_provenance(),
                        name,
                    ));
                }
                return Err(error);
            }
        }
    }
}

/// Like `kmem_valloc()`, with an aligned address and the pages wired in.
///
/// # Panics
///
/// The caller must pass a power-of-two `size`; anything else halts the
/// kernel, as the C `panic("kmem_alloc_aligned")` did.
pub fn kmem_alloc_aligned<P: Platform>(
    map: NonNull<VmMap<P>>,
    size: VmSize,
) -> Result<VmOffset, Error> {
    assert!(size & size.wrapping_sub(1) == 0, "kmem_alloc_aligned");

    let size = round_page(size);
    let object = vm_object::kernel_object();

    let mut attempts = 0;
    loop {
        // SAFETY: the caller promises a valid map; the write lock serializes
        // the entry search.
        VmMap::<P>::lock(map);
        // SAFETY: the map is live and write-locked above, so the search is
        // exclusive.
        let found = unsafe {
            VmMap::<P>::find_entry(
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
                VmMap::<P>::unlock(map);
                // SAFETY: `object` owns the range `addr..addr + size` the
                // entry just took.
                unsafe {
                    alloc_pages::<P>(
                        object,
                        offset,
                        addr,
                        addr.wrapping_add(size),
                        VmProt::READ | VmProt::WRITE,
                        PageSelect::HIGHMEM,
                    );
                };
                return Ok(addr);
            }
            Err(error) => {
                // The C `printf_once` guards a diagnostic; a relaxed flag is
                // enough because the worst case is printing it twice.
                static PRINTED: AtomicBool = AtomicBool::new(false);
                VmMap::<P>::unlock(map);
                if attempts == 0 {
                    attempts += 1;
                    P::slab_collect();
                    continue;
                }
                if !PRINTED.swap(true, Ordering::Relaxed) {
                    // SAFETY: `map.name` is the map's NUL-terminated name.
                    let name =
                        unsafe { CStrArg::from_ptr((*map.as_ptr()).name) };
                    P::print(format_args!(
                        "no more room for kmem_alloc_aligned in {:x} ({})\n",
                        map.as_ptr().expose_provenance(),
                        name,
                    ));
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
pub(crate) unsafe fn alloc_pages<P: Platform>(
    object: *mut VmObject,
    mut offset: VmOffset,
    mut start: VmOffset,
    end: VmOffset,
    protection: VmProt,
    flags: PageSelect,
) {
    P::pmap_pageable(P::kernel_pmap(), start, end, c_int::from(false));

    while start < end {
        let object_ref = unsafe { NonNull::new_unchecked(object) };
        // SAFETY: the object lock guards the page tables this walk reads.
        unsafe { (*object).lock.lock() };

        let mem = loop {
            // SAFETY: the object lock is held, as `alloc_flags` requires.
            if let Some(page) =
                // SAFETY: the object lock is held, as `alloc_flags` requires.
                unsafe {
                    vm_resident::alloc_flags::<P>(object_ref, offset, flags)
                }
            {
                break page;
            }
            // SAFETY: the C drops the object lock before waiting for a page.
            unsafe {
                (*object).lock.unlock();
                vm_page::wait::<P>(None);
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

        // SAFETY: `P::kernel_pmap()` is the boot pmap, and the page's
        // physical address is live; the page's lock bits are masked out of the
        // protection.
        unsafe {
            P::pmap_enter(
                NonNull::new(P::kernel_pmap()),
                start,
                (*mem.as_ptr()).phys_addr,
                protection & !(*mem.as_ptr()).page_lock(),
                c_int::from(true),
            );
        };

        // SAFETY: the object lock guards the page's busy state.
        unsafe {
            (*object).lock.lock();
            vm_object::page_wakeup_done::<P>(mem.as_ptr());
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
pub unsafe fn copyinmap<P: Platform>(
    map: &VmMap<P>,
    fromaddr: *const c_char,
    toaddr: *mut c_char,
    length: c_int,
) -> Result<(), UserFault> {
    // SAFETY: `P::kernel_pmap()` is the boot pmap.
    if map.pmap == P::kernel_pmap() {
        unsafe {
            ptr::copy_nonoverlapping(
                fromaddr,
                toaddr,
                usize::try_from(length).unwrap_or(0),
            );
        };
        return Ok(());
    }

    if ptr::eq(P::current_map(), map) {
        // SAFETY: `copyin` is the real asm routine, and the C's `int`
        // argument converts to its `size_t` parameter.
        return unsafe {
            P::copyin(
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
pub unsafe fn copyoutmap<P: Platform>(
    map: &VmMap<P>,
    fromaddr: *const c_char,
    toaddr: *mut c_char,
    length: c_int,
) -> Result<(), UserFault> {
    // SAFETY: `P::kernel_pmap()` is the boot pmap.
    if map.pmap == P::kernel_pmap() {
        unsafe {
            ptr::copy_nonoverlapping(
                fromaddr,
                toaddr,
                usize::try_from(length).unwrap_or(0),
            );
        };
        return Ok(());
    }

    if ptr::eq(P::current_map(), map) {
        // SAFETY: `copyout` is the real routine, and the
        // C's `int` argument converts to its `size_t` parameter.
        return unsafe {
            P::copyout(
                fromaddr.cast::<c_void>(),
                toaddr.cast::<c_void>(),
                length as usize,
            )
        };
    }

    Err(UserFault)
}
