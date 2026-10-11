// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The user-exported virtual memory calls.

use crate::error::Error;
use crate::memory_object::{self, Return};
use crate::memory_object_proxy;
use crate::param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::param::{RpcPhysAddr, VmOffset, VmSize};
use crate::platform::{Platform, Port};
use crate::types::{
    PagingCounters, VmInherit, VmObject, VmPage, VmProt, VmStatistics,
};
use crate::vm_kern::{kmem_alloc, projected_buffer_in_range};
use crate::vm_map::{EnterRequest, VmMap, VmMapCopy, round_page, trunc_page};
use crate::vm_object;
use crate::vm_page;
use crate::vm_resident;
use crate::vm_resident::VM_PAGE_QUEUE_LOCK;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{NonNull, null_mut, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicI32, Ordering};
use lock::lock_api::RawMutex as _;
use zerocopy::{Immutable, IntoBytes};

/// The kernel-object types of a plain port, the host name port and the
/// privileged host port.
const IKOT_NONE: c_uint = 0;
const IKOT_HOST: c_uint = 3;
const IKOT_HOST_PRIV: c_uint = 4;

/// `VM_WIRE_CURRENT | VM_WIRE_FUTURE`: wire every current mapping and every
/// future one.
const VM_WIRE_ALL: c_int = 3;

/// The 8 MiB cap `vm_wire()` puts on an unprivileged map's wired size.
const UNPRIVILEGED_WIRE_LIMIT: VmSize = 8 << 20;

/// The `unsigned int` run of `struct vm_cache_statistics`, the record
/// `vm_cache_statistics()` fills.
#[repr(C)]
#[allow(missing_docs)]
#[derive(IntoBytes, Immutable)]
pub struct VmCacheStatistics {
    pub cache_object_count: c_int,
    pub cache_count: c_int,
    pub active_tmp_count: c_int,
    pub inactive_tmp_count: c_int,
    pub active_perm_count: c_int,
    pub inactive_perm_count: c_int,
    pub dirty_count: c_int,
    pub laundry_count: c_int,
    pub writeback_count: c_int,
    pub slab_count: c_int,
    pub slab_reclaim_count: c_int,
}

const _: () =
    assert!(size_of::<VmCacheStatistics>() == 11 * size_of::<c_int>());
const _: () = assert!(align_of::<VmCacheStatistics>() == align_of::<c_int>());

/// The system-wide paging counters `vm_statistics()` reports.
pub(crate) static VM_STAT: PagingCounters = PagingCounters::new();

/// A table count as an index; the widening is lossless.
const fn as_index(count: c_uint) -> usize {
    count as usize
}

/// The kernel's counters, with the live page counts added.
pub fn statistics() -> VmStatistics {
    let count = |counter: &AtomicI32| counter.load(Ordering::Relaxed);
    VmStatistics {
        // The page size fits an integer_t.
        pagesize: PAGE_SIZE as c_int,
        // The C assigned the unsigned long count to an integer_t; those many
        // free pages cannot exist.
        free_count: vm_page::mem_free() as c_int,
        active_count: vm_resident::VM_PAGE_ACTIVE_COUNT
            .load(Ordering::Relaxed),
        inactive_count: vm_resident::VM_PAGE_INACTIVE_COUNT
            .load(Ordering::Relaxed),
        wire_count: vm_resident::VM_PAGE_WIRE_COUNT.load(Ordering::Relaxed),
        zero_fill_count: count(&VM_STAT.zero_fill_count),
        reactivations: count(&VM_STAT.reactivations),
        pageins: count(&VM_STAT.pageins),
        pageouts: count(&VM_STAT.pageouts),
        faults: count(&VM_STAT.faults),
        cow_faults: count(&VM_STAT.cow_faults),
        lookups: count(&VM_STAT.lookups),
        hits: count(&VM_STAT.hits),
    }
}

/// The object cache's counters, as `vm_cache_statistics()` reports them.
pub fn cache_statistics() -> VmCacheStatistics {
    VmCacheStatistics {
        cache_object_count: vm_resident::VM_OBJECT_EXTERNAL_COUNT
            .load(Ordering::Relaxed),
        cache_count: vm_resident::VM_OBJECT_EXTERNAL_PAGES
            .load(Ordering::Relaxed),
        // XXX Not implemented yet.
        active_tmp_count: 0,
        inactive_tmp_count: 0,
        active_perm_count: 0,
        inactive_perm_count: 0,
        dirty_count: 0,
        laundry_count: 0,
        writeback_count: 0,
        slab_count: 0,
        slab_reclaim_count: 0,
    }
}

/// The mapping `vm_map()` asks for.
pub struct MapRequest<'a> {
    /// The requested address, written with the result on success.
    pub address: &'a mut VmOffset,
    /// Size of the mapping.
    pub size: VmSize,
    /// Alignment mask.
    pub mask: VmOffset,
    /// Whether the map chooses the address.
    pub anywhere: bool,
    /// `IP_NULL`, `IP_DEAD` or a live memory-object port.
    pub memory_object: *mut c_void,
    /// Offset into the memory object.
    pub offset: VmOffset,
    /// Whether the mapping copies the object rather than sharing it.
    pub copy: bool,
    /// Protection of the new mapping.
    pub cur_protection: VmProt,
    /// The most the protection may be raised to.
    pub max_protection: VmProt,
    /// What a child task's map gets of the mapping.
    pub inheritance: VmInherit,
}

/// Allocates a mapping backed by a memory object, a proxy for one, or
/// anonymous memory.
///
/// # Safety
///
/// `target_map` must be a live, unlocked map, and the request's
/// `memory_object` must be `IP_NULL`, `IP_DEAD` or a live port the caller
/// holds a reference to.
pub unsafe fn map<P: Platform>(
    target_map: &mut VmMap<P>,
    request: &mut MapRequest<'_>,
) -> Result<(), Error> {
    let mut cur_protection = request.cur_protection;
    let mut max_protection = request.max_protection;
    let mut offset = request.offset;
    let mut copy = request.copy;

    if cur_protection.bits() & !VmProt::ALL.bits() != 0
        || max_protection.bits() & !VmProt::ALL.bits() != 0
    {
        return Err(Error::InvalidArgument);
    }

    match request.inheritance {
        VmInherit::NONE | VmInherit::COPY | VmInherit::SHARE => (),
        _ => return Err(Error::InvalidArgument),
    }

    if request.size == 0 {
        return Err(Error::InvalidArgument);
    }

    *request.address = trunc_page(*request.address);
    let size = round_page(request.size);

    let mut object: *mut VmObject = null_mut();
    if Port::valid(request.memory_object).is_none() {
        offset = 0;
        copy = false;
    } else {
        // SAFETY: the port is valid and the caller holds its reference.
        if let Some(entered) =
            // SAFETY: the port is valid and the caller holds its reference.
            unsafe {
                vm_object::enter::<P>(request.memory_object, size, false)
            }
        {
            object = entered.as_ptr();
        } else {
            // SAFETY: the port is valid and unlocked.
            let target = unsafe {
                memory_object_proxy::lookup::<P>(request.memory_object)
            }?;

            if !copy {
                // Reduce the allowed access to the memory object.
                max_protection &= target.max_protection;
                cur_protection &= target.max_protection;
            } else if !target.max_protection.contains(VmProt::READ) {
                // Disallow making a copy unless the proxy allows reading.
                return Err(Error::ProtectionFailure);
            }

            let range_end =
                target.start.wrapping_add(offset).wrapping_add(size);
            if range_end > target.start.wrapping_add(target.len) {
                return Err(Error::InvalidArgument);
            }
            offset = offset.wrapping_add(target.start);

            // SAFETY: the proxy named a live port.
            match unsafe { vm_object::enter::<P>(target.object, size, false) }
            {
                Some(entered) => object = entered.as_ptr(),
                None => return Err(Error::InvalidArgument),
            }
        }
    }

    if copy {
        // SAFETY: the object is live and unlocked, and this call owns the
        // reference it deallocates below.
        let result = unsafe {
            vm_object::copy_strategically::<P>(object, offset, size)
        };
        // SAFETY: the object is live and owned by this call.
        unsafe { vm_object::deallocate::<P>(object) };

        match result {
            vm_object::StrategicResult::Copied {
                object: new_object,
                offset: new_offset,
                needs_copy,
            } => {
                object = new_object.as_ptr();
                offset = new_offset;
                copy = needs_copy;
            }
            vm_object::StrategicResult::Interrupted => {
                return Err(Error::Interrupted);
            }
            vm_object::StrategicResult::NullObject(error)
            | vm_object::StrategicResult::Failed(error) => return Err(error),
            // The strategy is one of the three cases above; the C left its
            // out-parameters uninitialized here.
            vm_object::StrategicResult::Unchanged => {
                return Err(Error::Failure);
            }
        }
    }

    let entered = target_map.enter(EnterRequest {
        address: request.address,
        size,
        mask: request.mask,
        anywhere: request.anywhere,
        object,
        offset,
        needs_copy: copy,
        cur_protection,
        max_protection,
        inheritance: request.inheritance,
    });

    if let Err(error) = entered {
        // SAFETY: the object is live and owned by this call.
        unsafe { vm_object::deallocate::<P>(object) };
        return Err(error);
    }

    Ok(())
}

/// Wires the pages of `start..start + size` for `map`.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port; `map` must be null or
/// a live, unlocked map.
pub unsafe fn wire<P: Platform>(
    port: *mut c_void,
    map: *mut VmMap<P>,
    start: VmOffset,
    size: VmSize,
    access: VmProt,
) -> Result<(), Error> {
    let Some(port) = Port::valid(port) else {
        return Err(Error::InvalidHost);
    };

    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { P::port_lock(port) };
    // SAFETY: the port lock is held.
    let active = unsafe { P::port_is_active(port) };
    // SAFETY: the port lock is held.
    let kind = if active {
        // SAFETY: the port lock is held.
        unsafe { P::port_kotype(port) }
    } else {
        IKOT_NONE
    };
    if !active || (kind != IKOT_HOST_PRIV && kind != IKOT_HOST) {
        // SAFETY: the port was locked above.
        unsafe { P::port_unlock(port) };
        return Err(Error::InvalidHost);
    }
    let privileged = kind == IKOT_HOST_PRIV;
    // SAFETY: the port was locked above.
    unsafe { P::port_unlock(port) };

    let Some(map) = NonNull::new(map) else {
        return Err(Error::InvalidTask);
    };
    if access.bits() & !VmProt::ALL.bits() != 0 {
        return Err(Error::InvalidArgument);
    }

    // A range that includes a projected buffer may not be wired directly.
    if projected_buffer_in_range(
        unsafe { &*map.as_ptr() },
        start,
        start.wrapping_add(size),
    ) {
        return Err(Error::InvalidArgument);
    }

    if !privileged
        && access != VmProt::empty()
        && unsafe { (*map.as_ptr()).size_wired.wrapping_add(size) }
            > UNPRIVILEGED_WIRE_LIMIT
    {
        return Err(Error::NoAccess);
    }

    // SAFETY: the map is live and unlocked, as `pageable()` requires.
    unsafe {
        (*map.as_ptr()).pageable(
            trunc_page(start),
            round_page(start.wrapping_add(size)),
            access,
            true,
            true,
        )
    }
}

/// Wires every mapping of `map`, now or for the future.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port; `map` must be null or
/// a live, unlocked map.
pub unsafe fn wire_all<P: Platform>(
    port: *mut c_void,
    map: *mut VmMap<P>,
    flags: c_int,
) -> Result<(), Error> {
    let Some(port) = Port::valid(port) else {
        return Err(Error::InvalidHost);
    };

    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { P::port_lock(port) };
    // SAFETY: the port lock is held.
    let active = unsafe { P::port_is_active(port) };
    // SAFETY: the port lock is held.
    let kind = if active {
        // SAFETY: the port lock is held.
        unsafe { P::port_kotype(port) }
    } else {
        IKOT_NONE
    };
    if !active || kind != IKOT_HOST_PRIV {
        // SAFETY: the port was locked above.
        unsafe { P::port_unlock(port) };
        return Err(Error::InvalidHost);
    }
    // SAFETY: the port was locked above.
    unsafe { P::port_unlock(port) };

    let Some(map) = NonNull::new(map) else {
        return Err(Error::InvalidTask);
    };
    if flags & !VM_WIRE_ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    let map_ref = unsafe { &*map.as_ptr() };
    if projected_buffer_in_range(
        map_ref,
        map_ref.hdr.links.start,
        map_ref.hdr.links.end,
    ) {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the map is live and unlocked.
    unsafe { (*map.as_ptr()).pageable_all(flags) }
}

/// `vm_allocate_contiguous()`'s selector chain: the narrowest segment set
/// that reaches `pmax`.
const fn page_selector<P: Platform>(pmax: RpcPhysAddr) -> c_uint {
    // The C compared the 64-bit interface address against the machine limit;
    // widening the limit cannot lose a bit.
    let pmax = pmax.bits();
    if pmax <= P::DMA_LIMIT as u64 {
        return vm_page::SEL_DMA;
    }
    if pmax <= P::DIRECTMAP_LIMIT as u64 {
        return vm_page::SEL_DIRECTMAP;
    }
    if pmax <= P::DMA32_LIMIT as u64 {
        return vm_page::SEL_DMA32;
    }
    vm_page::SEL_HIGHMEM
}

/// Insert the pages of a contiguous block into `object`, wiring the `size`
/// bytes of it, and release the order tail.
///
/// # Safety
///
/// `object` must be live and `pages_ptr` the live contiguous block the
/// allocator returned for it, with the page queues unlocked.
unsafe fn insert_contig_pages<P: Platform>(
    object: NonNull<VmObject>,
    pages_ptr: *mut VmPage,
    size: VmSize,
    npages: usize,
) {
    unsafe {
        (*object.as_ptr()).lock.lock();
        VM_PAGE_QUEUE_LOCK.lock();

        for i in 0..vm_page::atop(size) {
            let page = NonNull::new_unchecked(pages_ptr.add(i));
            (*page.as_ptr()).set_busy(false);
            vm_resident::insert::<P>(page, object, vm_page::ptoa(i));
            vm_page::wire(page);
        }

        VM_PAGE_QUEUE_LOCK.unlock();
        (*object.as_ptr()).lock.unlock();

        for i in vm_page::atop(size)..npages {
            vm_resident::release::<P>(
                NonNull::new_unchecked(pages_ptr.add(i)),
                false,
                false,
            );
        }
    }
}

/// Allocates a physically contiguous, zero-filled block and maps it.
///
/// # Safety
///
/// `map` must be null or a live, unlocked map, and this call must not hold
/// `VM_PAGE_QUEUE_FREE_LOCK`.
pub unsafe fn allocate_contiguous<P: Platform>(
    map: *mut VmMap<P>,
    size: VmSize,
    pmin: RpcPhysAddr,
    pmax: RpcPhysAddr,
    palign: RpcPhysAddr,
) -> Result<(VmOffset, RpcPhysAddr), Error> {
    let Some(map) = NonNull::new(map) else {
        return Err(Error::InvalidTask);
    };

    // FIXME: support a minimum physical address.
    if pmin != RpcPhysAddr::ZERO {
        return Err(Error::InvalidArgument);
    }

    // The C's page size as the 64-bit interface type; the widening cannot
    // lose a bit.
    let page_size = PAGE_SIZE as u64;
    let mut palign = palign.bits();
    if palign == 0 {
        palign = page_size;
    }

    // FIXME: Allows some small alignments less than page size.
    if palign < page_size && page_size.is_multiple_of(palign) {
        palign = page_size;
    }

    // FIXME: only page alignment is supported.
    if palign != page_size {
        return Err(Error::InvalidArgument);
    }

    let selector = page_selector::<P>(pmax);

    let size = vm_page::round_page(size);
    if size == 0 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the object allocator halts the kernel rather than fail.
    let object = unsafe { vm_object::allocate::<P>(size) };
    let object_ptr = object.as_ptr();

    let order = vm_resident::page_order(size);
    // The C's `1 << (order + PAGE_SHIFT)`; the allocator's order cannot reach
    // the word width in a live kernel.
    let alloc_size = 1usize.wrapping_shl(order.wrapping_add(PAGE_SHIFT));
    let npages = vm_page::atop(alloc_size);

    // SAFETY: nothing holds `VM_PAGE_QUEUE_FREE_LOCK`, and the caller permits
    // the allocator to spin.
    let Some(pages) =
        (unsafe { vm_resident::grab_contig::<P>(alloc_size, selector) })
    else {
        // SAFETY: the object is live and owned by this call.
        unsafe { vm_object::deallocate::<P>(object_ptr) };
        return Err(Error::ResourceShortage);
    };
    let pages_ptr = pages.as_ptr();

    unsafe { insert_contig_pages::<P>(object, pages_ptr, size, npages) };

    let mut vaddr: VmOffset = 0;
    // SAFETY: the map is live and unlocked, as `enter()` requires.
    let entered = unsafe {
        (*map.as_ptr()).enter(EnterRequest {
            address: &mut vaddr,
            size,
            mask: 0,
            anywhere: true,
            object: object_ptr,
            offset: 0,
            needs_copy: false,
            cur_protection: VmProt::READ | VmProt::WRITE,
            max_protection: VmProt::READ | VmProt::WRITE,
            inheritance: VmInherit::COPY,
        })
    };

    if let Err(error) = entered {
        // SAFETY: the object is live and owned by this call.
        unsafe { vm_object::deallocate::<P>(object_ptr) };
        return Err(error);
    }

    // SAFETY: the map is live and unlocked.
    let pageable_result = unsafe {
        (*map.as_ptr()).pageable(
            vaddr,
            vaddr.wrapping_add(size),
            VmProt::READ | VmProt::WRITE,
            true,
            true,
        )
    };

    if let Err(error) = pageable_result {
        // SAFETY: the map is live and unlocked.
        let _ =
            unsafe { (*map.as_ptr()).remove(vaddr, vaddr.wrapping_add(size)) };
        return Err(error);
    }

    // SAFETY: the object is live, the page-queues lock is free, and the block
    // is still the caller's.
    unsafe {
        (*object_ptr).lock.lock();
        VM_PAGE_QUEUE_LOCK.lock();
        for i in 0..vm_page::atop(size) {
            vm_page::unwire(pages_ptr.add(i));
        }
        VM_PAGE_QUEUE_LOCK.unlock();
        (*object_ptr).lock.unlock();

        // SAFETY: the first page is live and the object holds it.
        let paddr = RpcPhysAddr::from_vm_offset((*pages_ptr).phys_addr);
        Ok((vaddr, paddr))
    }
}

/// The physical address mapped at `address`, or zero when no entry covers it.
///
/// # Safety
///
/// `map` must be a live map, and the caller must permit taking its read lock.
unsafe fn mapped_phys_addr<P: Platform>(
    map: *mut VmMap<P>,
    address: VmOffset,
) -> RpcPhysAddr {
    let mut cmap = unsafe { NonNull::new_unchecked(map) };
    // SAFETY: the map is live and unlocked.
    unsafe { (*map).lock.lock() };

    let entry = loop {
        // SAFETY: `cmap` is live and read-locked.
        let (found, entry) = unsafe { (*cmap.as_ptr()).lookup_entry(address) };
        if !found {
            break None;
        }

        // SAFETY: `cmap` is live and read-locked.
        if unsafe { (*entry.as_ptr()).is_sub_map() } {
            // SAFETY: a submap entry names a live map.
            let nmap = unsafe { (*entry.as_ptr()).object.sub_map };
            // SAFETY: a submap entry names a live map.
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

        break Some(entry);
    };

    let mut paddr = RpcPhysAddr::ZERO;
    if let Some(entry) = entry {
        // SAFETY: the entry is live in the read-locked map.
        let entry = unsafe { &*entry.as_ptr() };
        let offset = address
            .wrapping_sub(entry.links.start)
            .wrapping_add(entry.offset);
        // SAFETY: the entry's union holds the object member it was tagged
        // with.
        let object = unsafe { entry.object.vm_object };

        if !object.is_null() {
            // SAFETY: the object is live and unlocked.
            unsafe { (*object).lock.lock() };
            // SAFETY: the object lock is held.
            let page = unsafe {
                vm_resident::lookup(NonNull::new_unchecked(object), offset)
            };
            if let Some(page) = page {
                // SAFETY: the page is live and the object lock is held.
                paddr = RpcPhysAddr::from_vm_offset(unsafe {
                    (*page.as_ptr()).phys_addr
                });
            }
            // SAFETY: the object was locked above.
            unsafe { (*object).lock.unlock() };
        }
    }
    // SAFETY: `cmap` was read-locked.
    unsafe { (*cmap.as_ptr()).lock.unlock() };

    paddr
}

/// The physical address of every page of `address..address + size`.
///
/// # Safety
///
/// `map` must be null or a live, unlocked map; `pagespp` and `countp` must be
/// writable storage, and the caller permits an allocation and a kernel-map
/// copy.
pub unsafe fn pages_phys<P: Platform>(
    map: *mut VmMap<P>,
    address: VmOffset,
    size: VmSize,
    pagespp: *mut *mut RpcPhysAddr,
    countp: *mut c_uint,
) -> Result<(), Error> {
    if map.is_null() {
        return Err(Error::InvalidTask);
    }
    if address & PAGE_MASK != 0 || size & PAGE_MASK != 0 {
        return Err(Error::InvalidArgument);
    }

    // The C assigned the page count to a `mach_msg_type_number_t`; a mapped
    // range that long cannot exist.
    let count = vm_page::atop(size) as c_uint;

    let initial = unsafe { *pagespp };
    let pages = if unsafe { *countp } < count {
        let bytes = as_index(count) * size_of::<RpcPhysAddr>();
        // SAFETY: the kernel map is live once VM is up.
        let kmap =
            unsafe { NonNull::new_unchecked(P::state().ipc_kernel_map()) };
        // SAFETY: the kernel map is live, nothing is locked, and the caller
        // permits the allocation.
        let allocated = kmem_alloc(kmap, bytes)?;
        with_exposed_provenance_mut(allocated)
    } else {
        initial
    };

    for cur in 0..as_index(count) {
        // SAFETY: the map is live and unlocked.
        let paddr = unsafe {
            mapped_phys_addr(map, address.wrapping_add(cur * PAGE_SIZE))
        };
        // SAFETY: `cur` is inside the `count`-record buffer.
        unsafe { pages.add(cur).write(paddr) };
    }

    if pages != initial {
        let bytes = as_index(count) * size_of::<RpcPhysAddr>();
        let kmap = P::state().ipc_kernel_map();
        // SAFETY: the region is live in the kernel map, which is unlocked,
        // and the caller permits the copy.
        if let Ok(copy) =
            // SAFETY: the region is live in the kernel map, which is
            // unlocked, and the caller permits the copy.
            unsafe {
                (*kmap).copyin(pages.expose_provenance(), bytes, true)
            }
        {
            unsafe { *pagespp = copy.as_ptr().cast() };
        }
    }
    unsafe { *countp = count };

    Ok(())
}

/// Sets the current and maximum virtual size limits of `map`.  Increasing the
/// maximum takes the privileged host port.
///
/// # Safety
///
/// `host_port` must be `IP_NULL`, `IP_DEAD` or a live port, and `map` must be
/// null or a live, unlocked map.
pub unsafe fn set_size_limit<P: Platform>(
    host_port: *mut c_void,
    map: *mut VmMap<P>,
    current_limit: VmSize,
    max_limit: VmSize,
) -> Result<(), Error> {
    if current_limit > max_limit {
        return Err(Error::InvalidArgument);
    }
    let Some(map) = NonNull::new(map) else {
        return Err(Error::InvalidTask);
    };

    let Some(host_port) = Port::valid(host_port) else {
        return Err(Error::InvalidHost);
    };

    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { P::port_lock(host_port) };
    // SAFETY: the port lock is held.
    let ikot_host = if unsafe { P::port_is_active(host_port) } {
        unsafe { P::port_kotype(host_port) }
    } else {
        IKOT_NONE
    };
    // SAFETY: the port was locked above.
    unsafe { P::port_unlock(host_port) };

    if ikot_host != IKOT_HOST && ikot_host != IKOT_HOST_PRIV {
        return Err(Error::InvalidHost);
    }

    // SAFETY: the map is live and unlocked.
    VmMap::<P>::lock(map);
    // SAFETY: the map is live and unlocked.
    if max_limit > unsafe { (*map.as_ptr()).size_max_limit }
        && ikot_host != IKOT_HOST_PRIV
    {
        // SAFETY: the map was locked above.
        VmMap::<P>::unlock(map);
        return Err(Error::NoAccess);
    }

    // SAFETY: the map lock is held.
    unsafe {
        (*map.as_ptr()).size_cur_limit = current_limit;
        (*map.as_ptr()).size_max_limit = max_limit;
    }
    // SAFETY: the map was locked above.
    VmMap::<P>::unlock(map);

    Ok(())
}

/// The lock-request policy that returns no pages to the pager.
const MEMORY_OBJECT_RETURN_NONE: c_int = 0;
/// The lock-request policy that returns every dirty and precious page to the
/// pager.
const MEMORY_OBJECT_RETURN_ALL: c_int = 2;

/// `VM_PROT_ALL | VM_PROT_NOTIFY`: the protection bits `vm_protect()` accepts.
const VM_PROT_SETTER_MASK: c_int = VmProt::ALL.bits() | VmProt::NOTIFY.bits();

/// Allocates zero-filled memory in `map`.
pub fn allocate<P: Platform>(
    map: &mut VmMap<P>,
    addr: &mut VmOffset,
    size: VmSize,
    anywhere: bool,
) -> Result<(), Error> {
    if size == 0 {
        *addr = 0;
        return Ok(());
    }

    if anywhere {
        *addr = map.hdr.links.start;
    } else {
        *addr = trunc_page(*addr);
    }

    map.enter(EnterRequest {
        address: addr,
        size: round_page(size),
        mask: 0,
        anywhere,
        object: null_mut(),
        offset: 0,
        needs_copy: false,
        cur_protection: VmProt::READ | VmProt::WRITE,
        max_protection: VmProt::ALL,
        inheritance: VmInherit::COPY,
    })
}

/// Drops the pages covering `start..start + size`.
pub fn deallocate<P: Platform>(
    map: &mut VmMap<P>,
    start: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    if size == 0 {
        return Ok(());
    }

    map.remove(trunc_page(start), round_page(start.wrapping_add(size)))
}

/// Sets the inheritance of a range.
pub fn inherit<P: Platform>(
    map: &mut VmMap<P>,
    start: VmOffset,
    size: VmSize,
    new_inheritance: VmInherit,
) -> Result<(), Error> {
    match new_inheritance {
        VmInherit::NONE | VmInherit::COPY | VmInherit::SHARE => (),
        _ => return Err(Error::InvalidArgument),
    }

    let end = start.wrapping_add(size);
    if projected_buffer_in_range(map, start, end) {
        return Err(Error::InvalidArgument);
    }

    map.inherit(trunc_page(start), round_page(end), new_inheritance);
    Ok(())
}

/// Sets the protection of a range.
pub fn protect<P: Platform>(
    map: &mut VmMap<P>,
    start: VmOffset,
    size: VmSize,
    set_maximum: bool,
    new_protection: VmProt,
) -> Result<(), Error> {
    if new_protection.bits() & !VM_PROT_SETTER_MASK != 0 {
        return Err(Error::InvalidArgument);
    }

    let end = start.wrapping_add(size);
    if projected_buffer_in_range(map, start, end) {
        return Err(Error::InvalidArgument);
    }

    map.protect(
        trunc_page(start),
        round_page(end),
        new_protection,
        set_maximum,
    )
}

/// Hands a machine attribute to the map's physical map.
pub fn machine_attribute<P: Platform>(
    map: &VmMap<P>,
    address: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    if projected_buffer_in_range(map, address, address.wrapping_add(size)) {
        return Err(Error::InvalidArgument);
    }

    VmMap::<P>::machine_attribute(NonNull::from(map), address, size)
}

/// Copies a range out as a map copy for the IPC layer.
pub fn read<P: Platform>(
    map: &mut VmMap<P>,
    address: VmOffset,
    size: VmSize,
) -> Result<Option<NonNull<VmMapCopy<P>>>, Error> {
    copyin(map, address, size)
}

/// Overwrites a range with the copy an IPC message carried.
pub fn write<P: Platform>(
    map: &mut VmMap<P>,
    address: VmOffset,
    copy: Option<NonNull<VmMapCopy<P>>>,
) -> Result<(), Error> {
    let Some(copy) = copy else {
        return Ok(());
    };

    // SAFETY: the caller owns the live copy; `copy_overwrite` consumes it on
    // success and leaves it to the caller on failure.
    unsafe { map.copy_overwrite(address, copy) }
}

/// Copies a range to another address in the same map.
pub fn copy<P: Platform>(
    map: &mut VmMap<P>,
    source_address: VmOffset,
    size: VmSize,
    dest_address: VmOffset,
) -> Result<(), Error> {
    let Some(copy) = copyin(map, source_address, size)? else {
        return Ok(());
    };

    // SAFETY: `copyin` returned a live copy this call owns; `copy_overwrite`
    // consumes it on success and leaves it here on failure.
    match unsafe { map.copy_overwrite(dest_address, copy) } {
        Ok(()) => Ok(()),
        Err(error) => {
            // SAFETY: the failed overwrite left the live copy to the caller.
            unsafe { VmMapCopy::<P>::discard(copy) };
            Err(error)
        }
    }
}

/// Writes a range of `object` back to its memory manager.
pub fn object_sync<P: Platform>(
    object: NonNull<VmObject>,
    offset: VmOffset,
    size: VmSize,
    should_flush: bool,
    should_return: bool,
) -> Result<(), Error> {
    // SAFETY: the caller promises a live object; `memory_object_lock_request`
    // consumes the reference taken here.
    unsafe { vm_object::reference(object.as_ptr()) };

    let size =
        round_page(offset.wrapping_add(size)).wrapping_sub(trunc_page(offset));
    let offset = trunc_page(offset);
    let should_return = if should_return {
        MEMORY_OBJECT_RETURN_ALL
    } else {
        MEMORY_OBJECT_RETURN_NONE
    };

    // SAFETY: the object reference was just taken, and the C passes a null
    // reply port with no right to consume.
    unsafe {
        memory_object::lock_request::<P>(
            object.as_ptr(),
            &memory_object::LockRequest {
                offset,
                size,
                should_return: Return::from_c(should_return),
                should_flush,
                prot: VmProt::NO_CHANGE,
                reply_to: null_mut(),
                reply_to_type: 0,
            },
        )
    }
}

/// Synchronizes a range with its memory manager.
pub fn msync<P: Platform>(
    map: &mut VmMap<P>,
    address: VmOffset,
    size: VmSize,
    sync_flags: c_int,
) -> Result<(), Error> {
    VmMap::<P>::msync(Some(NonNull::from(map)), address, size, sync_flags)
}

/// Reports the current and maximum virtual size limits of `map`.
pub fn get_size_limit<P: Platform>(map: &VmMap<P>) -> (VmSize, VmSize) {
    map.lock.lock();
    let limits = (map.size_cur_limit, map.size_max_limit);
    // SAFETY: the lock was taken just above.
    unsafe { map.lock.unlock() };
    limits
}

/// Copies a range in for the IPC layer, keeping the interface's zero-length
/// case: a zero-byte range yields no copy, while the map core rejects it as an
/// address overflow.
fn copyin<P: Platform>(
    map: &mut VmMap<P>,
    address: VmOffset,
    size: VmSize,
) -> Result<Option<NonNull<VmMapCopy<P>>>, Error> {
    if size == 0 {
        return Ok(None);
    }

    map.copyin(address, size, false).map(Some)
}
