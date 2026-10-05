// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_user.c and vm/vm_user.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The user-exported virtual memory calls, which `vm/vm_user.c` used to
//! define and `vm/vm_user.h` declares.

use crate::arch::types::{RpcPhysAddr, VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::biosmem::VM_PAGE_DMA32_LIMIT;
use crate::arch::x86_64::biosmem::{
    VM_PAGE_DIRECTMAP_LIMIT, VM_PAGE_DMA_LIMIT,
};
use crate::ipc::{IpcPort, ipc_init};
use crate::kern::host::Host;
use crate::vm::error::Error;
use crate::vm::memory_object::{self, Return};
use crate::vm::memory_object_proxy;
use crate::vm::types::{VmInherit, VmObject, VmPage, VmProt, VmStatistics};
use crate::vm::vm_kern::{kmem_alloc, projected_buffer_in_range};
use crate::vm::vm_map::{
    EnterRequest, VmMap, VmMapCopy, round_page, trunc_page,
};
use crate::vm::vm_object;
use crate::vm::vm_page;
use crate::vm::vm_resident;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{
    self, NonNull, addr_of, null_mut, with_exposed_provenance_mut,
};
use core::sync::atomic::Ordering;

/// `IKOT_NONE`, `IKOT_HOST` and `IKOT_HOST_PRIV` of <`kern/ipc_kobject.h`>.
const IKOT_NONE: c_uint = 0;
const IKOT_HOST: c_uint = 3;
const IKOT_HOST_PRIV: c_uint = 4;

/// `VM_WIRE_CURRENT | VM_WIRE_FUTURE` of <`mach/vm_wire.h`>.
const VM_WIRE_ALL: c_int = 3;

/// The 8 MiB cap `vm_wire()` puts on an unprivileged map's wired size.
const UNPRIVILEGED_WIRE_LIMIT: VmSize = 8 << 20;

/// The `unsigned int` run of `struct vm_cache_statistics` of
/// <`mach/vm_cache_statistics.h`>.
#[repr(C)]
#[allow(missing_docs)]
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

/// `vm_stat` of <`mach/vm_statistics.h>`: the system-wide statistics block the
/// C kept in `vm/vm_user.c`.
pub static mut VM_STAT: VmStatistics = VmStatistics::zeroed();

/// A table count as an index; the widening is lossless.
const fn as_index(count: c_uint) -> usize {
    count as usize
}

/// `vm_statistics()` in C: the kernel's counters, with the live page counts
/// added.
pub(crate) fn statistics() -> VmStatistics {
    // SAFETY: `vm_stat` is the plain C global; the C read it without a lock.
    let mut stat = unsafe { ptr::read(addr_of!(VM_STAT)) };

    // The page size fits an integer_t.
    stat.pagesize = PAGE_SIZE as c_int;
    // The C assigned the unsigned long count to an integer_t; those many
    // free pages cannot exist.
    stat.free_count = vm_page::mem_free() as c_int;
    stat.active_count =
        vm_resident::VM_PAGE_ACTIVE_COUNT.load(Ordering::Relaxed);
    stat.inactive_count =
        vm_resident::VM_PAGE_INACTIVE_COUNT.load(Ordering::Relaxed);
    stat.wire_count = vm_resident::VM_PAGE_WIRE_COUNT.load(Ordering::Relaxed);

    stat
}

/// `vm_cache_statistics()` in C.
pub(crate) fn cache_statistics() -> VmCacheStatistics {
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
pub(crate) struct MapRequest<'a> {
    /// The requested address, written with the result on success.
    pub(crate) address: &'a mut VmOffset,
    pub(crate) size: VmSize,
    pub(crate) mask: VmOffset,
    pub(crate) anywhere: bool,
    /// `IP_NULL`, `IP_DEAD` or a live memory-object port.
    pub(crate) memory_object: *mut c_void,
    pub(crate) offset: VmOffset,
    pub(crate) copy: bool,
    pub(crate) cur_protection: VmProt,
    pub(crate) max_protection: VmProt,
    pub(crate) inheritance: VmInherit,
}

/// `vm_map()` in C: allocate a mapping backed by a memory object, a proxy for
/// one, or anonymous memory.
///
/// # Safety
///
/// `target_map` must be a live, unlocked map, and the request's
/// `memory_object` must be `IP_NULL`, `IP_DEAD` or a live port the caller
/// holds a reference to.
pub(crate) unsafe fn map(
    target_map: &mut VmMap,
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
    if IpcPort::valid(request.memory_object).is_none() {
        offset = 0;
        copy = false;
    } else {
        // SAFETY: the port is valid and the caller holds its reference.
        if let Some(entered) =
            // SAFETY: the port is valid and the caller holds its reference.
            unsafe {
                vm_object::enter(request.memory_object, size, false)
            }
        {
            object = entered.as_ptr();
        } else {
            // SAFETY: the port is valid and unlocked.
            let target =
                unsafe { memory_object_proxy::lookup(request.memory_object) }?;

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
            match unsafe { vm_object::enter(target.object, size, false) } {
                Some(entered) => object = entered.as_ptr(),
                None => return Err(Error::InvalidArgument),
            }
        }
    }

    if copy {
        // SAFETY: the object is live and unlocked, and this call owns the
        // reference it deallocates below.
        let result =
            unsafe { vm_object::copy_strategically(object, offset, size) };
        // SAFETY: the object is live and owned by this call.
        unsafe { vm_object::deallocate(object) };

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
        unsafe { vm_object::deallocate(object) };
        return Err(error);
    }

    Ok(())
}

/// `vm_wire()` in C: wire the pages of `start..start + size` for `map`.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port; `map` must be null or
/// a live, unlocked map.
pub(crate) unsafe fn wire(
    port: *mut c_void,
    map: *mut VmMap,
    start: VmOffset,
    size: VmSize,
    access: VmProt,
) -> Result<(), Error> {
    let Some(port) = IpcPort::valid(port) else {
        return Err(Error::InvalidHost);
    };

    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { port.lock() };
    // SAFETY: the port lock is held.
    let active = unsafe { port.is_active() };
    // SAFETY: the port lock is held.
    let kind = if active {
        // SAFETY: the port lock is held.
        unsafe { port.kotype() }
    } else {
        IKOT_NONE
    };
    if !active || (kind != IKOT_HOST_PRIV && kind != IKOT_HOST) {
        // SAFETY: the port was locked above.
        unsafe { port.unlock() };
        return Err(Error::InvalidHost);
    }
    let privileged = kind == IKOT_HOST_PRIV;
    // SAFETY: the port was locked above.
    unsafe { port.unlock() };

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
        && access != VmProt::NONE
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

/// `vm_wire_all()` in C: wire every mapping of `map`, now or for the future.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port; `map` must be null or
/// a live, unlocked map.
pub(crate) unsafe fn wire_all(
    port: *mut c_void,
    map: *mut VmMap,
    flags: c_int,
) -> Result<(), Error> {
    let Some(port) = IpcPort::valid(port) else {
        return Err(Error::InvalidHost);
    };

    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { port.lock() };
    // SAFETY: the port lock is held.
    let active = unsafe { port.is_active() };
    // SAFETY: the port lock is held.
    let kind = if active {
        // SAFETY: the port lock is held.
        unsafe { port.kotype() }
    } else {
        IKOT_NONE
    };
    if !active || kind != IKOT_HOST_PRIV {
        // SAFETY: the port was locked above.
        unsafe { port.unlock() };
        return Err(Error::InvalidHost);
    }
    // SAFETY: the port was locked above.
    unsafe { port.unlock() };

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
const fn page_selector(pmax: RpcPhysAddr) -> c_uint {
    // The C compared the 64-bit interface address against the machine limit;
    // widening the limit cannot lose a bit.
    let pmax = pmax.bits();
    if pmax <= VM_PAGE_DMA_LIMIT as u64 {
        return vm_page::SEL_DMA;
    }
    if pmax <= VM_PAGE_DIRECTMAP_LIMIT as u64 {
        return vm_page::SEL_DIRECTMAP;
    }
    if pmax <= VM_PAGE_DMA32_LIMIT as u64 {
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
unsafe fn insert_contig_pages(
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
            vm_resident::insert(page, object, vm_page::ptoa(i));
            vm_page::wire(page);
        }

        VM_PAGE_QUEUE_LOCK.unlock();
        (*object.as_ptr()).lock.unlock();

        for i in vm_page::atop(size)..npages {
            vm_resident::release(
                NonNull::new_unchecked(pages_ptr.add(i)),
                false,
                false,
            );
        }
    }
}

/// `vm_allocate_contiguous()` in C: allocate a physically contiguous,
/// zero-filled block and map it.
///
/// # Safety
///
/// `host_priv` must be null or the live host pointer the generated server
/// converted the request port into; `map` must be null or a live, unlocked
/// map, and this call must not hold `vm_page_queue_free_lock`.
pub(crate) unsafe fn allocate_contiguous(
    host_priv: Option<NonNull<Host>>,
    map: *mut VmMap,
    size: VmSize,
    pmin: RpcPhysAddr,
    pmax: RpcPhysAddr,
    palign: RpcPhysAddr,
) -> Result<(VmOffset, RpcPhysAddr), Error> {
    if host_priv.is_none() {
        return Err(Error::InvalidHost);
    }
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

    let selector = page_selector(pmax);

    let size = vm_page::round_page(size);
    if size == 0 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the object allocator halts the kernel rather than fail.
    let object = unsafe { vm_object::allocate(size) };
    let object_ptr = object.as_ptr();

    let order = vm_resident::page_order(size);
    // The C's `1 << (order + PAGE_SHIFT)`; the allocator's order cannot reach
    // the word width in a live kernel.
    let alloc_size = 1usize.wrapping_shl(order.wrapping_add(PAGE_SHIFT));
    let npages = vm_page::atop(alloc_size);

    // SAFETY: nothing holds `vm_page_queue_free_lock`, and the caller permits
    // the allocator to spin.
    let Some(pages) =
        (unsafe { vm_resident::grab_contig(alloc_size, selector) })
    else {
        // SAFETY: the object is live and owned by this call.
        unsafe { vm_object::deallocate(object_ptr) };
        return Err(Error::ResourceShortage);
    };
    let pages_ptr = pages.as_ptr();

    unsafe { insert_contig_pages(object, pages_ptr, size, npages) };

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
        unsafe { vm_object::deallocate(object_ptr) };
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
unsafe fn mapped_phys_addr(map: *mut VmMap, address: VmOffset) -> RpcPhysAddr {
    let mut cmap = unsafe { NonNull::new_unchecked(map) };
    // SAFETY: the map is live and unlocked.
    unsafe { (*map).lock.read() };

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
            // SAFETY: the submap is live and unlocked.
            unsafe { (*nmap.as_ptr()).lock.read() };
            // SAFETY: `cmap` was read-locked.
            unsafe { (*cmap.as_ptr()).lock.done() };
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
    unsafe { (*cmap.as_ptr()).lock.done() };

    paddr
}

/// `vm_pages_phys()` in C: the physical address of every page of
/// `address..address + size`.
///
/// # Safety
///
/// `host` must be null or the live host pointer the generated server
/// converted the request port into; `map` must be null or a live, unlocked
/// map; `pagespp` and `countp` must be writable storage, and the caller
/// permits an allocation and a kernel-map copy.
pub(crate) unsafe fn pages_phys(
    host: Option<NonNull<Host>>,
    map: *mut VmMap,
    address: VmOffset,
    size: VmSize,
    pagespp: *mut *mut RpcPhysAddr,
    countp: *mut c_uint,
) -> Result<(), Error> {
    if host.is_none() {
        return Err(Error::InvalidHost);
    }
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
            unsafe { NonNull::new_unchecked(ipc_init::ipc_kernel_map()) };
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
        let kmap = ipc_init::ipc_kernel_map();
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

/// `vm_set_size_limit()` in C: set the current and maximum virtual size
/// limits of `map`.  Increasing the maximum takes the privileged host port.
///
/// # Safety
///
/// `host_port` must be `IP_NULL`, `IP_DEAD` or a live port, and `map` must be
/// null or a live, unlocked map.
pub(crate) unsafe fn set_size_limit(
    host_port: *mut c_void,
    map: *mut VmMap,
    current_limit: VmSize,
    max_limit: VmSize,
) -> Result<(), Error> {
    if current_limit > max_limit {
        return Err(Error::InvalidArgument);
    }
    let Some(map) = NonNull::new(map) else {
        return Err(Error::InvalidTask);
    };

    let Some(host_port) = IpcPort::valid(host_port) else {
        return Err(Error::InvalidHost);
    };

    // SAFETY: the port is live and this call does not hold its lock.
    unsafe { host_port.lock() };
    // SAFETY: the port lock is held.
    let ikot_host = if unsafe { host_port.is_active() } {
        unsafe { host_port.kotype() }
    } else {
        IKOT_NONE
    };
    // SAFETY: the port was locked above.
    unsafe { host_port.unlock() };

    if ikot_host != IKOT_HOST && ikot_host != IKOT_HOST_PRIV {
        return Err(Error::InvalidHost);
    }

    // SAFETY: the map is live and unlocked.
    VmMap::lock(map);
    // SAFETY: the map is live and unlocked.
    if max_limit > unsafe { (*map.as_ptr()).size_max_limit }
        && ikot_host != IKOT_HOST_PRIV
    {
        // SAFETY: the map was locked above.
        VmMap::unlock(map);
        return Err(Error::NoAccess);
    }

    // SAFETY: the map lock is held.
    unsafe {
        (*map.as_ptr()).size_cur_limit = current_limit;
        (*map.as_ptr()).size_max_limit = max_limit;
    }
    // SAFETY: the map was locked above.
    VmMap::unlock(map);

    Ok(())
}

/// `MEMORY_OBJECT_RETURN_NONE` of <`mach/memory_object.h`>.
const MEMORY_OBJECT_RETURN_NONE: c_int = 0;
/// `MEMORY_OBJECT_RETURN_ALL` of <`mach/memory_object.h`>.
const MEMORY_OBJECT_RETURN_ALL: c_int = 2;

/// `VM_PROT_ALL | VM_PROT_NOTIFY`: the protection bits `vm_protect()` accepts.
const VM_PROT_SETTER_MASK: c_int = VmProt::ALL.bits() | VmProt::NOTIFY.bits();

/// `vm_allocate()` in C: allocate zero-filled memory in `map`.
pub(crate) fn allocate(
    map: &mut VmMap,
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

/// `vm_deallocate()` in C: drop the pages covering `start..start + size`.
pub(crate) fn deallocate(
    map: &mut VmMap,
    start: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    if size == 0 {
        return Ok(());
    }

    map.remove(trunc_page(start), round_page(start.wrapping_add(size)))
}

/// `vm_inherit()` in C: set the inheritance of a range.
pub(crate) fn inherit(
    map: &mut VmMap,
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

/// `vm_protect()` in C: set the protection of a range.
pub(crate) fn protect(
    map: &mut VmMap,
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

/// `vm_machine_attribute()` in C: hand a machine attribute to the map's
/// physical map.
pub(crate) fn machine_attribute(
    map: &VmMap,
    address: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    if projected_buffer_in_range(map, address, address.wrapping_add(size)) {
        return Err(Error::InvalidArgument);
    }

    VmMap::machine_attribute(NonNull::from(map), address, size)
}

/// `vm_read()` in C: copy a range out as a map copy for the IPC layer.
pub(crate) fn read(
    map: &mut VmMap,
    address: VmOffset,
    size: VmSize,
) -> Result<Option<NonNull<VmMapCopy>>, Error> {
    copyin(map, address, size)
}

/// `vm_write()` in C: overwrite a range with the copy an IPC message
/// carried.
pub(crate) fn write(
    map: &mut VmMap,
    address: VmOffset,
    copy: Option<NonNull<VmMapCopy>>,
) -> Result<(), Error> {
    let Some(copy) = copy else {
        return Ok(());
    };

    // SAFETY: the caller owns the live copy; the C `vm_map_copy_overwrite()`
    // consumes it on success and leaves it to the caller on failure.
    unsafe { map.copy_overwrite(address, copy) }
}

/// `vm_copy()` in C: copy a range to another address in the same map.
pub(crate) fn copy(
    map: &mut VmMap,
    source_address: VmOffset,
    size: VmSize,
    dest_address: VmOffset,
) -> Result<(), Error> {
    let Some(copy) = copyin(map, source_address, size)? else {
        return Ok(());
    };

    // SAFETY: `copyin` returned a live copy this call owns;
    // `vm_map_copy_overwrite()` consumes it on success, and the C discards it
    // on failure.
    match unsafe { map.copy_overwrite(dest_address, copy) } {
        Ok(()) => Ok(()),
        Err(error) => {
            // SAFETY: the failed overwrite left the live copy to the caller.
            unsafe { VmMapCopy::discard(copy) };
            Err(error)
        }
    }
}

/// `vm_object_sync()` in C: write a range of `object` back to its memory
/// manager.
pub(crate) fn object_sync(
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
        memory_object::lock_request(
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

/// `vm_msync()` in C: synchronize a range with its memory manager.
pub(crate) fn msync(
    map: &mut VmMap,
    address: VmOffset,
    size: VmSize,
    sync_flags: c_int,
) -> Result<(), Error> {
    VmMap::msync(Some(NonNull::from(map)), address, size, sync_flags)
}

/// `vm_get_size_limit()` in C: report the current and maximum virtual size
/// limits of `map`.
pub(crate) fn get_size_limit(map: &VmMap) -> (VmSize, VmSize) {
    map.lock.read();
    let limits = (map.size_cur_limit, map.size_max_limit);
    map.lock.done();
    limits
}

/// `vm_map_copyin()`'s zero-length case, which its FFI adapter keeps: a
/// zero-byte range yields no copy, while the map core rejects it as an
/// address overflow.
fn copyin(
    map: &mut VmMap,
    address: VmOffset,
    size: VmSize,
) -> Result<Option<NonNull<VmMapCopy>>, Error> {
    if size == 0 {
        return Ok(None);
    }

    map.copyin(address, size, false).map(Some)
}
