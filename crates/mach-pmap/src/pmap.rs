// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The physical map: its page-table tree, its locks, and the calls that
//! enter, protect, wire, remove and collect its mappings.

use crate::bootstrap::{
    KERNEL_PAGE_DIR, KERNEL_VIRTUAL_END, KERNEL_VIRTUAL_START, directmap_end,
};
use crate::cell::SyncCell;
use crate::cpu_set::CpuSet;
use crate::lock::LockData;
use crate::param::{
    NPTES, PDE_MAPPED_SIZE, PDPNUM, PTES_PER_VM_PAGE, VM_MAX_USER_ADDRESS,
    VM_MIN_USER_ADDRESS, kvtolin, lin2l4num, lin2pdenum, lin2pdpnum, lintokv,
    pagenum2lin, phystokv, ptenum,
};
use crate::phys::kvtophys;
use crate::platform::Platform;
use crate::pte::{INTEL_OFFMASK, Pte, pa_to_pte, pte_to_pa, ptetokv};
use crate::pv::{
    READ_EXECUTE, READ_WRITE, link_pv, phys_attribute, pv_free, pv_lock,
    unlink_pv, valid_page,
};
use crate::shootdown::{CPUS_ACTIVE, update_tlbs};
use crate::types::{PmapCache, PmapStatistics, PvEntry};
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use mach_page::param::{
    PAGE_SHIFT, PAGE_SIZE, VM_MIN_KERNEL_ADDRESS, VmOffset, VmSize,
};
use mach_page::simple_lock::SimpleLock;
use mach_page::table;
use mach_page::types::VmProt;

/// The CPU type of an i486.
const CPU_TYPE_I486: c_int = 17;

/// One physical map.
///
/// The header's `__x86_64__` layout, whose table tree hangs from `l4base`.
#[repr(C)]
#[allow(missing_docs)]
pub struct Pmap {
    /// `l4base`: the level-4 table, or null.
    pub l4base: *mut Pte,
    pub ref_count: c_int,
    pub lock: SimpleLock,
    /// `stats`: resident and wired page counts.
    pub stats: PmapStatistics,
    /// `cpus_using`: the CPUs with this map active.
    pub cpus_using: CpuSet,
}

const _: () = {
    assert!(size_of::<Pmap>() == 32);
    assert!(align_of::<Pmap>() == 8);
    assert!(offset_of!(Pmap, l4base) == 0);
    assert!(offset_of!(Pmap, ref_count) == 8);
    assert!(offset_of!(Pmap, lock) == 12);
    assert!(offset_of!(Pmap, stats) == 16);
    assert!(offset_of!(Pmap, cpus_using) == 24);
};

// SAFETY: a live pmap is mutated under its own lock, and the boot code writes
// `KERNEL_PMAP_STORE` before another CPU can see it.
unsafe impl Sync for Pmap {}

impl Pmap {
    /// The zero image of a static map.
    pub(crate) const fn zeroed() -> Self {
        Self {
            l4base: ptr::null_mut(),
            ref_count: 0,
            lock: SimpleLock::new(),
            stats: PmapStatistics {
                resident_count: 0,
                wired_count: 0,
            },
            cpus_using: CpuSet::new(),
        }
    }
}

/// The kernel's statically allocated map, which [`KERNEL_PMAP`] names.
pub(crate) static KERNEL_PMAP_STORE: SyncCell<Pmap> =
    SyncCell(UnsafeCell::new(Pmap::zeroed()));

/// The kernel's physical map.
pub(crate) static KERNEL_PMAP: AtomicPtr<Pmap> =
    AtomicPtr::new(ptr::null_mut());

/// `PMAP_NULL`: the C's null map pointer.
pub(crate) const PMAP_NULL: *mut Pmap = ptr::null_mut();

/// The kernel pmap the C global holds.
pub fn kernel_pmap_ptr() -> *mut Pmap {
    KERNEL_PMAP.load(Ordering::Relaxed)
}

/// The pmap-system read/write lock.
static PMAP_SYSTEM_LOCK: LockData = LockData::new();

/// The flag that turns on the enter trace.
static PMAP_DEBUG: AtomicI32 = AtomicI32::new(0);

/// Raises to `splvm`, returning the level to restore.
fn raise_splvm<P: Platform>() -> c_int {
    // SAFETY: raising to `splvm` has no precondition.
    let spl = unsafe { P::splvm() };
    CPUS_ACTIVE.clear(P::current_cpu().bits() as c_int);
    spl
}

/// Restores the level [`raise_splvm`] returned.
fn restore_spl<P: Platform>(spl: c_int) {
    CPUS_ACTIVE.set(P::current_cpu().bits() as c_int);
    // SAFETY: `spl` came from `splvm()`, and `splx` accepts any level.
    unsafe { P::splx(spl) };
}

/// Takes the system lock for read, then the map's own lock, and returns the
/// level to restore.
///
/// # Safety
///
/// `pmap` must be a live physical map, and the caller must later pass the
/// returned level to [`read_unlock()`] on the same map to release both
/// locks and restore the priority level.
pub(crate) unsafe fn read_lock<P: Platform>(pmap: *mut Pmap) -> c_int {
    let spl = raise_splvm::<P>();
    PMAP_SYSTEM_LOCK.read();
    unsafe { (*pmap).lock.lock() };
    spl
}

/// Drops the locks [`read_lock`] took and restores the level.
///
/// # Safety
///
/// `pmap` must be the same live map passed to the matching
/// [`read_lock()`], whose read lock is still held, and `spl` must be the
/// level that call returned.
pub(crate) unsafe fn read_unlock<P: Platform>(pmap: *mut Pmap, spl: c_int) {
    unsafe { (*pmap).lock.unlock() };
    PMAP_SYSTEM_LOCK.done();
    restore_spl::<P>(spl);
}

/// Takes the system lock for write at `splvm`, returning the level to restore.
pub(crate) fn write_lock<P: Platform>() -> c_int {
    let spl = raise_splvm::<P>();
    PMAP_SYSTEM_LOCK.write();
    spl
}

/// Drops the system lock [`write_lock`] took and restores the level.
pub(crate) fn write_unlock<P: Platform>(spl: c_int) {
    PMAP_SYSTEM_LOCK.done();
    restore_spl::<P>(spl);
}

/// The level-4 entry of `addr` in `pmap`, or null.
///
/// # Safety
///
/// `pmap` must be a live physical map.
unsafe fn l4base_of(pmap: *mut Pmap, addr: VmOffset) -> *mut Pte {
    let base = unsafe { (*pmap).l4base };
    if base.is_null() {
        return ptr::null_mut();
    }
    base.wrapping_add(lin2l4num(addr))
}

/// The directory-pointer entry of `addr` in `pmap`, or null.
///
/// # Safety
///
/// `pmap` must be a live physical map.
unsafe fn ptp_of(pmap: *mut Pmap, addr: VmOffset) -> *mut Pte {
    let l4_table = unsafe { l4base_of(pmap, addr) };
    if l4_table.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `l4_table` is the live table `l4base_of()` returned.
    let pdp = unsafe { *l4_table };
    if !pdp.contains(Pte::VALID) {
        return ptr::null_mut();
    }
    ptetokv(pdp).wrapping_add(lin2pdpnum(addr))
}

/// The page-directory entry of `addr` in `pmap`, or null.
///
/// # Safety
///
/// `pmap` must be a live physical map.
unsafe fn pde_of(pmap: *mut Pmap, addr: VmOffset) -> *mut Pte {
    let addr = if pmap == kernel_pmap_ptr() {
        kvtolin(addr)
    } else {
        addr
    };
    let ptp = unsafe { ptp_of(pmap, addr) };
    if ptp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ptp` is the live table `ptp_of()` returned.
    let pde = unsafe { *ptp };
    if !pde.contains(Pte::VALID) {
        return ptr::null_mut();
    }
    ptetokv(pde).wrapping_add(lin2pdenum(addr))
}

/// The page-table entry of `addr` in `pmap`, or null for no mapping.
///
/// # Safety
///
/// `pmap` must be a live physical map.
pub(crate) unsafe fn pte_of(pmap: *mut Pmap, addr: VmOffset) -> *mut Pte {
    let base_null = unsafe { (*pmap).l4base }.is_null();
    if base_null {
        return ptr::null_mut();
    }
    let ptp = unsafe { pde_of(pmap, addr) };
    if ptp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ptp` is the live table `pde_of()` returned.
    let pte = unsafe { *ptp };
    if !pte.contains(Pte::VALID) {
        return ptr::null_mut();
    }
    ptetokv(pte).wrapping_add(ptenum(addr))
}

/// Allocate one object from a slab cache, or null.
///
/// # Safety
///
/// `cache` must have been initialized and no other access may hold its lock.
pub(crate) unsafe fn cache_alloc<P: Platform>(cache: PmapCache) -> *mut u8 {
    unsafe { P::pmap_cache_alloc(cache) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// Return one object to a slab cache.
///
/// # Safety
///
/// `obj` must be a live object of `cache`, and no other access may hold the
/// cache's lock.
unsafe fn cache_free<P: Platform>(cache: PmapCache, obj: *mut u8) {
    let Some(obj) = NonNull::new(obj) else {
        return;
    };
    unsafe { P::pmap_cache_free(cache, obj) };
}

/// Advisory, and empty, since [`pmap_enter`] already learns whether a page is
/// wired.
pub const fn pmap_pageable(
    _pmap: *mut Pmap,
    _start: VmOffset,
    _end: VmOffset,
    _pageable: c_int,
) {
}

/// The pages the pmap has resident.
///
/// # Safety
///
/// `pmap` must point at a live physical map.
pub unsafe fn resident_count(pmap: *mut Pmap) -> c_int {
    unsafe { (*pmap).stats.resident_count }
}

/// Builds a fresh physical map.
///
/// # Safety
///
/// The caches must be initialized, which `pmap_init()` does, and the caller
/// must be ready to run with the pmap system's locks free.
///
/// # Panics
///
/// When the level-4 cache is empty after the lower levels were allocated.
pub unsafe fn pmap_create<P: Platform>(size: VmSize) -> *mut Pmap {
    if size != 0 {
        return PMAP_NULL;
    }

    let p = unsafe { cache_alloc::<P>(PmapCache::Pmap) }.cast::<Pmap>();
    if p.is_null() {
        return PMAP_NULL;
    }

    let mut page_dir: [*mut Pte; PDPNUM] = [ptr::null_mut(); PDPNUM];
    let mut i = 0;
    while i < PDPNUM {
        page_dir[i] = unsafe { cache_alloc::<P>(PmapCache::PageDirectory) }
            .cast::<Pte>();
        if page_dir[i].is_null() {
            while i > 0 {
                i -= 1;
                // SAFETY: every earlier entry is an object this function
                // allocated from this cache.
                unsafe {
                    cache_free::<P>(
                        PmapCache::PageDirectory,
                        page_dir[i].cast(),
                    );
                };
            }
            // SAFETY: `p` is this function's object from the pmap cache.
            unsafe { cache_free::<P>(PmapCache::Pmap, p.cast()) };
            return PMAP_NULL;
        }
        // SAFETY: the new directory is one page, and `KERNEL_PAGE_DIR` maps
        // the same `PDPNUM` pages from `pmap_bootstrap()` on.
        unsafe {
            ptr::copy_nonoverlapping(
                KERNEL_PAGE_DIR
                    .load(Ordering::Relaxed)
                    .cast::<u8>()
                    .wrapping_add(i * PAGE_SIZE),
                page_dir[i].cast::<u8>(),
                PAGE_SIZE,
            );
        }
        i += 1;
    }

    // SAFETY: the caches are live, as above.
    unsafe {
        let pdp_kernel =
            cache_alloc::<P>(PmapCache::DirectoryPointer).cast::<Pte>();
        if pdp_kernel.is_null() {
            let mut k = 0;
            while k < PDPNUM {
                cache_free::<P>(PmapCache::PageDirectory, page_dir[k].cast());
                k += 1;
            }
            cache_free::<P>(PmapCache::Pmap, p.cast());
            return PMAP_NULL;
        }
        ptr::write_bytes(pdp_kernel.cast::<u8>(), 0, PAGE_SIZE);
        let mut k = 0;
        while k < PDPNUM {
            let index = k + lin2pdpnum(VM_MIN_KERNEL_ADDRESS);
            *pdp_kernel.wrapping_add(index) =
                pa_to_pte(kvtophys(page_dir[k].addr()))
                    | Pte::VALID
                    | Pte::WRITE;
            k += 1;
        }

        let l4base = cache_alloc::<P>(PmapCache::Level4).cast::<Pte>();
        assert!(!l4base.is_null(), "pmap_create");
        ptr::write_bytes(l4base.cast::<u8>(), 0, PAGE_SIZE);
        *l4base.wrapping_add(lin2l4num(VM_MIN_KERNEL_ADDRESS)) =
            pa_to_pte(kvtophys(pdp_kernel.addr())) | Pte::VALID | Pte::WRITE;
        (*p).l4base = l4base;
    }

    // SAFETY: `p` is this function's fresh pmap, not yet visible to another
    // thread; the C initialized exactly these fields.
    unsafe {
        (*p).ref_count = 1;
        (*p).lock.init();
        (*p).cpus_using.set_bits(0);
        (*p).stats.resident_count = 0;
        (*p).stats.wired_count = 0;
    }

    p
}

/// Drops a reference, freeing the page tables and the map when the last one
/// goes.
///
/// # Safety
///
/// A non-null `p` must be a live pmap.
pub unsafe fn pmap_destroy<P: Platform>(p: Option<NonNull<Pmap>>) {
    let Some(p) = p else {
        return;
    };
    let p = p.as_ptr();

    let spl = raise_splvm::<P>();
    let count = unsafe {
        (*p).lock.lock();
        (*p).ref_count = (*p).ref_count.wrapping_sub(1);
        let count = (*p).ref_count;
        (*p).lock.unlock();
        count
    };
    restore_spl::<P>(spl);

    if count != 0 {
        return;
    }

    let mut l4i = 0;
    while l4i < NPTES {
        // SAFETY: the map owns its L4 table for as long as it exists.
        let pdp = unsafe { *(*p).l4base.wrapping_add(l4i) };
        if !pdp.contains(Pte::VALID) {
            l4i += 1;
            continue;
        }
        let pdpbase = ptetokv(pdp);
        let mut l3i = 0;
        while l3i < NPTES {
            // SAFETY: `pdpbase` is the directory pointer table the entry
            // above names.
            let pde = unsafe { *pdpbase.wrapping_add(l3i) };
            if !pde.contains(Pte::VALID) {
                l3i += 1;
                continue;
            }
            let pdirbase = ptetokv(pde);
            if l4i < lin2l4num(VM_MAX_USER_ADDRESS)
                || (l4i == lin2l4num(VM_MAX_USER_ADDRESS)
                    && l3i < lin2pdpnum(VM_MAX_USER_ADDRESS))
            {
                let mut l2i = 0;
                while l2i < NPTES {
                    // SAFETY: `pdirbase` is the page directory the entry
                    // names.
                    let pte = unsafe { *pdirbase.wrapping_add(l2i) };
                    if pte.contains(Pte::VALID) {
                        // SAFETY: each valid entry names a page-table
                        // page from `pt_cache`.
                        unsafe {
                            cache_free::<P>(
                                PmapCache::PageTable,
                                ptetokv(pte).cast(),
                            );
                        };
                    }
                    l2i += 1;
                }
            }
            // SAFETY: `pdirbase` came from `PD_CACHE`.
            unsafe {
                cache_free::<P>(PmapCache::PageDirectory, pdirbase.cast());
            };
            l3i += 1;
        }
        // SAFETY: `pdpbase` came from `pdpt_cache`.
        unsafe {
            cache_free::<P>(PmapCache::DirectoryPointer, pdpbase.cast());
        };
        l4i += 1;
    }
    // SAFETY: the L4 table came from `l4_cache`.
    unsafe { cache_free::<P>(PmapCache::Level4, (*p).l4base.cast()) };

    // SAFETY: the map came from `pmap_cache`.
    unsafe { cache_free::<P>(PmapCache::Pmap, p.cast()) };
}

/// Takes a reference on the map.
///
/// # Safety
///
/// A non-null `p` must be a live pmap.
pub unsafe fn pmap_reference<P: Platform>(p: Option<NonNull<Pmap>>) {
    let Some(p) = p else {
        return;
    };
    let p = p.as_ptr();
    let spl = raise_splvm::<P>();
    unsafe {
        (*p).lock.lock();
        (*p).ref_count = (*p).ref_count.wrapping_add(1);
        (*p).lock.unlock();
    }
    restore_spl::<P>(spl);
}

/// Drops a run of hardware entries, collecting their modify and reference bits
/// and unlinking them from their pv lists.
///
/// # Safety
///
/// `pmap` must be live and locked, and `spte` to `epte` a run of its page
/// table entries, as the C's callers guaranteed.
unsafe fn remove_range<P: Platform>(
    pmap: *mut Pmap,
    mut va: VmOffset,
    spte: *mut Pte,
    epte: *mut Pte,
) {
    let count = (epte as usize - spte as usize) / size_of::<VmOffset>();
    let end = va.wrapping_add(count * PAGE_SIZE);
    if pmap == kernel_pmap_ptr()
        && (va < KERNEL_VIRTUAL_START.load(Ordering::Relaxed)
            || end > KERNEL_VIRTUAL_END.load(Ordering::Relaxed))
    {
        panic!(
            "pmap_remove_range({va:x}-{end:x}) falls in physical memory area!"
        );
    }

    let mut num_removed: c_int = 0;
    let mut num_unwired: c_int = 0;
    let mut cpte = spte;
    while cpte < epte {
        // SAFETY: `cpte` walks the run the caller passed.
        if unsafe { *cpte }.is_empty() {
            cpte = cpte.wrapping_add(PTES_PER_VM_PAGE);
            va = va.wrapping_add(PAGE_SIZE);
            continue;
        }

        // SAFETY: `cpte` walks the run the caller passed.
        let pa = pte_to_pa(unsafe { *cpte });
        num_removed += 1;
        if unsafe { *cpte }.contains(Pte::WIRED) {
            num_unwired += 1;
        }

        if !valid_page(pa) {
            let mut i = PTES_PER_VM_PAGE;
            let mut lpte = cpte;
            loop {
                // SAFETY: the entries are this page's run.
                unsafe { *lpte = Pte::empty() };
                lpte = lpte.wrapping_add(1);
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            cpte = cpte.wrapping_add(PTES_PER_VM_PAGE);
            va = va.wrapping_add(PAGE_SIZE);
            continue;
        }

        let pai = table::table_index(pa);
        let pv = pv_lock::<P>(pai).lock();

        {
            let mut i = PTES_PER_VM_PAGE;
            let mut lpte = cpte;
            loop {
                // SAFETY: the attributes array has a byte per managed page,
                // and `pv` serializes this byte.
                unsafe {
                    let attr = phys_attribute(pai);
                    *attr |=
                        (*lpte).intersection(Pte::MOD | Pte::REF).bits() as u8;
                    *lpte = Pte::empty();
                }
                lpte = lpte.wrapping_add(1);
                i -= 1;
                if i == 0 {
                    break;
                }
            }
        }

        // SAFETY: `pv` locks the pv list, the caller holds the pmap lock,
        // and `pmap` is live.
        unsafe { unlink_pv(pmap, pai, va) };
        drop(pv);

        cpte = cpte.wrapping_add(PTES_PER_VM_PAGE);
        va = va.wrapping_add(PAGE_SIZE);
    }

    unsafe {
        (*pmap).stats.resident_count =
            (*pmap).stats.resident_count.wrapping_sub(num_removed);
        (*pmap).stats.wired_count =
            (*pmap).stats.wired_count.wrapping_sub(num_unwired);
    }
}

/// Removes every mapping in a range.
///
/// # Safety
///
/// A non-null `map` must be a live pmap.
pub unsafe fn pmap_remove<P: Platform>(
    map: Option<NonNull<Pmap>>,
    s: VmOffset,
    e: VmOffset,
) {
    let Some(map) = map else {
        return;
    };
    unsafe { remove::<P>(map, s, e) };
}

/// # Safety
///
/// As `pmap_remove`.
pub(crate) unsafe fn remove<P: Platform>(
    map: NonNull<Pmap>,
    mut s: VmOffset,
    e: VmOffset,
) {
    let map = map.as_ptr();
    let start = s;

    let spl = unsafe { read_lock::<P>(map) };
    while s < e {
        // SAFETY: the map is live and locked.
        let pde = unsafe { pde_of(map, s) };
        let mut l = s.wrapping_add(PDE_MAPPED_SIZE) & !(PDE_MAPPED_SIZE - 1);
        if l > e || l < s {
            l = e;
        }
        // SAFETY: `pde` is the live directory entry `pde_of()` returned.
        if !pde.is_null() && unsafe { *pde }.contains(Pte::VALID) {
            // SAFETY: the entry is valid and names a page table, as the C
            // relied on for its own pointer arithmetic.
            let mut spte = ptetokv(unsafe { *pde });
            spte = spte.wrapping_add(ptenum(s));
            let epte = spte.wrapping_add((l - s) >> PAGE_SHIFT);
            // SAFETY: the run is inside that page table, as the C computed.
            unsafe { remove_range::<P>(map, s, spte, epte) };
        }
        s = l;
    }
    // SAFETY: `map` is live and held as `read_lock()` left it.
    unsafe { update_tlbs::<P>(map, start, e) };
    // SAFETY: the map is live and was locked throughout.
    unsafe { read_unlock::<P>(map, spl) };
}

/// Lowers permissions over a range.
///
/// # Safety
///
/// A non-null `map` must be a live pmap.
pub unsafe fn pmap_protect<P: Platform>(
    map: Option<NonNull<Pmap>>,
    mut s: VmOffset,
    e: VmOffset,
    prot: VmProt,
) {
    let Some(map) = map else {
        return;
    };
    let live_map = map;
    let map = map.as_ptr();

    match prot {
        VmProt::READ | READ_EXECUTE => (),
        READ_WRITE | VmProt::ALL => return,
        _ => {
            unsafe { remove::<P>(live_map, s, e) };
            return;
        }
    }

    let start = s;
    // The C's non-i486 fallback, which removes kernel mappings because the
    // i386 ignores the write bit in kernel mode, is not compiled here.
    let spl = raise_splvm::<P>();
    unsafe { (*map).lock.lock() };

    while s < e {
        // SAFETY: the map is live and locked.
        let pde = unsafe { pde_of(map, s) };
        let mut l = s.wrapping_add(PDE_MAPPED_SIZE) & !(PDE_MAPPED_SIZE - 1);
        if l > e || l < s {
            l = e;
        }
        // SAFETY: `pde` is the live directory entry `pde_of()` returned.
        if !pde.is_null() && unsafe { *pde }.contains(Pte::VALID) {
            // SAFETY: the entry is valid and names a page table.
            let mut spte = ptetokv(unsafe { *pde });
            spte = spte.wrapping_add(ptenum(s));
            let epte = spte.wrapping_add((l - s) >> PAGE_SHIFT);
            while spte < epte {
                // SAFETY: `spte` walks the page table.
                if unsafe { *spte }.contains(Pte::VALID) {
                    unsafe { (*spte).remove(Pte::WRITE) };
                }
                spte = spte.wrapping_add(1);
            }
        }
        s = l;
    }
    // SAFETY: the map is live and locked.
    unsafe { update_tlbs::<P>(map, start, e) };

    // SAFETY: the map is live and locked.
    unsafe { (*map).lock.unlock() };
    restore_spl::<P>(spl);
}

/// The page-table-level getter [`expand_level`] calls: one of [`l4base_of()`],
/// [`ptp_of()`], [`pde_of()`], or [`pte_of()`].
///
/// # Safety
///
/// Calling through a value of this type requires the same as calling the
/// function it names directly: the `*mut Pmap` argument must be a live
/// physical map.
type LevelGetter = unsafe fn(*mut Pmap, VmOffset) -> *mut Pte;

/// Allocates one level of the page-table tree, unlocking the pmap around the
/// allocation.
///
/// # Safety
///
/// `pmap` must be live and locked at `spl`, and `cache` initialized.
unsafe fn expand_level<P: Platform>(
    pmap: *mut Pmap,
    v: VmOffset,
    spl: c_int,
    level: LevelGetter,
    upper: LevelGetter,
    n_per_vm_page: c_int,
    cache: PmapCache,
) -> *mut Pte {
    loop {
        let pte = unsafe { level(pmap, v) };
        if !pte.is_null() {
            return pte;
        }

        assert!(
            pmap != kernel_pmap_ptr(),
            "pmap_expand kernel pmap to 0x{v:x}"
        );

        unsafe { read_unlock::<P>(pmap, spl) };
        let ptp = loop {
            let ptp = unsafe { cache_alloc::<P>(cache) };
            if !ptp.is_null() {
                break ptp;
            }
            unsafe { P::wait_for_page() };
        };
        // SAFETY: the cache returned one `PAGE_SIZE` object for a table.
        unsafe { ptr::write_bytes(ptp, 0, PAGE_SIZE) };

        let spl = unsafe { read_lock::<P>(pmap) };
        // SAFETY: the lock was taken above, and the map is live.
        if !unsafe { level(pmap, v) }.is_null() {
            // SAFETY: the lock was taken above.
            unsafe { read_unlock::<P>(pmap, spl) };
            // SAFETY: the fresh table is the one `cache_alloc()` returned.
            unsafe { cache_free::<P>(cache, ptp) };
            let _spl = unsafe { read_lock::<P>(pmap) };
            continue;
        }

        let mut i = n_per_vm_page;
        // SAFETY: the upper level now holds the entry.
        let mut pdp = unsafe { upper(pmap, v) };
        let mut table = ptp;
        loop {
            // SAFETY: `pdp` walks the upper level's run for this page, and
            // `table` the fresh page-table pages.
            unsafe {
                *pdp = pa_to_pte(kvtophys(table.addr()))
                    | Pte::VALID
                    | if pmap == kernel_pmap_ptr() {
                        Pte::empty()
                    } else {
                        Pte::USER
                    }
                    | Pte::WRITE;
            }
            pdp = pdp.wrapping_add(1);
            table = table.wrapping_add(PAGE_SIZE);
            i -= 1;
            if i == 0 {
                break;
            }
        }
    }
}

/// Grows every level the address needs.
///
/// # Safety
///
/// `pmap` must be live and locked at `spl`.
unsafe fn expand<P: Platform>(
    pmap: *mut Pmap,
    v: VmOffset,
    spl: c_int,
) -> *mut Pte {
    unsafe {
        expand_level::<P>(
            pmap,
            v,
            spl,
            ptp_of,
            l4base_of,
            1,
            PmapCache::DirectoryPointer,
        );
        expand_level::<P>(
            pmap,
            v,
            spl,
            pde_of,
            ptp_of,
            1,
            PmapCache::PageDirectory,
        );
        expand_level::<P>(
            pmap,
            v,
            spl,
            pte_of,
            pde_of,
            PTES_PER_VM_PAGE as c_int,
            PmapCache::PageTable,
        )
    }
}

/// The entry template `pmap_enter()` builds.
fn enter_template<P: Platform>(
    pmap: *mut Pmap,
    pa: VmOffset,
    prot: VmProt,
    wired: bool,
    is_physmem: bool,
) -> Pte {
    let mut template = pa_to_pte(pa) | Pte::VALID;
    if pmap != kernel_pmap_ptr() {
        template |= Pte::USER;
    }
    if prot.contains(VmProt::WRITE) {
        template |= Pte::WRITE;
    }
    if P::cpu_type() >= CPU_TYPE_I486 && !is_physmem {
        template |= Pte::NCACHE | Pte::WTHRU;
    }
    if wired {
        template |= Pte::WIRED;
    }
    template
}

/// Inserts one mapping.
///
/// # Panics
///
/// When `pmap` is the kernel's and `v` lies outside the kernel's virtual
/// range.
///
/// # Safety
///
/// A non-null `pmap` must be a live pmap, and `pa` a physical address the
/// kernel may map, as the C's callers guaranteed.
pub unsafe fn pmap_enter<P: Platform>(
    pmap: Option<NonNull<Pmap>>,
    v: VmOffset,
    pa: VmOffset,
    prot: VmProt,
    wired: c_int,
) {
    let Some(pmap) = pmap else {
        return;
    };
    let wired = wired != 0;
    let pmap = pmap.as_ptr();
    if PMAP_DEBUG.load(Ordering::Relaxed) != 0 {
        P::print(format_args!("pmap({v:x}, {pa:x})\n"));
    }

    if pmap == kernel_pmap_ptr()
        && (v < KERNEL_VIRTUAL_START.load(Ordering::Relaxed)
            || v >= KERNEL_VIRTUAL_END.load(Ordering::Relaxed))
    {
        panic!("pmap_enter({v:x}, {pa:x}) falls in physical memory area!");
    }

    let mut pv_e: *mut PvEntry = ptr::null_mut();
    loop {
        let spl = unsafe { read_lock::<P>(pmap) };
        // SAFETY: the map is live and locked.
        let mut pte = unsafe { expand::<P>(pmap, v, spl) };

        let is_physmem = if table::is_ready() {
            table::seg_of(pa).is_some()
        } else {
            pa < directmap_end()
        };

        // SAFETY: `pte` is the live entry for `v` in the locked map.
        let old_pa = pte_to_pa(unsafe { *pte });
        if !unsafe { *pte }.is_empty() && old_pa == pa {
            // SAFETY: `pte` is the live entry for `v` in the locked map.
            if wired && !unsafe { *pte }.contains(Pte::WIRED) {
                // SAFETY: the map is live and locked.
                unsafe { (*pmap).stats.wired_count += 1 };
            // SAFETY: `pte` is the live entry for `v` in the locked map.
            } else if !wired && unsafe { *pte }.contains(Pte::WIRED) {
                // SAFETY: the map is live and locked.
                unsafe { (*pmap).stats.wired_count -= 1 };
            }

            let mut template =
                enter_template::<P>(pmap, pa, prot, wired, is_physmem);
            let mut i = PTES_PER_VM_PAGE;
            loop {
                // SAFETY: `pte` walks the entry run of the locked map.
                if unsafe { *pte }.contains(Pte::MOD) {
                    template |= Pte::MOD;
                }
                // SAFETY: `pte` walks the page's run.
                unsafe { *pte = template };
                pte = pte.wrapping_add(1);
                template = template.next_page();
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            // SAFETY: the map is live and locked.
            unsafe { update_tlbs::<P>(pmap, v, v.wrapping_add(PAGE_SIZE)) };
        } else {
            // SAFETY: `pte` is the live entry for `v` in the locked map.
            if !unsafe { *pte }.is_empty() {
                // SAFETY: `pte` names the entry run to replace.
                unsafe {
                    remove_range::<P>(
                        pmap,
                        v,
                        pte,
                        pte.wrapping_add(PTES_PER_VM_PAGE),
                    );
                };
                // SAFETY: the map is live and locked.
                unsafe {
                    update_tlbs::<P>(pmap, v, v.wrapping_add(PAGE_SIZE));
                };
            }

            if valid_page(pa) {
                // SAFETY: the map is live and locked, and `pa` is a managed
                // page.
                if unsafe { link_pv::<P>(pmap, v, pa, &mut pv_e, spl) }
                    .is_err()
                {
                    continue;
                }
            }

            // SAFETY: the map is live and locked.
            unsafe {
                (*pmap).stats.resident_count += 1;
                if wired {
                    (*pmap).stats.wired_count += 1;
                }
            }

            let mut template =
                enter_template::<P>(pmap, pa, prot, wired, is_physmem);
            let mut i = PTES_PER_VM_PAGE;
            loop {
                // SAFETY: `pte` walks the page's run.
                unsafe { *pte = template };
                pte = pte.wrapping_add(1);
                template = template.next_page();
                i -= 1;
                if i == 0 {
                    break;
                }
            }
        }

        if !pv_e.is_null() {
            pv_free(pv_e);
        }
        // SAFETY: the map is live and was locked throughout.
        unsafe { read_unlock::<P>(pmap, spl) };
        break;
    }
}

/// Sets the wired bit on an existing mapping.
///
/// # Panics
///
/// When `map` has no page-table entry at `v`.
///
/// # Safety
///
/// `map` must be live and hold a mapping at `v`, as the C's callers
/// guaranteed.
pub unsafe fn pmap_change_wiring<P: Platform>(
    map: *mut Pmap,
    v: VmOffset,
    wired: c_int,
) {
    let wired = wired != 0;
    let spl = unsafe { read_lock::<P>(map) };
    // SAFETY: the map is live and locked.
    let pte = unsafe { pte_of(map, v) };
    assert!(!pte.is_null(), "pmap_change_wiring: pte missing");

    // SAFETY: `pte` is the live entry for `v` in the locked map.
    if wired && !unsafe { *pte }.contains(Pte::WIRED) {
        // SAFETY: the map is live and locked.
        unsafe { (*map).stats.wired_count += 1 };
        let mut i = PTES_PER_VM_PAGE;
        let mut p = pte;
        loop {
            // SAFETY: `p` walks the page's run.
            unsafe { (*p).insert(Pte::WIRED) };
            p = p.wrapping_add(1);
            i -= 1;
            if i == 0 {
                break;
            }
        }
    // SAFETY: `pte` is the live entry for `v` in the locked map.
    } else if !wired && unsafe { *pte }.contains(Pte::WIRED) {
        // SAFETY: the map is live and locked.
        unsafe { (*map).stats.wired_count -= 1 };
        let mut i = PTES_PER_VM_PAGE;
        let mut p = pte;
        loop {
            // SAFETY: `p` walks the page's run.
            unsafe { (*p).remove(Pte::WIRED) };
            p = p.wrapping_add(1);
            i -= 1;
            if i == 0 {
                break;
            }
        }
    }

    // SAFETY: the map is live and was locked throughout.
    unsafe { read_unlock::<P>(map, spl) };
}

/// The physical address a mapping holds, or zero.
///
/// # Safety
///
/// `pmap` must be a live pmap, as the C's callers guaranteed.
pub unsafe fn pmap_extract<P: Platform>(
    pmap: *mut Pmap,
    va: VmOffset,
) -> VmOffset {
    let spl = raise_splvm::<P>();
    unsafe { (*pmap).lock.lock() };
    // SAFETY: the map is live and locked.
    let pte = unsafe { pte_of(pmap, va) };
    let pa = if pte.is_null()
        // SAFETY: `pte` is the live entry for `va`.
        || !unsafe { *pte }.contains(Pte::VALID)
    {
        0
    } else {
        pte_to_pa(unsafe { *pte }) + (va & INTEL_OFFMASK)
    };
    // SAFETY: the map lock was taken above.
    unsafe { (*pmap).lock.unlock() };
    restore_spl::<P>(spl);
    pa
}

/// Frees the user page tables of a map whose pages are scarce.
///
/// # Safety
///
/// A non-null `p` must be a live user pmap.
pub unsafe fn pmap_collect<P: Platform>(p: Option<NonNull<Pmap>>) {
    let Some(p) = p else {
        return;
    };
    let p = p.as_ptr();
    if p == kernel_pmap_ptr() {
        return;
    }

    let mut spl = unsafe { read_lock::<P>(p) };

    let mut l4i = 0;
    while l4i < lin2l4num(VM_MAX_USER_ADDRESS) {
        // SAFETY: the map holds its L4 table while it exists.
        let pdp = unsafe { *(*p).l4base.wrapping_add(l4i) };
        if !pdp.contains(Pte::VALID) {
            l4i += 1;
            continue;
        }
        let pdpbase = ptetokv(pdp);
        let mut l3i = 0;
        while l3i < NPTES {
            // SAFETY: `pdpbase` is the table the entry names.
            let pde = unsafe { *pdpbase.wrapping_add(l3i) };
            if !pde.contains(Pte::VALID) {
                l3i += 1;
                continue;
            }
            let pdirbase = ptetokv(pde);
            let mut l2i = 0;
            while l2i < NPTES {
                // SAFETY: `pdirbase` is the directory the entry names.
                let pte = unsafe { *pdirbase.wrapping_add(l2i) };
                if !pte.contains(Pte::VALID) {
                    l2i += 1;
                    continue;
                }
                let ptp = with_exposed_provenance_mut::<Pte>(phystokv(
                    pte_to_pa(pte),
                ));
                let eptp = ptp.wrapping_add(NPTES * PTES_PER_VM_PAGE);

                let mut wired = false;
                let mut pt_entry = ptp;
                while pt_entry < eptp {
                    // SAFETY: `pt_entry` walks the page table.
                    if unsafe { *pt_entry }.contains(Pte::WIRED) {
                        wired = true;
                        break;
                    }
                    pt_entry = pt_entry.wrapping_add(1);
                }

                if !wired {
                    let mut va = pagenum2lin(l4i, l3i, l2i, 0);
                    if p == kernel_pmap_ptr() {
                        va = lintokv(va);
                    }
                    // SAFETY: the map is live and locked, and the run is
                    // the page table just walked.
                    unsafe { remove_range::<P>(p, va, ptp, eptp) };

                    let mut i = PTES_PER_VM_PAGE;
                    let mut pdir_entry = pdirbase.wrapping_add(l2i);
                    loop {
                        // SAFETY: `pdir_entry` walks the directory's run.
                        unsafe { *pdir_entry = Pte::empty() };
                        pdir_entry = pdir_entry.wrapping_add(1);
                        i -= 1;
                        if i == 0 {
                            break;
                        }
                    }

                    // SAFETY: the lock was taken above.
                    unsafe { read_unlock::<P>(p, spl) };
                    // SAFETY: the table was unlinked and has no holder.
                    unsafe {
                        cache_free::<P>(
                            PmapCache::PageTable,
                            ptetokv(pte).cast(),
                        );
                    };
                    spl = unsafe { read_lock::<P>(p) };
                }
                l2i += 1;
            }
            l3i += 1;
        }
        l4i += 1;
    }

    // SAFETY: the map is live and locked.
    unsafe { update_tlbs::<P>(p, VM_MIN_USER_ADDRESS, VM_MAX_USER_ADDRESS) };
    // SAFETY: the map lock was taken above.
    unsafe { read_unlock::<P>(p, spl) };
}
