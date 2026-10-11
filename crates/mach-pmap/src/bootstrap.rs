// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kernel map's bootstrap, the boot-time mappings outside the
//! direct map, and the page-directory load each CPU makes.

use crate::param::{
    MAPWINDOW_SIZE, NPTES, PDPNUM_KERNEL, VM_KERNEL_MAP_SIZE,
    VM_MAX_KERNEL_ADDRESS, kvtolin, kvtophys_early, lin2l4num,
    lin2pdenum_cont, lin2pdpnum, phystokv, ptenum,
};
use crate::platform::Platform;
use crate::pmap::{
    KERNEL_PMAP, KERNEL_PMAP_STORE, Pmap, kernel_pmap_ptr, pte_of, read_lock,
    read_unlock,
};
use crate::pte::{Pte, pa_to_pte};
use crate::pv::{PMAP_INITIALIZED, PMAP_PHYS_ATTRIBUTES, PV_HEAD_TABLE};
use crate::shootdown::{update_tlbs, write_cr3};
use crate::types::{Bootstrap, PmapCache, PmapMapwindow, PvEntry};
use crate::window::MAPWINDOWS;
use core::mem::size_of;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use lock::TicketLock;
use mach_page::param::round_page;
use mach_page::param::{
    PAGE_SHIFT, PAGE_SIZE, VM_MIN_KERNEL_ADDRESS, VmOffset, VmSize,
};
use mach_page::table;
use mach_page::types::VmProt;
use x86_64::VirtAddr;
use x86_64::instructions::tlb;
use x86_64::registers::control::{Cr4, Cr4Flags};

/// The end of the direct map, a physical address, as the bootstrap was told.
static DIRECTMAP_END: AtomicUsize = AtomicUsize::new(0);

/// Whether the CPU has global pages, as the bootstrap was told.
static GLOBAL_PAGES: AtomicBool = AtomicBool::new(false);

/// Whether the CPU has physical-address extension, as the bootstrap was told.
static PAE: AtomicBool = AtomicBool::new(false);

/// The end of the direct map, a physical address.
pub(crate) fn directmap_end() -> VmOffset {
    DIRECTMAP_END.load(Ordering::Relaxed)
}

/// Whether kernel mappings may be global.
pub(crate) fn global_pages() -> bool {
    GLOBAL_PAGES.load(Ordering::Relaxed)
}

/// One zeroed-to-be page from the boot allocator.
///
/// # Panics
///
/// When the boot allocator has no page left: the kernel cannot boot.
fn grab_page<P: Platform>() -> VmOffset {
    P::boot_alloc(PAGE_SIZE)
        .unwrap_or_else(|| panic!("Not enough memory to initialize Mach"))
}

/// The start of the kernel virtual range [`pmap_bootstrap`] sets once.
pub static KERNEL_VIRTUAL_START: AtomicUsize = AtomicUsize::new(0);

/// The end of that range.
pub static KERNEL_VIRTUAL_END: AtomicUsize = AtomicUsize::new(0);

/// The kernel's page directory.
pub(crate) static KERNEL_PAGE_DIR: AtomicPtr<Pte> =
    AtomicPtr::new(ptr::null_mut());

/// Unmap the page at virtual address zero so that a null reference faults.
///
/// # Safety
///
/// The kernel pmap must be initialized, so that `pte_of()` can walk it, and
/// nothing may depend on the zero page's mapping afterwards.
pub unsafe fn pmap_unmap_page_zero<P: Platform>() {
    P::print(format_args!(
        "Unmapping the zero page.  Some BIOS functions may not be working any more.\n"
    ));
    // SAFETY: `kernel_pmap_ptr()` is the kernel's live pmap from
    // `pmap_bootstrap()` on, and `pte_of()` returns null rather than something
    // invalid for an address with no page-table entry.
    let pte = unsafe { pte_of(kernel_pmap_ptr(), 0) };
    let Some(pte) = NonNull::new(pte) else {
        return;
    };
    // SAFETY: `pte_of()` returned a non-null pointer to a live page table
    // entry for address zero.
    unsafe { pte.as_ptr().write(Pte::empty()) };
    tlb::flush(VirtAddr::zero());
}

/// The boot-time back door that maps memory outside the direct map.
///
/// # Panics
///
/// When a page of the range has no kernel page-table entry.
///
/// # Safety
///
/// `virt` must name a free kernel-virtual range covering `start` to `end`,
/// and the caller must be running with the mapping machinery usable.
#[must_use]
pub unsafe fn pmap_map_bd<P: Platform>(
    mut virt: VmOffset,
    mut start: VmOffset,
    end: VmOffset,
    prot: VmProt,
) -> VmOffset {
    let mut template =
        pa_to_pte(start) | Pte::NCACHE | Pte::WTHRU | Pte::VALID;
    if global_pages() {
        template |= Pte::GLOBAL;
    }
    if prot.contains(VmProt::WRITE) {
        template |= Pte::WRITE;
    }

    let spl = unsafe { read_lock::<P>(kernel_pmap_ptr()) };
    while start < end {
        // SAFETY: the kernel map is live, as `map_bd`'s caller promised.
        let pte = unsafe { pte_of(kernel_pmap_ptr(), virt) };
        assert!(!pte.is_null(), "pmap_map_bd: Invalid kernel address");
        // SAFETY: `pte_of()` returned a live entry for `virt`.
        unsafe { *pte = template };
        template = template.next_page();
        virt = virt.wrapping_add(PAGE_SIZE);
        start = start.wrapping_add(PAGE_SIZE);
    }
    // SAFETY: the kernel map is live and the lock was taken above.
    unsafe { read_unlock::<P>(kernel_pmap_ptr(), spl) };
    virt
}

/// Takes back a range [`pmap_map_bd`] mapped.
///
/// The entries are cleared as `pmap_map_bd` set them, outside the pv
/// lists: no pv list ever held them, so `pmap_remove` would go looking for
/// a mapping of a managed page that is not there.
///
/// # Safety
///
/// `virt..end` must be a kernel range `pmap_map_bd` mapped, which nothing
/// uses afterwards.
pub unsafe fn pmap_unmap_bd<P: Platform>(virt: VmOffset, end: VmOffset) {
    let pmap = kernel_pmap_ptr();
    let spl = unsafe { read_lock::<P>(pmap) };
    let mut va = virt;
    while va < end {
        // SAFETY: the kernel map is live and locked.
        let pte = unsafe { pte_of(pmap, va) };
        if !pte.is_null() {
            // SAFETY: `pte_of()` returned the live entry for `va`.
            unsafe { *pte = Pte::empty() };
        }
        va = va.wrapping_add(PAGE_SIZE);
    }
    // SAFETY: the kernel map is live, locked at `splvm` by `read_lock()`.
    unsafe { update_tlbs::<P>(pmap, virt, end) };
    // SAFETY: the kernel map is live and the lock was taken above.
    unsafe { read_unlock::<P>(pmap, spl) };
}

/// Builds the kernel's level-4 table and directory-pointer tables.
fn bootstrap_pae<P: Platform>() {
    let l4 = with_exposed_provenance_mut::<Pte>(phystokv(grab_page::<P>()));
    // SAFETY: `kernel_pmap_ptr()` points at the static store, and the L4 table
    // was just grabbed for it.
    unsafe { (*kernel_pmap_ptr()).l4base = l4 };
    // SAFETY: the freshly grabbed page is the kernel's to clear.
    unsafe { ptr::write_bytes(l4.cast::<u8>(), 0, PAGE_SIZE) };

    // The C carried on with address zero when the boot allocator was empty.
    let addr = P::boot_alloc(PDPNUM_KERNEL * PAGE_SIZE).unwrap_or(0);
    let page_dir = with_exposed_provenance_mut::<Pte>(phystokv(addr));
    KERNEL_PAGE_DIR.store(page_dir, Ordering::Relaxed);
    // SAFETY: the boot allocator returned this page for the kernel directory;
    // the directory is PDPNUM_KERNEL pages.
    unsafe {
        ptr::write_bytes(page_dir.cast::<u8>(), 0, PDPNUM_KERNEL * PAGE_SIZE);
    };

    let pdp = with_exposed_provenance_mut::<Pte>(phystokv(grab_page::<P>()));
    // SAFETY: the freshly grabbed page is the kernel's to clear.
    unsafe { ptr::write_bytes(pdp.cast::<u8>(), 0, PAGE_SIZE) };
    for i in 0..PDPNUM_KERNEL {
        let index = i + lin2pdpnum(VM_MIN_KERNEL_ADDRESS);
        // SAFETY: the directory pointer table is one page, and the index is
        // below its `NPTES` entries.
        unsafe {
            *pdp.wrapping_add(index) = pa_to_pte(kvtophys_early(
                page_dir.cast::<u8>().wrapping_add(i * PAGE_SIZE).addr(),
            )) | Pte::VALID
                | Pte::WRITE;
        }
    }
    // SAFETY: the L4 table is one page and the kernel's index is in range.
    unsafe {
        *l4.wrapping_add(lin2l4num(VM_MIN_KERNEL_ADDRESS)) =
            pa_to_pte(kvtophys_early(pdp.addr())) | Pte::VALID | Pte::WRITE;
    }
}

/// Builds the kernel's page tables with mapping off, so only physical
/// addresses are reachable.
///
/// # Panics
///
/// When the boot allocator runs out of pages for the tables.
pub fn pmap_bootstrap<P: Platform>(boot: &Bootstrap) {
    DIRECTMAP_END.store(boot.directmap_end, Ordering::Relaxed);
    GLOBAL_PAGES.store(boot.global_pages, Ordering::Relaxed);
    PAE.store(boot.pae, Ordering::Relaxed);
    KERNEL_PMAP.store(KERNEL_PMAP_STORE.0.get(), Ordering::Relaxed);

    // SAFETY: the lock's storage is unshared at this point in the boot; for
    // the kernel map's own lock and count.
    unsafe {
        (*kernel_pmap_ptr()).lock.init();
        (*kernel_pmap_ptr()).ref_count = 1;
    }

    let start = phystokv(directmap_end());
    let mut end = start.wrapping_add(VM_KERNEL_MAP_SIZE);
    if end < start || end > VM_MAX_KERNEL_ADDRESS.wrapping_sub(PAGE_SIZE) {
        end = VM_MAX_KERNEL_ADDRESS.wrapping_sub(PAGE_SIZE);
    }
    KERNEL_VIRTUAL_START.store(start, Ordering::Relaxed);
    KERNEL_VIRTUAL_END.store(end, Ordering::Relaxed);
    P::print(format_args!("kernel virtual area: {start:x}-{end:x}\n"));

    bootstrap_pae::<P>();

    let global = if global_pages() {
        Pte::GLOBAL
    } else {
        Pte::empty()
    };
    let image_start = boot.text_start;
    let image_end = boot.text_end;
    let directmap_end = phystokv(directmap_end());
    // SAFETY: the kernel directory is live from `bootstrap_pae()` above, and
    // the physical memory it maps is the machine's RAM.
    unsafe {
        let directory = KERNEL_PAGE_DIR.load(Ordering::Relaxed);
        let mut va = phystokv(0);
        while va >= phystokv(0) && va < end {
            let pde = directory.wrapping_add(lin2pdenum_cont(kvtolin(va)));
            let ptable =
                with_exposed_provenance_mut::<Pte>(phystokv(grab_page::<P>()));
            *pde = pa_to_pte(kvtophys_early(ptable.addr()))
                | Pte::VALID
                | Pte::WRITE;

            let mut pte = ptable;
            while va < directmap_end && pte < ptable.wrapping_add(NPTES) {
                if (pte.offset_from(ptable) as usize) < ptenum(va) {
                    *pte = Pte::empty();
                } else {
                    if va >= image_start
                        && va.wrapping_add(PAGE_SIZE) <= image_end
                    {
                        *pte = pa_to_pte(kvtophys_early(va))
                            | Pte::VALID
                            | global;
                    } else {
                        *pte = pa_to_pte(kvtophys_early(va))
                            | Pte::VALID
                            | Pte::WRITE
                            | global;
                    }
                    va = va.wrapping_add(PAGE_SIZE);
                }
                pte = pte.wrapping_add(1);
            }
            while pte < ptable.wrapping_add(NPTES) {
                let window_start = end - MAPWINDOW_SIZE;
                if va >= window_start && va < end {
                    let index = (va - window_start) >> PAGE_SHIFT;
                    let win = MAPWINDOWS
                        .0
                        .get()
                        .cast::<PmapMapwindow>()
                        .wrapping_add(index);
                    (*win).entry = pte;
                    (*win).vaddr = va;
                }
                *pte = Pte::empty();
                va = va.wrapping_add(PAGE_SIZE);
                pte = pte.wrapping_add(1);
            }
        }
    }
}

/// The kernel virtual range left for the VM system, as its start and end.
#[must_use]
pub fn pmap_virtual_space() -> (VmOffset, VmOffset) {
    let start = KERNEL_VIRTUAL_START.load(Ordering::Relaxed);
    let end = KERNEL_VIRTUAL_END.load(Ordering::Relaxed);
    (start, end.wrapping_sub(MAPWINDOW_SIZE))
}

/// The bytes of wired kernel memory [`pmap_init`] carves the pv tables from:
/// a pv head, a lock and an attribute byte per page, rounded to a page.
#[must_use]
pub fn pv_tables_size<P: Platform>() -> VmSize {
    round_page(
        (size_of::<PvEntry>() + size_of::<TicketLock<()>>() + 1)
            * table::table_size(),
    )
}

/// Carves the pv tables from the `pv_tables_size()` bytes of wired kernel
/// memory at `addr`, and sets up the caches of maps, tables and pv entries.
///
/// # Safety
///
/// `addr` must point at [`pv_tables_size`] bytes of wired kernel memory no
/// one else uses, and the call must happen once, after the page table.
pub unsafe fn pmap_init<P: Platform>(mut addr: VmOffset) {
    let npages = table::table_size();
    // SAFETY: the caller hands over `pv_tables_size()` writable bytes.
    unsafe { ptr::write_bytes(addr as *mut u8, 0, pv_tables_size::<P>()) };

    // SAFETY: the block the VM system handed over is now carved into the pv
    // head table, its locks and the attribute bytes; the locks are written
    // in place and the slice over them is published before any pv use.
    unsafe {
        PV_HEAD_TABLE.store(addr as *mut PvEntry, Ordering::Relaxed);
        addr += size_of::<PvEntry>() * npages;
        let locks = addr as *mut TicketLock<()>;
        for i in 0..npages {
            ptr::write(locks.add(i), TicketLock::new(()));
        }
        P::pmap_state().set_pv_locks(slice::from_raw_parts(locks, npages));
        addr += size_of::<TicketLock<()>>() * npages;
        PMAP_PHYS_ATTRIBUTES.store(addr as *mut u8, Ordering::Relaxed);
    }

    // SAFETY: each cache is set up once, before its first allocation.  The
    // names are the C strings the C passed; the sizes are the mirror's.
    unsafe {
        P::pmap_cache_init(
            PmapCache::Pmap,
            c"pmap".to_bytes(),
            size_of::<Pmap>(),
            0,
            false,
        );
        P::pmap_cache_init(
            PmapCache::PageTable,
            c"pmap_L1".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            true,
        );
        P::pmap_cache_init(
            PmapCache::PageDirectory,
            c"pmap_L2".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            true,
        );
        P::pmap_cache_init(
            PmapCache::DirectoryPointer,
            c"pmap_L3".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            true,
        );
        P::pmap_cache_init(
            PmapCache::Level4,
            c"pmap_L4".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            true,
        );
        P::pmap_cache_init(
            PmapCache::PvEntry,
            c"pv_entry".to_bytes(),
            size_of::<PvEntry>(),
            0,
            false,
        );
    }

    PMAP_INITIALIZED.store(1, Ordering::Relaxed);
}

/// Does nothing, because the initial and linear kernel bases coincide and no
/// temporary mapping is needed.
pub const fn pmap_make_temporary_mapping() {}

/// Loads the kernel's page tables into CR3 and turns on the paging features
/// they need.
///
/// # Panics
///
/// When the CPU has no physical-address extension, which the tables need.
pub fn pmap_set_page_dir() {
    // SAFETY: the kernel map holds its L4 table from `pmap_bootstrap()`.
    let physical =
        kvtophys_early(unsafe { (*kernel_pmap_ptr()).l4base }.addr());
    write_cr3(physical);
    assert!(
        PAE.load(Ordering::Relaxed),
        "CPU doesn't have support for PAE."
    );
    // SAFETY: PAE is the format the kernel's tables are built in.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION);
        });
    }
}

/// Flushes the TLB; there is no temporary low mapping to drop here.
pub fn pmap_remove_temporary_mapping() {
    tlb::flush_all();
}
