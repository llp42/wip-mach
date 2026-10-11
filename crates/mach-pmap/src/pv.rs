// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The pv lists: every mapping of each managed physical page, with the
//! page's modify and reference bits.

use crate::cell::SyncCell;
use crate::param::PTES_PER_VM_PAGE;
use crate::platform::Platform;
use crate::pmap::{
    PMAP_NULL, Pmap, cache_alloc, kernel_pmap_ptr, pte_of, read_unlock,
    write_lock, write_unlock,
};
use crate::pte::Pte;
use crate::shootdown::update_tlbs;
use crate::types::{PmapCache, PvEntry};
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::ptr::{self};
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use lock::TicketLock;
use mach_page::param::{PAGE_SIZE, VmOffset};
use mach_page::simple_lock::SimpleLock;
use mach_page::table;
use mach_page::types::VmProt;

/// Whether [`pmap_init`](crate::bootstrap::pmap_init) has run.
pub(crate) static PMAP_INITIALIZED: AtomicI32 = AtomicI32::new(0);

/// One pv list head per physical page.
pub(crate) static PV_HEAD_TABLE: AtomicPtr<PvEntry> =
    AtomicPtr::new(ptr::null_mut());

/// The free pv entries, under [`PV_FREE_LIST_LOCK`] at `splvm`.
static PV_FREE_LIST: SyncCell<*mut PvEntry> =
    SyncCell(UnsafeCell::new(ptr::null_mut()));

/// Guards [`PV_FREE_LIST`].
static PV_FREE_LIST_LOCK: SimpleLock = SimpleLock::new();

// `pmap_init()` carves the locks out right after the pv head table.
/// One attribute byte per physical page.
pub(crate) static PMAP_PHYS_ATTRIBUTES: AtomicPtr<u8> =
    AtomicPtr::new(ptr::null_mut());

/// The pv list head of a page index.
fn pv_head(pai: usize) -> *mut PvEntry {
    PV_HEAD_TABLE.load(Ordering::Relaxed).wrapping_add(pai)
}

/// The attribute byte of a page index.
pub(crate) fn phys_attribute(pai: usize) -> *mut u8 {
    PMAP_PHYS_ATTRIBUTES
        .load(Ordering::Relaxed)
        .wrapping_add(pai)
}

/// Returns the lock guarding the pv list and attribute byte of page `pai`.
///
/// # Panics
///
/// Panics if `pai` is not a managed page's index.
pub(crate) fn pv_lock<P: Platform>(pai: usize) -> &'static TicketLock<()> {
    &P::pmap_state().pv_locks()[pai]
}

/// Takes a pv entry from the free list, or null.
fn pv_alloc() -> *mut PvEntry {
    // SAFETY: the free list is only touched under its own lock.
    unsafe {
        PV_FREE_LIST_LOCK.lock();
        let list = PV_FREE_LIST.0.get();
        let entry = *list;
        if !entry.is_null() {
            *list = (*entry).next;
        }
        PV_FREE_LIST_LOCK.unlock();
        entry
    }
}

/// Puts a pv entry back on the free list.
pub(crate) fn pv_free(entry: *mut PvEntry) {
    // SAFETY: the entry came from the pv list of a managed page, and the free
    // list is only touched under its own lock.
    unsafe {
        PV_FREE_LIST_LOCK.lock();
        let list = PV_FREE_LIST.0.get();
        (*entry).next = *list;
        *list = entry;
        PV_FREE_LIST_LOCK.unlock();
    }
}

/// Whether the physical address is a managed page.
pub(crate) fn valid_page(addr: VmOffset) -> bool {
    if PMAP_INITIALIZED.load(Ordering::Relaxed) == 0 {
        return false;
    }
    table::seg_of(addr).is_some()
}

/// Unlink the pv-list entry for `va` from `pai`'s head, as the C's locked
/// walk did.
///
/// # Safety
///
/// The caller must hold the pmap lock and `pai`'s pv lock bit, and `pmap`
/// must be live.
pub(crate) unsafe fn unlink_pv(pmap: *mut Pmap, pai: usize, va: VmOffset) {
    // SAFETY: the pv list is locked by the caller's bit, and the C required
    // a non-empty head for a mapped page.
    unsafe {
        let pv_h = pv_head(pai);
        assert!(
            !(*pv_h).pmap.is_null(),
            "pmap_remove: null pv_list for pai {pai:x} at va {va:x}!"
        );
        if (*pv_h).va == va && (*pv_h).pmap == pmap {
            let cur = (*pv_h).next;
            if cur.is_null() {
                (*pv_h).pmap = PMAP_NULL;
            } else {
                ptr::copy_nonoverlapping(cur, pv_h, 1);
                pv_free(cur);
            }
        } else {
            let mut cur = pv_h;
            let mut prev;
            loop {
                prev = cur;
                cur = (*prev).next;
                assert!(
                    !cur.is_null(),
                    "pmap-remove: mapping not in pv_list!"
                );
                if (*cur).va == va && (*cur).pmap == pmap {
                    break;
                }
            }
            (*prev).next = (*cur).next;
            pv_free(cur);
        }
    }
}

/// The read-and-execute case of `pmap_page_protect()` and `pmap_protect()`.
pub(crate) const READ_EXECUTE: VmProt = VmProt::READ.union(VmProt::EXECUTE);

/// The read-and-write case of `pmap_protect()`.
pub(crate) const READ_WRITE: VmProt = VmProt::READ.union(VmProt::WRITE);

/// Lowers the permission of every mapping of a physical page.
///
/// Any address is safe to pass: one that is not a managed page is ignored.
pub fn pmap_page_protect<P: Platform>(phys: VmOffset, prot: VmProt) {
    if !valid_page(phys) {
        return;
    }

    let remove = match prot {
        VmProt::READ | READ_EXECUTE => false,
        VmProt::ALL => return,
        _ => true,
    };

    let spl = write_lock::<P>();
    let pai = table::table_index(phys);
    let pv_h = pv_head(pai);

    // SAFETY: the pmap system is locked for write, so the pv list is stable.
    if !unsafe { (*pv_h).pmap }.is_null() {
        let mut prev = pv_h;
        let mut pv_e = pv_h;
        loop {
            // SAFETY: `pv_e` is a live pv list entry.
            let pmap = unsafe { (*pv_e).pmap };
            // SAFETY: the pmap came from the pv list, which holds live maps.
            unsafe { (*pmap).lock.lock() };
            // SAFETY: `pv_e` is the live pv entry just locked.
            let va = unsafe { (*pv_e).va };
            // SAFETY: the entry is live and locked.
            let pte = unsafe { pte_of(pmap, va) };

            if remove || pmap == kernel_pmap_ptr() {
                // SAFETY: `pte` is the live entry for `va` in the map.
                if unsafe { *pte }.contains(Pte::WIRED) {
                    // SAFETY: the map is live and locked.
                    unsafe { (*pmap).stats.wired_count -= 1 };
                }
                let mut i = PTES_PER_VM_PAGE;
                let mut p = pte;
                loop {
                    // SAFETY: the pv lock is covered by the system write
                    // lock here, and `p` walks the page's run.
                    unsafe {
                        let attr = phys_attribute(pai);
                        *attr |= (*p).intersection(Pte::MOD | Pte::REF).bits()
                            as u8;
                        *p = Pte::empty();
                    }
                    p = p.wrapping_add(1);
                    i -= 1;
                    if i == 0 {
                        break;
                    }
                }
                // SAFETY: the map is live and locked.
                unsafe { (*pmap).stats.resident_count -= 1 };

                if pv_e == pv_h {
                    // SAFETY: the head itself held this mapping.
                    unsafe { (*pv_h).pmap = PMAP_NULL };
                } else {
                    // SAFETY: the entry is in the list, behind `prev`.
                    unsafe {
                        (*prev).next = (*pv_e).next;
                        pv_free(pv_e);
                    }
                }
            } else {
                let mut i = PTES_PER_VM_PAGE;
                let mut p = pte;
                loop {
                    // SAFETY: `p` walks the page's run.
                    unsafe { (*p).remove(Pte::WRITE) };
                    p = p.wrapping_add(1);
                    i -= 1;
                    if i == 0 {
                        break;
                    }
                }
                prev = pv_e;
            }

            // SAFETY: the map is live and locked.
            unsafe { update_tlbs::<P>(pmap, va, va.wrapping_add(PAGE_SIZE)) };
            // SAFETY: the map is live and locked.
            unsafe { (*pmap).lock.unlock() };

            // SAFETY: the list link is kept under the system write lock.
            pv_e = unsafe { (*prev).next };
            if pv_e.is_null() {
                break;
            }
        }

        // SAFETY: if the walk emptied the list, its head is dead.
        if unsafe { (*pv_h).pmap }.is_null() {
            // SAFETY: `pv_h` is the pv list head.
            let pv_e = unsafe { (*pv_h).next };
            if !pv_e.is_null() {
                // SAFETY: the next entry becomes the new head.
                unsafe {
                    ptr::copy_nonoverlapping(pv_e, pv_h, 1);
                    pv_free(pv_e);
                }
            }
        }
    }

    write_unlock::<P>(spl);
}

/// Link the new mapping's pv entry for `v` into `pa`'s pv list, as the C's
/// locked insert did.
///
/// Returns `Err` when the pv entry must be reallocated from the slab cache
/// with the locks released, as the C's refill path did.
///
/// # Safety
///
/// The map must be locked, `pa` must be a managed page, and `pv_e` must be
/// this call's scratch slot.
pub(crate) unsafe fn link_pv<P: Platform>(
    pmap: *mut Pmap,
    v: VmOffset,
    pa: VmOffset,
    pv_e: &mut *mut PvEntry,
    spl: c_int,
) -> Result<(), ()> {
    let pai = table::table_index(pa);
    let pv = pv_lock::<P>(pai).lock();
    let pv_h = pv_head(pai);

    // SAFETY: `pv_h` is the pv head under the pv lock.
    if unsafe { (*pv_h).pmap }.is_null() {
        // SAFETY: the head was empty and the pv lock is held.
        unsafe {
            (*pv_h).va = v;
            (*pv_h).pmap = pmap;
            (*pv_h).next = ptr::null_mut();
        }
    } else {
        if pv_e.is_null() {
            *pv_e = pv_alloc();
            if pv_e.is_null() {
                // The pv lock nests inside the map lock, so it goes first.
                drop(pv);
                // SAFETY: the caller took `pmap`'s read lock at `spl`.
                unsafe { read_unlock::<P>(pmap, spl) };
                // SAFETY: the C refilled from the slab cache while unlocked.
                *pv_e = unsafe {
                    cache_alloc::<P>(PmapCache::PvEntry).cast::<PvEntry>()
                };
                return Err(());
            }
        }
        // SAFETY: the head is non-empty and the new entry is this
        // function's.
        unsafe {
            (**pv_e).va = v;
            (**pv_e).pmap = pmap;
            (**pv_e).next = (*pv_h).next;
            (*pv_h).next = *pv_e;
        }
        *pv_e = ptr::null_mut();
    }
    drop(pv);
    Ok(())
}

/// Clears the modify and reference bits of `attr` on every mapping of a
/// page; any other bit of `attr` is left alone, and an address that is not a
/// managed page is ignored.
fn attribute_clear<P: Platform>(phys: VmOffset, attr: Pte) {
    if !valid_page(phys) {
        return;
    }
    let attr = attr.intersection(Pte::MOD | Pte::REF);

    let spl = write_lock::<P>();
    let pai = table::table_index(phys);
    let pv_h = pv_head(pai);

    // SAFETY: the pmap system is locked for write, so the pv list is stable.
    if !unsafe { (*pv_h).pmap }.is_null() {
        let mut pv_e = pv_h;
        while !pv_e.is_null() {
            // SAFETY: `pv_e` is a live pv list entry.
            let pmap = unsafe { (*pv_e).pmap };
            // SAFETY: the pmap came from the pv list, which holds live maps.
            unsafe { (*pmap).lock.lock() };
            // SAFETY: `pv_e` is the live pv entry just locked.
            let va = unsafe { (*pv_e).va };
            // SAFETY: the entry is live and locked.
            let pte = unsafe { pte_of(pmap, va) };

            for _ in 0..PTES_PER_VM_PAGE {
                // SAFETY: the pv lock is covered by the system write lock
                // here, and the C's loop cleared the same entry each time.
                unsafe { (*pte).remove(attr) };
            }

            // SAFETY: the map is live and locked.
            unsafe { update_tlbs::<P>(pmap, va, va.wrapping_add(PAGE_SIZE)) };
            // SAFETY: the map is live and locked.
            unsafe { (*pmap).lock.unlock() };

            // SAFETY: the list link is kept under the system write lock.
            pv_e = unsafe { (*pv_e).next };
        }
    }

    // SAFETY: the attribute byte is serialized by the system write lock.
    unsafe { *phys_attribute(pai) &= !(attr.bits() as u8) };

    write_unlock::<P>(spl);
}

/// Whether any mapping of a page has the bits set; an address that is not a
/// managed page has none.
fn attribute_test<P: Platform>(phys: VmOffset, attr: Pte) -> bool {
    if !valid_page(phys) {
        return false;
    }

    let spl = write_lock::<P>();
    let pai = table::table_index(phys);
    let pv_h = pv_head(pai);

    // SAFETY: the attribute byte is serialized by the system write lock.
    if unsafe { *phys_attribute(pai) } & attr.bits() as u8 != 0 {
        write_unlock::<P>(spl);
        return true;
    }

    // SAFETY: the pmap system is locked for write, so the pv list is stable.
    if !unsafe { (*pv_h).pmap }.is_null() {
        let mut pv_e = pv_h;
        while !pv_e.is_null() {
            // SAFETY: `pv_e` is a live pv list entry.
            let pmap = unsafe { (*pv_e).pmap };
            // SAFETY: the pmap came from the pv list, which holds live maps.
            unsafe { (*pmap).lock.lock() };
            // SAFETY: `pv_e` is the live pv entry just locked.
            let va = unsafe { (*pv_e).va };
            // SAFETY: the entry is live and locked.
            let pte = unsafe { pte_of(pmap, va) };

            for _ in 0..PTES_PER_VM_PAGE {
                // SAFETY: the C's loop checked the same entry each time.
                if unsafe { *pte }.intersects(attr) {
                    // SAFETY: the map is live and locked.
                    unsafe { (*pmap).lock.unlock() };
                    write_unlock::<P>(spl);
                    return true;
                }
            }

            // SAFETY: the map is live and locked.
            unsafe { (*pmap).lock.unlock() };

            // SAFETY: the list link is kept under the system write lock.
            pv_e = unsafe { (*pv_e).next };
        }
    }

    write_unlock::<P>(spl);
    false
}

/// Clears the modify bits of a page.
///
/// An address that is not a managed page is ignored.
pub fn pmap_clear_modify<P: Platform>(phys: VmOffset) {
    attribute_clear::<P>(phys, Pte::MOD);
}

/// Whether a page was modified.
///
/// An address that is not a managed page is ignored.
#[must_use]
pub fn pmap_is_modified<P: Platform>(phys: VmOffset) -> bool {
    attribute_test::<P>(phys, Pte::MOD)
}

/// Clears the reference bits of a page.
///
/// An address that is not a managed page is ignored.
pub fn pmap_clear_reference<P: Platform>(phys: VmOffset) {
    attribute_clear::<P>(phys, Pte::REF);
}

/// Whether a page was referenced.
///
/// An address that is not a managed page is ignored.
#[must_use]
pub fn pmap_is_referenced<P: Platform>(phys: VmOffset) -> bool {
    attribute_test::<P>(phys, Pte::REF)
}
