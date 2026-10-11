// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The data-only records of the physical map.

use crate::param::UPDATE_LIST_SIZE;
use crate::pmap::Pmap;
use crate::pte::Pte;
use core::ffi::c_int;
use core::mem::{offset_of, size_of};
use mach_page::param::VmOffset;

/// `struct pmap_statistics`: the resident and wired page counts of a map.
#[repr(C)]
#[allow(missing_docs)]
pub struct PmapStatistics {
    pub resident_count: c_int,
    pub wired_count: c_int,
}

const _: () = assert!(size_of::<PmapStatistics>() == 2 * size_of::<c_int>());

const _: () = assert!(offset_of!(PmapStatistics, resident_count) == 0);

const _: () = assert!(offset_of!(PmapStatistics, wired_count) == 4);

/// One virtual mapping of a physical page.
#[repr(C)]
#[allow(missing_docs)]
pub struct PvEntry {
    pub next: *mut Self,
    pub pmap: *mut Pmap,
    pub va: VmOffset,
}

const _: () = {
    assert!(size_of::<PvEntry>() == 24);
    assert!(align_of::<PvEntry>() == 8);
    assert!(offset_of!(PvEntry, next) == 0);
    assert!(offset_of!(PvEntry, pmap) == 8);
    assert!(offset_of!(PvEntry, va) == 16);
};

/// One temporary physical mapping.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct PmapMapwindow {
    pub entry: *mut Pte,
    pub vaddr: VmOffset,
}

const _: () = {
    assert!(size_of::<PmapMapwindow>() == 16);
    assert!(align_of::<PmapMapwindow>() == 8);
    assert!(offset_of!(PmapMapwindow, entry) == 0);
    assert!(offset_of!(PmapMapwindow, vaddr) == 8);
};

/// One queued invalidation: the range, and the map it was changed in by
/// address, which the flush only compares.
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct PmapUpdateItem {
    pub pmap: usize,
    pub start: VmOffset,
    pub end: VmOffset,
}

/// The invalidations queued for one CPU, owned by that CPU's queue lock.
#[allow(missing_docs)]
pub struct PmapUpdateList {
    pub count: usize,
    pub item: [PmapUpdateItem; UPDATE_LIST_SIZE],
}

impl PmapUpdateList {
    /// An empty queue.
    pub(crate) const fn new() -> Self {
        Self {
            count: 0,
            item: [PmapUpdateItem {
                pmap: 0,
                start: 0,
                end: 0,
            }; UPDATE_LIST_SIZE],
        }
    }
}

/// A slab cache the physical map's records come from; the platform keeps one
/// of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmapCache {
    /// Physical maps.
    Pmap,
    /// Page tables, the level the page-table entries are in.
    PageTable,
    /// Page directories.
    PageDirectory,
    /// Page-directory-pointer tables.
    DirectoryPointer,
    /// Level-4 tables.
    Level4,
    /// Pv entries.
    PvEntry,
}

impl PmapCache {
    /// The number of caches.
    pub const COUNT: usize = 6;
}

/// What the kernel map's bootstrap is told about the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    /// The start of the kernel's text, which the bootstrap maps read-only.
    pub text_start: VmOffset,
    /// The end of the kernel's text.
    pub text_end: VmOffset,
    /// The end of the direct map, a physical address.
    pub directmap_end: VmOffset,
    /// Whether the CPU has global pages.
    pub global_pages: bool,
    /// Whether the CPU has physical-address extension.
    pub pae: bool,
}
