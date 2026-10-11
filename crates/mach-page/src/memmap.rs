// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The boot memory map: the boot loader's map of physical memory, resolved
//! into the segments the page table covers, and the bootstrap heap the
//! kernel allocates from before the page table exists.
//!
//! The kernel hands the loader's map over as [`MapEntry`] values, and
//! [`bootstrap`] returns the page it claims for the other CPUs' boot code;
//! the report [`setup`] prints goes to a writer the kernel passes.

use crate::cell::SyncCell;
use crate::param::{
    PAGE_SHIFT, PAGE_SIZE, VM_PAGE_DIRECTMAP_LIMIT, VmOffset, VmSize,
    round_page, trunc_page,
};
use crate::table::{
    self, MAX_SEGS, SEG_DIRECTMAP, SEG_DMA, SEG_DMA32, SEG_HIGHMEM,
};
use core::cell::UnsafeCell;
use core::cmp::{max, min};
use core::ffi::c_uint;
use core::fmt::{self, Write};

/// The most boot data ranges.
const BIOSMEM_MAX_BOOT_DATA: usize = 64;

/// The most memory map entries; resolving overlapping ranges can grow the map
/// to twice this size.
const BIOSMEM_MAX_MAP_SIZE: usize = 128;

/// The end of the first 64 KiB, which the BIOS data and hardware workarounds
/// reserve.
const BIOSMEM_BASE: VmOffset = 0x0001_0000;

/// The end of low memory.
const BIOSMEM_END: VmOffset = 0x0010_0000;

/// The end of the DMA segment.
pub const VM_PAGE_DMA_LIMIT: VmOffset = 0x0100_0000;

/// The end of the DMA32 segment.
pub const VM_PAGE_DMA32_LIMIT: VmOffset = 0x1_0000_0000;

/// The end of the highmem segment.
pub const VM_PAGE_HIGHMEM_LIMIT: VmOffset = 0x0010_0000_0000_0000;

/// The largest tested memory size.
const MAX_PHYS_END: u64 = 27 * 1024 * 1024 * 1024;

/// The panic message of an invalid boot data range.
const INVAL_BOOT_DATA: &str = "biosmem: invalid boot data";
/// The panic message of a full boot data table.
const TOO_MANY_BOOT_DATA: &str = "biosmem: too many boot data ranges";
/// The panic message of a full memory map.
const TOO_BIG_MSG: &str = "biosmem: too many memory map entries";
/// The panic message of an allocator that cannot be set up.
const SETUP_MSG: &str = "biosmem: unable to set up the early memory allocator";
/// The panic message of a map without a segment.
const NOSEG_MSG: &str = "biosmem: unable to find any memory segment";
/// The panic message of an empty allocation.
const INVAL_MSG: &str = "biosmem: attempt to allocate 0 page";
/// The panic message of an exhausted allocator.
const NOMEM_MSG: &str = "biosmem: unable to allocate memory";

/// The type of a memory map entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct MemType(u32);

impl MemType {
    const AVAILABLE: Self = Self(1);
    const RESERVED: Self = Self(2);
    const ACPI: Self = Self(3);
    const NVS: Self = Self(4);
    const UNUSABLE: Self = Self(5);
    const DISABLED: Self = Self(6);

    /// Whether ranges of this type are narrowed to page boundaries.
    const fn needs_narrow(self) -> bool {
        matches!(self, Self::AVAILABLE | Self::NVS | Self::DISABLED)
    }

    /// The type's name, for [`map_show`].
    const fn desc(self) -> &'static str {
        match self {
            Self::AVAILABLE => "available",
            Self::RESERVED => "reserved",
            Self::ACPI => "ACPI",
            Self::NVS => "ACPI NVS",
            Self::UNUSABLE => "unusable",
            _ => "unknown (reserved)",
        }
    }
}

/// A reserved physical range.
///
/// The bounds need not be page-aligned, since one page may hold more than
/// one range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BiosmemBootData {
    start: VmOffset,
    end: VmOffset,
    temporary: bool,
}

/// One range of the boot loader's memory map: its base, its length and its
/// type, as the multiboot memory map spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapEntry {
    /// The first physical address of the range.
    pub base_addr: u64,
    /// The length of the range in bytes.
    pub length: u64,
    /// The range's type: 1 for available memory.
    pub type_: u32,
}

/// One range of the memory map, with its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BiosmemMapEntry {
    base_addr: u64,
    length: u64,
    type_: MemType,
}

/// One contiguous block of physical memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BiosmemSegment {
    start: VmOffset,
    end: VmOffset,
}

/// The C file's file-scope state.  Bootstrap runs on one CPU and nothing
/// writes it after `setup()`.
struct State {
    boot_data: [BiosmemBootData; BIOSMEM_MAX_BOOT_DATA],
    nr_boot_data: u32,
    map: [BiosmemMapEntry; BIOSMEM_MAX_MAP_SIZE * 2],
    map_size: u32,
    segments: [BiosmemSegment; MAX_SEGS],
    heap_start: VmOffset,
    heap_bottom: VmOffset,
    heap_top: VmOffset,
    heap_end: VmOffset,
    heap_topdown: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            boot_data: [BiosmemBootData {
                start: 0,
                end: 0,
                temporary: false,
            }; BIOSMEM_MAX_BOOT_DATA],
            nr_boot_data: 0,
            map: [BiosmemMapEntry {
                base_addr: 0,
                length: 0,
                type_: MemType(0),
            }; BIOSMEM_MAX_MAP_SIZE * 2],
            map_size: 0,
            segments: [BiosmemSegment { start: 0, end: 0 }; MAX_SEGS],
            heap_start: 0,
            heap_bottom: 0,
            heap_top: 0,
            heap_end: 0,
            heap_topdown: false,
        }
    }
}

static STATE: SyncCell<State> = SyncCell(UnsafeCell::new(State::new()));

fn state() -> *mut State {
    STATE.0.get()
}

/// Halts the kernel with `message`, naming `func`.
fn die(func: &'static str, message: &'static str) -> ! {
    panic!("{func}: {message}")
}

/// Rounds the map address `addr` up to a page.
const fn round_page64(addr: u64) -> u64 {
    addr.wrapping_add(PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
}

/// Truncates the map address `addr` down to a page.
const fn trunc_page64(addr: u64) -> u64 {
    addr & !(PAGE_SIZE as u64 - 1)
}

/// The `uint64_t` the C printed with `%#lx`.
const fn hex64(value: VmOffset) -> u64 {
    value as u64
}

/// Reserves `start..end` as boot data, which the allocator keeps away from;
/// `temporary` data is released once the kernel is set up.
///
/// # Safety
///
/// Must run during bootstrap, on one CPU, before [`free_usable`].
pub unsafe fn register_boot_data(
    start: VmOffset,
    end: VmOffset,
    temporary: bool,
) {
    let s = unsafe { &mut *state() };
    register(s, start, end, temporary);
}

fn register(s: &mut State, start: VmOffset, end: VmOffset, temporary: bool) {
    if start >= end {
        die("biosmem_register_boot_data", INVAL_BOOT_DATA);
    }

    let nr = s.nr_boot_data as usize;
    if nr == s.boot_data.len() {
        die("biosmem_register_boot_data", TOO_MANY_BOOT_DATA);
    }

    let mut i = 0;
    while i < nr {
        let data = s.boot_data[i];

        if end > data.start && start < data.end {
            if start >= data.start && end <= data.end {
                // A permanent range inside a temporary one keeps the whole
                // range permanent, as in the C.
                if data.temporary != temporary {
                    s.boot_data[i].temporary = false;
                }
                return;
            }

            die("biosmem_register_boot_data", INVAL_BOOT_DATA);
        }

        if end <= data.start {
            break;
        }

        i += 1;
    }

    s.boot_data.copy_within(i..nr, i + 1);
    s.boot_data[i] = BiosmemBootData {
        start,
        end,
        temporary,
    };
    s.nr_boot_data += 1;
}

/// Removes the boot data range `start..end`.
fn unregister_boot_data(s: &mut State, start: VmOffset, end: VmOffset) {
    if start >= end {
        die("biosmem_unregister_boot_data", INVAL_BOOT_DATA);
    }

    let nr = s.nr_boot_data as usize;
    // The bound keeps the search inside the array, which the not-found test
    // below assumes.
    let mut i = 0;
    while i < nr {
        let data = s.boot_data[i];
        if start == data.start && end == data.end {
            break;
        }
        i += 1;
    }

    if i == nr {
        return;
    }

    s.nr_boot_data -= 1;
    s.boot_data.copy_within(i + 1..nr, i);
}

/// Narrows the entry to page boundaries when its type needs it.
const fn map_adjust_alignment(entry: &mut BiosmemMapEntry) {
    let end = entry.base_addr.wrapping_add(entry.length);

    if entry.type_.needs_narrow() {
        entry.base_addr = round_page64(entry.base_addr);
        entry.length = trunc_page64(end).wrapping_sub(entry.base_addr);
    }
}

/// Builds the map from the loader's memory map, keeping its first
/// `BIOSMEM_MAX_MAP_SIZE` entries.
fn map_build(s: &mut State, entries: impl IntoIterator<Item = MapEntry>) {
    let mut count = 0;

    for entry in entries.into_iter().take(BIOSMEM_MAX_MAP_SIZE) {
        s.map[count] = BiosmemMapEntry {
            base_addr: entry.base_addr,
            length: entry.length,
            type_: MemType(entry.type_),
        };
        map_adjust_alignment(&mut s.map[count]);
        count += 1;
    }

    s.map_size = count as u32;
}

/// Whether the entry's length wrapped.
const fn map_entry_is_invalid(entry: &BiosmemMapEntry) -> bool {
    entry.base_addr.wrapping_add(entry.length) <= entry.base_addr
}

/// Drops the entries whose length wrapped.
fn map_filter(s: &mut State) {
    let mut i = 0;
    while i < s.map_size as usize {
        if map_entry_is_invalid(&s.map[i]) {
            let size = s.map_size as usize;
            s.map_size -= 1;
            s.map.copy_within(i + 1..size, i);
            continue;
        }

        i += 1;
    }
}

/// Sorts the map by base address, with a simple insertion sort.
fn map_sort(s: &mut State) {
    let size = s.map_size as usize;

    for i in 1..size {
        let tmp = s.map[i];
        let mut j = i;

        while j > 0 && s.map[j - 1].base_addr >= tmp.base_addr {
            s.map[j] = s.map[j - 1];
            j -= 1;
        }

        s.map[j] = tmp;
    }
}

/// Resolves overlapping ranges, giving priority to the numerically higher
/// types.
fn map_adjust(s: &mut State) {
    map_filter(s);

    let mut i = 0;
    while i < s.map_size as usize {
        // The C computed this once per `i`, and the loops below may mutate
        // the entry, so the value stays as the C left it.
        let a_end = s.map[i].base_addr.wrapping_add(s.map[i].length);
        let mut j = i + 1;

        while j < s.map_size as usize {
            let a_entry = s.map[i];
            let b_entry = s.map[j];
            let b_end = b_entry.base_addr.wrapping_add(b_entry.length);

            if a_entry.base_addr >= b_end || a_end <= b_entry.base_addr {
                j += 1;
                continue;
            }

            let (first, second) = if a_entry.base_addr < b_entry.base_addr {
                (i, j)
            } else {
                (j, i)
            };

            let (last_end, last_type) = if a_end > b_end {
                (a_end, a_entry.type_)
            } else {
                (b_end, b_entry.type_)
            };

            let tmp = BiosmemMapEntry {
                base_addr: s.map[second].base_addr,
                length: min(a_end, b_end)
                    .wrapping_sub(s.map[second].base_addr),
                type_: max(a_entry.type_, b_entry.type_),
            };

            s.map[first].length =
                tmp.base_addr.wrapping_sub(s.map[first].base_addr);
            s.map[second].base_addr =
                s.map[second].base_addr.wrapping_add(tmp.length);
            s.map[second].length =
                last_end.wrapping_sub(s.map[second].base_addr);
            s.map[second].type_ = last_type;

            if map_entry_is_invalid(&s.map[i])
                && map_entry_is_invalid(&s.map[j])
            {
                s.map[i] = tmp;
                s.map_size -= 1;
                let size = s.map_size as usize;
                s.map.copy_within(j + 1..=size, j);
                continue;
            }

            if map_entry_is_invalid(&s.map[i]) {
                s.map[i] = tmp;
                j += 1;
                continue;
            }

            if map_entry_is_invalid(&s.map[j]) {
                s.map[j] = tmp;
                j += 1;
                continue;
            }

            let target = if tmp.type_ == s.map[i].type_ {
                i
            } else if tmp.type_ == s.map[j].type_ {
                j
            } else {
                if s.map_size as usize >= s.map.len() {
                    die("biosmem_map_adjust", TOO_BIG_MSG);
                }

                s.map[s.map_size as usize] = tmp;
                s.map_size += 1;
                j += 1;
                continue;
            };

            if s.map[target].base_addr > tmp.base_addr {
                s.map[target].base_addr = tmp.base_addr;
            }

            s.map[target].length =
                s.map[target].length.wrapping_add(tmp.length);
            j += 1;
        }

        i += 1;
    }

    map_sort(s);
}

/// The lowest available address and the highest following unusable one in a
/// range.
fn map_find_avail(
    s: &State,
    phys_start: VmOffset,
    phys_end: VmOffset,
) -> Option<(VmOffset, VmOffset)> {
    let mut seg_start = VmOffset::MAX;
    let mut seg_end = VmOffset::MAX;

    for entry in &s.map[..s.map_size as usize] {
        if entry.type_ != MemType::AVAILABLE {
            continue;
        }

        let start = round_page64(entry.base_addr);
        if start >= phys_end as u64 {
            break;
        }

        let end = trunc_page64(entry.base_addr.wrapping_add(entry.length));

        if start < end && start < phys_end as u64 && end > phys_start as u64 {
            if seg_start == VmOffset::MAX {
                seg_start = start as VmOffset;
            }
            seg_end = end as VmOffset;
        }
    }

    if seg_start == VmOffset::MAX || seg_end == VmOffset::MAX {
        return None;
    }

    let mut start = phys_start;
    let mut end = phys_end;
    if seg_start > start {
        start = seg_start;
    }
    if seg_end < end {
        end = seg_end;
    }
    Some((start, end))
}

/// Sets the bounds of the segment `seg_index`.
fn set_segment(
    s: &mut State,
    seg_index: c_uint,
    start: VmOffset,
    end: VmOffset,
) {
    let Some(segment) = s.segments.get_mut(seg_index as usize) else {
        die("biosmem_set_segment", "biosmem: invalid segment index");
    };

    segment.start = start;
    segment.end = end;
}

/// The end of the segment `seg_index`.
fn segment_end(s: &State, seg_index: c_uint) -> VmOffset {
    s.segments.get(seg_index as usize).map_or_else(
        || die("biosmem_segment_end", "biosmem: invalid segment index"),
        |segment| segment.end,
    )
}

/// The size of the segment `seg_index`.
fn segment_size(s: &State, seg_index: c_uint) -> VmOffset {
    s.segments.get(seg_index as usize).map_or_else(
        || die("biosmem_segment_size", "biosmem: invalid segment index"),
        |segment| segment.end.wrapping_sub(segment.start),
    )
}

/// Clips `avail` around one boot-data range, returning `None` when the range
/// leaves no space.
fn find_avail_clip(
    avail: (VmOffset, VmOffset),
    data_start: VmOffset,
    data_end: VmOffset,
) -> Option<(VmOffset, VmOffset)> {
    let (avail_start, avail_end) = avail;
    let orig_end = data_end;
    let data_start = trunc_page(data_start);
    let data_end = round_page(data_end);

    if data_end < orig_end {
        die("biosmem_find_avail_clip", INVAL_BOOT_DATA);
    }

    if data_end <= avail_start || data_start >= avail_end {
        return Some(avail);
    }

    if data_start > avail_start {
        Some((avail_start, data_start))
    } else if data_end < avail_end {
        Some((data_end, avail_end))
    } else {
        None
    }
}

/// The page-aligned part of `start..end` clear of every boot data range, or
/// `None` when nothing is left.
fn find_avail(
    s: &State,
    start: VmOffset,
    end: VmOffset,
) -> Option<(VmOffset, VmOffset)> {
    let rounded = round_page(start);
    let truncated = trunc_page(end);

    if rounded < start || rounded >= truncated {
        return None;
    }

    let mut avail = (rounded, truncated);
    let nr = s.nr_boot_data as usize;

    for data in &s.boot_data[..nr] {
        avail = find_avail_clip(avail, data.start, data.end)?;
    }

    Some(avail)
}

/// Makes the largest unused area in upper memory the bootstrap heap.
fn setup_allocator(s: &mut State, mem_upper: u32) {
    let upper = mem_upper.wrapping_add(1024).wrapping_shl(PAGE_SHIFT);
    let mut end = (upper & !(PAGE_SIZE as u32 - 1)) as VmOffset;

    if end > VM_PAGE_DIRECTMAP_LIMIT {
        end = VM_PAGE_DIRECTMAP_LIMIT;
    }

    let mut max_heap_start: VmOffset = 0;
    let mut max_heap_end: VmOffset = 0;
    let mut start = BIOSMEM_END;

    while let Some((heap_start, heap_end)) = find_avail(s, start, end) {
        if heap_end.wrapping_sub(heap_start)
            > max_heap_end.wrapping_sub(max_heap_start)
        {
            max_heap_start = heap_start;
            max_heap_end = heap_end;
        }

        start = heap_end;
    }

    if max_heap_start >= max_heap_end {
        die("biosmem_setup_allocator", SETUP_MSG);
    }

    s.heap_start = max_heap_start;
    s.heap_end = max_heap_end;
    s.heap_bottom = max_heap_start;
    s.heap_top = max_heap_end;
    s.heap_topdown = true;

    // Keep `free_usable()` from releasing the heap.
    register(s, max_heap_start, max_heap_end, false);
}

/// Resolves the map, claims the AP boot page, and sets the DMA, DMA32,
/// direct-map and highmem segments up.  Returns the AP boot page.
fn bootstrap_common(s: &mut State) -> VmOffset {
    map_adjust(s);

    let Some((phys_start, phys_end)) =
        map_find_avail(s, BIOSMEM_BASE, VM_PAGE_DMA_LIMIT)
    else {
        die("biosmem_bootstrap_common", NOSEG_MSG);
    };

    let apboot = phys_start;

    let phys_start = phys_start.wrapping_add(PAGE_SIZE);
    set_segment(s, SEG_DMA, phys_start, phys_end);

    let Some((phys_start, phys_end)) =
        map_find_avail(s, VM_PAGE_DMA_LIMIT, VM_PAGE_DIRECTMAP_LIMIT)
    else {
        return apboot;
    };
    set_segment(s, SEG_DIRECTMAP, phys_start, phys_end);

    let phys_start = VM_PAGE_DIRECTMAP_LIMIT;

    let phys_start = {
        let Some((start, end)) =
            map_find_avail(s, phys_start, VM_PAGE_DMA32_LIMIT)
        else {
            return apboot;
        };
        set_segment(s, SEG_DMA32, start, end);
        VM_PAGE_DMA32_LIMIT
    };

    let Some((phys_start, phys_end)) =
        map_find_avail(s, phys_start, VM_PAGE_HIGHMEM_LIMIT)
    else {
        return apboot;
    };
    set_segment(s, SEG_HIGHMEM, phys_start, phys_end);
    apboot
}

/// Builds the memory map, the segments and the bootstrap allocator.
///
/// `entries` is the loader's memory map, and `mem_upper` its upper-memory
/// size in KiB.  Returns the page claimed for the other CPUs' boot code.
///
/// # Safety
///
/// The call must happen once, on one CPU, before any other entry point but
/// [`register_boot_data`].
pub unsafe fn bootstrap(
    entries: impl IntoIterator<Item = MapEntry>,
    mem_upper: u32,
) -> VmOffset {
    let s = unsafe { &mut *state() };
    map_build(s, entries);
    let apboot = bootstrap_common(s);
    setup_allocator(s, mem_upper);
    apboot
}

/// Allocates `nr_pages` pages from the bootstrap heap, halting when it is
/// exhausted.
#[must_use]
pub fn bootalloc(nr_pages: c_uint) -> VmOffset {
    // SAFETY: the caller runs between `bootstrap()` and `setup()`, on one
    // CPU.
    let s = unsafe { &mut *state() };
    let size = nr_pages.wrapping_shl(PAGE_SHIFT) as VmSize;

    if size == 0 {
        die("biosmem_bootalloc", INVAL_MSG);
    }

    if s.heap_topdown {
        let addr = s.heap_top.wrapping_sub(size);

        if addr < s.heap_start || addr > s.heap_top {
            die("biosmem_bootalloc", NOMEM_MSG);
        }

        s.heap_top = addr;
        addr
    } else {
        let addr = s.heap_bottom;
        let end = addr.wrapping_add(size);

        if end > s.heap_end || end < s.heap_bottom {
            die("biosmem_bootalloc", NOMEM_MSG);
        }

        s.heap_bottom = end;
        addr
    }
}

/// The end of the segment the direct map covers.
#[must_use]
pub fn directmap_end() -> VmOffset {
    // SAFETY: the segment table is written once during bootstrap; the page
    // map's startup and the fault path only read it.
    let s = unsafe { &*state() };

    // The C's middle branch, which returns the DMA32 end when that segment
    // is shorter than the direct map, is behind a `#if` that is false on
    // x86_64.
    if segment_size(s, SEG_DIRECTMAP) != 0 {
        return segment_end(s, SEG_DIRECTMAP);
    }

    segment_end(s, SEG_DMA)
}

/// The name of the segment `seg_index`, halting on an unknown one.
fn seg_name(seg_index: c_uint) -> &'static str {
    let Some(name) = table::seg_name(seg_index) else {
        die("biosmem_load_segment", "biosmem: invalid segment index")
    };
    // The names are ASCII literals.
    name.to_str().unwrap_or("?")
}

/// Prints the memory map to `out`.
fn map_show(s: &State, out: &mut dyn Write) -> fmt::Result {
    out.write_str("biosmem: physical memory map:\n")?;

    for entry in &s.map[..s.map_size as usize] {
        writeln!(
            out,
            "biosmem: {:018x}:{:018x}, {}",
            entry.base_addr,
            entry.base_addr.wrapping_add(entry.length),
            entry.type_.desc(),
        )?;
    }

    Ok(())
}

/// Loads the segment `seg_index` into the page allocator, clipped to
/// `max_phys_end`, reporting a clipped segment to `out`.
fn load_segment(
    s: &State,
    seg_index: c_uint,
    max_phys_end: VmOffset,
    out: &mut dyn Write,
) -> fmt::Result {
    let segment = s.segments.get(seg_index as usize).map_or_else(
        || die("biosmem_load_segment", "biosmem: invalid segment index"),
        |segment| *segment,
    );
    let phys_start = segment.start;
    let mut phys_end = segment.end;

    if phys_end > max_phys_end {
        if max_phys_end <= phys_start {
            return writeln!(
                out,
                "biosmem: warning: segment {} physically unreachable, not loaded",
                seg_name(seg_index),
            );
        }

        writeln!(
            out,
            "biosmem: warning: segment {} truncated to {:#x}",
            seg_name(seg_index),
            hex64(max_phys_end),
        )?;
        phys_end = max_phys_end;
    }

    if phys_end as u64 > MAX_PHYS_END {
        if MAX_PHYS_END <= phys_start as u64 {
            return writeln!(
                out,
                "biosmem: warning: segment {} beyond tested memory size, not loaded",
                seg_name(seg_index),
            );
        }

        writeln!(
            out,
            "biosmem: warning: segment {} truncated to tested {:#x}",
            seg_name(seg_index),
            MAX_PHYS_END,
        )?;
        phys_end = MAX_PHYS_END as VmOffset;
    }

    table::load(seg_index, phys_start, phys_end);

    // Clip the remaining heap to the loaded segment when it fits inside.
    if s.heap_top > phys_start && s.heap_bottom < phys_end {
        let avail_start = max(s.heap_bottom, phys_start);
        let avail_end = min(s.heap_top, phys_end);
        table::load_heap(seg_index, avail_start, avail_end);
    }

    Ok(())
}

/// Prints the map to `out` and loads every segment into the page allocator.
///
/// # Safety
///
/// Must run once, after [`bootstrap`] and the kernel page map's startup.
pub unsafe fn setup(out: &mut dyn Write) {
    let s = unsafe { &mut *state() };
    // The report is best effort: a writer that fails loses lines, never
    // segments.
    let _ = map_show(s, out);

    for i in 0..MAX_SEGS as c_uint {
        if segment_size(s, i) == 0 {
            break;
        }

        let _ = load_segment(s, i, VM_PAGE_HIGHMEM_LIMIT, out);
    }
}

/// Removes the temporary boot data ranges.
fn unregister_temporary_boot_data(s: &mut State) {
    let mut i = 0;
    while i < s.nr_boot_data as usize {
        let data = s.boot_data[i];

        if !data.temporary {
            i += 1;
            continue;
        }

        unregister_boot_data(s, data.start, data.end);
        i = 0;
    }
}

/// Gives the pages of `start..end` to the page allocator.
fn free_usable_range(start: VmOffset, end: VmOffset) {
    let mut start = start;

    while start < end {
        let Some(page) = table::lookup_pa::<()>(start) else {
            die("biosmem_free_usable_range", "biosmem: no page for address");
        };

        // SAFETY: the pages come from a loaded segment, so the lookup
        // returned the segment's live descriptor, and the boot path is
        // single-threaded.
        unsafe { table::manage(page.as_ptr()) };
        start = start.wrapping_add(PAGE_SIZE);
    }
}

/// Gives the part of `start..end` clear of boot data to the page allocator.
fn free_usable_entry(s: &State, start: VmOffset, end: VmOffset) {
    let mut start = start;

    while let Some((avail_start, avail_end)) = find_avail(s, start, end) {
        free_usable_range(avail_start, avail_end);
        start = avail_end;
    }
}

/// Gives the available memory the segments did not load, and the temporary
/// boot data, to the page allocator.
///
/// # Safety
///
/// Must run once, after [`setup`].
pub unsafe fn free_usable() {
    let s = unsafe { &mut *state() };
    unregister_temporary_boot_data(s);

    let mut i = 0;
    while i < s.map_size as usize {
        let entry = s.map[i];
        i += 1;

        if entry.type_ != MemType::AVAILABLE {
            continue;
        }

        let mut start = round_page64(entry.base_addr);

        if start >= VM_PAGE_HIGHMEM_LIMIT as u64 {
            break;
        }

        if start >= MAX_PHYS_END {
            break;
        }

        let mut end = trunc_page64(entry.base_addr.wrapping_add(entry.length));

        if end > VM_PAGE_HIGHMEM_LIMIT as u64 {
            end = VM_PAGE_HIGHMEM_LIMIT as u64;
        }

        if end > MAX_PHYS_END {
            end = MAX_PHYS_END;
        }

        if start < BIOSMEM_BASE as u64 {
            start = BIOSMEM_BASE as u64;
        }

        if start >= end {
            continue;
        }

        free_usable_entry(s, start as VmOffset, end as VmOffset);
    }
}

/// Whether `addr` lies in available memory of the map.
#[must_use]
pub fn addr_available(addr: VmOffset) -> bool {
    if addr < BIOSMEM_BASE {
        return false;
    }

    // SAFETY: the map is written only during bootstrap; `/dev/mem` reads it
    // after `setup()`.
    let s = unsafe { &*state() };
    let addr = addr as u64;

    for entry in &s.map[..s.map_size as usize] {
        let range =
            entry.base_addr..entry.base_addr.wrapping_add(entry.length);

        if range.contains(&addr) {
            return entry.type_ == MemType::AVAILABLE;
        }
    }

    false
}
