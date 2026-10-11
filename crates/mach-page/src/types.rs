// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The page descriptor's flag words, and the records the segment table keeps
//! and reports.

use crate::page::NodeList;
use crate::param::VmOffset;
use crate::simple_lock::SimpleLock;
use core::ffi::c_int;

bitflags::bitflags! {
    /// `vm_prot_t`: a set of protection bits.
    ///
    /// The values come from userspace with any bits set; every bit is kept,
    /// so a complement leaves the ones the kernel does not name in place.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmProt: c_int {
        /// `VM_PROT_READ`.
        const READ = 0x1;
        /// `VM_PROT_WRITE`.
        const WRITE = 0x2;
        /// `VM_PROT_EXECUTE`.
        const EXECUTE = 0x4;
        /// `VM_PROT_ALL`: read, write and execute.
        const ALL = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
        /// `VM_PROT_NO_CHANGE`: a marker `VmMap::protect` refuses to set.
        const NO_CHANGE = 0x08;
        /// `VM_PROT_NOTIFY`: a marker bit for callers of `VmMap::protect`.
        const NOTIFY = 0x10;
        // The bits userspace passes that the kernel does not name.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The flag word of a [`Page`](crate::page::Page): the wire count in bits
    /// 0 to 14, then one bit per boolean flag, from bit 15 through bit 31.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFlags: u32 {
        /// The page is on an inactive queue.
        const INACTIVE = 1 << 15;
        /// The page is on an active queue.
        const ACTIVE = 1 << 16;
        /// The page is being cleaned.
        const LAUNDRY = 1 << 17;
        /// The page is being cleaned to an external pager.
        const EXTERNAL_LAUNDRY = 1 << 18;
        /// The page is on a free list.
        const FREE = 1 << 19;
        /// The page was referenced since the last scan.
        const REFERENCE = 1 << 20;
        /// The page belongs to an external pager's object.
        const EXTERNAL = 1 << 21;
        /// The page is being worked on; wait rather than touch it.
        const BUSY = 1 << 22;
        /// A thread waits for the page to stop being busy.
        const WANTED = 1 << 23;
        /// The page is in its object's hash table.
        const TABLED = 1 << 24;
        /// The descriptor stands for no physical page.
        const FICTITIOUS = 1 << 25;
        /// The page belongs to its owner alone, outside the queues.
        const PRIVATE = 1 << 26;
        /// The data was requested from the pager and has not arrived.
        const ABSENT = 1 << 27;
        /// The pager reported an error for the data.
        const ERROR = 1 << 28;
        /// The page differs from its pager's copy.
        const DIRTY = 1 << 29;
        /// The pager must be given the page back even when it is clean.
        const PRECIOUS = 1 << 30;
        /// The page is being overwritten in full.
        const OVERWRITING = 1 << 31;
        // The wire count.
        const _ = 0x7fff;
    }
}

/// A segment's page and free-page counts, and its free-page thresholds.
#[derive(Clone, Copy, Debug)]
pub struct SegInfo {
    /// The pages the segment covers.
    pub pages: usize,
    /// Its free pages.
    pub free: usize,
    /// Below this, only privileged threads allocate.
    pub min_free: usize,
    /// At or below this, the pageout daemon is wanted.
    pub low_free: usize,
    /// Above this, the segment has pages to spare.
    pub high_free: usize,
}

/// A per-CPU cache of single free pages in front of a segment's buddy lists.
pub(crate) struct CpuPool {
    pub(crate) lock: SimpleLock,
    pub(crate) size: c_int,
    pub(crate) transfer_size: c_int,
    pub(crate) nr_pages: c_int,
    pub(crate) pages: NodeList,
}

impl CpuPool {
    pub(crate) const fn new() -> Self {
        Self {
            lock: SimpleLock::new(),
            size: 0,
            transfer_size: 0,
            nr_pages: 0,
            pages: NodeList::new(),
        }
    }
}

/// The free blocks of one order.
pub(crate) struct FreeList {
    pub(crate) size: usize,
    pub(crate) blocks: NodeList,
}

impl FreeList {
    pub(crate) const fn new() -> Self {
        Self {
            size: 0,
            blocks: NodeList::new(),
        }
    }
}

/// A segment as the boot loader reported it, with the part of it the boot heap
/// may use.
pub(crate) struct BootSeg {
    pub(crate) start: VmOffset,
    pub(crate) end: VmOffset,
    pub(crate) heap_present: bool,
    pub(crate) avail_start: VmOffset,
    pub(crate) avail_end: VmOffset,
}

impl BootSeg {
    pub(crate) const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            heap_present: false,
            avail_start: 0,
            avail_end: 0,
        }
    }
}
