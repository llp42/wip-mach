// SPDX-License-Identifier: CMU-Mach
// Derived from i386/intel/pmap.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The Intel physical-map module.
//!
//! With the [`Pmap`], [`PvEntry`], [`PmapUpdateList`] and [`PmapMapwindow`]
//! records.
//!
//! This is the header's PAE build, with the L4 table and the four-level
//! walk from it down to the page-table entry: the `__x86_64__` layout.

use crate::arch::types::{AtomicVmOffset, VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::biosmem;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::model_dep::alloc_aligned;
use crate::arch::x86_64::model_dep::pmap_grab_page;
use crate::arch::x86_64::mp_desc::interrupt_processor;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::phys::kvtophys;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::config::MAX_NCPUS;
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::lock::{LockData, SimpleLock};
use crate::kern::machine::slot as machine_slot;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::kern::smp::CpuId;
use crate::kern::thread::Thread;
use crate::mig;
use crate::utils::cell::SyncCell;
use crate::vm::types::VmProt;
use crate::vm::vm_kern::{self, KERNEL_MAP, VM_MIN_KERNEL_ADDRESS};
use crate::vm::vm_map::{VmMap, round_page};
use crate::vm::vm_page;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::slice;
use core::sync::atomic::{AtomicI32, AtomicIsize, AtomicPtr, Ordering, fence};
use lock::SpinLock;

/// The flat data selector the GDT builds with base zero, which makes an offset
/// in it a linear address.
const LINEAR_DS: u16 = 0x38;

/// The kernel data selector, which the TLB invalidation puts back in `%es`.
const KERNEL_DS: u16 = 0x10;

/// The offset within a page.
const INTEL_OFFMASK: VmOffset = 0xfff;

/// `INTEL_PTE_PFN`: the page-frame field of a page table entry, whose width
/// follows the `phys_addr_t` the entry is.
pub(crate) const INTEL_PTE_PFN: VmOffset = 0xffff_ffff_ffff_f000;

pub(crate) const INTEL_PTE_VALID: VmOffset = 0x0000_0001;
pub(crate) const INTEL_PTE_WRITE: VmOffset = 0x0000_0002;
/// A large-page directory entry.
pub(crate) const INTEL_PTE_PS: VmOffset = 0x0000_0080;
const INTEL_PTE_USER: VmOffset = 0x0000_0004;
const INTEL_PTE_WTHRU: VmOffset = 0x0000_0008;
const INTEL_PTE_NCACHE: VmOffset = 0x0000_0010;
pub(crate) const INTEL_PTE_REF: VmOffset = 0x0000_0020;
pub(crate) const INTEL_PTE_MOD: VmOffset = 0x0000_0040;
const INTEL_PTE_GLOBAL: VmOffset = 0x0000_0100;
const INTEL_PTE_WIRED: VmOffset = 0x0000_0200;

/// The low byte of `INTEL_PTE_MOD`.
const PHYS_MODIFIED: u8 = INTEL_PTE_MOD as u8;
/// The low byte of `INTEL_PTE_REF`.
const PHYS_REFERENCED: u8 = INTEL_PTE_REF as u8;

/// The read protection, as [`pmap_page_protect`] switches on the raw value.
const VM_PROT_READ: c_int = 0x1;
const VM_PROT_WRITE: c_int = 0x2;
const VM_PROT_EXECUTE: c_int = 0x4;
const VM_PROT_ALL: c_int = 0x7;

/// The CPU feature bit of global pages.
pub(crate) const CPU_FEATURE_PGE: u32 = 13;
/// The CPU feature bit of the SYSENTER/SYSEXIT pair.
pub(crate) const CPU_FEATURE_SEP: u32 = 11;
const CPU_FEATURE_PAE: u32 = 6;

/// The CPU type of an i486.
const CPU_TYPE_I486: c_int = 17;

const CR4_PAE: usize = 0x0020;

/// The invalidation requests one CPU can queue before the last becomes a
/// whole-address-space flush.
const UPDATE_LIST_SIZE: usize = 4;

/// The temporary map windows per CPU.
const PMAP_NMAPWINDOWS: usize = 2;

/// `MAPWINDOW_SIZE`: the virtual space the map windows take from the kernel
/// map's tail.
const MAPWINDOW_SIZE: VmOffset = PMAP_NMAPWINDOWS * MAX_NCPUS * PAGE_SIZE;

/// One hardware entry per VM page.
const PTES_PER_VM_PAGE: usize = 1;

/// The entries in one page table.
const NPTES: usize = PAGE_SIZE / size_of::<VmOffset>();

/// The protected page directories at the kernel end of the address space.
const PDPNUM_KERNEL: usize =
    ((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) >> PDPSHIFT) + 1;

/// The page directories [`pmap_create`] allocates, the same count
/// [`pmap_bootstrap`] writes at the kernel end.
const PDPNUM: usize = PDPNUM_KERNEL;

/// The lowest linear kernel address.
const LINEAR_MIN_KERNEL_ADDRESS: VmOffset = VM_MIN_KERNEL_ADDRESS;

/// The highest linear kernel address.
const LINEAR_MAX_KERNEL_ADDRESS: VmOffset = usize::MAX;

/// The highest kernel virtual address.
pub(crate) const VM_MAX_KERNEL_ADDRESS: VmOffset = LINEAR_MAX_KERNEL_ADDRESS
    - LINEAR_MIN_KERNEL_ADDRESS
    + VM_MIN_KERNEL_ADDRESS;

/// The room reserved for the kernel map.
pub(crate) const VM_KERNEL_MAP_SIZE: VmOffset = 1000 * 1024 * 1024;

/// The top of a user map.
const VM_MAX_USER_ADDRESS: VmOffset = 0x8000_0000_0000;

/// The lowest user address.
const VM_MIN_USER_ADDRESS: VmOffset = 0;

/// The page-directory-pointer shift.
const PDPSHIFT: u32 = 30;

pub(crate) const PDESHIFT: u32 = 21;
/// `PDE_MAPPED_SIZE`: the virtual memory one page-directory entry covers.
const PDE_MAPPED_SIZE: VmOffset = 1 << PDESHIFT;

/// The page-directory index of `addr`.
const fn lin2pdenum(addr: VmOffset) -> usize {
    (addr >> PDESHIFT) & 0x1ff
}

/// The page-directory index of `addr`, including the directory-pointer index
/// when the directories are contiguous.
const fn lin2pdenum_cont(addr: VmOffset) -> usize {
    (addr >> PDESHIFT) & 0x3ff
}

/// The page-table index of `addr`.
const fn ptenum(addr: VmOffset) -> usize {
    (addr >> 12) & 0x1ff
}

/// The level-4 index of `addr`.
const fn lin2l4num(addr: VmOffset) -> usize {
    (addr >> 39) & 0x1ff
}

/// The directory-pointer index of `addr`.
const fn lin2pdpnum(addr: VmOffset) -> usize {
    (addr >> 30) & 0x1ff
}

/// The linear address of a page, from its indices.
const fn pagenum2lin(l4: usize, l3: usize, l2: usize, l1: usize) -> VmOffset {
    ((l4) << 39) + ((l3) << 30) + ((l2) << 21) + ((l1) << 12)
}

/// The page-table entry bits of the physical address `pa`.
pub(crate) const fn pa_to_pte(pa: VmOffset) -> VmOffset {
    pa & INTEL_PTE_PFN
}

/// The physical address in the entry `pte`.
const fn pte_to_pa(pte: VmOffset) -> VmOffset {
    pte & INTEL_PTE_PFN
}

/// The kernel virtual address of the physical address `pa`.
pub(crate) const fn phystokv(pa: VmOffset) -> VmOffset {
    pa.wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// The physical address of the kernel virtual address `va`, before paging is
/// up.
const fn kvtophys_early(va: VmOffset) -> VmOffset {
    va.wrapping_sub(VM_MIN_KERNEL_ADDRESS)
}

/// The linear address of the kernel virtual address `va`: an identity here
/// because the linear and kernel virtual bases coincide.
const fn kvtolin(va: VmOffset) -> VmOffset {
    va.wrapping_sub(VM_MIN_KERNEL_ADDRESS)
        .wrapping_add(LINEAR_MIN_KERNEL_ADDRESS)
}

/// The kernel virtual address of the linear address `lin`.
const fn lintokv(lin: VmOffset) -> VmOffset {
    lin.wrapping_sub(LINEAR_MIN_KERNEL_ADDRESS)
        .wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// The kernel virtual address of the table the entry `pte` points at.
const fn ptetokv(pte: VmOffset) -> *mut VmOffset {
    phystokv(pte_to_pa(pte)) as *mut VmOffset
}

/// Whether the CPU has `feature`, from the table the early CPU probe fills.
pub(crate) fn cpu_has_feature(feature: u32) -> bool {
    // SAFETY: `CPU_FEATURES` is the two-word table the early CPU probe fills
    // before any caller runs, and every caller passes a `CPU_FEATURE_*`
    // constant below 64, so the index is 0 or 1.
    let table = core::ptr::addr_of!(locore::CPU_FEATURES);
    let word =
        // SAFETY: the feature index is below the table's two words.
        unsafe { table.cast::<u32>().add((feature / 32) as usize).read() };
    word & (1u32 << (feature % 32)) != 0
}

/// The set of CPUs a pmap is in use on, one bit each.
#[derive(Debug)]
#[repr(transparent)]
pub struct CpuSet(AtomicIsize);

impl CpuSet {
    const fn new() -> Self {
        Self(AtomicIsize::new(0))
    }

    /// The bit a CPU number selects; the set holds at most 32 CPUs.
    const fn mask(cpu: c_int) -> isize {
        1isize.wrapping_shl(cpu as u32)
    }

    fn bits(&self) -> isize {
        self.0.load(Ordering::Relaxed)
    }

    fn set_bits(&self, bits: isize) {
        self.0.store(bits, Ordering::Relaxed);
    }

    fn set(&self, cpu: c_int) {
        self.0.fetch_or(Self::mask(cpu), Ordering::SeqCst);
    }

    fn clear(&self, cpu: c_int) {
        self.0.fetch_and(!Self::mask(cpu), Ordering::SeqCst);
    }

    fn contains(&self, cpu: c_int) -> bool {
        self.bits() & Self::mask(cpu) != 0
    }
}

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

/// One physical map.
///
/// The header's `__x86_64__` layout, whose table tree hangs from `l4base`.
#[repr(C)]
#[allow(missing_docs)]
pub struct Pmap {
    /// `l4base`: the level-4 table, or null.
    pub l4base: *mut VmOffset,
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
    const fn zeroed() -> Self {
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
    pub entry: *mut VmOffset,
    pub vaddr: VmOffset,
}

const _: () = {
    assert!(size_of::<PmapMapwindow>() == 16);
    assert!(align_of::<PmapMapwindow>() == 8);
    assert!(offset_of!(PmapMapwindow, entry) == 0);
    assert!(offset_of!(PmapMapwindow, vaddr) == 8);
};

/// One queued invalidation.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct PmapUpdateItem {
    pub pmap: *mut Pmap,
    pub start: VmOffset,
    pub end: VmOffset,
}

/// The invalidations queued for one CPU.
#[repr(C)]
#[allow(missing_docs)]
pub struct PmapUpdateList {
    pub lock: SimpleLock,
    pub count: c_int,
    pub item: [PmapUpdateItem; UPDATE_LIST_SIZE],
}

const _: () =
    assert!(size_of::<PmapUpdateItem>() == 3 * size_of::<VmOffset>());
const _: () =
    assert!(offset_of!(PmapUpdateItem, start) == size_of::<VmOffset>());
const _: () =
    assert!(offset_of!(PmapUpdateItem, end) == 2 * size_of::<VmOffset>());

const _: () = {
    assert!(size_of::<PmapUpdateList>() == 104);
    assert!(align_of::<PmapUpdateList>() == 8);
    assert!(offset_of!(PmapUpdateList, lock) == 0);
    assert!(offset_of!(PmapUpdateList, count) == 4);
    assert!(offset_of!(PmapUpdateList, item) == 8);
};

impl PmapUpdateList {
    const fn new() -> Self {
        Self {
            lock: SimpleLock::new(),
            count: 0,
            item: [PmapUpdateItem {
                pmap: ptr::null_mut(),
                start: 0,
                end: 0,
            }; UPDATE_LIST_SIZE],
        }
    }
}

/// The kernel's statically allocated map.
static mut KERNEL_PMAP_STORE: Pmap = Pmap::zeroed();

/// The kernel's physical map.
static KERNEL_PMAP: AtomicPtr<Pmap> = AtomicPtr::new(ptr::null_mut());

/// `PMAP_NULL`: the C's null map pointer.
const PMAP_NULL: *mut Pmap = ptr::null_mut();

/// The kernel pmap the C global holds.
pub(crate) fn kernel_pmap_ptr() -> *mut Pmap {
    KERNEL_PMAP.load(Ordering::Relaxed)
}

/// The pmap-system read/write lock.
static mut PMAP_SYSTEM_LOCK: LockData = LockData::zeroed();

/// Whether [`pmap_init`] has run.
static PMAP_INITIALIZED: AtomicI32 = AtomicI32::new(0);

/// The flag that turns on the enter trace.
static PMAP_DEBUG: AtomicI32 = AtomicI32::new(0);

/// The start of the kernel virtual range [`pmap_bootstrap`] sets once.
pub static KERNEL_VIRTUAL_START: AtomicVmOffset = AtomicVmOffset::new(0);

/// The end of that range.
pub static KERNEL_VIRTUAL_END: AtomicVmOffset = AtomicVmOffset::new(0);

/// The kernel's page directory.
static KERNEL_PAGE_DIR: AtomicPtr<VmOffset> = AtomicPtr::new(ptr::null_mut());

/// One pv list head per physical page.
static PV_HEAD_TABLE: AtomicPtr<PvEntry> = AtomicPtr::new(ptr::null_mut());

/// The free pv entries, under [`PV_FREE_LIST_LOCK`] at `splvm`.
static PV_FREE_LIST: SyncCell<*mut PvEntry> =
    SyncCell(UnsafeCell::new(ptr::null_mut()));

/// Guards [`PV_FREE_LIST`].
static PV_FREE_LIST_LOCK: SimpleLock = SimpleLock::new();

/// One lock per managed page, guarding that page's pv list and attribute
/// byte; `pmap_init()` fills it in before any pv list is used.
static mut PV_LOCKS: &[SpinLock<(), MachPlatform>] = &[];

// `pmap_init()` carves the locks out right after the pv head table.
const _: () =
    assert!(align_of::<SpinLock<(), MachPlatform>>() <= align_of::<PvEntry>());

/// One attribute byte per physical page.
static PMAP_PHYS_ATTRIBUTES: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

/// The CPUs that may use a pmap.
pub static CPUS_ACTIVE: CpuSet = CpuSet::new();

/// The CPUs that are idle but will want the kernel pmap updates when they
/// wake.
pub static CPUS_IDLE: CpuSet = CpuSet::new();

/// The CPUs with queued invalidations.
pub static CPU_UPDATE_NEEDED: [AtomicI32; MAX_NCPUS] =
    [const { AtomicI32::new(0) }; MAX_NCPUS];

/// The queued invalidations.
static mut CPU_UPDATE_LIST: [PmapUpdateList; MAX_NCPUS] =
    [const { PmapUpdateList::new() }; MAX_NCPUS];

/// The per-CPU temporary mappings.
static mut MAPWINDOWS: [PmapMapwindow; PMAP_NMAPWINDOWS * MAX_NCPUS] =
    [PmapMapwindow {
        entry: ptr::null_mut(),
        vaddr: 0,
    }; PMAP_NMAPWINDOWS * MAX_NCPUS];

/// The slab cache of [`Pmap`] records.
static mut PMAP_CACHE: KmemCache = KmemCache::zeroed();

/// The page-table slab cache.
static mut PT_CACHE: KmemCache = KmemCache::zeroed();

/// The page-directory slab cache.
static mut PD_CACHE: KmemCache = KmemCache::zeroed();

/// The directory-pointer slab cache.
static mut PDPT_CACHE: KmemCache = KmemCache::zeroed();

/// The level-4 slab cache.
static mut L4_CACHE: KmemCache = KmemCache::zeroed();

/// The slab cache of [`PvEntry`] records.
static mut PV_LIST_CACHE: KmemCache = KmemCache::zeroed();

/// Invalidate the TLB entry for one page, given its linear address.
fn invalidate_linear_page(linear: VmOffset) {
    // SAFETY: The two selectors are architectural constants the kernel's GDT
    // describes from `gdt_init()` on, so neither load can fault.
    unsafe {
        asm!(
            "movw {linear_ds:x}, %es",
            "invlpg %es:({addr})",
            "movw {kernel_ds:x}, %es",
            addr = in(reg) linear,
            linear_ds = in(reg) LINEAR_DS,
            kernel_ds = in(reg) KERNEL_DS,
            options(att_syntax, nostack, preserves_flags),
        );
    }
}

/// Reads CR3.
fn read_cr3() -> usize {
    let value: usize;
    // SAFETY: reading CR3 is legal at CPL 0.
    unsafe {
        asm!(
            "mov {value}, cr3",
            value = out(reg) value,
            options(nostack, preserves_flags, readonly),
        );
    }
    value
}

/// Writes CR3.
fn write_cr3(value: usize) {
    // SAFETY: writing CR3 is legal at CPL 0; the caller supplies a page
    // directory with the mappings the kernel is already using.
    unsafe {
        asm!(
            "mov cr3, {value}",
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads CR4.
fn read_cr4() -> usize {
    let value: usize;
    // SAFETY: reading CR4 is legal at CPL 0.
    unsafe {
        asm!(
            "mov {value}, cr4",
            value = out(reg) value,
            options(nostack, preserves_flags, readonly),
        );
    }
    value
}

/// Writes CR4.
fn write_cr4(value: usize) {
    // SAFETY: writing CR4 is legal at CPL 0; the caller only adds the PAE bit
    // the page tables were built for.
    unsafe {
        asm!(
            "mov cr4, {value}",
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Flushes the TLB by reloading CR3.
fn flush_tlb() {
    write_cr3(read_cr3());
}

/// Loads `pmap`'s page tables into CR3.
fn set_pmap(pmap: *mut Pmap) {
    // SAFETY: the caller passes a live map whose `l4base` the kernel built.
    unsafe { write_cr3(kvtophys((*pmap).l4base as VmOffset)) };
}

/// Makes `pmap` current on `cpu` and adds the CPU to its active set.
///
/// # Safety
///
/// `pmap` must be live, and `cpu` must be the calling CPU with interrupts
/// blocked, as the context switch has them.
pub unsafe fn activate_user(pmap: *mut Pmap, cpu: c_int) {
    if pmap == kernel_pmap_ptr() {
        set_pmap(pmap);
        return;
    }

    CPUS_ACTIVE.clear(cpu);
    unsafe {
        (*pmap).lock.lock();
        set_pmap(pmap);
        (*pmap).cpus_using.set(cpu);
    }
    CPUS_ACTIVE.set(cpu);
    unsafe { (*pmap).lock.unlock() };
}

/// Removes `cpu` from `pmap`'s active set.
///
/// # Safety
///
/// `pmap` must be live, and `cpu` must be the calling CPU.
pub unsafe fn deactivate_user(pmap: *mut Pmap, cpu: c_int) {
    if pmap != kernel_pmap_ptr() {
        unsafe { (*pmap).cpus_using.clear(cpu) };
    }
}

/// Removes `cpu` from the kernel map's active set.
///
/// # Safety
///
/// `cpu` must be the calling CPU.
pub(crate) unsafe fn deactivate_kernel(cpu: c_int) {
    // SAFETY: the kernel map is live from `pmap_bootstrap()`, and the C macro
    // cleared the bit without the lock.
    unsafe { (*kernel_pmap_ptr()).cpus_using.clear(cpu) };
}

/// Makes the kernel pmap current on `cpu` and flushes its queued updates.
///
/// # Safety
///
/// `cpu` must be the calling CPU with interrupts blocked, as the boot and
/// context-switch paths have them.
pub(crate) unsafe fn activate_kernel(cpu: c_int) {
    CPUS_ACTIVE.clear(cpu);
    // SAFETY: the kernel map is live from `pmap_bootstrap()`, and the lock
    // protects the queued updates and `cpus_using`.
    unsafe {
        (*kernel_pmap_ptr()).lock.lock();

        if CPU_UPDATE_NEEDED[cpu as usize].load(Ordering::Relaxed) != 0 {
            process_pmap_updates(kernel_pmap_ptr());
        }

        (*kernel_pmap_ptr()).cpus_using.set(cpu);
        CPUS_ACTIVE.set(cpu);

        (*kernel_pmap_ptr()).lock.unlock();
    }
}

/// Raises to `splvm`, returning the level to restore.
fn raise_splvm() -> c_int {
    // SAFETY: raising to `splvm` has no precondition.
    let spl = unsafe { spl::splvm() };
    CPUS_ACTIVE.clear(cpu_id().bits() as c_int);
    spl
}

/// Restores the level [`raise_splvm`] returned.
fn restore_spl(spl: c_int) {
    CPUS_ACTIVE.set(cpu_id().bits() as c_int);
    // SAFETY: `spl` came from `splvm()`, and `splx` accepts any level.
    unsafe { spl::splx(spl) };
}

/// The pmap-system lock.
fn system_lock() -> *mut LockData {
    &raw mut PMAP_SYSTEM_LOCK
}

/// Takes the system lock for read, then the map's own lock, and returns the
/// level to restore.
///
/// # Safety
///
/// `pmap` must be a live physical map, and the caller must later pass the
/// returned level to [`read_unlock()`] on the same map to release both
/// locks and restore the priority level.
unsafe fn read_lock(pmap: *mut Pmap) -> c_int {
    let spl = raise_splvm();
    unsafe {
        (*system_lock()).read();
        (*pmap).lock.lock();
    }
    spl
}

/// Drops the locks [`read_lock`] took and restores the level.
///
/// # Safety
///
/// `pmap` must be the same live map passed to the matching
/// [`read_lock()`], whose read lock is still held, and `spl` must be the
/// level that call returned.
unsafe fn read_unlock(pmap: *mut Pmap, spl: c_int) {
    unsafe {
        (*pmap).lock.unlock();
        (*system_lock()).done();
    }
    restore_spl(spl);
}

/// Takes the system lock for write at `splvm`, returning the level to restore.
fn write_lock() -> c_int {
    let spl = raise_splvm();
    // SAFETY: the system lock is live from `pmap_bootstrap()` on.
    unsafe { (*system_lock()).write() };
    spl
}

/// Drops the system lock [`write_lock`] took and restores the level.
fn write_unlock(spl: c_int) {
    // SAFETY: the caller holds the system lock for write.
    unsafe { (*system_lock()).done() };
    restore_spl(spl);
}

/// Invalidates the TLB of this CPU for `s..e` of `pmap`: one INVLPG for a
/// single page, a CR3 reload for anything wider.
///
/// # Safety
///
/// `pmap` must be live, and `[s, e)` must be the linear range just
/// unmapped or remapped on the calling CPU, as the C's callers held.
unsafe fn invalidate_tlb(pmap: *mut Pmap, s: VmOffset, e: VmOffset) {
    if e.wrapping_sub(s) == PAGE_SIZE {
        let addr = if pmap == kernel_pmap_ptr() {
            kvtolin(s)
        } else {
            s
        };
        invalidate_linear_page(addr);
    } else {
        flush_tlb();
    }
}

/// Signals every other CPU using the map, waits for them to acknowledge, then
/// invalidates locally.
///
/// # Safety
///
/// `pmap` must be live and locked, and the caller must be at `splvm` or above
/// with interrupts blocked.
unsafe fn update_tlbs(pmap: *mut Pmap, s: VmOffset, e: VmOffset) {
    let cpu_mask = CpuSet::mask(cpu_id().bits() as c_int);
    let users = unsafe { (*pmap).cpus_using.bits() } & !cpu_mask;
    if users != 0 {
        unsafe { signal_cpus(users, pmap, s, e) };
        while unsafe { (*pmap).cpus_using.bits() }
            & CPUS_ACTIVE.bits()
            & !cpu_mask
            != 0
        {
            core::hint::spin_loop();
        }
    }
    if unsafe { (*pmap).cpus_using.contains(cpu_id().bits() as c_int) } {
        // SAFETY: `pmap` is live and locked; the range is the one entered.
        unsafe { invalidate_tlb(pmap, s, e) };
    }
}

/// The level-4 entry of `addr` in `pmap`, or null.
///
/// # Safety
///
/// `pmap` must be a live physical map.
unsafe fn l4base_of(pmap: *mut Pmap, addr: VmOffset) -> *mut VmOffset {
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
unsafe fn ptp_of(pmap: *mut Pmap, addr: VmOffset) -> *mut VmOffset {
    let l4_table = unsafe { l4base_of(pmap, addr) };
    if l4_table.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `l4_table` is the live table `l4base_of()` returned.
    let pdp = unsafe { *l4_table };
    if pdp & INTEL_PTE_VALID == 0 {
        return ptr::null_mut();
    }
    ptetokv(pdp).wrapping_add(lin2pdpnum(addr))
}

/// The page-directory entry of `addr` in `pmap`, or null.
///
/// # Safety
///
/// `pmap` must be a live physical map.
unsafe fn pde_of(pmap: *mut Pmap, addr: VmOffset) -> *mut VmOffset {
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
    if pde & INTEL_PTE_VALID == 0 {
        return ptr::null_mut();
    }
    ptetokv(pde).wrapping_add(lin2pdenum(addr))
}

/// The page-table entry of `addr` in `pmap`, or null for no mapping.
///
/// # Safety
///
/// `pmap` must be a live physical map.
unsafe fn pte_of(pmap: *mut Pmap, addr: VmOffset) -> *mut VmOffset {
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
    if pte & INTEL_PTE_VALID == 0 {
        return ptr::null_mut();
    }
    ptetokv(pte).wrapping_add(ptenum(addr))
}

/// The page-table entry of `addr` in `pmap`, or null for no mapping.
///
/// # Safety
///
/// `pmap` must be a live physical map, as the C's callers guaranteed.
pub(crate) unsafe fn pmap_pte(
    pmap: *mut Pmap,
    addr: VmOffset,
) -> *mut VmOffset {
    unsafe { pte_of(pmap, addr) }
}

/// Allocate one object from a slab cache, or null.
///
/// # Safety
///
/// `cache` must have been initialized and no other access may hold its lock.
unsafe fn cache_alloc(cache: *mut KmemCache) -> *mut u8 {
    unsafe { (*cache).alloc() }.map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// Return one object to a slab cache.
///
/// # Safety
///
/// `obj` must be a live object of `cache`, and no other access may hold the
/// cache's lock.
unsafe fn cache_free(cache: *mut KmemCache, obj: *mut u8) {
    let Some(obj) = NonNull::new(obj) else {
        return;
    };
    unsafe { (*cache).free(obj) };
}

/// The pv list head of a page index.
fn pv_head(pai: usize) -> *mut PvEntry {
    PV_HEAD_TABLE.load(Ordering::Relaxed).wrapping_add(pai)
}

/// The attribute byte of a page index.
fn phys_attribute(pai: usize) -> *mut u8 {
    PMAP_PHYS_ATTRIBUTES
        .load(Ordering::Relaxed)
        .wrapping_add(pai)
}

/// Returns the lock guarding the pv list and attribute byte of page `pai`.
///
/// # Panics
///
/// Panics if `pai` is not a managed page's index.
fn pv_lock(pai: usize) -> &'static SpinLock<(), MachPlatform> {
    // SAFETY: `pmap_init()` writes the table once, before any pv list is
    // used, and it is only read from then on.
    let locks = unsafe { PV_LOCKS };
    &locks[pai]
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
fn pv_free(entry: *mut PvEntry) {
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
fn valid_page(addr: VmOffset) -> bool {
    if PMAP_INITIALIZED.load(Ordering::Relaxed) == 0 {
        return false;
    }
    vm_page::lookup_pa(addr).is_some()
}

/// Advisory, and empty, since [`pmap_enter`] already learns whether a page is
/// wired.
pub(crate) const fn pmap_pageable(
    _pmap: *mut Pmap,
    _start: VmOffset,
    _end: VmOffset,
    _pageable: c_int,
) {
}

/// Unmap the page at virtual address zero so that a null reference faults.
fn unmap_page_zero() {
    kprint!(
        "Unmapping the zero page.  Some BIOS functions may not be working any more.\n"
    );
    // SAFETY: `kernel_pmap_ptr()` is the kernel's live pmap from
    // `pmap_bootstrap()` on, and `pte_of()` returns null rather than something
    // invalid for an address with no page-table entry.
    let pte = unsafe { pte_of(kernel_pmap_ptr(), 0) };
    let Some(pte) = NonNull::new(pte) else {
        return;
    };
    // SAFETY: `pmap_pte()` returned a non-null pointer to a live page table
    // entry for address zero.
    unsafe { pte.as_ptr().write(0) };
    invalidate_linear_page(0);
}

/// Unmap the page at virtual address zero so that a null reference faults.
///
/// # Safety
///
/// The kernel pmap must be initialized, so that `pmap_pte()` can walk it, and
/// nothing may depend on the zero page's mapping afterwards.
pub(crate) unsafe fn pmap_unmap_page_zero() {
    unmap_page_zero();
}

/// The boot-time back door that maps memory outside the direct map.
///
/// # Safety
///
/// `virt` must name a free kernel-virtual range covering `start` to `end`,
/// and the caller must be running with the mapping machinery usable.
pub(crate) unsafe fn pmap_map_bd(
    virt: VmOffset,
    start: VmOffset,
    end: VmOffset,
    prot: VmProt,
) -> VmOffset {
    unsafe { map_bd(virt, start, end, prot) }
}

/// # Safety
///
/// As `pmap_map_bd`.
unsafe fn map_bd(
    mut virt: VmOffset,
    mut start: VmOffset,
    end: VmOffset,
    prot: VmProt,
) -> VmOffset {
    let mut template = pa_to_pte(start)
        | INTEL_PTE_NCACHE
        | INTEL_PTE_WTHRU
        | INTEL_PTE_VALID;
    if cpu_has_feature(CPU_FEATURE_PGE) {
        template |= INTEL_PTE_GLOBAL;
    }
    if prot.contains(VmProt::WRITE) {
        template |= INTEL_PTE_WRITE;
    }

    let spl = unsafe { read_lock(kernel_pmap_ptr()) };
    while start < end {
        // SAFETY: the kernel map is live, as `map_bd`'s caller promised.
        let pte = unsafe { pte_of(kernel_pmap_ptr(), virt) };
        if pte.is_null() {
            kpanic!("pmap_map_bd", "pmap_map_bd: Invalid kernel address\n");
        }
        // SAFETY: `pmap_pte()` returned a live entry for `virt`.
        unsafe { *pte = template };
        template = template.wrapping_add(PAGE_SIZE);
        virt = virt.wrapping_add(PAGE_SIZE);
        start = start.wrapping_add(PAGE_SIZE);
    }
    // SAFETY: the kernel map is live and the lock was taken above.
    unsafe { read_unlock(kernel_pmap_ptr(), spl) };
    virt
}

/// Builds the kernel's level-4 table and directory-pointer tables.
fn bootstrap_pae() {
    let l4 =
        with_exposed_provenance_mut::<VmOffset>(phystokv(pmap_grab_page()));
    // SAFETY: `kernel_pmap_ptr()` points at the static store, and the L4 table
    // was just grabbed for it.
    unsafe { (*kernel_pmap_ptr()).l4base = l4 };
    // SAFETY: the freshly grabbed page is the kernel's to clear.
    unsafe { ptr::write_bytes(l4.cast::<u8>(), 0, PAGE_SIZE) };

    // The C carried on with address zero when the boot allocator was empty.
    let addr = alloc_aligned(PDPNUM_KERNEL * PAGE_SIZE).unwrap_or(0);
    let page_dir = with_exposed_provenance_mut::<VmOffset>(phystokv(addr));
    KERNEL_PAGE_DIR.store(page_dir, Ordering::Relaxed);
    // SAFETY: the boot allocator returned this page for the kernel directory;
    // the directory is PDPNUM_KERNEL pages.
    unsafe {
        ptr::write_bytes(page_dir.cast::<u8>(), 0, PDPNUM_KERNEL * PAGE_SIZE);
    };

    let pdp =
        with_exposed_provenance_mut::<VmOffset>(phystokv(pmap_grab_page()));
    // SAFETY: the freshly grabbed page is the kernel's to clear.
    unsafe { ptr::write_bytes(pdp.cast::<u8>(), 0, PAGE_SIZE) };
    for i in 0..PDPNUM_KERNEL {
        let index = i + lin2pdpnum(VM_MIN_KERNEL_ADDRESS);
        // SAFETY: the directory pointer table is one page, and the index is
        // below its `NPTES` entries.
        unsafe {
            *pdp.wrapping_add(index) = pa_to_pte(kvtophys_early(
                page_dir.cast::<u8>().wrapping_add(i * PAGE_SIZE).addr(),
            )) | INTEL_PTE_VALID
                | INTEL_PTE_WRITE;
        }
    }
    // SAFETY: the L4 table is one page and the kernel's index is in range.
    unsafe {
        *l4.wrapping_add(lin2l4num(VM_MIN_KERNEL_ADDRESS)) =
            pa_to_pte(kvtophys_early(pdp.addr()))
                | INTEL_PTE_VALID
                | INTEL_PTE_WRITE;
    }
}

/// Builds the kernel's page tables with mapping off, so only physical
/// addresses are reachable.
pub(crate) fn pmap_bootstrap() {
    KERNEL_PMAP.store(&raw mut KERNEL_PMAP_STORE, Ordering::Relaxed);

    // SAFETY: the lock's storage is unshared at this point in the boot.
    unsafe { LockData::init(&raw mut PMAP_SYSTEM_LOCK, false) };
    // SAFETY: the lock's storage is unshared at this point in the boot; for
    // the kernel map's own lock and count.
    unsafe {
        (*kernel_pmap_ptr()).lock.init();
        (*kernel_pmap_ptr()).ref_count = 1;
    }

    let start = phystokv(biosmem::directmap_end());
    let mut end = start.wrapping_add(VM_KERNEL_MAP_SIZE);
    if end < start || end > VM_MAX_KERNEL_ADDRESS.wrapping_sub(PAGE_SIZE) {
        end = VM_MAX_KERNEL_ADDRESS.wrapping_sub(PAGE_SIZE);
    }
    KERNEL_VIRTUAL_START.store(start, Ordering::Relaxed);
    KERNEL_VIRTUAL_END.store(end, Ordering::Relaxed);
    kprint!("kernel virtual area: {:x}-{:x}\n", start, end);

    bootstrap_pae();

    let global = if cpu_has_feature(CPU_FEATURE_PGE) {
        INTEL_PTE_GLOBAL
    } else {
        0
    };
    let image_start = ptr::addr_of!(mig::_start).addr();
    let image_end = ptr::addr_of!(mig::etext).addr();
    let directmap_end = phystokv(biosmem::directmap_end());
    // SAFETY: the kernel directory is live from `bootstrap_pae()` above, and
    // the physical memory it maps is the machine's RAM.
    unsafe {
        let directory = KERNEL_PAGE_DIR.load(Ordering::Relaxed);
        let mut va = phystokv(0);
        while va >= phystokv(0) && va < end {
            let pde = directory.wrapping_add(lin2pdenum_cont(kvtolin(va)));
            let ptable = with_exposed_provenance_mut::<VmOffset>(phystokv(
                pmap_grab_page(),
            ));
            *pde = pa_to_pte(kvtophys_early(ptable.addr()))
                | INTEL_PTE_VALID
                | INTEL_PTE_WRITE;

            let mut pte = ptable;
            while va < directmap_end && pte < ptable.wrapping_add(NPTES) {
                if (pte.offset_from(ptable) as usize) < ptenum(va) {
                    *pte = 0;
                } else {
                    if va >= image_start
                        && va.wrapping_add(PAGE_SIZE) <= image_end
                    {
                        *pte = pa_to_pte(kvtophys_early(va))
                            | INTEL_PTE_VALID
                            | global;
                    } else {
                        *pte = pa_to_pte(kvtophys_early(va))
                            | INTEL_PTE_VALID
                            | INTEL_PTE_WRITE
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
                    let win = (&raw mut MAPWINDOWS)
                        .cast::<PmapMapwindow>()
                        .wrapping_add(index);
                    (*win).entry = pte;
                    (*win).vaddr = va;
                }
                *pte = 0;
                va = va.wrapping_add(PAGE_SIZE);
                pte = pte.wrapping_add(1);
            }
        }
    }
}

/// Maps a physical page in the calling CPU's temporary window.
///
/// # Safety
///
/// `entry` must be a page-table template the caller intends to map now.
///
/// # Panics
///
/// Halts when both of the CPU's windows are busy, a state the two nested
/// users cannot reach.
pub(crate) unsafe fn pmap_get_mapwindow(
    entry: VmOffset,
) -> *mut PmapMapwindow {
    // SAFETY: `kernel_pmap_ptr()` is live from `pmap_bootstrap()` on, and a
    // `CpuId` indexes the `MAX_NCPUS` window runs.
    unsafe {
        let cpu = cpu_id().as_usize();
        let windows = (&raw mut MAPWINDOWS).cast::<PmapMapwindow>();
        let start = windows.wrapping_add(cpu * PMAP_NMAPWINDOWS);
        let end = windows.wrapping_add((cpu + 1) * PMAP_NMAPWINDOWS);
        let mut map = start;
        while map < end {
            let slot = (*map).entry;
            if slot.is_null() || *slot == 0 {
                break;
            }
            map = map.wrapping_add(1);
        }
        if map == end {
            kpanic!(
                "pmap_get_mapwindow",
                "pmap_get_mapwindow: no free map window\n"
            )
        }
        *(*map).entry = entry;
        invalidate_tlb(
            kernel_pmap_ptr(),
            (*map).vaddr,
            (*map).vaddr.wrapping_add(PAGE_SIZE),
        );
        map
    }
}

/// Drops a temporary mapping.
///
/// # Safety
///
/// `map` must be a window `pmap_get_mapwindow()` returned and not yet
/// released.
pub(crate) unsafe fn pmap_put_mapwindow(map: *mut PmapMapwindow) {
    unsafe {
        *(*map).entry = 0;
        invalidate_tlb(
            kernel_pmap_ptr(),
            (*map).vaddr,
            (*map).vaddr.wrapping_add(PAGE_SIZE),
        );
    }
}

/// The kernel virtual range left for the VM system.
///
/// # Safety
///
/// `startp` and `endp` must be valid for a write, as the C required.
pub(crate) unsafe fn pmap_virtual_space(
    startp: *mut VmOffset,
    endp: *mut VmOffset,
) {
    let start = KERNEL_VIRTUAL_START.load(Ordering::Relaxed);
    let end = KERNEL_VIRTUAL_END.load(Ordering::Relaxed);
    unsafe {
        *startp = start;
        *endp = end.wrapping_sub(MAPWINDOW_SIZE);
    }
}

/// Allocates the pv tables and the cache of maps.
pub(crate) fn pmap_init() {
    let npages = vm_page::table_size();
    let size = round_page(
        (size_of::<PvEntry>() + size_of::<SpinLock<(), MachPlatform>>() + 1)
            * npages,
    );

    // SAFETY: `kernel_map` is the live kernel map by the time `pmap_init()`
    // runs.
    let map = unsafe { NonNull::new_unchecked(KERNEL_MAP) };
    let Ok(mut addr) = vm_kern::kmem_alloc_wired(map, size) else {
        kpanic!("pmap_init", "pmap_init\n")
    };
    // SAFETY: `kmem_alloc_wired()` returned `size` writable bytes at `addr`.
    unsafe { ptr::write_bytes(addr as *mut u8, 0, size) };

    // SAFETY: the block the VM system handed over is now carved into the pv
    // head table, its locks and the attribute bytes; the locks are written
    // in place and the slice over them is published before any pv use.
    unsafe {
        PV_HEAD_TABLE.store(addr as *mut PvEntry, Ordering::Relaxed);
        addr += size_of::<PvEntry>() * npages;
        let locks = addr as *mut SpinLock<(), MachPlatform>;
        for i in 0..npages {
            ptr::write(locks.add(i), SpinLock::new(()));
        }
        PV_LOCKS = slice::from_raw_parts(locks, npages);
        addr += size_of::<SpinLock<(), MachPlatform>>() * npages;
        PMAP_PHYS_ATTRIBUTES.store(addr as *mut u8, Ordering::Relaxed);
    }

    // SAFETY: each cache's storage is unshared and this runs once.  The
    // names are the C strings the C passed; the sizes are the mirror's.
    unsafe {
        let pmap_cache = &raw mut PMAP_CACHE;
        (*pmap_cache).init(
            c"pmap".to_bytes(),
            size_of::<Pmap>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
        let pt_cache = &raw mut PT_CACHE;
        (*pt_cache).init(
            c"pmap_L1".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            None,
            CacheInitFlags::PHYSMEM,
        );
        let pdir_cache = &raw mut PD_CACHE;
        (*pdir_cache).init(
            c"pmap_L2".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            None,
            CacheInitFlags::PHYSMEM,
        );
        let pdpt_cache = &raw mut PDPT_CACHE;
        (*pdpt_cache).init(
            c"pmap_L3".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            None,
            CacheInitFlags::PHYSMEM,
        );
        let l4_cache = &raw mut L4_CACHE;
        (*l4_cache).init(
            c"pmap_L4".to_bytes(),
            PAGE_SIZE,
            PAGE_SIZE,
            None,
            CacheInitFlags::PHYSMEM,
        );
        let pv_list_cache = &raw mut PV_LIST_CACHE;
        (*pv_list_cache).init(
            c"pv_entry".to_bytes(),
            size_of::<PvEntry>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }

    for i in 0..MAX_NCPUS {
        let up = update_list(i as c_int);
        // SAFETY: each update list is this file's own storage.
        unsafe {
            (*up).lock.init();
            (*up).count = 0;
        }
    }

    PMAP_INITIALIZED.store(1, Ordering::Relaxed);
}

/// Builds a fresh physical map.
///
/// # Safety
///
/// The caches must be initialized, which `pmap_init()` does, and the caller
/// must be ready to run with the pmap system's locks free.
pub(crate) unsafe fn pmap_create(size: VmSize) -> *mut Pmap {
    if size != 0 {
        return PMAP_NULL;
    }

    let p = unsafe { cache_alloc(&raw mut PMAP_CACHE) }.cast::<Pmap>();
    if p.is_null() {
        return PMAP_NULL;
    }

    let mut page_dir: [*mut VmOffset; PDPNUM] = [ptr::null_mut(); PDPNUM];
    let mut i = 0;
    while i < PDPNUM {
        page_dir[i] =
            unsafe { cache_alloc(&raw mut PD_CACHE) }.cast::<VmOffset>();
        if page_dir[i].is_null() {
            while i > 0 {
                i -= 1;
                // SAFETY: every earlier entry is an object this function
                // allocated from this cache.
                unsafe { cache_free(&raw mut PD_CACHE, page_dir[i].cast()) };
            }
            // SAFETY: `p` is this function's object from the pmap cache.
            unsafe { cache_free(&raw mut PMAP_CACHE, p.cast()) };
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
        let pdp_kernel = cache_alloc(&raw mut PDPT_CACHE).cast::<VmOffset>();
        if pdp_kernel.is_null() {
            let mut k = 0;
            while k < PDPNUM {
                cache_free(&raw mut PD_CACHE, page_dir[k].cast());
                k += 1;
            }
            cache_free(&raw mut PMAP_CACHE, p.cast());
            return PMAP_NULL;
        }
        ptr::write_bytes(pdp_kernel.cast::<u8>(), 0, PAGE_SIZE);
        let mut k = 0;
        while k < PDPNUM {
            let index = k + lin2pdpnum(VM_MIN_KERNEL_ADDRESS);
            *pdp_kernel.wrapping_add(index) =
                pa_to_pte(kvtophys(page_dir[k].addr()))
                    | INTEL_PTE_VALID
                    | INTEL_PTE_WRITE;
            k += 1;
        }

        let l4base = cache_alloc(&raw mut L4_CACHE).cast::<VmOffset>();
        if l4base.is_null() {
            kpanic!("pmap_create", "pmap_create\n");
        }
        ptr::write_bytes(l4base.cast::<u8>(), 0, PAGE_SIZE);
        *l4base.wrapping_add(lin2l4num(VM_MIN_KERNEL_ADDRESS)) =
            pa_to_pte(kvtophys(pdp_kernel.addr()))
                | INTEL_PTE_VALID
                | INTEL_PTE_WRITE;
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
pub(crate) unsafe fn pmap_destroy(p: Option<NonNull<Pmap>>) {
    let Some(p) = p else {
        return;
    };
    let p = p.as_ptr();

    let spl = raise_splvm();
    let count = unsafe {
        (*p).lock.lock();
        (*p).ref_count = (*p).ref_count.wrapping_sub(1);
        let count = (*p).ref_count;
        (*p).lock.unlock();
        count
    };
    restore_spl(spl);

    if count != 0 {
        return;
    }

    let mut l4i = 0;
    while l4i < NPTES {
        // SAFETY: the map owns its L4 table for as long as it exists.
        let pdp = unsafe { *(*p).l4base.wrapping_add(l4i) };
        if pdp & INTEL_PTE_VALID == 0 {
            l4i += 1;
            continue;
        }
        let pdpbase = ptetokv(pdp);
        let mut l3i = 0;
        while l3i < NPTES {
            // SAFETY: `pdpbase` is the directory pointer table the entry
            // above names.
            let pde = unsafe { *pdpbase.wrapping_add(l3i) };
            if pde & INTEL_PTE_VALID == 0 {
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
                    if pte & INTEL_PTE_VALID != 0 {
                        // SAFETY: each valid entry names a page-table
                        // page from `pt_cache`.
                        unsafe {
                            cache_free(&raw mut PT_CACHE, ptetokv(pte).cast());
                        };
                    }
                    l2i += 1;
                }
            }
            // SAFETY: `pdirbase` came from `PD_CACHE`.
            unsafe { cache_free(&raw mut PD_CACHE, pdirbase.cast()) };
            l3i += 1;
        }
        // SAFETY: `pdpbase` came from `pdpt_cache`.
        unsafe { cache_free(&raw mut PDPT_CACHE, pdpbase.cast()) };
        l4i += 1;
    }
    // SAFETY: the L4 table came from `l4_cache`.
    unsafe { cache_free(&raw mut L4_CACHE, (*p).l4base.cast()) };

    // SAFETY: the map came from `pmap_cache`.
    unsafe { cache_free(&raw mut PMAP_CACHE, p.cast()) };
}

/// Takes a reference on the map.
///
/// # Safety
///
/// A non-null `p` must be a live pmap.
pub(crate) unsafe fn pmap_reference(p: Option<NonNull<Pmap>>) {
    let Some(p) = p else {
        return;
    };
    let p = p.as_ptr();
    let spl = raise_splvm();
    unsafe {
        (*p).lock.lock();
        (*p).ref_count = (*p).ref_count.wrapping_add(1);
        (*p).lock.unlock();
    }
    restore_spl(spl);
}

/// Drops a run of hardware entries, collecting their modify and reference bits
/// and unlinking them from their pv lists.
///
/// # Safety
///
/// `pmap` must be live and locked, and `spte` to `epte` a run of its page
/// table entries, as the C's callers guaranteed.
unsafe fn remove_range(
    pmap: *mut Pmap,
    mut va: VmOffset,
    spte: *mut VmOffset,
    epte: *mut VmOffset,
) {
    let count = (epte as usize - spte as usize) / size_of::<VmOffset>();
    let end = va.wrapping_add(count * PAGE_SIZE);
    if pmap == kernel_pmap_ptr()
        && (va < KERNEL_VIRTUAL_START.load(Ordering::Relaxed)
            || end > KERNEL_VIRTUAL_END.load(Ordering::Relaxed))
    {
        kpanic!(
            "pmap_remove_range",
            "pmap_remove_range({:x}-{:x}) falls in physical memory area!\n",
            va,
            end,
        );
    }

    let mut num_removed: c_int = 0;
    let mut num_unwired: c_int = 0;
    let mut cpte = spte;
    while cpte < epte {
        // SAFETY: `cpte` walks the run the caller passed.
        if unsafe { *cpte } == 0 {
            cpte = cpte.wrapping_add(PTES_PER_VM_PAGE);
            va = va.wrapping_add(PAGE_SIZE);
            continue;
        }

        // SAFETY: `cpte` walks the run the caller passed.
        let pa = pte_to_pa(unsafe { *cpte });
        num_removed += 1;
        if unsafe { *cpte } & INTEL_PTE_WIRED != 0 {
            num_unwired += 1;
        }

        if !valid_page(pa) {
            let mut i = PTES_PER_VM_PAGE;
            let mut lpte = cpte;
            loop {
                // SAFETY: the entries are this page's run.
                unsafe { *lpte = 0 };
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

        let pai = vm_page::table_index(pa);
        let pv = pv_lock(pai).lock();

        {
            let mut i = PTES_PER_VM_PAGE;
            let mut lpte = cpte;
            loop {
                // SAFETY: the attributes array has a byte per managed page,
                // and `pv` serializes this byte.
                unsafe {
                    let attr = phys_attribute(pai);
                    *attr |= (*lpte as u8) & (PHYS_MODIFIED | PHYS_REFERENCED);
                    *lpte = 0;
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

/// Unlink the pv-list entry for `va` from `pai`'s head, as the C's locked
/// walk did.
///
/// # Safety
///
/// The caller must hold the pmap lock and `pai`'s pv lock bit, and `pmap`
/// must be live.
unsafe fn unlink_pv(pmap: *mut Pmap, pai: usize, va: VmOffset) {
    // SAFETY: the pv list is locked by the caller's bit, and the C required
    // a non-empty head for a mapped page.
    unsafe {
        let pv_h = pv_head(pai);
        if (*pv_h).pmap.is_null() {
            kpanic!(
                "pmap_remove",
                "pmap_remove: null pv_list for pai {:x} at va {:x}!",
                pai,
                va,
            )
        }
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
                if cur.is_null() {
                    kpanic!(
                        "pmap_remove",
                        "pmap-remove: mapping not in pv_list!"
                    )
                }
                if (*cur).va == va && (*cur).pmap == pmap {
                    break;
                }
            }
            (*prev).next = (*cur).next;
            pv_free(cur);
        }
    }
}

/// Removes every mapping in a range.
///
/// # Safety
///
/// A non-null `map` must be a live pmap.
pub(crate) unsafe fn pmap_remove(
    map: Option<NonNull<Pmap>>,
    s: VmOffset,
    e: VmOffset,
) {
    let Some(map) = map else {
        return;
    };
    unsafe { remove(map, s, e) };
}

/// # Safety
///
/// As `pmap_remove`.
unsafe fn remove(map: NonNull<Pmap>, mut s: VmOffset, e: VmOffset) {
    let map = map.as_ptr();
    let start = s;

    let spl = unsafe { read_lock(map) };
    while s < e {
        // SAFETY: the map is live and locked.
        let pde = unsafe { pde_of(map, s) };
        let mut l = s.wrapping_add(PDE_MAPPED_SIZE) & !(PDE_MAPPED_SIZE - 1);
        if l > e || l < s {
            l = e;
        }
        // SAFETY: `pde` is the live directory entry `pde_of()` returned.
        if !pde.is_null() && unsafe { *pde } & INTEL_PTE_VALID != 0 {
            // SAFETY: the entry is valid and names a page table, as the C
            // relied on for its own pointer arithmetic.
            let mut spte = ptetokv(unsafe { *pde });
            spte = spte.wrapping_add(ptenum(s));
            let epte = spte.wrapping_add((l - s) >> PAGE_SHIFT);
            // SAFETY: the run is inside that page table, as the C computed.
            unsafe { remove_range(map, s, spte, epte) };
        }
        s = l;
    }
    // SAFETY: `map` is live and held as `read_lock()` left it.
    unsafe { update_tlbs(map, start, e) };
    // SAFETY: the map is live and was locked throughout.
    unsafe { read_unlock(map, spl) };
}

/// Lowers the permission of every mapping of a physical page.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, as the C's callers
/// guaranteed.
pub(crate) unsafe fn pmap_page_protect(phys: VmOffset, prot: c_int) {
    unsafe { page_protect(phys, prot) };
}

/// The `VM_PROT_READ|VM_PROT_EXECUTE` case of `pmap_page_protect()`.
const VM_PROT_READ_EXECUTE: c_int = VM_PROT_READ | VM_PROT_EXECUTE;
/// The `VM_PROT_READ|VM_PROT_WRITE` case of `pmap_protect()`.
const VM_PROT_READ_WRITE: c_int = VM_PROT_READ | VM_PROT_WRITE;

/// # Safety
///
/// As `pmap_page_protect`.
unsafe fn page_protect(phys: VmOffset, prot: c_int) {
    if !valid_page(phys) {
        return;
    }

    let remove = match prot {
        VM_PROT_READ | VM_PROT_READ_EXECUTE => false,
        VM_PROT_ALL => return,
        _ => true,
    };

    let spl = write_lock();
    let pai = vm_page::table_index(phys);
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
                if unsafe { *pte } & INTEL_PTE_WIRED != 0 {
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
                        *attr |=
                            (*p as u8) & (PHYS_MODIFIED | PHYS_REFERENCED);
                        *p = 0;
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
                    unsafe { *p &= !INTEL_PTE_WRITE };
                    p = p.wrapping_add(1);
                    i -= 1;
                    if i == 0 {
                        break;
                    }
                }
                prev = pv_e;
            }

            // SAFETY: the map is live and locked.
            unsafe { update_tlbs(pmap, va, va.wrapping_add(PAGE_SIZE)) };
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

    write_unlock(spl);
}

/// Lowers permissions over a range.
///
/// # Safety
///
/// A non-null `map` must be a live pmap.
pub(crate) unsafe fn pmap_protect(
    map: Option<NonNull<Pmap>>,
    s: VmOffset,
    e: VmOffset,
    prot: c_int,
) {
    let Some(map) = map else {
        return;
    };
    unsafe { protect(map, s, e, prot) };
}

/// # Safety
///
/// As `pmap_protect`.
unsafe fn protect(
    map: NonNull<Pmap>,
    mut s: VmOffset,
    e: VmOffset,
    prot: c_int,
) {
    let live_map = map;
    let map = map.as_ptr();

    match prot {
        VM_PROT_READ | VM_PROT_READ_EXECUTE => (),
        VM_PROT_READ_WRITE | VM_PROT_ALL => return,
        _ => {
            unsafe { remove(live_map, s, e) };
            return;
        }
    }

    let start = s;
    // The C's non-i486 fallback, which removes kernel mappings because the
    // i386 ignores the write bit in kernel mode, is not compiled here.
    let spl = raise_splvm();
    unsafe { (*map).lock.lock() };

    while s < e {
        // SAFETY: the map is live and locked.
        let pde = unsafe { pde_of(map, s) };
        let mut l = s.wrapping_add(PDE_MAPPED_SIZE) & !(PDE_MAPPED_SIZE - 1);
        if l > e || l < s {
            l = e;
        }
        // SAFETY: `pde` is the live directory entry `pde_of()` returned.
        if !pde.is_null() && unsafe { *pde } & INTEL_PTE_VALID != 0 {
            // SAFETY: the entry is valid and names a page table.
            let mut spte = ptetokv(unsafe { *pde });
            spte = spte.wrapping_add(ptenum(s));
            let epte = spte.wrapping_add((l - s) >> PAGE_SHIFT);
            while spte < epte {
                // SAFETY: `spte` walks the page table.
                if unsafe { *spte } & INTEL_PTE_VALID != 0 {
                    unsafe { *spte &= !INTEL_PTE_WRITE };
                }
                spte = spte.wrapping_add(1);
            }
        }
        s = l;
    }
    // SAFETY: the map is live and locked.
    unsafe { update_tlbs(map, start, e) };

    // SAFETY: the map is live and locked.
    unsafe { (*map).lock.unlock() };
    restore_spl(spl);
}

/// The page-table-level getter [`expand_level`] calls: one of [`l4base_of()`],
/// [`ptp_of()`], [`pde_of()`], or [`pte_of()`].
///
/// # Safety
///
/// Calling through a value of this type requires the same as calling the
/// function it names directly: the `*mut Pmap` argument must be a live
/// physical map.
type LevelGetter = unsafe fn(*mut Pmap, VmOffset) -> *mut VmOffset;

/// Allocates one level of the page-table tree, unlocking the pmap around the
/// allocation.
///
/// # Safety
///
/// `pmap` must be live and locked at `spl`, and `cache` initialized.
unsafe fn expand_level(
    pmap: *mut Pmap,
    v: VmOffset,
    spl: c_int,
    level: LevelGetter,
    upper: LevelGetter,
    n_per_vm_page: c_int,
    cache: *mut KmemCache,
) -> *mut VmOffset {
    loop {
        let pte = unsafe { level(pmap, v) };
        if !pte.is_null() {
            return pte;
        }

        if pmap == kernel_pmap_ptr() {
            kpanic!(
                "pmap_expand_level",
                "pmap_expand kernel pmap to 0x{:x}",
                v
            )
        }

        unsafe { read_unlock(pmap, spl) };
        let ptp = loop {
            let ptp = unsafe { cache_alloc(cache) };
            if !ptp.is_null() {
                break ptp;
            }
            unsafe { vm_page::wait(None) };
        };
        // SAFETY: the cache returned one `PAGE_SIZE` object for a table.
        unsafe { ptr::write_bytes(ptp, 0, PAGE_SIZE) };

        let spl = unsafe { read_lock(pmap) };
        // SAFETY: the lock was taken above, and the map is live.
        if !unsafe { level(pmap, v) }.is_null() {
            // SAFETY: the lock was taken above.
            unsafe { read_unlock(pmap, spl) };
            // SAFETY: the fresh table is the one `cache_alloc()` returned.
            unsafe { cache_free(cache, ptp) };
            let _spl = unsafe { read_lock(pmap) };
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
                    | INTEL_PTE_VALID
                    | if pmap == kernel_pmap_ptr() {
                        0
                    } else {
                        INTEL_PTE_USER
                    }
                    | INTEL_PTE_WRITE;
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
unsafe fn expand(pmap: *mut Pmap, v: VmOffset, spl: c_int) -> *mut VmOffset {
    unsafe {
        expand_level(pmap, v, spl, ptp_of, l4base_of, 1, &raw mut PDPT_CACHE);
        expand_level(pmap, v, spl, pde_of, ptp_of, 1, &raw mut PD_CACHE);
        expand_level(
            pmap,
            v,
            spl,
            pte_of,
            pde_of,
            PTES_PER_VM_PAGE as c_int,
            &raw mut PT_CACHE,
        )
    }
}

/// The CPU type the machine probe recorded for the running CPU.
fn cpu_type() -> c_int {
    // SAFETY: `cpu_id()` names this CPU's slot, one the probe filled
    // before any pmap call.
    unsafe { (*machine_slot(cpu_id())).cpu_type }
}

/// The entry template `pmap_enter()` builds.
fn enter_template(
    pmap: *mut Pmap,
    pa: VmOffset,
    prot: c_int,
    wired: bool,
    is_physmem: bool,
) -> VmOffset {
    let mut template = pa_to_pte(pa) | INTEL_PTE_VALID;
    if pmap != kernel_pmap_ptr() {
        template |= INTEL_PTE_USER;
    }
    if prot & VM_PROT_WRITE != 0 {
        template |= INTEL_PTE_WRITE;
    }
    if cpu_type() >= CPU_TYPE_I486 && !is_physmem {
        template |= INTEL_PTE_NCACHE | INTEL_PTE_WTHRU;
    }
    if wired {
        template |= INTEL_PTE_WIRED;
    }
    template
}

/// Inserts one mapping.
///
/// # Safety
///
/// A non-null `pmap` must be a live pmap, and `pa` a physical address the
/// kernel may map, as the C's callers guaranteed.
pub(crate) unsafe fn pmap_enter(
    pmap: Option<NonNull<Pmap>>,
    v: VmOffset,
    pa: VmOffset,
    prot: c_int,
    wired: c_int,
) {
    let Some(pmap) = pmap else {
        return;
    };
    unsafe { enter(pmap, v, pa, prot, wired != 0) };
}

/// # Safety
///
/// As `pmap_enter`.
unsafe fn enter(
    pmap: NonNull<Pmap>,
    v: VmOffset,
    pa: VmOffset,
    prot: c_int,
    wired: bool,
) {
    let pmap = pmap.as_ptr();
    if PMAP_DEBUG.load(Ordering::Relaxed) != 0 {
        kprint!("pmap({:x}, {:x})\n", v, pa);
    }

    if pmap == kernel_pmap_ptr()
        && (v < KERNEL_VIRTUAL_START.load(Ordering::Relaxed)
            || v >= KERNEL_VIRTUAL_END.load(Ordering::Relaxed))
    {
        kpanic!(
            "pmap_enter",
            "pmap_enter({:x}, {:x}) falls in physical memory area!\n",
            v,
            pa,
        );
    }

    let mut pv_e: *mut PvEntry = ptr::null_mut();
    loop {
        let spl = unsafe { read_lock(pmap) };
        // SAFETY: the map is live and locked.
        let mut pte = unsafe { expand(pmap, v, spl) };

        let is_physmem = if vm_page::is_ready() {
            vm_page::lookup_pa(pa).is_some()
        } else {
            pa < biosmem::directmap_end()
        };

        // SAFETY: `pte` is the live entry for `v` in the locked map.
        let old_pa = pte_to_pa(unsafe { *pte });
        if unsafe { *pte } != 0 && old_pa == pa {
            // SAFETY: `pte` is the live entry for `v` in the locked map.
            if wired && unsafe { *pte } & INTEL_PTE_WIRED == 0 {
                // SAFETY: the map is live and locked.
                unsafe { (*pmap).stats.wired_count += 1 };
            // SAFETY: `pte` is the live entry for `v` in the locked map.
            } else if !wired && unsafe { *pte } & INTEL_PTE_WIRED != 0 {
                // SAFETY: the map is live and locked.
                unsafe { (*pmap).stats.wired_count -= 1 };
            }

            let mut template =
                enter_template(pmap, pa, prot, wired, is_physmem);
            let mut i = PTES_PER_VM_PAGE;
            loop {
                // SAFETY: `pte` walks the entry run of the locked map.
                if unsafe { *pte } & INTEL_PTE_MOD != 0 {
                    template |= INTEL_PTE_MOD;
                }
                // SAFETY: `pte` walks the page's run.
                unsafe { *pte = template };
                pte = pte.wrapping_add(1);
                template = template.wrapping_add(PAGE_SIZE);
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            // SAFETY: the map is live and locked.
            unsafe { update_tlbs(pmap, v, v.wrapping_add(PAGE_SIZE)) };
        } else {
            // SAFETY: `pte` is the live entry for `v` in the locked map.
            if unsafe { *pte } != 0 {
                // SAFETY: `pte` names the entry run to replace.
                unsafe {
                    remove_range(
                        pmap,
                        v,
                        pte,
                        pte.wrapping_add(PTES_PER_VM_PAGE),
                    );
                };
                // SAFETY: the map is live and locked.
                unsafe { update_tlbs(pmap, v, v.wrapping_add(PAGE_SIZE)) };
            }

            if valid_page(pa) {
                // SAFETY: the map is live and locked, and `pa` is a managed
                // page.
                if unsafe { link_pv(pmap, v, pa, &mut pv_e, spl) }.is_err() {
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
                enter_template(pmap, pa, prot, wired, is_physmem);
            let mut i = PTES_PER_VM_PAGE;
            loop {
                // SAFETY: `pte` walks the page's run.
                unsafe { *pte = template };
                pte = pte.wrapping_add(1);
                template = template.wrapping_add(PAGE_SIZE);
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
        unsafe { read_unlock(pmap, spl) };
        break;
    }
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
unsafe fn link_pv(
    pmap: *mut Pmap,
    v: VmOffset,
    pa: VmOffset,
    pv_e: &mut *mut PvEntry,
    spl: c_int,
) -> Result<(), ()> {
    let pai = vm_page::table_index(pa);
    let pv = pv_lock(pai).lock();
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
                unsafe { read_unlock(pmap, spl) };
                // SAFETY: the C refilled from the slab cache while unlocked.
                *pv_e = unsafe {
                    cache_alloc(&raw mut PV_LIST_CACHE).cast::<PvEntry>()
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

/// Sets the wired bit on an existing mapping.
///
/// # Safety
///
/// `map` must be live and hold a mapping at `v`, as the C's callers
/// guaranteed.
pub(crate) unsafe fn pmap_change_wiring(
    map: *mut Pmap,
    v: VmOffset,
    wired: c_int,
) {
    unsafe { change_wiring(map, v, wired != 0) };
}

/// # Safety
///
/// As `pmap_change_wiring`.
unsafe fn change_wiring(map: *mut Pmap, v: VmOffset, wired: bool) {
    let spl = unsafe { read_lock(map) };
    // SAFETY: the map is live and locked.
    let pte = unsafe { pte_of(map, v) };
    if pte.is_null() {
        kpanic!("pmap_change_wiring", "pmap_change_wiring: pte missing");
    }

    // SAFETY: `pte` is the live entry for `v` in the locked map.
    if wired && unsafe { *pte } & INTEL_PTE_WIRED == 0 {
        // SAFETY: the map is live and locked.
        unsafe { (*map).stats.wired_count += 1 };
        let mut i = PTES_PER_VM_PAGE;
        let mut p = pte;
        loop {
            // SAFETY: `p` walks the page's run.
            unsafe { *p |= INTEL_PTE_WIRED };
            p = p.wrapping_add(1);
            i -= 1;
            if i == 0 {
                break;
            }
        }
    // SAFETY: `pte` is the live entry for `v` in the locked map.
    } else if !wired && unsafe { *pte } & INTEL_PTE_WIRED != 0 {
        // SAFETY: the map is live and locked.
        unsafe { (*map).stats.wired_count -= 1 };
        let mut i = PTES_PER_VM_PAGE;
        let mut p = pte;
        loop {
            // SAFETY: `p` walks the page's run.
            unsafe { *p &= !INTEL_PTE_WIRED };
            p = p.wrapping_add(1);
            i -= 1;
            if i == 0 {
                break;
            }
        }
    }

    // SAFETY: the map is live and was locked throughout.
    unsafe { read_unlock(map, spl) };
}

/// The physical address a mapping holds, or zero.
///
/// # Safety
///
/// `pmap` must be a live pmap, as the C's callers guaranteed.
pub(crate) unsafe fn pmap_extract(pmap: *mut Pmap, va: VmOffset) -> VmOffset {
    unsafe { extract(pmap, va) }
}

/// # Safety
///
/// As `pmap_extract`.
unsafe fn extract(pmap: *mut Pmap, va: VmOffset) -> VmOffset {
    let spl = raise_splvm();
    unsafe { (*pmap).lock.lock() };
    // SAFETY: the map is live and locked.
    let pte = unsafe { pte_of(pmap, va) };
    let pa = if pte.is_null()
        // SAFETY: `pte` is the live entry for `va`.
        || unsafe { *pte } & INTEL_PTE_VALID == 0
    {
        0
    } else {
        pte_to_pa(unsafe { *pte }) + (va & INTEL_OFFMASK)
    };
    // SAFETY: the map lock was taken above.
    unsafe { (*pmap).lock.unlock() };
    restore_spl(spl);
    pa
}

/// Frees the user page tables of a map whose pages are scarce.
///
/// # Safety
///
/// A non-null `p` must be a live user pmap.
pub(crate) unsafe fn pmap_collect(p: Option<NonNull<Pmap>>) {
    let Some(p) = p else {
        return;
    };
    unsafe { collect(p) };
}

/// # Safety
///
/// As `pmap_collect`.
unsafe fn collect(p: NonNull<Pmap>) {
    let p = p.as_ptr();
    if p == kernel_pmap_ptr() {
        return;
    }

    let mut spl = unsafe { read_lock(p) };

    let mut l4i = 0;
    while l4i < lin2l4num(VM_MAX_USER_ADDRESS) {
        // SAFETY: the map holds its L4 table while it exists.
        let pdp = unsafe { *(*p).l4base.wrapping_add(l4i) };
        if pdp & INTEL_PTE_VALID == 0 {
            l4i += 1;
            continue;
        }
        let pdpbase = ptetokv(pdp);
        let mut l3i = 0;
        while l3i < NPTES {
            // SAFETY: `pdpbase` is the table the entry names.
            let pde = unsafe { *pdpbase.wrapping_add(l3i) };
            if pde & INTEL_PTE_VALID == 0 {
                l3i += 1;
                continue;
            }
            let pdirbase = ptetokv(pde);
            let mut l2i = 0;
            while l2i < NPTES {
                // SAFETY: `pdirbase` is the directory the entry names.
                let pte = unsafe { *pdirbase.wrapping_add(l2i) };
                if pte & INTEL_PTE_VALID == 0 {
                    l2i += 1;
                    continue;
                }
                let ptp = with_exposed_provenance_mut::<VmOffset>(phystokv(
                    pte_to_pa(pte),
                ));
                let eptp = ptp.wrapping_add(NPTES * PTES_PER_VM_PAGE);

                let mut wired = false;
                let mut pt_entry = ptp;
                while pt_entry < eptp {
                    // SAFETY: `pt_entry` walks the page table.
                    if unsafe { *pt_entry } & INTEL_PTE_WIRED != 0 {
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
                    unsafe { remove_range(p, va, ptp, eptp) };

                    let mut i = PTES_PER_VM_PAGE;
                    let mut pdir_entry = pdirbase.wrapping_add(l2i);
                    loop {
                        // SAFETY: `pdir_entry` walks the directory's run.
                        unsafe { *pdir_entry = 0 };
                        pdir_entry = pdir_entry.wrapping_add(1);
                        i -= 1;
                        if i == 0 {
                            break;
                        }
                    }

                    // SAFETY: the lock was taken above.
                    unsafe { read_unlock(p, spl) };
                    // SAFETY: the table was unlinked and has no holder.
                    unsafe {
                        cache_free(&raw mut PT_CACHE, ptetokv(pte).cast());
                    };
                    spl = unsafe { read_lock(p) };
                }
                l2i += 1;
            }
            l3i += 1;
        }
        l4i += 1;
    }

    // SAFETY: the map is live and locked.
    unsafe { update_tlbs(p, VM_MIN_USER_ADDRESS, VM_MAX_USER_ADDRESS) };
    // SAFETY: the map lock was taken above.
    unsafe { read_unlock(p, spl) };
}

/// Clears modify or reference bits on every mapping of a page.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, and `bits` the C
/// caller's attribute mask.
unsafe fn attribute_clear(phys: VmOffset, bits: c_int) {
    if !valid_page(phys) {
        return;
    }

    let spl = write_lock();
    let pai = vm_page::table_index(phys);
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
                unsafe { *pte &= !(bits as VmOffset) };
            }

            // SAFETY: the map is live and locked.
            unsafe { update_tlbs(pmap, va, va.wrapping_add(PAGE_SIZE)) };
            // SAFETY: the map is live and locked.
            unsafe { (*pmap).lock.unlock() };

            // SAFETY: the list link is kept under the system write lock.
            pv_e = unsafe { (*pv_e).next };
        }
    }

    // SAFETY: the attribute byte is serialized by the system write lock.
    unsafe { *phys_attribute(pai) &= !(bits as u8) };

    write_unlock(spl);
}

/// Whether any mapping of a page has the bits set.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, and `bits` the C
/// caller's attribute mask.
unsafe fn attribute_test(phys: VmOffset, bits: c_int) -> bool {
    if !valid_page(phys) {
        return false;
    }

    let spl = write_lock();
    let pai = vm_page::table_index(phys);
    let pv_h = pv_head(pai);

    // SAFETY: the attribute byte is serialized by the system write lock.
    if c_int::from(unsafe { *phys_attribute(pai) }) & bits != 0 {
        write_unlock(spl);
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
                if unsafe { *pte } & (bits as VmOffset) != 0 {
                    // SAFETY: the map is live and locked.
                    unsafe { (*pmap).lock.unlock() };
                    write_unlock(spl);
                    return true;
                }
            }

            // SAFETY: the map is live and locked.
            unsafe { (*pmap).lock.unlock() };

            // SAFETY: the list link is kept under the system write lock.
            pv_e = unsafe { (*pv_e).next };
        }
    }

    write_unlock(spl);
    false
}

/// Clears the modify bits of a page.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, as the C's callers
/// guaranteed.
pub(crate) unsafe fn pmap_clear_modify(phys: VmOffset) {
    unsafe { attribute_clear(phys, c_int::from(PHYS_MODIFIED)) };
}

/// Whether a page was modified.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, as the C's callers
/// guaranteed.
pub(crate) unsafe fn pmap_is_modified(phys: VmOffset) -> bool {
    unsafe { attribute_test(phys, c_int::from(PHYS_MODIFIED)) }
}

/// Clears the reference bits of a page.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, as the C's callers
/// guaranteed.
pub(crate) unsafe fn pmap_clear_reference(phys: VmOffset) {
    unsafe { attribute_clear(phys, c_int::from(PHYS_REFERENCED)) };
}

/// Whether a page was referenced.
///
/// # Safety
///
/// `phys` must be a physical address the kernel may map, as the C's callers
/// guaranteed.
pub(crate) unsafe fn pmap_is_referenced(phys: VmOffset) -> bool {
    unsafe { attribute_test(phys, c_int::from(PHYS_REFERENCED)) }
}

/// The one-based index of the lowest set bit, or zero.
const fn ffs(value: isize) -> u32 {
    if value == 0 {
        0
    } else {
        value.trailing_zeros() + 1
    }
}

/// The update list of one CPU.
fn update_list(cpu: c_int) -> *mut PmapUpdateList {
    // SAFETY: taking the address of the array element does not read it, and
    // CPU numbers are below MAX_NCPUS.
    unsafe { &raw mut CPU_UPDATE_LIST[cpu as usize] }
}

/// Queues an invalidation for every CPU in `use_list` and interrupts the ones
/// that are awake.
///
/// # Safety
///
/// `pmap` must be a live, locked map and the range one it was changed in, as
/// [`update_tlbs`] requires.
pub(crate) unsafe fn signal_cpus(
    use_list: isize,
    pmap: *mut Pmap,
    start: VmOffset,
    end: VmOffset,
) {
    let mut use_list = use_list;
    loop {
        let which = ffs(use_list);
        if which == 0 {
            break;
        }
        let which_cpu = (which - 1) as c_int;
        let update_list_p = update_list(which_cpu);

        // SAFETY: each update list has its own lock, live from `pmap_init()`.
        unsafe { (*update_list_p).lock.lock() };
        // SAFETY: the lock above serializes the list.
        let j = unsafe { (*update_list_p).count };
        if j >= UPDATE_LIST_SIZE as c_int {
            // SAFETY: the last entry becomes the whole-space flush, as the
            // C made it.
            unsafe {
                (*update_list_p).item[UPDATE_LIST_SIZE - 1].pmap =
                    kernel_pmap_ptr();
                (*update_list_p).item[UPDATE_LIST_SIZE - 1].start =
                    VM_MIN_USER_ADDRESS;
                (*update_list_p).item[UPDATE_LIST_SIZE - 1].end =
                    VM_MAX_KERNEL_ADDRESS;
            }
        } else {
            // SAFETY: `j` is below the list's capacity.
            unsafe {
                (*update_list_p).item[j as usize].pmap = pmap;
                (*update_list_p).item[j as usize].start = start;
                (*update_list_p).item[j as usize].end = end;
                (*update_list_p).count = j + 1;
            }
        }
        // SAFETY: the target CPU publishes the request with the same store.
        CPU_UPDATE_NEEDED[which_cpu as usize].store(1, Ordering::Relaxed);
        // SAFETY: the update list lock was taken above.
        unsafe { (*update_list_p).lock.unlock() };

        fence(Ordering::SeqCst);
        if CPUS_IDLE.bits() & CpuSet::mask(which_cpu) == 0 {
            // SAFETY: a map's `cpus_using` holds only the bits of running
            // CPUs' `cpu_id()`, each below `MAX_NCPUS`.
            interrupt_processor(unsafe { CpuId::from_c_int(which_cpu) });
        }
        use_list &= !CpuSet::mask(which_cpu);
    }
}

/// Flushes the calling CPU's queued invalidations.
///
/// # Safety
///
/// Must be called at `splvm`, with the caller's pmap live if it is not the
/// kernel map.
pub(crate) unsafe fn process_pmap_updates(my_pmap: *mut Pmap) {
    // The C `pmap` routines take the CPU number as an `int`.
    let my_cpu = cpu_id().bits() as c_int;
    let update_list_p = update_list(my_cpu);

    // SAFETY: each update list has its own lock.
    unsafe { (*update_list_p).lock.lock() };
    let mut j = 0;
    // SAFETY: the lock above serializes the list.
    while j < unsafe { (*update_list_p).count } {
        // SAFETY: the list is locked, and `j` is below its count.
        let pmap = unsafe { (*update_list_p).item[j as usize].pmap };
        if pmap == my_pmap || pmap == kernel_pmap_ptr() {
            // SAFETY: the list is locked and `j` is a live entry.
            let start = unsafe { (*update_list_p).item[j as usize].start };
            let end = unsafe { (*update_list_p).item[j as usize].end };
            // SAFETY: the queued range belongs to `pmap`, which the queueing
            // CPU held locked.
            unsafe { invalidate_tlb(pmap, start, end) };
        }
        j += 1;
    }
    // SAFETY: the lock above serializes the list.
    unsafe {
        (*update_list_p).count = 0;
    }
    CPU_UPDATE_NEEDED[my_cpu as usize].store(0, Ordering::Relaxed);
    // SAFETY: the update list lock was taken above.
    unsafe { (*update_list_p).lock.unlock() };
}

/// The pmap `thread` runs in.
///
/// # Safety
///
/// `thread` must be a live thread whose task has a map, as the C's interrupt
/// path ensured before calling.
unsafe fn current_pmap(thread: *mut Thread) -> *mut Pmap {
    unsafe {
        let task = (*thread).task;
        let map = (*task).map.cast::<VmMap>();
        (*map).pmap
    }
}

/// The interprocessor handler that flushes this CPU's TLB for another.
pub(crate) extern "C" fn pmap_update_interrupt() {
    // The C `pmap` routines take the CPU number as an `int`.
    let my_cpu = cpu_id().bits() as c_int;

    if CPUS_IDLE.bits() & CpuSet::mask(my_cpu) != 0 {
        return;
    }

    let thread = per_cpu::thread();
    let mut my_pmap = kernel_pmap_ptr();
    if !thread.is_null() {
        // SAFETY: the running thread is live, and `current_pmap()` follows
        // its task's map.
        my_pmap = unsafe { current_pmap(thread) };
        // SAFETY: the pmap came from a live map, and the interrupt runs at
        // `SPLIP` so the field cannot change under it.
        if !unsafe { (*my_pmap).cpus_using.contains(my_cpu) } {
            my_pmap = kernel_pmap_ptr();
        }
    }

    // SAFETY: raising to `splvm` has no precondition.
    let s = unsafe { spl::splvm() };
    loop {
        CPUS_ACTIVE.clear(my_cpu);
        // SAFETY: both maps are the kernel's and a live user map; the spin
        // is the C's, waiting for updates in progress.
        while unsafe {
            (*my_pmap).lock.is_locked()
                || (*kernel_pmap_ptr()).lock.is_locked()
        } {
            core::hint::spin_loop();
        }
        // SAFETY: this runs at `splvm` with the interrupt blocked.
        unsafe { process_pmap_updates(my_pmap) };
        CPUS_ACTIVE.set(my_cpu);
        if CPU_UPDATE_NEEDED[my_cpu as usize].load(Ordering::Relaxed) == 0 {
            break;
        }
    }
    // SAFETY: `s` came from `splvm()`.
    unsafe { spl::splx(s) };
}

/// Does nothing, because the initial and linear kernel bases coincide and no
/// temporary mapping is needed.
pub(crate) const fn pmap_make_temporary_mapping() {}

/// Loads the kernel's page tables into CR3 and turns on the paging features
/// they need.
pub(crate) fn pmap_set_page_dir() {
    // SAFETY: the kernel map holds its L4 table from `pmap_bootstrap()`.
    let physical =
        kvtophys_early(unsafe { (*kernel_pmap_ptr()).l4base }.addr());
    write_cr3(physical);
    if !cpu_has_feature(CPU_FEATURE_PAE) {
        kpanic!("pmap_set_page_dir", "CPU doesn't have support for PAE.");
    }
    write_cr4(read_cr4() | CR4_PAE);
}

/// Flushes the TLB; there is no temporary low mapping to drop here.
pub(crate) fn pmap_remove_temporary_mapping() {
    flush_tlb();
}
