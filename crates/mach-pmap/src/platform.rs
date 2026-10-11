// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the physical map asks of the kernel.

use crate::pmap::Pmap;
use crate::state::PmapState;
use crate::types::PmapCache;
use core::ffi::c_int;
use core::fmt;
use core::ptr::NonNull;
use mach_page::param::{VmOffset, VmSize};
use mach_page::smp::CpuId;

/// The kernel services the physical map needs.
///
/// The kernel implements it on the same zero-sized type as the other
/// platforms. The pmap sits below VM and the scheduler, so what it needs of
/// them crosses here: the running CPU and thread, the pmap the running
/// thread uses, the sleep and wakeup its lock may take, the wait for a free
/// page, spl, the machine, the allocators its records come from, and
/// printing.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform: Sized + 'static {
    /// The lock platform of the pv-list spin locks.
    type Lock: lock::Platform;

    /// The physical map's state that names the platform.
    fn pmap_state() -> &'static PmapState<Self>;

    /// The CPU the caller runs on.
    fn current_cpu() -> CpuId;

    /// The pmap of the running thread's task, or `None` with no thread.
    ///
    /// # Safety
    ///
    /// The running thread's task must have a map, as it does whenever a
    /// shootdown interrupt can reach it.
    unsafe fn current_pmap() -> Option<NonNull<Pmap>>;

    /// The CPU type the machine probe recorded for the running CPU.
    fn cpu_type() -> c_int;

    /// Raises the interrupt level to `splvm`, returning the level to restore
    /// with [`Self::splx`].
    ///
    /// # Safety
    ///
    /// The caller hands the returned level back to `splx`.
    unsafe fn splvm() -> c_int;

    /// Restores the interrupt level `s`.
    ///
    /// # Safety
    ///
    /// `s` must be a level an spl call returned.
    unsafe fn splx(s: c_int);

    /// Blocks until a free page may be available.
    ///
    /// # Safety
    ///
    /// The caller holds no page lock and may block.
    unsafe fn wait_for_page();

    /// Interrupts `cpu` so it runs its queued TLB invalidations.
    fn interrupt_processor(cpu: CpuId);

    /// Takes `size` bytes of page-aligned physical memory from the boot
    /// allocator, or `None` when it is empty.
    fn boot_alloc(size: VmSize) -> Option<VmOffset>;

    /// Sets up `cache` for records of `size` bytes aligned to `align`,
    /// reported as `name`, from directly mapped memory when `physmem`.
    ///
    /// # Safety
    ///
    /// Once per cache, before its first allocation.
    unsafe fn pmap_cache_init(
        cache: PmapCache,
        name: &'static [u8],
        size: usize,
        align: usize,
        physmem: bool,
    );

    /// Allocates a record from `cache`, or `None` when memory is short.
    ///
    /// # Safety
    ///
    /// [`Self::pmap_cache_init`] must have set `cache` up.
    unsafe fn pmap_cache_alloc(cache: PmapCache) -> Option<NonNull<u8>>;

    /// Returns a record to `cache`.
    ///
    /// # Safety
    ///
    /// `record` must have come from `cache` and not be used again.
    unsafe fn pmap_cache_free(cache: PmapCache, record: NonNull<u8>);

    /// Writes `args` to the console.
    fn print(args: fmt::Arguments<'_>);
}
