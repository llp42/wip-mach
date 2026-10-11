// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`Fake`] as VM's platform: heap caches, boxed pmaps, `kalloc` over the
//! global allocator and per-thread pmap counts; every function no test
//! reaches panics with its name.

use crate::fake::Fake;
use crate::host::Host;
use crate::types::{FakePmap, PmapCounts};
use core::cell::Cell;
use core::ffi::{CStr, c_int, c_uint, c_void};
use core::fmt;
use core::ptr::{self, NonNull};
use mach_vm::error::Error;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::platform::{
    CacheFlags, Continuation, Platform, Port, TaskEvent, UserFault, VmCache,
};
use mach_vm::state::VmState;
use mach_vm::types::VmProt;
use mach_vm::vm_map::VmMap;
use std::alloc::{self, Layout};

/// The kernel pmap the fake reports.
static KERNEL_PMAP: FakePmap = FakePmap;

/// VM's state for the tests.
static STATE: VmState<Fake> = VmState::new();

/// The layout of every fake cache record, roomy enough for the largest.
const RECORD: Layout = match Layout::from_size_align(1024, 64) {
    Ok(layout) => layout,
    Err(_) => panic!("the fake record layout is invalid"),
};

/// The alignment of a fake `kalloc` buffer, the kernel's minimum.
const KALLOC_ALIGN: usize = 8;

std::thread_local! {
    /// The running thread's pmap counts.
    pub static PMAPS: PmapCounts = const {
        PmapCounts { created: Cell::new(0), destroyed: Cell::new(0) }
    };
}

// SAFETY: the implemented functions keep the trait's contracts on the heap
// and in per-thread counters; the rest panic before doing anything.
unsafe impl Platform for Fake {
    type Lock = Host;
    type Pmap = FakePmap;
    type SendError = ();

    const CLOCK_HZ: c_int = 100;
    const DMA_LIMIT: VmOffset = 0x0100_0000;
    const DMA32_LIMIT: VmOffset = 0x1_0000_0000;
    const DIRECTMAP_LIMIT: VmOffset = 0x4000_0000;
    const SEND_INTERRUPTED: () = ();

    fn state() -> &'static VmState<Self> {
        &STATE
    }

    fn kernel_pmap() -> *mut FakePmap {
        ptr::from_ref(&KERNEL_PMAP).cast_mut()
    }

    unsafe fn pmap_create(_size: VmSize) -> *mut FakePmap {
        PMAPS.with(|pmaps| pmaps.created.set(pmaps.created.get() + 1));
        Box::into_raw(Box::new(FakePmap))
    }

    unsafe fn pmap_destroy(pmap: Option<NonNull<FakePmap>>) {
        if let Some(pmap) = pmap {
            PMAPS.with(|pmaps| pmaps.destroyed.set(pmaps.destroyed.get() + 1));
            // SAFETY: the map hands back the pmap `pmap_create` boxed.
            drop(unsafe { Box::from_raw(pmap.as_ptr()) });
        }
    }

    unsafe fn pmap_reference(_pmap: Option<NonNull<FakePmap>>) {
        unimplemented!("pmap_reference")
    }

    unsafe fn pmap_remove(
        _pmap: Option<NonNull<FakePmap>>,
        _start: VmOffset,
        _end: VmOffset,
    ) {
    }

    fn pmap_page_protect(_phys: VmOffset, _prot: VmProt) {
        unimplemented!("pmap_page_protect")
    }

    unsafe fn pmap_protect(
        _pmap: Option<NonNull<FakePmap>>,
        _start: VmOffset,
        _end: VmOffset,
        _prot: VmProt,
    ) {
        unimplemented!("pmap_protect")
    }

    unsafe fn pmap_enter(
        _pmap: Option<NonNull<FakePmap>>,
        _va: VmOffset,
        _pa: VmOffset,
        _prot: VmProt,
        _wired: c_int,
    ) {
        unimplemented!("pmap_enter")
    }

    unsafe fn pmap_change_wiring(
        _pmap: *mut FakePmap,
        _va: VmOffset,
        _wired: c_int,
    ) {
        unimplemented!("pmap_change_wiring")
    }

    unsafe fn pmap_extract(_pmap: *mut FakePmap, _va: VmOffset) -> VmOffset {
        unimplemented!("pmap_extract")
    }

    fn pmap_clear_modify(_phys: VmOffset) {
        unimplemented!("pmap_clear_modify")
    }

    fn pmap_is_modified(_phys: VmOffset) -> bool {
        unimplemented!("pmap_is_modified")
    }

    fn pmap_clear_reference(_phys: VmOffset) {
        unimplemented!("pmap_clear_reference")
    }

    fn pmap_is_referenced(_phys: VmOffset) -> bool {
        unimplemented!("pmap_is_referenced")
    }

    fn pmap_pageable(
        _pmap: *mut FakePmap,
        _start: VmOffset,
        _end: VmOffset,
        _pageable: c_int,
    ) {
        unimplemented!("pmap_pageable")
    }

    unsafe fn pmap_map_bd(
        _virt: VmOffset,
        _start: VmOffset,
        _end: VmOffset,
        _prot: VmProt,
    ) -> VmOffset {
        unimplemented!("pmap_map_bd")
    }

    unsafe fn pmap_unmap_bd(_virt: VmOffset, _end: VmOffset) {
        unimplemented!("pmap_unmap_bd")
    }

    fn pmap_virtual_space() -> (VmOffset, VmOffset) {
        unimplemented!("pmap_virtual_space")
    }

    fn pmap_init() {
        unimplemented!("pmap_init")
    }

    unsafe fn pmap_resident_count(_pmap: *mut Self::Pmap) -> c_int {
        unimplemented!("pmap_resident_count")
    }

    fn kernel_virtual_start() -> VmOffset {
        unimplemented!("kernel_virtual_start")
    }

    fn kernel_virtual_end() -> VmOffset {
        unimplemented!("kernel_virtual_end")
    }

    unsafe fn zero_page(_pa: VmOffset) {
        unimplemented!("zero_page")
    }

    unsafe fn copy_page(_src: VmOffset, _dst: VmOffset) {
        unimplemented!("copy_page")
    }

    unsafe fn assert_wait(
        _event: Option<NonNull<c_void>>,
        _interruptible: c_int,
    ) {
        unimplemented!("assert_wait")
    }

    unsafe fn thread_block(_continuation: Continuation) {
        unimplemented!("thread_block")
    }

    fn thread_wakeup_prim(
        _event: *mut c_void,
        _one_thread: c_int,
        _result: c_int,
    ) -> bool {
        unimplemented!("thread_wakeup_prim")
    }

    unsafe fn thread_set_timeout(_ticks: c_int) {
        unimplemented!("thread_set_timeout")
    }

    unsafe fn clear_wait(_result: c_int, _interrupt_only: c_int) {
        unimplemented!("clear_wait")
    }

    unsafe fn wait_result() -> c_int {
        unimplemented!("wait_result")
    }

    fn has_thread() -> bool {
        false
    }

    unsafe fn vm_privilege() -> c_uint {
        unimplemented!("vm_privilege")
    }

    unsafe fn set_vm_privilege(_privilege: c_uint) {
        unimplemented!("set_vm_privilege")
    }

    unsafe fn fault_state() -> *mut c_void {
        unimplemented!("fault_state")
    }

    unsafe fn set_fault_state(_state: *mut c_void) {
        unimplemented!("set_fault_state")
    }

    unsafe fn stack_privilege() {
        unimplemented!("stack_privilege")
    }

    unsafe fn set_own_priority(_priority: c_int) {
        unimplemented!("set_own_priority")
    }

    fn count(_event: TaskEvent) {
        unimplemented!("count")
    }

    fn cpu_id() -> usize {
        unimplemented!("cpu_id")
    }

    fn lock_pause() {
        unimplemented!("lock_pause")
    }

    fn current_map() -> *mut VmMap<Self> {
        unimplemented!("current_map")
    }

    unsafe fn collect() {
        unimplemented!("collect")
    }

    unsafe fn port_lock(_port: Port) {
        unimplemented!("port_lock")
    }

    unsafe fn port_unlock(_port: Port) {
        unimplemented!("port_unlock")
    }

    unsafe fn port_is_active(_port: Port) -> bool {
        unimplemented!("port_is_active")
    }

    unsafe fn port_kotype(_port: Port) -> c_uint {
        unimplemented!("port_kotype")
    }

    unsafe fn port_kobject(_port: Port) -> *mut c_void {
        unimplemented!("port_kobject")
    }

    unsafe fn port_set_kobject(_port: Port, _kobject: *mut c_void) {
        unimplemented!("port_set_kobject")
    }

    unsafe fn port_receiver(_port: Port) -> *mut c_void {
        unimplemented!("port_receiver")
    }

    unsafe fn port_reference(_port: Port) {
        unimplemented!("port_reference")
    }

    unsafe fn port_release(_port: Port) {
        unimplemented!("port_release")
    }

    unsafe fn port_alloc() -> Option<Port> {
        unimplemented!("port_alloc")
    }

    unsafe fn port_dealloc(_port: Port) {
        unimplemented!("port_dealloc")
    }

    unsafe fn port_make_send(_port: Port) -> Port {
        unimplemented!("port_make_send")
    }

    unsafe fn port_release_send(_port: Port) {
        unimplemented!("port_release_send")
    }

    unsafe fn port_copy_send(_port: *mut c_void) -> *mut c_void {
        unimplemented!("port_copy_send")
    }

    unsafe fn port_make_sonce(_port: Port) -> Port {
        unimplemented!("port_make_sonce")
    }

    unsafe fn port_nsrequest(
        _port: Port,
        _sync: c_uint,
        _notify: Option<NonNull<c_void>>,
    ) -> Option<NonNull<c_void>> {
        unimplemented!("port_nsrequest")
    }

    unsafe fn kobject_set(
        _port: *mut c_void,
        _kobject: VmOffset,
        _kotype: c_uint,
    ) {
        unimplemented!("kobject_set")
    }

    unsafe fn cache_init(
        _cache: VmCache,
        _name: &'static [u8],
        size: usize,
        _flags: CacheFlags,
    ) {
        assert!(size <= RECORD.size(), "a record outgrows the fake caches");
    }

    unsafe fn cache_alloc(_cache: VmCache) -> Option<NonNull<u8>> {
        // SAFETY: the layout has a nonzero size.
        NonNull::new(unsafe { alloc::alloc_zeroed(RECORD) })
    }

    unsafe fn cache_free(_cache: VmCache, record: NonNull<u8>) {
        // SAFETY: the record came from `cache_alloc`, with this layout.
        unsafe { alloc::dealloc(record.as_ptr(), RECORD) };
    }

    fn kalloc(size: usize) -> Option<NonNull<u8>> {
        let layout = Layout::from_size_align(size, KALLOC_ALIGN).ok()?;
        if size == 0 {
            return None;
        }
        // SAFETY: the size is not zero.
        NonNull::new(unsafe { alloc::alloc(layout) })
    }

    unsafe fn kfree(data: NonNull<u8>, size: usize) {
        let Ok(layout) = Layout::from_size_align(size, KALLOC_ALIGN) else {
            return;
        };
        // SAFETY: `data` came from `kalloc` for `size` bytes, with this
        // layout.
        unsafe { alloc::dealloc(data.as_ptr(), layout) };
    }

    fn slab_collect() {
        unimplemented!("slab_collect")
    }

    fn allocators_init() {
        unimplemented!("allocators_init")
    }

    unsafe fn copyin(
        _user: *const c_void,
        _kernel: *mut c_void,
        _len: usize,
    ) -> Result<(), UserFault> {
        unimplemented!("copyin")
    }

    unsafe fn copyout(
        _kernel: *const c_void,
        _user: *mut c_void,
        _len: usize,
    ) -> Result<(), UserFault> {
        unimplemented!("copyout")
    }

    fn print(args: fmt::Arguments<'_>) {
        print!("{args}");
    }

    fn soft_debugger(_message: &CStr) {
        unimplemented!("soft_debugger")
    }

    unsafe fn memory_object_data_request(
        _memory_object: *mut c_void,
        _memory_control: *mut c_void,
        _offset: VmOffset,
        _length: VmSize,
        _desired_access: VmProt,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_data_request")
    }

    unsafe fn memory_object_data_unlock(
        _memory_object: *mut c_void,
        _memory_control: *mut c_void,
        _offset: VmOffset,
        _length: VmSize,
        _desired_access: VmProt,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_data_unlock")
    }

    unsafe fn memory_object_data_return(
        _memory_object: *mut c_void,
        _memory_control: *mut c_void,
        _offset: VmOffset,
        _data: VmOffset,
        _data_cnt: c_uint,
        _dirty: c_int,
        _kernel_copy: c_int,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_data_return")
    }

    unsafe fn memory_object_data_initialize(
        _memory_object: *mut c_void,
        _memory_control: *mut c_void,
        _offset: VmOffset,
        _data: VmOffset,
        _data_cnt: c_uint,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_data_initialize")
    }

    unsafe fn memory_object_lock_completed(
        _memory_object: *mut c_void,
        _memory_object_poly: c_uint,
        _memory_control: *mut c_void,
        _offset: VmOffset,
        _length: VmSize,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_lock_completed")
    }

    unsafe fn memory_object_supply_completed(
        _memory_object: *mut c_void,
        _memory_object_poly: c_uint,
        _memory_control: *mut c_void,
        _offset: VmOffset,
        _length: VmSize,
        _result: Result<(), Error>,
        _error_offset: VmOffset,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_supply_completed")
    }

    unsafe fn memory_object_change_completed(
        _memory_object: *mut c_void,
        _memory_object_poly: c_uint,
        _may_cache: c_int,
        _copy_strategy: c_int,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_change_completed")
    }

    unsafe fn memory_object_init(
        _pager: *mut c_void,
        _pager_request: *mut c_void,
        _pager_name: *mut c_void,
        _page_size: VmSize,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_init")
    }

    unsafe fn memory_object_create(
        _memory_object: *mut c_void,
        _pager: *mut c_void,
        _size: VmSize,
        _pager_request: *mut c_void,
        _pager_name: *mut c_void,
        _page_size: VmSize,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_create")
    }

    unsafe fn memory_object_copy(
        _memory_object: *mut c_void,
        _pager_request: *mut c_void,
        _offset: VmOffset,
        _size: VmSize,
        _new_memory_object: *mut c_void,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_copy")
    }

    unsafe fn memory_object_terminate(
        _pager: *mut c_void,
        _pager_request: *mut c_void,
        _pager_name: *mut c_void,
    ) -> Result<(), ()> {
        unimplemented!("memory_object_terminate")
    }
}
