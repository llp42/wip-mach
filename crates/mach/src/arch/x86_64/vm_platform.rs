// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel's side of VM's seam: [`MachPlatform`] as VM's platform.
//!
//! VM is built against its own copy of the machine values it needs at
//! compile time; the assertions here hold the kernel's definitions to them.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::{mp_desc, per_cpu, user_access};
use crate::config;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::kern::{console, debug, ipc_kobject, ipc_mig, slab};
use crate::mig;
use crate::vm::VmMap;
use core::ffi::{CStr, c_int, c_uint, c_void};
use core::fmt;
use core::ptr::NonNull;
use core::slice;
use core::sync::atomic::Ordering;
use mach_ipc::error::SendError;
use mach_ipc::{IpcPort, ipc_port, ipc_space};
use mach_pmap::pmap::{self, Pmap};
use mach_pmap::{bootstrap, phys, pv};
use mach_thread::thread::Thread;
use mach_thread::{sched_prim, task};
use mach_vm::error::Error;
use mach_vm::param;
use mach_vm::platform::{
    self, CacheFlags, Continuation, Platform, Port, TaskEvent, UserFault,
    VmCache,
};
use mach_vm::state::VmState;
use mach_vm::types::VmProt;

const _: () = {
    assert!(param::PAGE_SHIFT == vm_param::PAGE_SHIFT);
    assert!(param::PAGE_SIZE == vm_param::PAGE_SIZE);
    assert!(param::PAGE_MASK == vm_param::PAGE_MASK);
    assert!(param::VM_MIN_KERNEL_ADDRESS == vm_param::VM_MIN_KERNEL_ADDRESS);
    assert!(param::MAX_NCPUS == config::MAX_NCPUS);
    assert!(platform::THREAD_AWAKENED == sched_prim::THREAD_AWAKENED);
    assert!(platform::THREAD_INTERRUPTED == sched_prim::THREAD_INTERRUPTED);
    assert!(platform::THREAD_RESTART == sched_prim::THREAD_RESTART);
    assert!(VmCache::Proxy as usize + 1 == VmCache::COUNT);
};

/// VM's global state.
pub static VM_STATE: VmState<MachPlatform> = VmState::new();

/// The slab cache behind each of VM's [`VmCache`]s.
static VM_CACHES: [KmemCache; VmCache::COUNT] =
    [const { KmemCache::zeroed() }; VmCache::COUNT];

/// The slab cache behind `cache`.
fn vm_cache(cache: VmCache) -> &'static KmemCache {
    &VM_CACHES[cache as usize]
}

// SAFETY: each function forwards to the kernel routine VM called before the
// seam, whose contract the trait restates.
unsafe impl Platform for MachPlatform {
    type Lock = Self;
    type Pmap = Pmap;

    fn state() -> &'static VmState<Self> {
        &VM_STATE
    }

    fn kernel_pmap() -> *mut Pmap {
        pmap::kernel_pmap_ptr()
    }

    unsafe fn pmap_create(size: VmSize) -> *mut Pmap {
        unsafe { pmap::pmap_create::<Self>(size) }
    }

    unsafe fn pmap_destroy(pmap: Option<NonNull<Pmap>>) {
        unsafe { pmap::pmap_destroy::<Self>(pmap) }
    }

    unsafe fn pmap_reference(pmap: Option<NonNull<Pmap>>) {
        unsafe { pmap::pmap_reference::<Self>(pmap) }
    }

    unsafe fn pmap_remove(
        pmap: Option<NonNull<Pmap>>,
        start: VmOffset,
        end: VmOffset,
    ) {
        unsafe { pmap::pmap_remove::<Self>(pmap, start, end) }
    }

    fn pmap_page_protect(phys: VmOffset, prot: VmProt) {
        pv::pmap_page_protect::<Self>(phys, prot);
    }

    unsafe fn pmap_protect(
        pmap: Option<NonNull<Pmap>>,
        start: VmOffset,
        end: VmOffset,
        prot: VmProt,
    ) {
        unsafe { pmap::pmap_protect::<Self>(pmap, start, end, prot) }
    }

    unsafe fn pmap_enter(
        pmap: Option<NonNull<Pmap>>,
        va: VmOffset,
        pa: VmOffset,
        prot: VmProt,
        wired: c_int,
    ) {
        unsafe { pmap::pmap_enter::<Self>(pmap, va, pa, prot, wired) }
    }

    unsafe fn pmap_change_wiring(pmap: *mut Pmap, va: VmOffset, wired: c_int) {
        unsafe { pmap::pmap_change_wiring::<Self>(pmap, va, wired) }
    }

    unsafe fn pmap_extract(pmap: *mut Pmap, va: VmOffset) -> VmOffset {
        unsafe { pmap::pmap_extract::<Self>(pmap, va) }
    }

    fn pmap_clear_modify(phys: VmOffset) {
        pv::pmap_clear_modify::<Self>(phys);
    }

    fn pmap_is_modified(phys: VmOffset) -> bool {
        pv::pmap_is_modified::<Self>(phys)
    }

    fn pmap_clear_reference(phys: VmOffset) {
        pv::pmap_clear_reference::<Self>(phys);
    }

    fn pmap_is_referenced(phys: VmOffset) -> bool {
        pv::pmap_is_referenced::<Self>(phys)
    }

    fn pmap_pageable(
        pmap: *mut Pmap,
        start: VmOffset,
        end: VmOffset,
        pageable: c_int,
    ) {
        pmap::pmap_pageable(pmap, start, end, pageable);
    }

    unsafe fn pmap_map_bd(
        virt: VmOffset,
        start: VmOffset,
        end: VmOffset,
        prot: VmProt,
    ) -> VmOffset {
        unsafe { bootstrap::pmap_map_bd::<Self>(virt, start, end, prot) }
    }

    unsafe fn pmap_unmap_bd(virt: VmOffset, end: VmOffset) {
        unsafe { bootstrap::pmap_unmap_bd::<Self>(virt, end) }
    }

    fn pmap_virtual_space() -> (VmOffset, VmOffset) {
        bootstrap::pmap_virtual_space()
    }

    fn pmap_init() {
        let size = bootstrap::pv_tables_size::<Self>();
        // SAFETY: the kernel map is live by the time VM initializes the pmap.
        let map =
            unsafe { NonNull::new_unchecked(Self::state().kernel_map()) };
        let Ok(addr) = mach_vm::vm_kern::kmem_alloc_wired(map, size) else {
            panic!("pmap_init")
        };
        // SAFETY: `kmem_alloc_wired()` returned `size` wired bytes no one
        // else uses, and VM initializes the pmap once.
        unsafe { bootstrap::pmap_init::<Self>(addr) };
    }

    unsafe fn pmap_resident_count(pmap: *mut Pmap) -> c_int {
        // SAFETY: the caller hands a live physical map.
        unsafe { pmap::resident_count(pmap) }
    }

    fn kernel_virtual_start() -> VmOffset {
        bootstrap::KERNEL_VIRTUAL_START.load(Ordering::Relaxed)
    }

    fn kernel_virtual_end() -> VmOffset {
        bootstrap::KERNEL_VIRTUAL_END.load(Ordering::Relaxed)
    }

    unsafe fn zero_page(pa: VmOffset) {
        unsafe { phys::zero_page::<Self>(pa) }
    }

    unsafe fn copy_page(src: VmOffset, dst: VmOffset) {
        unsafe { phys::copy_page::<Self>(src, dst) }
    }

    const CLOCK_HZ: c_int = mach_sched::sched::CLOCK_HZ;

    unsafe fn assert_wait(
        event: Option<NonNull<c_void>>,
        interruptible: c_int,
    ) {
        unsafe {
            sched_prim::assert_wait::<Self>(event, interruptible);
        }
    }

    unsafe fn thread_block(continuation: Continuation) {
        unsafe { sched_prim::thread_block::<Self>(continuation) }
    }

    fn thread_wakeup_prim(
        event: *mut c_void,
        one_thread: c_int,
        result: c_int,
    ) -> bool {
        sched_prim::thread_wakeup_prim::<Self>(event, one_thread, result)
    }

    unsafe fn thread_set_timeout(ticks: c_int) {
        unsafe { sched_prim::thread_set_timeout::<Self>(ticks) }
    }

    unsafe fn clear_wait(result: c_int, interrupt_only: c_int) {
        unsafe {
            sched_prim::clear_wait(per_cpu::thread(), result, interrupt_only);
        }
    }

    unsafe fn wait_result() -> c_int {
        // SAFETY: thread context, so the running thread is live.
        unsafe { (*per_cpu::thread()).wait_result }
    }

    fn has_thread() -> bool {
        !per_cpu::thread().is_null()
    }

    unsafe fn vm_privilege() -> c_uint {
        // SAFETY: the caller checked that a thread runs.
        unsafe { (*per_cpu::thread()).vm_privilege }
    }

    unsafe fn set_vm_privilege(privilege: c_uint) {
        // SAFETY: the caller checked that a thread runs, and only it writes
        // its own privilege.
        unsafe { (*per_cpu::thread()).vm_privilege = privilege };
    }

    unsafe fn fault_state() -> *mut c_void {
        // SAFETY: thread context, so the running thread is live.
        unsafe { (*per_cpu::thread()).saved.other }
    }

    unsafe fn set_fault_state(state: *mut c_void) {
        // SAFETY: thread context, and only the thread writes its own slot.
        unsafe { (*per_cpu::thread()).saved.other = state };
    }

    unsafe fn stack_privilege() {
        // SAFETY: thread context, so the call runs on the thread it names.
        unsafe { (*per_cpu::thread()).stack_privilege() };
    }

    unsafe fn set_own_priority(priority: c_int) {
        unsafe { Thread::<Self>::set_own_priority(priority) };
    }

    fn count(event: TaskEvent) {
        let thread = per_cpu::thread();
        if thread.is_null() {
            return;
        }
        // SAFETY: a running thread's task is live while it runs, and the
        // counts are statistics only the running thread bumps.
        unsafe {
            let task = (*thread).task;
            let counter = match event {
                TaskEvent::Fault => &raw mut (*task).faults,
                TaskEvent::ZeroFill => &raw mut (*task).zero_fills,
                TaskEvent::Reactivation => &raw mut (*task).reactivations,
                TaskEvent::Pagein => &raw mut (*task).pageins,
                TaskEvent::CowFault => &raw mut (*task).cow_faults,
            };
            counter.write(counter.read().wrapping_add(1));
        }
    }

    fn cpu_id() -> usize {
        per_cpu::cpu_id().as_usize()
    }

    fn lock_pause() {
        mp_desc::simple_lock_pause();
    }

    fn current_map() -> *mut VmMap {
        ipc_mig::current_map()
    }

    unsafe fn collect() {
        // SAFETY: the caller holds no lock, which each collector needs.
        unsafe {
            Thread::<Self>::stack_collect();
            task::consider_collect::<Self>();
        }
        slab::slab_collect();
    }

    unsafe fn port_lock(port: Port) {
        unsafe { ipc(port).lock() };
    }

    unsafe fn port_unlock(port: Port) {
        unsafe { ipc(port).unlock() };
    }

    unsafe fn port_is_active(port: Port) -> bool {
        unsafe { ipc(port).is_active() }
    }

    unsafe fn port_kotype(port: Port) -> c_uint {
        unsafe { ipc(port).kotype() }
    }

    unsafe fn port_kobject(port: Port) -> *mut c_void {
        unsafe { ipc(port).kobject() }
    }

    unsafe fn port_set_kobject(port: Port, kobject: *mut c_void) {
        unsafe { ipc(port).set_kobject(kobject) };
    }

    unsafe fn port_receiver(port: Port) -> *mut c_void {
        unsafe { ipc(port).receiver() }
    }

    unsafe fn port_reference(port: Port) {
        unsafe { ipc(port).reference() };
    }

    unsafe fn port_release(port: Port) {
        unsafe { ipc(port).release::<Self>() };
    }

    unsafe fn port_alloc() -> Option<Port> {
        unsafe { ipc_port::alloc_special::<Self>(ipc_space::kernel()) }.map(vm)
    }

    unsafe fn port_dealloc(port: Port) {
        unsafe { ipc_port::dealloc_special::<Self>(ipc(port)) };
    }

    unsafe fn port_make_send(port: Port) -> Port {
        vm(unsafe { ipc_port::make_send(ipc(port)) })
    }

    unsafe fn port_release_send(port: Port) {
        unsafe { ipc_port::release_send::<Self>(ipc(port)) };
    }

    unsafe fn port_copy_send(port: *mut c_void) -> *mut c_void {
        unsafe { ipc_port::copy_send(port) }
    }

    unsafe fn port_make_sonce(port: Port) -> Port {
        vm(unsafe { ipc_port::make_sonce(ipc(port)) })
    }

    unsafe fn port_nsrequest(
        port: Port,
        sync: c_uint,
        notify: Option<NonNull<c_void>>,
    ) -> Option<NonNull<c_void>> {
        unsafe { ipc_port::nsrequest::<Self>(ipc(port), sync, notify) }
    }

    unsafe fn kobject_set(
        port: *mut c_void,
        kobject: VmOffset,
        kotype: c_uint,
    ) {
        unsafe { ipc_kobject::set(port, kobject, kotype) };
    }
    type SendError = SendError;

    const SEND_INTERRUPTED: SendError = SendError::Interrupted;

    unsafe fn cache_init(
        cache: VmCache,
        name: &'static [u8],
        size: usize,
        flags: CacheFlags,
    ) {
        vm_cache(cache).init(
            name,
            size,
            0,
            None,
            CacheInitFlags::from_bits_retain(flags.bits()),
        );
    }

    unsafe fn cache_alloc(cache: VmCache) -> Option<NonNull<u8>> {
        vm_cache(cache).alloc()
    }

    unsafe fn cache_free(cache: VmCache, record: NonNull<u8>) {
        // SAFETY: the record came from this cache, as the caller promises.
        unsafe { vm_cache(cache).free(record) };
    }

    fn kalloc(size: usize) -> Option<NonNull<u8>> {
        slab::kalloc(size)
    }

    unsafe fn kfree(data: NonNull<u8>, size: usize) {
        unsafe { slab::kfree(data, size) };
    }

    fn slab_collect() {
        slab::slab_collect();
    }

    fn allocators_init() {
        mach_slab::slab_init::<Self>();
        mach_slab::kalloc_init::<Self>();
    }

    const DMA_LIMIT: VmOffset = mach_page::memmap::VM_PAGE_DMA_LIMIT;

    const DMA32_LIMIT: VmOffset = mach_page::memmap::VM_PAGE_DMA32_LIMIT;

    const DIRECTMAP_LIMIT: VmOffset =
        mach_pmap::param::VM_PAGE_DIRECTMAP_LIMIT;

    unsafe fn copyin(
        user: *const c_void,
        kernel: *mut c_void,
        len: usize,
    ) -> Result<(), UserFault> {
        // An empty copy may name a null buffer, which no slice can.
        let kernel: &mut [u8] = if len == 0 {
            &mut []
        } else {
            // SAFETY: the caller promises `kernel` is writable kernel memory
            // for `len` bytes.
            unsafe { slice::from_raw_parts_mut(kernel.cast(), len) }
        };
        user_access::copyin(user.addr(), kernel).map_err(|_| UserFault)
    }

    unsafe fn copyout(
        kernel: *const c_void,
        user: *mut c_void,
        len: usize,
    ) -> Result<(), UserFault> {
        // An empty copy may name a null buffer, which no slice can.
        let kernel: &[u8] = if len == 0 {
            &[]
        } else {
            // SAFETY: the caller promises `kernel` is readable kernel memory
            // for `len` bytes.
            unsafe { slice::from_raw_parts(kernel.cast(), len) }
        };
        user_access::copyout(kernel, user.addr()).map_err(|_| UserFault)
    }

    fn print(args: fmt::Arguments<'_>) {
        console::write_fmt(args);
    }

    fn soft_debugger(message: &CStr) {
        debug::soft_debugger(message);
    }

    unsafe fn memory_object_data_request(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        desired_access: VmProt,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_data_request(
                memory_object,
                memory_control,
                offset,
                length,
                desired_access,
            )
        }
    }

    unsafe fn memory_object_data_unlock(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        desired_access: VmProt,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_data_unlock(
                memory_object,
                memory_control,
                offset,
                length,
                desired_access,
            )
        }
    }

    unsafe fn memory_object_data_return(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        data: VmOffset,
        data_cnt: c_uint,
        dirty: c_int,
        kernel_copy: c_int,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_data_return(
                memory_object,
                memory_control,
                offset,
                data,
                data_cnt,
                dirty,
                kernel_copy,
            )
        }
    }

    unsafe fn memory_object_data_initialize(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        data: VmOffset,
        data_cnt: c_uint,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_data_initialize(
                memory_object,
                memory_control,
                offset,
                data,
                data_cnt,
            )
        }
    }

    unsafe fn memory_object_lock_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_lock_completed(
                memory_object,
                memory_object_poly,
                memory_control,
                offset,
                length,
            )
        }
    }

    unsafe fn memory_object_supply_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        result: Result<(), Error>,
        error_offset: VmOffset,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_supply_completed(
                memory_object,
                memory_object_poly,
                memory_control,
                offset,
                length,
                result,
                error_offset,
            )
        }
    }

    unsafe fn memory_object_change_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        may_cache: c_int,
        copy_strategy: c_int,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_change_completed(
                memory_object,
                memory_object_poly,
                may_cache,
                copy_strategy,
            )
        }
    }

    unsafe fn memory_object_init(
        pager: *mut c_void,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
        page_size: VmSize,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_init(
                pager,
                pager_request,
                pager_name,
                page_size,
            )
        }
    }

    unsafe fn memory_object_create(
        memory_object: *mut c_void,
        pager: *mut c_void,
        size: VmSize,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
        page_size: VmSize,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_create(
                memory_object,
                pager,
                size,
                pager_request,
                pager_name,
                page_size,
            )
        }
    }

    unsafe fn memory_object_copy(
        memory_object: *mut c_void,
        pager_request: *mut c_void,
        offset: VmOffset,
        size: VmSize,
        new_memory_object: *mut c_void,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_copy(
                memory_object,
                pager_request,
                offset,
                size,
                new_memory_object,
            )
        }
    }

    unsafe fn memory_object_terminate(
        pager: *mut c_void,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
    ) -> Result<(), SendError> {
        unsafe {
            mig::memory_object_terminate(pager, pager_request, pager_name)
        }
    }
}

/// The kernel's handle for a port VM holds.
const fn ipc(port: Port) -> IpcPort {
    IpcPort::from_non_null(port.as_non_null())
}

/// VM's handle for a port the kernel holds.
const fn vm(port: IpcPort) -> Port {
    // SAFETY: an `IpcPort` is non-null and never dead.
    unsafe { Port::from_raw(port.as_ptr()) }
}
