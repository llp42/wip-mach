// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `mach_thread`'s platform: what tasks, threads and the scheduler ask of the
//! `x86_64` machine.

use crate::arch::vm_param::KERNEL_STACK_SIZE;
use crate::arch::x86_64::ast::MACHINE_PER_THREAD;
use crate::arch::x86_64::clock_platform::wheel;
use crate::arch::x86_64::machine_task::{self, MachineTask};
use crate::arch::x86_64::pcb::{self, Pcb};
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::{
    cswitch, locore, model_dep, mp_desc, per_cpu, smp, spl,
};
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::mig;
use clock::{Clock, HashedWheel};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;
use mach_host::host;
use mach_host::machine;
use mach_host::time as host_time;
use mach_pmap::pmap::{self, Pmap};
use mach_pmap::shootdown;
use mach_sched::ast::AstReason;
use mach_sched::time_value::TimeValue64;
use mach_thread::error::Error;
use mach_thread::platform::Platform;
use mach_thread::processor::Processor;
use mach_thread::processor_ref::ProcessorRef;
use mach_thread::smp::CpuId;
use mach_thread::state::TaskState;
use mach_thread::task::Task;
use mach_thread::thread::{Continuation, StackResume, Thread};
use mach_thread::types::TaskCache;
use mach_vm::param::VmOffset;

/// The slab cache behind each of the scheduler's [`TaskCache`]s.
static TASK_CACHES: [KmemCache; TaskCache::COUNT] =
    [const { KmemCache::zeroed() }; TaskCache::COUNT];

/// The slab cache behind `cache`.
fn task_cache(cache: TaskCache) -> &'static KmemCache {
    &TASK_CACHES[cache as usize]
}

const _: () = assert!(KERNEL_STACK_SIZE.is_multiple_of(size_of::<VmOffset>()));

/// The scheduler's processors, sets, queues and kernel task.
static TASK_STATE: TaskState<MachPlatform> = TaskState::new();

/// `i386_DEBUG_STATE`: the debug registers.
const I386_DEBUG_STATE: c_int = 6;
/// `i386_FSGS_BASE_STATE`: the FS and GS segment bases.
const I386_FSGS_BASE_STATE: c_int = 7;

// SAFETY: the per-CPU reads go through `%gs`, which the boot code bases on
// the running CPU's block, and `splsched()` masks the clock and the IPIs.
unsafe impl Platform for MachPlatform {
    type Pcb = Pcb;
    type TimeBase = &'static Clock<Self>;
    const WHEEL: Pin<&'static HashedWheel<Self::TimeBase>> = wheel();
    const KERNEL_STACK_SIZE: usize = KERNEL_STACK_SIZE;
    const AST_PER_THREAD: AstReason = MACHINE_PER_THREAD;
    const BOOTSTRAP_RETURN: unsafe extern "C" fn() =
        locore::thread_bootstrap_return;
    const EXCEPTION_RETURN: unsafe extern "C" fn() =
        locore::thread_exception_return;

    fn splsched() -> c_int {
        // SAFETY: kernel code runs with `%gs` based at its CPU's per-CPU
        // block, the invariant every per-CPU read of this trait rests on.
        unsafe { spl::splsched() }
    }

    fn splhigh() -> c_int {
        // SAFETY: as in `splsched`.
        unsafe { spl::splhigh() }
    }

    unsafe fn spl0() -> c_int {
        unsafe { spl::spl0() }
    }

    unsafe fn splx(level: c_int) -> c_int {
        unsafe { spl::splx(level) }
    }

    fn current_cpu() -> CpuId {
        per_cpu::cpu_id()
    }

    fn cpu_thread() -> *mut Thread<Self> {
        per_cpu::thread()
    }

    fn cpu_thread_at(cpu: CpuId) -> *mut Thread<Self> {
        per_cpu::per_cpu_at(cpu).thread()
    }

    fn cpu_processor() -> ProcessorRef<Self> {
        per_cpu::processor()
    }

    fn cpu_stack() -> VmOffset {
        per_cpu::stack()
    }

    fn cpu_stack_at(cpu: CpuId) -> VmOffset {
        per_cpu::per_cpu_at(cpu).stack()
    }

    fn remote_ast(cpu: CpuId) {
        smp::remote_ast(cpu);
    }

    unsafe fn cpu_control(
        cpu: CpuId,
        info: *const c_int,
        count: c_uint,
    ) -> Result<(), Error> {
        Ok(unsafe { mp_desc::cpu_control(cpu, info, count) }?)
    }

    fn machine_idle(cpu: CpuId) {
        model_dep::machine_idle(cpu.bits() as c_int);
    }

    fn halt_cpu() -> ! {
        model_dep::halt_cpu()
    }

    unsafe fn switch_to_shutdown_context(
        thread: *mut Thread<Self>,
        routine: unsafe extern "C" fn(*mut Processor<Self>),
        processor: *mut Processor<Self>,
    ) {
        unsafe {
            cswitch::switch_to_shutdown_context(
                thread,
                Some(routine),
                processor,
            );
        }
    }

    unsafe fn cpu_shutdown(cpu: CpuId) {
        unsafe {
            shootdown::deactivate_kernel(cpu.bits() as c_int);
            per_cpu::per_cpu_at(cpu).set_thread(ptr::null_mut());
        }
    }

    unsafe fn pcb_module_init() {
        unsafe { pcb::pcb_module_init() };
    }

    unsafe fn pcb_init(task: *mut Task<Self>, thread: *mut Thread<Self>) {
        unsafe { pcb::pcb_init(task, thread) };
    }

    unsafe fn pcb_terminate(thread: *mut Thread<Self>) {
        unsafe { pcb::pcb_terminate(thread) };
    }

    fn reads_own_state(flavor: c_int) -> bool {
        flavor == I386_DEBUG_STATE
    }

    fn writes_own_state(flavor: c_int) -> bool {
        flavor == I386_DEBUG_STATE || flavor == I386_FSGS_BASE_STATE
    }

    unsafe fn get_state(
        thread: *mut Thread<Self>,
        flavor: c_int,
        state: *mut c_uint,
        count: *mut c_uint,
    ) -> Result<(), Error> {
        Ok(unsafe { pcb::thread_getstatus(thread, flavor, state, count) }?)
    }

    unsafe fn set_state(
        thread: *mut Thread<Self>,
        flavor: c_int,
        state: *mut c_uint,
        count: c_uint,
    ) -> Result<(), Error> {
        Ok(unsafe { pcb::thread_setstatus(thread, flavor, state, count) }?)
    }

    unsafe fn set_syscall_return(thread: *mut Thread<Self>, code: c_int) {
        unsafe { pcb::thread_set_syscall_return(thread, code) };
    }

    unsafe fn stack_attach(
        thread: *mut Thread<Self>,
        stack: VmOffset,
        resume: StackResume<Self>,
    ) {
        unsafe { pcb::stack_attach(thread, stack, resume) };
    }

    unsafe fn stack_detach(thread: *mut Thread<Self>) -> VmOffset {
        unsafe { pcb::stack_detach(thread) }
    }

    unsafe fn stack_handoff(old: *mut Thread<Self>, new: *mut Thread<Self>) {
        unsafe { pcb::stack_handoff(old, new) };
    }

    unsafe fn switch_context(
        old: *mut Thread<Self>,
        continuation: Continuation,
        new: *mut Thread<Self>,
    ) -> *mut Thread<Self> {
        unsafe { pcb::switch_context(old, continuation, new) }
    }

    unsafe fn call_continuation(continuation: Continuation) -> ! {
        unsafe { locore::call_continuation(continuation) }
    }

    unsafe fn syscall_return(code: c_int) -> ! {
        unsafe { locore::thread_syscall_return(code) }
    }

    unsafe fn pmap_collect(pmap: Option<NonNull<Pmap>>) {
        unsafe { pmap::pmap_collect::<Self>(pmap) };
    }

    fn task_state() -> &'static TaskState<Self> {
        &TASK_STATE
    }

    fn read_time_stamp(stamp: TimeValue64) -> TimeValue64 {
        host_time::read_time_stamp(stamp)
    }

    fn time_stamp() -> TimeValue64 {
        host_time::record_time_stamp::<Self>()
    }

    unsafe fn task_cache_init(
        cache: TaskCache,
        name: &'static [u8],
        size: usize,
        align: usize,
    ) {
        task_cache(cache).init(
            name,
            size,
            align,
            None,
            CacheInitFlags::empty(),
        );
    }

    unsafe fn task_cache_alloc(cache: TaskCache) -> Option<NonNull<u8>> {
        task_cache(cache).alloc()
    }

    unsafe fn task_cache_free(cache: TaskCache, record: NonNull<u8>) {
        // SAFETY: the record came from this cache, as the caller promises.
        unsafe { task_cache(cache).free(record) };
    }

    fn cpu_present(cpu: CpuId) -> bool {
        machine::slot(cpu).is_cpu.load(Ordering::Relaxed) != 0
    }

    fn set_cpu_running(cpu: CpuId, running: bool) {
        // Release: the boot CPU's wait for an AP acquires this store.
        machine::slot(cpu)
            .running
            .store(c_int::from(running), Ordering::Release);
        let avail = &machine::info().avail_cpus;
        if running {
            avail.fetch_add(1, Ordering::Relaxed);
        } else {
            avail.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn host() -> *mut c_void {
        host::realhost().cast()
    }

    unsafe fn notify_new_task(
        notification: *mut c_void,
        task: *mut c_void,
        parent: *mut c_void,
    ) {
        let _ =
            unsafe { mig::mach_notify_new_task(notification, task, parent) };
    }
}

// SAFETY: each function forwards to the machine-task routine the task
// code called before the seam.
unsafe impl mach_task::Platform for MachPlatform {
    type MachineTask = MachineTask;

    unsafe fn machine_task_module_init() {
        unsafe { machine_task::module_init() };
    }

    fn machine_task_init(machine: &mut MachineTask) {
        machine.init();
    }

    fn machine_task_terminate(machine: &MachineTask) {
        machine.terminate();
    }

    fn machine_task_collect(machine: &mut MachineTask) {
        machine.collect();
    }
}
