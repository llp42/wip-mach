// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What tasks, threads and the scheduler ask of the machine.
//!
//! The scheduler runs on the machine's CPUs at the machine's interrupt
//! levels: [`Platform`] hands it the running CPU's per-CPU block, the
//! priority levels it masks the clock and the IPIs with, and the CPU
//! controls it starts, idles and stops processors through.

use crate::error::Error;
use crate::processor::Processor;
use crate::processor_ref::ProcessorRef;
use crate::smp::CpuId;
use crate::state::TaskState;
use crate::task::Task;
use crate::thread::{Continuation, StackResume, Thread};
use crate::types::TaskCache;
use core::ffi::{c_int, c_uint, c_void};
use core::pin::Pin;
use core::ptr::NonNull;
use mach_sched::ast::AstReason;
use mach_sched::time_value::TimeValue64;
use mach_vm::param::VmOffset;

/// The machine and kernel services tasks, threads and the scheduler use.
///
/// # Safety
///
/// The implementor's per-CPU reads must name the running CPU's block, and
/// its interrupt levels must mask what the scheduler's locks assume: at
/// `splsched()` neither the clock nor an IPI reaches the CPU.
pub unsafe trait Platform: mach_task::Platform {
    // Interrupt levels.

    /// Masks the clock and the IPIs, returning the level the caller restores
    /// with [`Self::splx`].  Raising the level asks nothing of the caller; a
    /// level never restored leaves the CPU masked, not memory unsound.
    fn splsched() -> c_int;
    /// Masks every interrupt, returning the level to restore, as
    /// [`Self::splsched`] does.
    fn splhigh() -> c_int;
    /// Unmasks every interrupt, returning the level to restore.
    ///
    /// # Safety
    ///
    /// The caller must hold no lock taken at a raised level.
    unsafe fn spl0() -> c_int;
    /// Restores the level `level`, returning the one it replaced.
    ///
    /// # Safety
    ///
    /// `level` must be a level a raise returned on this CPU.
    unsafe fn splx(level: c_int) -> c_int;

    // The running CPU.

    /// The running CPU.
    fn current_cpu() -> CpuId;
    /// The thread the running CPU runs, null before its first.
    fn cpu_thread() -> *mut Thread<Self>;
    /// The thread CPU `cpu` runs, null before its first.
    fn cpu_thread_at(cpu: CpuId) -> *mut Thread<Self>;
    /// The running CPU's processor record.
    fn cpu_processor() -> ProcessorRef<Self>;
    /// The kernel stack the running CPU runs on.
    fn cpu_stack() -> VmOffset;
    /// The kernel stack CPU `cpu` runs on.
    fn cpu_stack_at(cpu: CpuId) -> VmOffset;

    // CPU control.

    /// Interrupts CPU `cpu` to check its ASTs.
    fn remote_ast(cpu: CpuId);
    /// Passes the machine-dependent `info` words to CPU `cpu`'s controls.
    ///
    /// # Errors
    ///
    /// Whatever the machine reports: the controls it lacks or refuses.
    ///
    /// # Safety
    ///
    /// `info` must be readable for `count` words.
    unsafe fn cpu_control(
        cpu: CpuId,
        info: *const c_int,
        count: c_uint,
    ) -> Result<(), Error>;
    /// Idles CPU `cpu` until an interrupt.
    fn machine_idle(cpu: CpuId);
    /// Stops the running CPU for good.
    fn halt_cpu() -> !;
    /// Leaves `thread` for the running CPU's shutdown stack, where `routine`
    /// takes `processor` out of the system.
    ///
    /// # Safety
    ///
    /// `thread` must be the running thread, `processor` the running CPU's,
    /// and `routine` must never return.
    unsafe fn switch_to_shutdown_context(
        thread: *mut Thread<Self>,
        routine: unsafe extern "C" fn(*mut Processor<Self>),
        processor: *mut Processor<Self>,
    );
    /// Detaches CPU `cpu` from the kernel's address space and its running
    /// thread, as it leaves the system.
    ///
    /// # Safety
    ///
    /// `cpu` must be the running CPU, on its shutdown stack.
    unsafe fn cpu_shutdown(cpu: CpuId);

    // A thread's machine state.

    /// The machine part of a thread: its registers and saved state.
    type Pcb;
    /// The bytes of a kernel stack, a multiple of the word size: the stack
    /// cache links a free stack through its last word.
    const KERNEL_STACK_SIZE: usize;
    /// The AST reasons the machine keeps per thread, which a context switch
    /// clears with the scheduler's own.
    const AST_PER_THREAD: AstReason;
    /// Where a new thread starts the first time it runs.
    const BOOTSTRAP_RETURN: unsafe extern "C" fn();
    /// Where a thread resumes to return from an exception to user mode.
    const EXCEPTION_RETURN: unsafe extern "C" fn();

    /// Readies the pcb allocator.
    ///
    /// # Safety
    ///
    /// Runs once at boot, before the first thread is created.
    unsafe fn pcb_module_init();
    /// Gives `thread`, of `task`, its machine state.
    ///
    /// # Safety
    ///
    /// `thread` must be fresh and unshared, and `task` live.
    unsafe fn pcb_init(task: *mut Task<Self>, thread: *mut Thread<Self>);
    /// Frees `thread`'s machine state.
    ///
    /// # Safety
    ///
    /// `thread` must be dead, and nothing may touch its state again.
    unsafe fn pcb_terminate(thread: *mut Thread<Self>);
    /// Whether the running thread may read its own `flavor` of machine state
    /// without being stopped.
    fn reads_own_state(flavor: c_int) -> bool;
    /// Whether the running thread may write its own `flavor` of machine state
    /// without being stopped.
    fn writes_own_state(flavor: c_int) -> bool;
    /// Copies `thread`'s `flavor` of machine state out to `state`.
    ///
    /// # Errors
    ///
    /// Whatever the machine reports: a flavor or a count it does not take.
    ///
    /// # Safety
    ///
    /// `thread` must be stopped or the running thread, `state` writable for
    /// `*count` words, and `count` valid for a read and a write.
    unsafe fn get_state(
        thread: *mut Thread<Self>,
        flavor: c_int,
        state: *mut c_uint,
        count: *mut c_uint,
    ) -> Result<(), Error>;
    /// Sets `thread`'s `flavor` of machine state from `state`.
    ///
    /// # Errors
    ///
    /// Whatever the machine reports: a flavor, a count or a value it does not
    /// take.
    ///
    /// # Safety
    ///
    /// `thread` must be stopped or the running thread, and `state` readable
    /// for `count` words.
    unsafe fn set_state(
        thread: *mut Thread<Self>,
        flavor: c_int,
        state: *mut c_uint,
        count: c_uint,
    ) -> Result<(), Error>;
    /// Sets the value `thread`'s system call returns.
    ///
    /// # Safety
    ///
    /// `thread` must be live and not running.
    unsafe fn set_syscall_return(thread: *mut Thread<Self>, code: c_int);

    // Kernel stacks and context switch.

    /// Gives `thread` the kernel stack `stack`, to resume through `resume`.
    ///
    /// # Safety
    ///
    /// `stack` must be a whole kernel stack no other thread holds, and
    /// `thread` must have none.
    unsafe fn stack_attach(
        thread: *mut Thread<Self>,
        stack: VmOffset,
        resume: StackResume<Self>,
    );
    /// Takes `thread`'s kernel stack away, returning it.
    ///
    /// # Safety
    ///
    /// `thread` must not be running on the stack.
    unsafe fn stack_detach(thread: *mut Thread<Self>) -> VmOffset;
    /// Moves the running stack from `old` to `new`, which resumes on it.
    ///
    /// # Safety
    ///
    /// `old` must be the running thread, leaving through a continuation, and
    /// `new` a thread with no stack.
    unsafe fn stack_handoff(old: *mut Thread<Self>, new: *mut Thread<Self>);
    /// Saves `old`, to resume at `continuation` or where it stopped, and runs
    /// `new`; returns the thread switched from when `old` resumes.
    ///
    /// # Safety
    ///
    /// `old` must be the running thread and `new` a thread ready to run with
    /// a stack.
    unsafe fn switch_context(
        old: *mut Thread<Self>,
        continuation: Continuation,
        new: *mut Thread<Self>,
    ) -> *mut Thread<Self>;
    /// Resets the running stack and calls `continuation` on it.
    ///
    /// # Safety
    ///
    /// The running thread must own the stack, and nothing on it may be live.
    unsafe fn call_continuation(continuation: Continuation) -> !;
    /// Returns from the running thread's system call with `code`.
    ///
    /// # Safety
    ///
    /// The running thread must be in a system call, and nothing on its stack
    /// may be live.
    unsafe fn syscall_return(code: c_int) -> !;

    // A task's machine state.

    /// Frees the page tables `pmap` holds but no longer uses.
    ///
    /// # Safety
    ///
    /// `pmap` must be `None` or a live physical map; the caller holds no
    /// lock.
    unsafe fn pmap_collect(
        pmap: Option<NonNull<<Self as mach_vm::Platform>::Pmap>>,
    );

    // State.

    /// The one task state, which the kernel keeps in a static.
    fn task_state() -> &'static TaskState<Self>;

    // Time.

    /// The time base the scheduler's callouts count the ticks of.
    type TimeBase: clock::TickSource + clock::Locking + Sync + 'static;
    /// The wheel the scheduler's callouts run on.
    const WHEEL: Pin<&'static clock::HashedWheel<Self::TimeBase>>;
    /// The time now, in the boot-time frame creation times are kept in.
    fn time_stamp() -> TimeValue64;
    /// The real time `stamp`, a time in the boot-time frame, stands for.
    fn read_time_stamp(stamp: TimeValue64) -> TimeValue64;

    // Allocation.

    /// Sets up `cache` for records of `size` bytes aligned to `align`
    /// (0 for the natural alignment), reported as `name`.
    ///
    /// # Safety
    ///
    /// Once per cache, before its first allocation.
    unsafe fn task_cache_init(
        cache: TaskCache,
        name: &'static [u8],
        size: usize,
        align: usize,
    );
    /// Allocates a record from `cache`, or `None` when memory is short.
    ///
    /// # Safety
    ///
    /// [`Self::task_cache_init`] must have set `cache` up.
    unsafe fn task_cache_alloc(cache: TaskCache) -> Option<NonNull<u8>>;
    /// Returns a record to `cache`.
    ///
    /// # Safety
    ///
    /// `record` must have come from `cache` and not be used again.
    unsafe fn task_cache_free(cache: TaskCache, record: NonNull<u8>);

    // Kernel services.

    /// Whether the machine has CPU `cpu`.
    fn cpu_present(cpu: CpuId) -> bool;
    /// Records that CPU `cpu` came up, or went down when not `running`.
    fn set_cpu_running(cpu: CpuId, running: bool);
    /// The host the processor sets belong to.
    fn host() -> *mut c_void;
    /// Sends the new-task notification on `notification`, naming `task` and
    /// `parent`, both naked send rights the send consumes.
    ///
    /// # Safety
    ///
    /// `notification` must be a live send right, and the rights the
    /// caller's references back.
    unsafe fn notify_new_task(
        notification: *mut c_void,
        task: *mut c_void,
        parent: *mut c_void,
    );
}
