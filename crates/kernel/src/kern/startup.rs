// SPDX-License-Identifier: CMU-Mach
// Derived from kern/startup.c and kern/startup.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Kernel startup, which `kern/startup.c` used to define and `kern/startup.h`
//! declares.

use crate::arch::x86_64::clock_platform;
use crate::arch::x86_64::model_dep::{self, KERNEL_CMDLINE};
use crate::arch::x86_64::pcb;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::pmap;
use crate::arch::x86_64::spl;
use crate::device::device_init;
use crate::ipc::ipc_init;
use crate::kern::console::write_cstr;
use crate::kern::debug::kpanic;
use crate::kern::gsync;
use crate::kern::host_time::record_time_stamp;
use crate::kern::mach_factor;
use crate::kern::machine;
use crate::kern::processor::{self, processor_at};
use crate::kern::rdxtree;
use crate::kern::sched_prim;
use crate::kern::smp::CpuId;
use crate::kern::task::{self, KERNEL_TASK};
use crate::kern::thread::{self, TH_RUN, TH_UNINT, Thread};
use crate::kern::thread_swap;
use crate::kern::timer;
use crate::vm::vm_init;
use crate::vm::vm_page;
use crate::vm::vm_pageout;
use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/// `KERNEL_MAJOR_VERSION` of <mach/version.h>.
const KERNEL_MAJOR_VERSION: c_int = 4;
/// `KERNEL_MINOR_VERSION` of <mach/version.h>.
const KERNEL_MINOR_VERSION: c_int = 0;

/// `reboot_on_panic` of kern/startup.c: whether the panic path reboots or
/// halts.  The C `Panic()` reads the same symbol.
static REBOOT_ON_PANIC: AtomicU32 = AtomicU32::new(1);

/// The `reboot_on_panic` flag as the panic path takes it.
pub(crate) fn reboot_on_panic() -> c_int {
    // The C wrote only 0 or 1 into the `boolean_t` this symbol is.
    REBOOT_ON_PANIC.load(Ordering::Relaxed) as c_int
}

/// `setup_main()` in C: start the kernel from the boot processor.
///
/// # Safety
///
/// Runs once, on the interrupt stack of the boot processor, before any other
/// CPU or thread exists.
pub(crate) unsafe fn setup_main() {
    // SAFETY: the boot set `KERNEL_CMDLINE` before `setup_main` ran.
    if unsafe { command_line_has_halt() } {
        // The store runs before any other CPU starts, and the C `Panic()`
        // read the same word without synchronization.
        REBOOT_ON_PANIC.store(0, Ordering::Relaxed);
    }

    crate::kern::debug::panic_init();

    // SAFETY: the boot sequence calls each initializer exactly once, in the
    // order the C used.
    unsafe {
        sched_prim::sched_init();
        vm_init::vm_mem_bootstrap();
        rdxtree::cache_init();
        ipc_init::ipc_bootstrap();
        vm_init::vm_mem_init();
        ipc_init::ipc_init();

        pmap::activate_kernel(CpuId::BOOT.bits() as c_int);
        timer::init_timers();
        model_dep::machine_init();
        clock_platform::mapable_time_init();
    }

    let info = machine::info();
    // SAFETY: no other CPU is running, and `machine_info` is the boot
    // record.
    unsafe {
        let memsize = vm_page::mem_size();
        (*info).max_cpus = crate::config::MAX_NCPUS as c_int;
        (*info).memory_size = memsize;
        if (*info).memory_size < memsize {
            (*info).memory_size = usize::MAX;
        }
        (*info).avail_cpus = 0;
        (*info).major_version = KERNEL_MAJOR_VERSION;
        (*info).minor_version = KERNEL_MINOR_VERSION;
    }

    unsafe {
        task::init();
        Thread::init();
        thread_swap::swapper_init();
        processor::system_init();

        sched_prim::recompute_priorities_start();
        mach_factor::compute();
        gsync::setup();

        let startup_thread =
            Thread::create(KERNEL_TASK).unwrap_or(ptr::null_mut());
        let _ = Thread::set_name(startup_thread, c"startup".as_ptr());
        (*startup_thread).start(Some(start_kernel_threads));
        thread_swap::thread_doswapin(startup_thread);

        (*startup_thread).set_state((*startup_thread).state() | TH_RUN);
        let _ = Thread::resume(startup_thread);

        cpu_launch_first_thread(startup_thread);
    }
}

/// The `strstr(kernel_cmdline, "-H ")` test of `setup_main()`.
///
/// # Safety
///
/// `kernel_cmdline` must point at the live NUL-terminated boot command line.
unsafe fn command_line_has_halt() -> bool {
    let line = unsafe { core::ffi::CStr::from_ptr(KERNEL_CMDLINE) };
    line.to_bytes().windows(3).any(|window| window == b"-H ")
}

/// `start_kernel_threads()` in C: create the kernel's service threads and the
/// bootstrap task.
///
/// # Safety
///
/// Runs once, in the startup thread, before the other CPUs are started.
pub(crate) unsafe extern "C" fn start_kernel_threads() {
    for cpu in CpuId::all() {
        // SAFETY: the slot is `cpu`'s own `machine_slot`, which the probe
        // filled before this thread ran.
        if unsafe { (*machine::slot(cpu)).is_cpu } == 0 {
            continue;
        }

        // SAFETY: the kernel task is live, and the slot below is writable;
        // the C ignored a failure the same way.
        unsafe {
            let th = Thread::create(KERNEL_TASK).unwrap_or(ptr::null_mut());

            let mut name = [0; 10];
            write_cstr(&mut name, format_args!("idle/{cpu}"));
            let _ = Thread::set_name(th, name.as_ptr());
            sched_prim::thread_bind(th, processor_at(cpu).as_ptr());
            (*th).start(Some(sched_prim::idle_thread_entry));
            thread_swap::thread_doswapin(th);
            let _ = Thread::resume(th);
        }
    }

    // SAFETY: the kernel task is live, and each continuation runs as its own
    // kernel thread, as the C started them.
    unsafe {
        let _ = thread::kernel_thread(
            KERNEL_TASK,
            c"reaper".as_ptr(),
            Some(thread::reaper_thread_continue),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread(
            KERNEL_TASK,
            c"rcu".as_ptr(),
            Some(crate::kern::rcu::gp_thread_continue),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread(
            KERNEL_TASK,
            c"swapin".as_ptr(),
            Some(swapin_thread_continuation),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread(
            KERNEL_TASK,
            c"sched".as_ptr(),
            Some(sched_prim::sched_thread_entry),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread(
            KERNEL_TASK,
            c"intr".as_ptr(),
            Some(crate::device::intr::intr_thread_entry),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread(
            KERNEL_TASK,
            c"action".as_ptr(),
            Some(machine::action_thread),
            ptr::null_mut(),
        );

        crate::arch::x86_64::mp_desc::start_other_cpus();
        device_init::device_service_create();
        record_time_stamp(&raw mut (*KERNEL_TASK).creation_time);
        crate::kern::bootstrap::create();
    }

    // SAFETY: the startup thread becomes the pageout daemon, which never
    // returns.
    unsafe {
        let _ = spl::spl0();
        let _ = Thread::set_name(per_cpu::thread(), c"pageout".as_ptr());
        vm_pageout::pageout();
    }
}

/// `cpu_launch_first_thread()` in C: hand a CPU its first thread, never to
/// return.
///
/// # Safety
///
/// Runs on a CPU that is taking its first thread, with no thread of its own
/// yet.
pub(crate) unsafe extern "C" fn cpu_launch_first_thread(
    mut th: *mut Thread,
) -> ! {
    let mycpu = cpu_id();
    // The C `machine` and `pmap` routines take the CPU number as an `int`.
    let cpu = mycpu.bits() as c_int;

    // SAFETY: the boot CPU and every AP reach this once, on their own
    // processor.
    unsafe {
        machine::cpu_up(cpu);

        // The C `start_timer()` is an empty macro in <kern/timer.h>.

        spl::splhigh();

        if th.is_null() {
            th = sched_prim::choose_thread(per_cpu::processor().as_ptr());
        }
        if th.is_null() {
            panic_no_thread();
        }

        pmap::activate_kernel(cpu);
        per_cpu::set_thread(th);
        per_cpu::set_stack((*th).kernel_stack);

        (*th).lock.lock();
        (*th).set_state((*th).state() & !TH_UNINT);
        (*th).lock.unlock();
        (*th).last_processor = per_cpu::processor().as_ptr();

        // The C `timer_switch()` is an empty macro in <kern/timer.h>.

        let map = (*(*th).task).map.cast::<crate::vm::vm_map::VmMap>();
        pmap::activate_user((*map).pmap, cpu);

        model_dep::startrtclock();
        pcb::load_context(th);
    }
}

/// The `swapin_thread()` continuation, which `kernel_thread()` starts.
unsafe extern "C" fn swapin_thread_continuation() {
    // SAFETY: the swapper thread runs once and never returns.
    unsafe { thread_swap::swapin_thread() }
}

/// The `panic("cpu_launch_first_thread")` of the C.
fn panic_no_thread() -> ! {
    kpanic!("cpu_launch_first_thread", "cpu_launch_first_thread")
}
