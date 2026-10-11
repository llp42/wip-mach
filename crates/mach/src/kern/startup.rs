// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Kernel startup.

use crate::arch::x86_64::clock_platform;
use crate::arch::x86_64::model_dep;
use crate::arch::x86_64::pcb;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::device::device_init;
use crate::kern::console::write_cstr;
use crate::kern::debug::kpanic;
use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use mach_boot::types::BootInfo;
use mach_host::host;
use mach_host::machine;
use mach_host::port as ipc_host;
use mach_host::time::record_time_stamp;
use mach_ipc::ipc_init;
use mach_pmap::shootdown;
use mach_sched::timer;
use mach_thread::mach_factor;
use mach_thread::processor::{self, processor_at};
use mach_thread::processor_action;
use mach_thread::sched_prim;
use mach_thread::smp::CpuId;
use mach_thread::task::{self, kernel_task};
use mach_thread::thread::{self, Thread};
use mach_thread::thread_swap;
use mach_thread::types::ThreadState;
use mach_vm::vm_init;
use mach_vm::vm_page;
use mach_vm::vm_pageout;

/// The major version `host_info()` reports.
const KERNEL_MAJOR_VERSION: c_int = 4;
/// The minor version `host_info()` reports.
const KERNEL_MINOR_VERSION: c_int = 0;

/// Whether the panic path reboots or halts.
static REBOOT_ON_PANIC: AtomicU32 = AtomicU32::new(1);

/// The `reboot_on_panic` flag as the panic path takes it.
pub(crate) fn reboot_on_panic() -> c_int {
    // The C wrote only 0 or 1 into the `boolean_t` this symbol is.
    REBOOT_ON_PANIC.load(Ordering::Relaxed) as c_int
}

/// Starts the kernel from the boot processor.
///
/// # Safety
///
/// Runs once, on the interrupt stack of the boot processor, before any other
/// CPU or thread exists.
pub(crate) unsafe fn setup_main() {
    // The `-H` option asks the panic path to halt instead of rebooting.
    let line = model_dep::kernel_cmdline().to_bytes();
    if line.windows(3).any(|window| window == b"-H ") {
        // The store runs before any other CPU starts, so it needs no ordering.
        REBOOT_ON_PANIC.store(0, Ordering::Relaxed);
    }

    crate::kern::debug::panic_init();

    // SAFETY: the boot sequence calls each initializer exactly once, in the
    // order the C used.
    unsafe {
        sched_prim::sched_init::<MachPlatform>();
        vm_init::vm_mem_bootstrap::<MachPlatform>();
        ipc_init::ipc_bootstrap::<MachPlatform>();
        vm_init::vm_mem_init::<MachPlatform>();
        ipc_init::ipc_init::<MachPlatform>();
        ipc_host::init::<MachPlatform>();

        shootdown::activate_kernel::<MachPlatform>(CpuId::BOOT.bits() as c_int);
        timer::init_timers();
        model_dep::machine_init();
        clock_platform::mapable_time_init();
    }

    let info = machine::info();
    info.max_cpus
        .store(crate::config::MAX_NCPUS as c_int, Ordering::Relaxed);
    info.memory_size
        .store(vm_page::mem_size(), Ordering::Relaxed);
    info.avail_cpus.store(0, Ordering::Relaxed);
    info.major_version
        .store(KERNEL_MAJOR_VERSION, Ordering::Relaxed);
    info.minor_version
        .store(KERNEL_MINOR_VERSION, Ordering::Relaxed);

    unsafe {
        task::init::<MachPlatform>();
        Thread::<MachPlatform>::init();
        processor::system_init::<MachPlatform>();

        sched_prim::recompute_priorities_start::<MachPlatform>();
        mach_factor::compute::<MachPlatform>();
        let startup_thread = Thread::<MachPlatform>::create(kernel_task())
            .unwrap_or(ptr::null_mut());
        let _ = Thread::<MachPlatform>::set_name(
            startup_thread,
            c"startup".as_ptr(),
        );
        (*startup_thread).start(Some(start_kernel_threads));
        thread_swap::doswapin(startup_thread);

        (*startup_thread)
            .set_state((*startup_thread).state() | ThreadState::RUN);
        let _ = Thread::<MachPlatform>::resume(startup_thread);

        cpu_launch_first_thread(startup_thread);
    }
}

/// Creates the kernel's service threads and the bootstrap task.
///
/// # Safety
///
/// Runs once, in the startup thread, before the other CPUs are started.
pub(crate) unsafe extern "C" fn start_kernel_threads() {
    for cpu in CpuId::all() {
        if machine::slot(cpu).is_cpu.load(Ordering::Relaxed) == 0 {
            continue;
        }

        // SAFETY: the kernel task is live, and the slot below is writable;
        // the C ignored a failure the same way.
        unsafe {
            let th = Thread::<MachPlatform>::create(kernel_task())
                .unwrap_or(ptr::null_mut());

            let mut name = [0; 10];
            write_cstr(&mut name, format_args!("idle/{cpu}"));
            let _ = Thread::<MachPlatform>::set_name(th, name.as_ptr());
            sched_prim::thread_bind(th, processor_at(cpu).as_ptr());
            (*th).start(Some(sched_prim::idle_thread_entry::<MachPlatform>));
            thread_swap::doswapin(th);
            let _ = Thread::<MachPlatform>::resume(th);
        }
    }

    // SAFETY: the kernel task is live, and each continuation runs as its own
    // kernel thread, as the C started them.
    unsafe {
        let _ = thread::kernel_thread::<MachPlatform>(
            kernel_task(),
            c"reaper".as_ptr(),
            Some(thread::reaper_thread_continue::<MachPlatform>),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread::<MachPlatform>(
            kernel_task(),
            c"swapin".as_ptr(),
            Some(swapin_thread_continuation),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread::<MachPlatform>(
            kernel_task(),
            c"sched".as_ptr(),
            Some(sched_prim::sched_thread_entry::<MachPlatform>),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread::<MachPlatform>(
            kernel_task(),
            c"intr".as_ptr(),
            Some(crate::device::intr::intr_thread_entry),
            ptr::null_mut(),
        );
        let _ = thread::kernel_thread::<MachPlatform>(
            kernel_task(),
            c"action".as_ptr(),
            Some(processor_action::action_thread::<MachPlatform>),
            ptr::null_mut(),
        );

        crate::arch::x86_64::mp_desc::start_other_cpus();
        device_init::device_service_create();
        (*kernel_task::<MachPlatform>()).creation_time =
            record_time_stamp::<MachPlatform>();
        let Ok(modules) = model_dep::boot_modules() else {
            kpanic!("bootstrap_create", "cannot copy the boot modules");
        };
        mach_boot::bootstrap::create::<MachPlatform>(BootInfo {
            modules,
            cmdline: model_dep::kernel_cmdline(),
            host_port: host::host_self(),
            host_priv_port: host::host_priv_self(),
            device_port: mach_device::ds_routines::master_device_port(),
        });
    }

    // SAFETY: the startup thread becomes the pageout daemon, which never
    // returns.
    unsafe {
        let _ = spl::spl0();
        let _ = Thread::<MachPlatform>::set_name(
            per_cpu::thread(),
            c"pageout".as_ptr(),
        );
        vm_pageout::pageout::<MachPlatform>();
    }
}

/// Hands a CPU its first thread, never to return.
///
/// # Safety
///
/// Runs on a CPU that is taking its first thread, with no thread of its own
/// yet.
pub(crate) unsafe fn cpu_launch_first_thread(
    mut th: *mut Thread<MachPlatform>,
) -> ! {
    let mycpu = cpu_id();
    // The C `machine` and `pmap` routines take the CPU number as an `int`.
    let cpu = mycpu.bits() as c_int;

    // SAFETY: the boot CPU and every AP reach this once, on their own
    // processor.
    unsafe {
        processor_action::cpu_up::<MachPlatform>(cpu);

        spl::splhigh();

        if th.is_null() {
            th = sched_prim::choose_thread(per_cpu::processor().as_ptr());
        }
        if th.is_null() {
            panic_no_thread();
        }

        shootdown::activate_kernel::<MachPlatform>(cpu);
        per_cpu::set_thread(th);
        per_cpu::set_stack((*th).kernel_stack);

        (*th).lock.lock();
        (*th).set_state((*th).state() & !ThreadState::UNINT);
        (*th).lock.unlock();
        (*th).last_processor = per_cpu::processor().as_ptr();

        let map = (*(*th).task).map.cast::<crate::vm::VmMap>();
        shootdown::activate_user((*map).pmap, cpu);

        model_dep::startrtclock();
        pcb::load_context(th);
    }
}

/// The `swapin_thread()` continuation, which `kernel_thread()` starts.
unsafe extern "C" fn swapin_thread_continuation() {
    // SAFETY: the swapper thread runs once and never returns.
    unsafe { thread_swap::swapin_thread::<MachPlatform>() }
}

/// Halts the kernel: the CPU has no thread to run first.
fn panic_no_thread() -> ! {
    kpanic!("cpu_launch_first_thread", "cpu_launch_first_thread")
}
