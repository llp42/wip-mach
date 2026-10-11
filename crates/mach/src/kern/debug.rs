// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The soft debugger and the panic path.

use crate::arch::x86_64::model_dep;
use crate::arch::x86_64::per_cpu::cpu_id;
use crate::arch::x86_64::spl;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::startup::reboot_on_panic;
use crate::utils::delay::delay;
use core::ffi::CStr;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use mach_vm::simple_lock::SimpleLock;

/// The lock that serializes panic reports.
static PANIC_LOCK: SimpleLock = SimpleLock::new();

/// The marker that says a panic is already being reported.
static PANIC_TAKEN: AtomicBool = AtomicBool::new(false);

/// The CPU that took the panic.
static PANIC_CPU: AtomicU32 = AtomicU32::new(0);

/// Prints `message` as a panic and halts the machine.
pub(crate) fn panic_fmt(
    file: &str,
    line: u32,
    fun: &str,
    message: fmt::Arguments<'_>,
) -> ! {
    panic_init();

    // SAFETY: `splhigh()` is the C spl call and returns the level to restore.
    let spl = unsafe { spl::splhigh() };
    PANIC_LOCK.lock();
    if PANIC_TAKEN.load(Ordering::Acquire) {
        if cpu_id().bits() != PANIC_CPU.load(Ordering::Acquire) {
            PANIC_LOCK.unlock();
            // SAFETY: `spl` is the value `splhigh()` returned.
            unsafe { spl::splx(spl) };
            model_dep::halt_cpu();
        }
    } else {
        PANIC_TAKEN.store(true, Ordering::Release);
        PANIC_CPU.store(cpu_id().bits(), Ordering::Release);
    }
    PANIC_LOCK.unlock();
    // SAFETY: `spl` is the value `splhigh()` returned.
    unsafe { spl::splx(spl) };

    kprint!("panic ");
    kprint!("{{cpu{}}} ", PANIC_CPU.load(Ordering::Acquire));
    kprint!("{}:{}: {}: ", file, line, fun);
    crate::kern::console::write_fmt(message);
    kprint!("\n");

    let mut i = 1000;
    while i > 0 {
        delay(1_000_000);
        i -= 1;
    }

    model_dep::halt_all_cpus(reboot_on_panic())
}

/// Report a panic from Rust.
macro_rules! kpanic {
    ($fun:expr, $($arg:tt)*) => {
        $crate::kern::debug::panic_fmt(
            file!(),
            line!(),
            $fun,
            format_args!($($arg)*),
        )
    };
}
pub(crate) use kpanic;

/// Reports a debugger entry with `message` and continues: the kernel has no
/// debugger.
pub(crate) fn soft_debugger(message: &CStr) {
    kprint!("Debugger invoked: {}\n", CStrArg::from(message));
    kprint!("But no debugger, continuing.\n");
}

/// Halts the machine: the kernel has no debugger to enter.
pub(crate) fn debugger(_message: &CStr) {
    kpanic!("debugger", "Debugger invoked, but there isn't one!")
}

/// Initializes the panic lock.
pub(crate) fn panic_init() {
    PANIC_LOCK.init();
}
