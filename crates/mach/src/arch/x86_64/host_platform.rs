// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The host's platform: what the host asks of the `x86_64` machine.

use crate::arch::x86_64::clock_platform::CLOCK;
use crate::arch::x86_64::model_dep::halt_all_cpus;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::kern::debug;
use clock::Clock;
use core::ffi::c_int;
use mach_host::platform::Platform;
use mach_host::types::Halt;

// SAFETY: each item keeps its documented contract: the clock is the
// machine's one clock, the level is the clock interrupt's, and the halt
// stops every CPU.
unsafe impl Platform for MachPlatform {
    fn clock() -> &'static Clock<Self> {
        &CLOCK
    }

    unsafe fn splclock() -> c_int {
        // SAFETY: the caller hands the level back to `splx`.
        unsafe { spl::splclock() }
    }

    fn halt(halt: Halt) -> ! {
        match halt {
            Halt::Debugger => {
                debug::debugger(c"debugger");
                halt_all_cpus(0)
            }
            Halt::Halt => halt_all_cpus(0),
            Halt::Reboot => halt_all_cpus(1),
        }
    }
}
