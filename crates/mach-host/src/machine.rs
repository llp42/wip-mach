// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine slots and the machine abstraction: CPUs coming up and going
//! down, processor assignment and shutdown, and reboot.

use crate::error::Error;
use crate::platform::Platform;
use crate::types::Halt;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::offset_of;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use mach_thread::priority;
use mach_thread::processor::processor_at;
use mach_thread::smp::{CpuId, MAX_NCPUS};
use mach_thread::thread::Thread;
use mach_thread::types::ProcessorState;

/// The per-state tick counters every machine slot carries.
pub(crate) const CPU_STATE_MAX: usize = 3;

/// The `cpu_ticks` user index.
pub(crate) const CPU_STATE_USER: c_int = 0;
/// The `cpu_ticks` system index.
pub(crate) const CPU_STATE_SYSTEM: c_int = 1;
/// The `cpu_ticks` idle index.
pub(crate) const CPU_STATE_IDLE: c_int = 2;
const _: () = assert!(CPU_STATE_IDLE == priority::CPU_STATE_IDLE);

/// `struct machine_slot`: what the arch probe records about each possible CPU.
///
/// Other CPUs read a CPU's slot while it is written, so every field is an
/// atomic, laid out as the C record's integer.
#[repr(C)]
#[derive(Debug)]
#[allow(missing_docs)]
pub struct MachineSlot {
    pub is_cpu: AtomicI32,
    pub cpu_type: AtomicI32,
    pub cpu_subtype: AtomicI32,
    pub running: AtomicI32,
    /// `cpu_ticks`: the ticks accumulated per `CPU_STATE_*`.
    pub cpu_ticks: [AtomicI32; CPU_STATE_MAX],
    /// `clock_freq`: the clock interrupt frequency.
    pub clock_freq: AtomicI32,
}

impl MachineSlot {
    /// The all-zero image a C `static struct machine_slot` began with.
    const fn zeroed() -> Self {
        Self {
            is_cpu: AtomicI32::new(0),
            cpu_type: AtomicI32::new(0),
            cpu_subtype: AtomicI32::new(0),
            running: AtomicI32::new(0),
            cpu_ticks: [const { AtomicI32::new(0) }; CPU_STATE_MAX],
            clock_freq: AtomicI32::new(0),
        }
    }
}

const _: () = assert!(size_of::<MachineSlot>() == 32);
const _: () = assert!(align_of::<MachineSlot>() == align_of::<c_int>());
const _: () = assert!(offset_of!(MachineSlot, is_cpu) == 0);
const _: () = assert!(offset_of!(MachineSlot, cpu_type) == 4);
const _: () = assert!(offset_of!(MachineSlot, cpu_subtype) == 8);
const _: () = assert!(offset_of!(MachineSlot, running) == 12);
const _: () = assert!(offset_of!(MachineSlot, cpu_ticks) == 16);
const _: () = assert!(offset_of!(MachineSlot, clock_freq) == 28);

/// `struct machine_info`: what the boot path records about the machine as a
/// whole, read by any CPU, so every field is an atomic.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachineInfo {
    pub major_version: AtomicI32,
    pub minor_version: AtomicI32,
    pub max_cpus: AtomicI32,
    pub avail_cpus: AtomicI32,
    /// `memory_size`: a `vm_size_t`, eight bytes on `x86_64`.
    pub memory_size: AtomicUsize,
}

const _: () = {
    assert!(size_of::<MachineInfo>() == 24);
    assert!(align_of::<MachineInfo>() == 8);
    assert!(offset_of!(MachineInfo, major_version) == 0);
    assert!(offset_of!(MachineInfo, minor_version) == 4);
    assert!(offset_of!(MachineInfo, max_cpus) == 8);
    assert!(offset_of!(MachineInfo, avail_cpus) == 12);
    assert!(offset_of!(MachineInfo, memory_size) == 16);
};

/// What the boot path records about the machine as a whole.
static MACHINE_INFO: MachineInfo = MachineInfo {
    major_version: AtomicI32::new(0),
    minor_version: AtomicI32::new(0),
    max_cpus: AtomicI32::new(0),
    avail_cpus: AtomicI32::new(0),
    memory_size: AtomicUsize::new(0),
};

/// The slot of each possible CPU.
static MACHINE_SLOT: [MachineSlot; MAX_NCPUS] =
    [const { MachineSlot::zeroed() }; MAX_NCPUS];

/// The slot of CPU `cpu`; `cpu` is below `MAX_NCPUS`, the array's length.
#[must_use]
pub fn slot(cpu: CpuId) -> &'static MachineSlot {
    &MACHINE_SLOT[cpu.as_usize()]
}

/// Whether CPU `cpu` is idle.
fn cpu_idle<P: Platform>(cpu: CpuId) -> bool {
    processor_at::<P>(cpu).state() == ProcessorState::Idle
}

/// Charge one clock tick to the interrupted context's user/system timers
/// and this CPU's `cpu_ticks`.
///
/// # Safety
///
/// `thread` must be the interrupted thread or null, and only this CPU may
/// write its own `cpu_ticks` slot.
pub unsafe fn tick_accounting<P: Platform>(
    thread: *mut Thread<P>,
    usec: c_uint,
    usermode: bool,
) {
    let my_cpu = P::current_cpu();

    if usermode {
        // SAFETY: the clock interrupt runs on the interrupted thread, and
        // `usermode` says that thread is live.
        unsafe { (*thread).sched.user_timer.bump(usec) };
    } else if !thread.is_null() {
        // SAFETY: the interrupted thread is live and this CPU is the only
        // writer of its timer.
        unsafe { (*thread).sched.system_timer.bump(usec) };
    }

    let state = if usermode {
        CPU_STATE_USER
    } else if cpu_idle::<P>(my_cpu) {
        CPU_STATE_IDLE
    } else {
        CPU_STATE_SYSTEM
    };

    // `state` is one of the three `CPU_STATE_*` values `cpu_ticks` holds.
    slot(my_cpu).cpu_ticks[state as usize].fetch_add(1, Ordering::Relaxed);

    // SAFETY: `thread` is the interrupted thread or null before the
    // scheduler exists, which is what the C passed; the routine reads it for
    // the quantum.
    unsafe {
        priority::thread_quantum_update(thread, 1, state);
    }
}

/// The live `machine_info`.
#[must_use]
pub fn info() -> &'static MachineInfo {
    &MACHINE_INFO
}

bitflags::bitflags! {
    /// The option word of `host_reboot()`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RebootOptions: c_int {
        /// Enter the kernel debugger from user level instead of rebooting.
        const DEBUGGER = 0x1000;
        /// Halt instead of rebooting.
        const HALT = 0x08;
        // The options the kernel ignores.
        const _ = !0;
    }
}

/// Reboots or halts the machine, as `options` asks. The host privilege
/// pointer is only tested for null: the MIG stub that converted the request
/// port owns whether it is live.
pub fn host_reboot<P: Platform>(
    host_priv: *mut c_void,
    options: c_int,
) -> Result<(), Error> {
    if host_priv.is_null() {
        return Err(Error::InvalidHost);
    }

    let options = RebootOptions::from_bits_retain(options);
    let halt = if options.contains(RebootOptions::DEBUGGER) {
        Halt::Debugger
    } else if options.contains(RebootOptions::HALT) {
        Halt::Halt
    } else {
        Halt::Reboot
    };
    P::halt(halt)
}
