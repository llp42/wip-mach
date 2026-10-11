// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The basic, scheduling and load information `host_info()` reports, and the
//! conversions that fill them from the machine.

use crate::host::Host;
use crate::machine;
use crate::platform::Platform;
use core::ffi::{c_int, c_uint};
use core::mem::{offset_of, size_of};
use core::sync::atomic::Ordering;
use mach_sched::sched::TICK;
use mach_thread::mach_factor;
use mach_thread::processor::boot_processor;
use mach_thread::smp::{CpuId, MAX_NCPUS};
use zerocopy::{Immutable, IntoBytes};

/// `HOST_INFO_MAX`: the elements the host-info array holds.
pub const HOST_INFO_MAX: usize = 1024;

/// The basic information `host_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct HostBasicInfo {
    /// The most CPUs the machine can have.
    pub max_cpus: c_int,
    /// The CPUs now available.
    pub avail_cpus: c_int,
    /// `memory_size`: an `rpc_vm_size_t`, pointer-sized on `x86_64`.
    pub memory_size: usize,
    /// The CPU type.
    pub cpu_type: c_int,
    /// The CPU subtype.
    pub cpu_subtype: c_int,
}

impl HostBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

/// The scheduling information `host_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct HostSchedInfo {
    /// The shortest timeout, in milliseconds.
    pub min_timeout: c_int,
    /// The shortest quantum, in milliseconds.
    pub min_quantum: c_int,
}

impl HostSchedInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

/// The load information `host_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct HostLoadInfo {
    /// `avenrun`: the load averages, scaled by `LOAD_SCALE`.
    pub avenrun: [c_int; 3],
    /// `mach_factor`: the mach factors, scaled by `LOAD_SCALE`.
    pub mach_factor: [c_int; 3],
}

impl HostLoadInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

impl HostBasicInfo {
    /// The basic information of `_host`, a host the caller holds.
    #[must_use]
    pub fn of<P: Platform>(_host: &Host) -> Self {
        // SAFETY: `boot_processor` is the live processor
        // `processor::bootstrap` initialized.
        let slot = machine::slot(unsafe { (*boot_processor::<P>()).cpu_id });
        let machine_info = machine::info();

        Self {
            max_cpus: machine_info.max_cpus.load(Ordering::Relaxed),
            avail_cpus: machine_info.avail_cpus.load(Ordering::Relaxed),
            memory_size: machine_info.memory_size.load(Ordering::Relaxed),
            cpu_type: slot.cpu_type.load(Ordering::Relaxed),
            cpu_subtype: slot.cpu_subtype.load(Ordering::Relaxed),
        }
    }
}

impl From<&Host> for HostSchedInfo {
    fn from(_host: &Host) -> Self {
        let tick_rate = TICK;
        let min_quantum = mach_sched::sched::min_quantum();

        Self {
            min_timeout: tick_rate / 1000,
            // The C overflowed an `int` the same way; the clock and the
            // quantum are both small at run time.
            min_quantum: min_quantum.wrapping_mul(tick_rate) / 1000,
        }
    }
}

impl From<&Host> for HostLoadInfo {
    fn from(_host: &Host) -> Self {
        let avenrun = mach_factor::avenrun();
        let factor = mach_factor::mach_factor();
        let mut load = Self {
            avenrun: [0; 3],
            mach_factor: [0; 3],
        };

        for (i, (average, factor)) in
            avenrun.iter().zip(factor.iter()).enumerate()
        {
            // The C assigned a `long` to an `integer_t`, a deliberate
            // truncation.
            load.avenrun[i] = *average as c_int;
            load.mach_factor[i] = *factor as c_int;
        }

        load
    }
}

/// The `HOST_PROCESSOR_SLOTS` flavor: write the number of every running CPU,
/// and return how many there are.
///
/// # Safety
///
/// `out` must be writable for [`MAX_NCPUS`] `c_int`s.
pub unsafe fn processor_slots(_host: &Host, out: *mut c_int) -> c_uint {
    let mut count = 0;
    for cpu in CpuId::all() {
        let slot = machine::slot(cpu);
        let is_cpu = slot.is_cpu.load(Ordering::Relaxed);
        let running = slot.running.load(Ordering::Relaxed);
        if is_cpu != 0 && running != 0 {
            // SAFETY: at most `MAX_NCPUS` CPUs are written, and the caller
            // holds that many slots.
            unsafe { out.add(count).write(cpu.bits() as c_int) };
            count += 1;
        }
    }

    count as c_uint
}

// struct host_basic_info {
//  integer_t      max_cpus;     /* max number of cpus possible */
//  integer_t      avail_cpus;   /* number of cpus now available */
//  vm_size_t      memory_size;  /* size of memory in bytes */
//  cpu_type_t     cpu_type;     /* cpu type */
//  cpu_subtype_t  cpu_subtype;  /* cpu subtype */
// };
const _: () = assert!(size_of::<HostBasicInfo>() == 24);
const _: () = assert!(align_of::<HostBasicInfo>() == 8);
const _: () = assert!(offset_of!(HostBasicInfo, max_cpus) == 0);
const _: () = assert!(offset_of!(HostBasicInfo, avail_cpus) == 4);
const _: () = assert!(offset_of!(HostBasicInfo, memory_size) == 8);
const _: () = assert!(offset_of!(HostBasicInfo, cpu_type) == 16);
const _: () = assert!(offset_of!(HostBasicInfo, cpu_subtype) == 20);

// struct host_sched_info {
//  integer_t  min_timeout;  /* minimum timeout in milliseconds */
//  integer_t  min_quantum;  /* minimum quantum in milliseconds */
// };
const _: () = assert!(size_of::<HostSchedInfo>() == 8);
const _: () = assert!(offset_of!(HostSchedInfo, min_timeout) == 0);
const _: () = assert!(offset_of!(HostSchedInfo, min_quantum) == 4);

// struct host_load_info {
//  integer_t  avenrun[3];      /* scaled by LOAD_SCALE */
//  integer_t  mach_factor[3];  /* scaled by LOAD_SCALE */
// };
const _: () = assert!(size_of::<HostLoadInfo>() == 24);
const _: () = assert!(offset_of!(HostLoadInfo, avenrun) == 0);
const _: () = assert!(offset_of!(HostLoadInfo, mach_factor) == 12);

const _: () = assert!(MAX_NCPUS <= HOST_INFO_MAX);
