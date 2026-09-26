// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/mach_clock.h:
//   Copyright (C) 2006, 2007 Free Software Foundation, Inc.
// Derived from kern/mach_clock.c:
//   Copyright (c) 1994-1988 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The clock primitives, which `kern/mach_clock.c` used to define for
//! `kern/mach_clock.h`: the timeout wheel, the wall clock and the host time
//! entries.

use crate::arch::x86_64::apic::{
    hpclock_get_counter_period_nsec, hpclock_read_counter,
};
use crate::arch::x86_64::io_req::{DevT, IoReq};
use crate::arch::x86_64::model_dep::resettodr;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::device::r#return::{DeviceSuccess, IoResultExt};
use crate::glue::time_value::{
    MACH_ADJTIME_NSECS_OMIT, MappedTimeValue, TimeValue, TimeValue64,
};
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
use crate::kern::priority;
use crate::kern::processor::{self, ProcessorState, processor_at};
use crate::kern::sched_prim::{thread_bind, thread_block};
use crate::kern::smp::CpuId;
use crate::kern::timer::Timer;
use crate::kern::types::KernError;
use crate::vm::vm_kern::{self, KERNEL_MAP};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull, addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};
use intrusive_collections::{LinkedList, LinkedListLink, UnsafeRef};

/// `MICROSECONDS_IN_ONE_SECOND` in `kern/mach_clock.c`.
const MICROSECONDS_IN_ONE_SECOND: c_int = 1_000_000;

/// `HZ` in <`machine/mach_param.h>`: the ticks per second on `x86_64`.
const HZ: c_int = 100;

/// `TIMEOUT_WHEEL_BITS` in `kern/mach_clock.c`.
const TIMEOUT_WHEEL_BITS: usize = 8;
const TIMEOUT_WHEEL_SIZE: usize = 1 << TIMEOUT_WHEEL_BITS;
const TIMEOUT_WHEEL_MASK: usize = TIMEOUT_WHEEL_SIZE - 1;

/// `MAX_SOFTCLOCK_STEPS` in `kern/mach_clock.c`.
const MAX_SOFTCLOCK_STEPS: c_int = 100;

/// `NTIMERS` in `kern/mach_clock.c`.
const NTIMERS: usize = 20;

/// `TIMER_LOW_FULL` in <kern/timer.h>: the microsecond count's carry bit.
const TIMER_LOW_FULL: c_uint = 0x8000_0000;

/// `CPU_STATE_*` in <mach/machine.h>: the `cpu_ticks` index.
const CPU_STATE_USER: c_int = 0;
const CPU_STATE_SYSTEM: c_int = 1;
pub(crate) const CPU_STATE_IDLE: c_int = 2;

/// `hz` of `kern/mach_clock.c`: the ticks per second.  The C initializer is
/// `HZ`, and nothing writes it after the boot, but the remaining C half still
/// reads the symbol through <`kern/mach_clock.h`>.
pub static CLOCK_HZ: c_int = HZ;

/// `tick` of `kern/mach_clock.c`: the microseconds per tick.
pub static TICK: c_int = MICROSECONDS_IN_ONE_SECOND / HZ;

/// `struct timeout` of <`kern/mach_clock.h>`: a kernel timeout element.
#[repr(C)]
pub struct Timeout {
    /// `chain`: links the element into the timeout queue.
    pub chain: LinkedListLink,
    /// `fcn`: the routine called at expiry.
    ///
    /// # Safety
    ///
    /// [`softclock()`] calls it at `splhigh()` with no lock held and passes
    /// it [`param`](Self::param) unchanged, so it must accept that
    /// parameter, must not sleep or block, and must not re-enter the timer
    /// wheel except through [`timeout()`] or [`reset_timeout()`].
    pub fcn: Option<unsafe fn(*mut c_void)>,
    /// `param`: the argument passed to `fcn`.
    pub param: *mut c_void,
    /// `t_time`: the expiration time, in ticks since boot.
    pub t_time: usize,
    /// `set`: the `TIMEOUT_*` bits.
    pub set: u8,
}

impl Timeout {
    /// The zero image a C `static` of `struct timeout` began with.
    pub(crate) const fn unlinked() -> Self {
        Self {
            chain: LinkedListLink::new(),
            fcn: None,
            param: ptr::null_mut(),
            t_time: 0,
            set: 0,
        }
    }
}

// The macro-emitted items stay undocumented (`NEW`, `new()`) and hand-roll
// `Clone` on a `Copy` type, so the lints are off around the expansions.
#[allow(missing_docs, clippy::expl_impl_clone_on_copy)]
mod wheel_adapter {
    use super::{LinkedListLink, Timeout};
    use intrusive_collections::UnsafeRef;
    use intrusive_collections::intrusive_adapter;

    intrusive_adapter!(
        /// The adapter for a timeout's `chain` in a timeout-wheel spoke.
        pub TimeoutWheelAdapter = UnsafeRef<Timeout>: Timeout {
            chain => LinkedListLink
        }
    );
}

pub use wheel_adapter::TimeoutWheelAdapter;

// The link and list stand in for the C `queue_entry` member and heads, so
// their sizes keep the offsets below valid.
const _: () = assert!(size_of::<LinkedListLink>() == 16);
const _: () = assert!(size_of::<LinkedList<TimeoutWheelAdapter>>() == 16);

/// `TIMEOUT_ALLOC` in <`kern/mach_clock.h>`: allocated from the pool.
pub const TIMEOUT_ALLOC: u8 = 0x1;
/// `TIMEOUT_ACTIVE`: set while the entry is on the timer queue.
pub const TIMEOUT_ACTIVE: u8 = 0x2;
/// `TIMEOUT_PENDING`: set while the handler has yet to run.
pub const TIMEOUT_PENDING: u8 = 0x4;

/// `time` of `kern/mach_clock.c`: the wall clock, unadjusted.
static mut TIME: TimeValue64 = TimeValue64 {
    seconds: 0,
    nanoseconds: 0,
};

/// `uptime` of `kern/mach_clock.c`: the elapsed time since the boot.
static mut UPTIME: TimeValue64 = TimeValue64 {
    seconds: 0,
    nanoseconds: 0,
};

/// `clock_boottime_offset` of `kern/mach_clock.c`: the boot clock less the
/// real-time clock.
static mut CLOCK_BOOTTIME_OFFSET: TimeValue64 = TimeValue64 {
    seconds: 0,
    nanoseconds: 0,
};

/// `elapsed_ticks` of `kern/mach_clock.c`.  The C type is `unsigned long`,
/// which is the target's `usize`.
static mut ELAPSED_TICKS: usize = 0;

/// `softticks` of `kern/mach_clock.c`: the last tick checked for timers.
static mut SOFTTICKS: usize = 0;

/// `timedelta` and `tickdelta` of `kern/mach_clock.c`: the outstanding
/// gradual adjustment, in microseconds and per tick.
static mut TIMEDELTA: c_int = 0;
static mut TICKDELTA: c_int = 0;

/// `tickadj` of `kern/mach_clock.c`: the C takes its `#else` branch because
/// `HZ` is 100, so the adjustment is `500 / HZ` microseconds per second.
static mut TICKADJ: c_uint = (500 / HZ) as c_uint;

/// `bigadj` of `kern/mach_clock.c`: the bound above which the adjustment is
/// ten times `tickadj`.
static mut BIGADJ: c_uint = 1_000_000;

/// `last_hpc_read` of `kern/mach_clock.c`: the HPET counter at the last
/// clock interrupt.
static mut LAST_HPC_READ: u32 = 0;

/// `nextsoftcheck` of `kern/mach_clock.c`: the next timeout `softclock()`
/// checks.
static mut NEXTSOFTCHECK: *mut Timeout = ptr::null_mut();

/// `mtime` of `kern/mach_clock.c`: the page `mapable_time_init()` wired, or
/// null before that.
static mut MTIME: *mut MappedTimeValue = ptr::null_mut();

/// `timeoutwheel[TIMEOUT_WHEEL_SIZE]` of `kern/mach_clock.c`.
static mut TIMEOUTWHEEL: [LinkedList<TimeoutWheelAdapter>;
    TIMEOUT_WHEEL_SIZE] = [const { LinkedList::new(TimeoutWheelAdapter::new()) };
    TIMEOUT_WHEEL_SIZE];

/// `timeout_timers[NTIMERS]` of `kern/mach_clock.c`.
static mut TIMEOUT_TIMERS: [Timeout; NTIMERS] =
    [const { Timeout::unlinked() }; NTIMERS];

/// `timeout_lock` of `kern/mach_clock.c`: serializes the timer pool.
static TIMEOUT_LOCK: SimpleLock = SimpleLock::new();

/// `twheel_lock` of `kern/mach_clock.c`: serializes the timeout wheel.
static TWHEEL_LOCK: SimpleLock = SimpleLock::new();

/// The spoke `ticks` names.
fn timeout_wheel(ticks: usize) -> *mut LinkedList<TimeoutWheelAdapter> {
    // SAFETY: the mask keeps the index inside the array, which never moves.
    unsafe {
        addr_of_mut!(TIMEOUTWHEEL)
            .cast::<LinkedList<TimeoutWheelAdapter>>()
            .add(ticks & TIMEOUT_WHEEL_MASK)
    }
}

/// `timer_bump()` of <kern/timer.h>: add `usec` and carry into the seconds
/// once the low word fills.
fn timer_bump(timer: &mut Timer, usec: c_uint) {
    timer.low_bits = timer.low_bits.wrapping_add(usec);
    if timer.low_bits & TIMER_LOW_FULL != 0 {
        timer.normalize();
    }
}

/// `cpu_idle()` of <kern/processor.h>: whether CPU `cpu` is idle.
fn cpu_idle(cpu: CpuId) -> bool {
    processor_at(cpu).state() == ProcessorState::Idle
}

/// `update_mapped_time()` in `kern/mach_clock.c`.
fn update_mapped_time(value: TimeValue64) {
    // SAFETY: `MTIME` is the page `mapable_time_init()` wired before any
    // clock interrupt can publish, and it is never unmapped.  Its only
    // writer is the master CPU's clock interrupt, where this runs.
    let mtime = unsafe { MTIME };
    if mtime.is_null() {
        return;
    }

    // The C stored the `int64_t` seconds into the page's `int` fields, and
    // the truncation is part of the interface `include/mach/time_value.h`
    // documents.  The volatile stores and SeqCst fences are the C's
    // `volatile` pointer and `__sync_synchronize()`.
    // SAFETY: `mtime` is the page above; every field written is a plain
    // scalar of the `mapped_time_value_t` mirror.
    unsafe {
        addr_of_mut!((*mtime).check_seconds)
            .write_volatile(value.seconds as c_int);
        addr_of_mut!((*mtime).check_seconds64).write_volatile(value.seconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).microseconds)
            .write_volatile((value.nanoseconds / 1000) as c_int);
        addr_of_mut!((*mtime).time_value.nanoseconds)
            .write_volatile(value.nanoseconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).seconds).write_volatile(value.seconds as c_int);
        addr_of_mut!((*mtime).time_value.seconds)
            .write_volatile(value.seconds);
    }
}

/// `update_mapped_uptime()` in `kern/mach_clock.c`.
fn update_mapped_uptime(value: TimeValue64) {
    // SAFETY: `MTIME` is the page `mapable_time_init()` wired before any clock
    // interrupt can publish, and it is never unmapped. Its only writer
    // is the master CPU's clock interrupt, where this runs; this runs
    // beside it.
    let mtime = unsafe { MTIME };
    if mtime.is_null() {
        return;
    }

    // SAFETY: `MTIME` is the page `mapable_time_init()` wired before any clock
    // interrupt can publish, and it is never unmapped. Its only writer
    // is the master CPU's clock interrupt, where this runs; the uptime
    // fields are plain scalars of the same mirror.
    unsafe {
        addr_of_mut!((*mtime).check_upseconds64).write_volatile(value.seconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).uptime_value.nanoseconds)
            .write_volatile(value.nanoseconds);
        fence(Ordering::SeqCst);
        addr_of_mut!((*mtime).uptime_value.seconds)
            .write_volatile(value.seconds);
    }
}

/// `read_mapped_time()` in `kern/mach_clock.c`, with the C's double-check
/// protocol.
fn read_mapped_time() -> TimeValue64 {
    // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
    // caller; the read-only accesses below are volatile and fenced, as the
    // C's were.
    let mtime = unsafe { MTIME };
    let mut value = TimeValue64 {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
    // caller; the read-only accesses below are volatile and fenced, as
    // the C's were; `last_hpc_read` is the master CPU's counter stamp,
    // read as the C read it.
    let mut last_hpc = unsafe { LAST_HPC_READ };
    loop {
        // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
        // caller; the read-only accesses below are volatile and fenced, as
        // the C's were.
        value.seconds =
            unsafe { addr_of!((*mtime).time_value.seconds).read_volatile() };
        fence(Ordering::SeqCst);
        // SAFETY: `mtime` is the wired time page; the access is volatile and
        // fenced.
        value.nanoseconds = unsafe {
            addr_of!((*mtime).time_value.nanoseconds).read_volatile()
        };
        fence(Ordering::SeqCst);
        // SAFETY: `mtime` is the wired time page; the access is volatile and
        // fenced; the check field is the writer's `seconds` copy.
        let check =
            unsafe { addr_of!((*mtime).check_seconds64).read_volatile() };
        // SAFETY: `last_hpc_read` is the master CPU's counter stamp, read as
        // the C read it.
        if value.seconds == check && last_hpc == unsafe { LAST_HPC_READ } {
            break;
        }
        // SAFETY: the page moved between the reads, so the C retried with
        // a fresh stamp.
        last_hpc = unsafe { LAST_HPC_READ };
    }

    time_value64_add_hpc(&mut value, last_hpc);
    value
}

/// `read_mapped_uptime()` in `kern/mach_clock.c`.
fn read_mapped_uptime() -> TimeValue64 {
    // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
    // caller; the read-only accesses below are volatile and fenced, as
    // the C's were.
    let mtime = unsafe { MTIME };
    let mut value = TimeValue64 {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
    // caller; the read-only accesses below are volatile and fenced, as
    // the C's were; `last_hpc_read` is the master CPU's counter stamp.
    let mut last_hpc = unsafe { LAST_HPC_READ };
    loop {
        // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
        // caller; the read-only accesses below are volatile and
        // fenced, as the C's were; the uptime fields are plain scalars
        // of the same mirror.
        value.seconds =
            unsafe { addr_of!((*mtime).uptime_value.seconds).read_volatile() };
        fence(Ordering::SeqCst);
        // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
        // caller; the read-only accesses below are volatile and
        // fenced, as the C's were; the uptime fields are plain scalars
        // of the same mirror.
        value.nanoseconds = unsafe {
            addr_of!((*mtime).uptime_value.nanoseconds).read_volatile()
        };
        fence(Ordering::SeqCst);
        // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
        // caller; the read-only accesses below are volatile and
        // fenced, as the C's were; the uptime fields are plain scalars
        // of the same mirror.
        let check =
            unsafe { addr_of!((*mtime).check_upseconds64).read_volatile() };
        // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
        // caller; the read-only accesses below are volatile and
        // fenced, as the C's were; the uptime fields are plain scalars
        // of the same mirror.
        if value.seconds == check && last_hpc == unsafe { LAST_HPC_READ } {
            break;
        }
        // SAFETY: `mtime` is the page `mapable_time_init()` wired before any
        // caller; the read-only accesses below are volatile and
        // fenced, as the C's were; the uptime fields are plain scalars
        // of the same mirror; a fresh stamp is read with the value.
        last_hpc = unsafe { LAST_HPC_READ };
    }

    time_value64_add_hpc(&mut value, last_hpc);
    value
}

/// `time_value64_add_hpc()` in `kern/mach_clock.c`: add the nanoseconds since
/// the last clock interrupt, bounded by one tick.
fn time_value64_add_hpc(value: &mut TimeValue64, last_hpc: u32) {
    let now = hpclock_read_counter();
    // The C multiplied the two `uint32_t`s and widened the wrapped product.
    let ns = now
        .wrapping_sub(last_hpc)
        .wrapping_mul(hpclock_get_counter_period_nsec());
    let limit = i64::from(TICK).wrapping_mul(1000);
    let ns = if i64::from(ns) >= limit {
        limit - 1
    } else {
        i64::from(ns)
    };
    *value = (*value).add_nanos(ns);
}

/// `clock_boottime_update()` in `kern/mach_clock.c`: fold the real-time clock's
/// change into the boot clock's offset.
fn clock_boottime_update(new_time: TimeValue64) {
    // SAFETY: the caller runs at `splhigh()`, which serializes the clock
    // interrupt that owns both fields.
    let time = unsafe { TIME };
    let delta = time.sub(new_time);
    // SAFETY: the caller runs at `splhigh()`, which serializes the clock
    // interrupt that owns the offset.
    let offset = unsafe { CLOCK_BOOTTIME_OFFSET };
    // SAFETY: the caller runs at `splhigh()`, which serializes the clock
    // interrupt that owns the offset.
    unsafe { CLOCK_BOOTTIME_OFFSET = offset.add(delta) };
}

/// `clock_interrupt()` in `kern/mach_clock.c`, without the unused PC and with
/// the `boolean_t`s resolved by the adapter.
pub(crate) fn interrupt(usec: c_int, usermode: bool, basepri: bool) {
    let my_cpu = cpu_id();
    let thread = per_cpu::thread();

    if usermode {
        // SAFETY: the clock interrupt runs on the interrupted thread, and
        // `usermode` says that thread is live.
        unsafe { timer_bump(&mut (*thread).user_timer, usec as c_uint) };
    } else if !thread.is_null() {
        // SAFETY: the interrupted thread is live and this CPU is the only
        // writer of its timer.
        unsafe { timer_bump(&mut (*thread).system_timer, usec as c_uint) };
    }

    if usermode {
        // A tick from user mode interrupted no RCU read section.
        crate::kern::rcu::note_qs();
    }

    let state = if usermode {
        CPU_STATE_USER
    } else if cpu_idle(my_cpu) {
        CPU_STATE_IDLE
    } else {
        CPU_STATE_SYSTEM
    };

    // SAFETY: `my_cpu` is the running CPU, so it indexes `machine_slot`, and
    // `state` is one of the three `CPU_STATE_*` values the `cpu_ticks` array
    // holds.  Only this CPU's clock interrupt writes its counters.
    unsafe {
        let slot = machine::slot(my_cpu);
        let ticks = &mut (*slot).cpu_ticks[state as usize];
        *ticks = ticks.wrapping_add(1);
    }

    // SAFETY: `thread` is the interrupted thread or null before the
    // scheduler exists, which is what the C passed; the routine reads it for
    // the quantum.
    unsafe {
        priority::thread_quantum_update(thread, 1, state);
    };

    if my_cpu == CpuId::BOOT {
        // SAFETY: `splhigh()` is the routine <i386/spl.h> declares, and its
        // value is only handed back to `splx()`.
        let s = unsafe { spl::splhigh() };

        TWHEEL_LOCK.lock();
        // SAFETY: the interrupt holds the wheel lock, which serializes every
        // writer of the tick count.
        let ticks = unsafe { ELAPSED_TICKS }.wrapping_add(1);
        // SAFETY: the interrupt holds the wheel lock, which serializes every
        // writer of the tick count.
        unsafe { ELAPSED_TICKS = ticks };
        // SAFETY: the wheel head is initialized and stays at its address.
        let needsoft = !unsafe { (*timeout_wheel(ticks)).is_empty() };
        TWHEEL_LOCK.unlock();
        // SAFETY: `s` is the level `splhigh()` returned.
        unsafe { spl::splx(s) };

        // SAFETY: only the master CPU's clock interrupt touches these
        // globals, and the C updated them the same way.
        let timedelta = unsafe { TIMEDELTA };
        if timedelta == 0 {
            // SAFETY: only the master CPU's clock interrupt touches these
            // globals, and the C updated them the same way; the C
            // widened the `int` product to the nanosecond count.
            unsafe {
                TIME = TIME.add_nanos(i64::from(usec) * 1000);
                UPTIME = UPTIME.add_nanos(i64::from(usec) * 1000);
            }
        } else {
            // SAFETY: only the master CPU's clock interrupt touches
            // `TICKDELTA`.
            let tickdelta = unsafe { TICKDELTA };
            let delta;
            if timedelta < 0 {
                if usec > tickdelta {
                    delta = usec - tickdelta;
                    // SAFETY: only the master CPU's clock interrupt touches
                    // `TICKDELTA`; the C added the two signed ints.
                    unsafe { TIMEDELTA = TIMEDELTA.wrapping_add(tickdelta) };
                } else {
                    // Not enough time passed: keep one microsecond and defer
                    // the correction.
                    delta = 1;
                    // SAFETY: only the master CPU's clock interrupt touches
                    // `TICKDELTA`; the C added the two signed ints.
                    unsafe {
                        TIMEDELTA =
                            TIMEDELTA.wrapping_add(usec).wrapping_sub(1);
                    };
                }
            } else {
                delta = usec.wrapping_add(tickdelta);
                // SAFETY: only the master CPU's clock interrupt touches
                // `TICKDELTA`; the C added the two signed ints.
                unsafe { TIMEDELTA = TIMEDELTA.wrapping_sub(tickdelta) };
            }
            // SAFETY: only the master CPU's clock interrupt touches the
            // counters; the C widened the `int` product.
            unsafe {
                TIME = TIME.add_nanos(i64::from(delta) * 1000);
                UPTIME = UPTIME.add_nanos(i64::from(delta) * 1000);
            }
        }
        // SAFETY: the interrupt owns the globals and the page's only writer.
        update_mapped_time(unsafe { TIME });
        // SAFETY: the interrupt owns the globals and the page's only writer.
        update_mapped_uptime(unsafe { UPTIME });

        if needsoft {
            if basepri {
                // SAFETY: `splsoftclock()` is the routine <i386/spl.h>
                // declares; the C discarded its level because the interrupt
                // return restores it.
                let _ = unsafe { spl::splsoftclock() };
                softclock();
            } else {
                spl::setsoftclock();
            }
        // SAFETY: `splsoftclock()` is the routine <i386/spl.h> declares; the C
        // discarded its level because the interrupt return restores
        // it; the interrupt owns both counters.
        } else if unsafe { SOFTTICKS }.wrapping_add(1)
                // SAFETY: `splsoftclock()` is the routine <i386/spl.h>
                // declares; the C discarded its level because the
                // interrupt return restores it; the interrupt owns
                // both counters.
                == unsafe { ELAPSED_TICKS }
        {
            // When no timer expires in this tick, the catch-up keeps
            // `softticks` from falling behind.
            // SAFETY: the clock interrupt owns both counters.
            unsafe { SOFTTICKS = SOFTTICKS.wrapping_add(1) };
        }

        // SAFETY: the HPET read is side-effect-free and the interrupt owns
        // the stamp.
        unsafe { LAST_HPC_READ = hpclock_read_counter() };
    }
}

/// `softclock()` in `kern/mach_clock.c`: expire every timeout the wheel has
/// reached.
pub(crate) fn softclock() {
    let mut steps: c_int = 0;
    // SAFETY: `splhigh()` is the routine <i386/spl.h> declares, and its
    // value is only handed back to `splx()` or replaced by another
    // `splhigh()`.
    let mut s = unsafe { spl::splhigh() };
    TWHEEL_LOCK.lock();

    // SAFETY: the wheel lock above serializes both tick counters.
    while unsafe { SOFTTICKS } != unsafe { ELAPSED_TICKS } {
        // SAFETY: the wheel lock above serializes the tick count.
        let curticks = unsafe { SOFTTICKS }.wrapping_add(1);
        // SAFETY: the wheel lock above serializes the tick count.
        unsafe { SOFTTICKS = curticks };
        let spoke = timeout_wheel(curticks);

        // The resume point: the saved element when it is still linked, else
        // the spoke's front.  `None` then means the end of the spoke.
        let mut current = match NonNull::new(unsafe { NEXTSOFTCHECK }) {
            // SAFETY: the element is live and the lock guards its links.
            Some(timeout)
                if unsafe { (*timeout.as_ptr()).chain.is_linked() } =>
            {
                Some(timeout)
            }
            // SAFETY: the lock guards the spoke's links.
            _ => unsafe { (*spoke).front().get_ptr() },
        };
        while let Some(timeout) = current {
            if !unsafe { (*timeout.as_ptr()).chain.is_linked() } {
                // A callback removed the saved element; rescan the spoke.
                // SAFETY: the lock guards the spoke's links.
                current = unsafe { (*spoke).front().get_ptr() };
                continue;
            }

            // Capture the successor before a removal clears the links.
            let next = {
                // SAFETY: `timeout` is linked into `spoke`, and the lock
                // keeps that true.
                let mut cursor =
                    unsafe { (*spoke).cursor_mut_from_ptr(timeout.as_ptr()) };
                cursor.move_next();
                cursor.get_ptr()
            };

            // SAFETY: the lock guards the element and its links.
            if unsafe { (*timeout.as_ptr()).t_time } == curticks {
                // SAFETY: the lock above guards the resume pointer.
                unsafe {
                    NEXTSOFTCHECK =
                        next.map_or(ptr::null_mut(), NonNull::as_ptr);
                }
                // SAFETY: `timeout` is linked, and the lock keeps it live.
                let fcn = unsafe { (*timeout.as_ptr()).fcn };
                // SAFETY: `timeout` is linked, and the lock keeps it live.
                let param = unsafe { (*timeout.as_ptr()).param };
                // SAFETY: `timeout` is linked, and the lock keeps it live.
                let allocated =
                    unsafe { (*timeout.as_ptr()).set } & TIMEOUT_ALLOC != 0;
                // SAFETY: `timeout` is linked into `spoke`, and the lock
                // keeps that true; `remove()` also clears the links.
                unsafe {
                    let _ = (*spoke)
                        .cursor_mut_from_ptr(timeout.as_ptr())
                        .remove();
                    if allocated {
                        (*timeout.as_ptr()).set = TIMEOUT_ALLOC;
                    } else {
                        (*timeout.as_ptr()).set &= !TIMEOUT_PENDING;
                    }
                }
                TWHEEL_LOCK.unlock();
                if let Some(fcn) = fcn {
                    // SAFETY: the C armed this callback on the element and
                    // passes the parameter that was stored with it.
                    unsafe { fcn(param) };
                }
                // SAFETY: `splhigh()` is the real asm routine.
                s = unsafe { spl::splhigh() };
                TWHEEL_LOCK.lock();
                steps = 0;
                current = next;
            } else {
                current = next;
                steps += 1;
                if steps >= MAX_SOFTCLOCK_STEPS {
                    // SAFETY: the lock above guards the resume pointer.
                    unsafe {
                        NEXTSOFTCHECK =
                            current.map_or(ptr::null_mut(), NonNull::as_ptr);
                    }
                    TWHEEL_LOCK.unlock();
                    // SAFETY: `s` is the level the last `splhigh()` returned.
                    unsafe { spl::splx(s) };
                    // SAFETY: `splhigh()` is the real asm routine.
                    s = unsafe { spl::splhigh() };
                    TWHEEL_LOCK.lock();
                    steps = 0;
                }
            }
        }
    }

    // SAFETY: the wheel lock above serializes every reader and writer.
    unsafe { NEXTSOFTCHECK = ptr::null_mut() };
    TWHEEL_LOCK.unlock();
    // SAFETY: `s` is the level the last `splhigh()` returned.
    unsafe { spl::splx(s) };
}

/// `timeopen()` of `kern/mach_clock.c`.
pub(crate) fn timeopen(_dev: DevT, _flag: c_int, _ior: *mut IoReq) -> c_int {
    Ok(DeviceSuccess::Success).as_io_return()
}

/// `timeclose()` of `kern/mach_clock.c`.
pub(crate) const fn timeclose(_dev: DevT, _flag: c_int) {}

/// `set_timeout()` in `kern/mach_clock.c`.
///
/// # Safety
///
/// `t` must point at a live [`Timeout`] whose `fcn` and `param` are already
/// set, and it must stay at its address until the timeout expires or
/// `reset_timeout()` cancels it.
pub(crate) unsafe fn set_timeout(t: *mut Timeout, interval: c_uint) {
    if unsafe { (*t).set } & (TIMEOUT_ACTIVE | TIMEOUT_PENDING) != 0 {
        unsafe { reset_timeout(t) };
    }

    // SAFETY: `splhigh()` is the real asm routine, and its value is only
    // handed back to `splx()`.
    let s = unsafe { spl::splhigh() };
    TWHEEL_LOCK.lock();
    unsafe {
        (*t).set |= TIMEOUT_ACTIVE | TIMEOUT_PENDING;
        // Start counting after the next tick, to avoid partial ticks.
        (*t).t_time = ELAPSED_TICKS
            // The C `unsigned long` addition promotes the `unsigned int`
            // interval, which the cast spells.
            .wrapping_add(interval as usize)
            .wrapping_add(1);
        (*timeout_wheel((*t).t_time)).push_back(UnsafeRef::from_raw(t));
    }
    TWHEEL_LOCK.unlock();
    // SAFETY: `s` is the level `splhigh()` returned.
    unsafe { spl::splx(s) };
}

/// `reset_timeout()` in `kern/mach_clock.c`: cancel the timeout when it is
/// pending.
///
/// # Safety
///
/// `t` must point at a live [`Timeout`] that stays at its address across the
/// call.
pub(crate) unsafe fn reset_timeout(t: *mut Timeout) -> bool {
    // SAFETY: `splhigh()` is the real asm routine, and its value is only
    // handed back to `splx()`.
    let s = unsafe { spl::splhigh() };
    TWHEEL_LOCK.lock();

    if unsafe { (*t).set } & TIMEOUT_PENDING == 0 {
        unsafe { (*t).set &= !TIMEOUT_ACTIVE };
        TWHEEL_LOCK.unlock();
        // SAFETY: `s` is the level `splhigh()` returned.
        unsafe { spl::splx(s) };
        return false;
    }

    // SAFETY: the lock above guards the wheel and the `nextsoftcheck`
    // stamp, and `t` is a live linked timeout.
    unsafe {
        (*t).set &= !(TIMEOUT_PENDING | TIMEOUT_ACTIVE);
        let spoke = timeout_wheel((*t).t_time);
        if NEXTSOFTCHECK == t {
            let mut cursor = (*spoke).cursor_mut_from_ptr(t);
            cursor.move_next();
            NEXTSOFTCHECK =
                cursor.get_ptr().map_or(ptr::null_mut(), NonNull::as_ptr);
        }
        let _ = (*spoke).cursor_mut_from_ptr(t).remove();
    }

    TWHEEL_LOCK.unlock();
    // SAFETY: `s` is the level `splhigh()` returned.
    unsafe { spl::splx(s) };
    true
}

/// `reset_timeout_check()` of <`kern/mach_clock.h>`: cancel the timeout if one
/// is active.
///
/// # Safety
///
/// The caller holds the lock protecting `t`, so it is stable and only its
/// owner can have set it.
pub(crate) unsafe fn reset_timeout_check(t: *mut Timeout) {
    if unsafe { (*t).set } & TIMEOUT_ACTIVE != 0 {
        unsafe { reset_timeout(t) };
    }
}

/// `init_timeout()` in `kern/mach_clock.c`.
pub(crate) fn init_timeout() {
    TIMEOUT_LOCK.init();
    TWHEEL_LOCK.init();
    // SAFETY: `kern/startup.c` calls this once during the boot, before any
    // other CPU or interrupt can reach the wheel.
    unsafe {
        ELAPSED_TICKS = 0;
        SOFTTICKS = 0;
    }
}

/// `record_time_stamp()` in `kern/mach_clock.c`: the caller's `stamp` becomes
/// the boot-time frame reading.
///
/// # Safety
///
/// `stamp` must be valid for a write, and `mapable_time_init()` must have
/// run.
pub(crate) unsafe fn record_time_stamp(stamp: *mut TimeValue64) {
    let value = read_mapped_time();
    // SAFETY: `mtime` is live, so the clock offset below is the maintained
    // one.
    let offset = unsafe { CLOCK_BOOTTIME_OFFSET };
    unsafe { stamp.write(value.add(offset)) };
}

/// `read_time_stamp()` of <`kern/mach_clock.h>`: translate a boot-time-frame
/// `stamp` into the caller's real-time `result`.
///
/// # Safety
///
/// `stamp` must point at a readable [`TimeValue64`] and `result` at writable
/// storage for one.
pub(crate) unsafe fn read_time_stamp(
    stamp: *const TimeValue64,
    result: *mut TimeValue64,
) {
    let value = unsafe { stamp.read() };
    // SAFETY: the offset is the maintained global; the reader takes one
    // value of it, exactly as the C `read_time_stamp()` did.
    let offset = unsafe { CLOCK_BOOTTIME_OFFSET };
    unsafe { result.write(value.sub(offset)) };
}

/// `host_get_time()` in `kern/mach_clock.c`: the 32-bit wall clock.
pub(crate) fn get_time(host: *mut c_void) -> Result<TimeValue, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }
    Ok(TimeValue::from(read_mapped_time()))
}

/// `host_get_time64()` in `kern/mach_clock.c`.
pub(crate) fn get_time64(host: *mut c_void) -> Result<TimeValue64, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }
    Ok(read_mapped_time())
}

/// `host_get_uptime64()` in `kern/mach_clock.c`.
pub(crate) fn get_uptime64(
    host: *mut c_void,
) -> Result<TimeValue64, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }
    Ok(read_mapped_uptime())
}

/// `host_set_time64()` in `kern/mach_clock.c`, which is also the body the
/// 32-bit entry falls through to.
pub(crate) fn set_time64(
    host: *mut c_void,
    new_time: TimeValue64,
) -> Result<(), KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }

    let thread = per_cpu::thread();
    let boot = processor::boot_processor();
    // SAFETY: `thread` is the live current thread and `boot` the live
    // boot processor; `thread_bind()` only stores the pairing under the
    // thread lock.
    unsafe { thread_bind(thread, boot) };

    if per_cpu::processor().as_ptr() != boot {
        // SAFETY: the thread is bound to `boot`, so the block resumes
        // there; the C passed `thread_no_continuation`, a null continuation.
        unsafe { thread_block(None) };
    }

    // SAFETY: `splhigh()` is the real asm routine, and its value is only
    // handed back to `splx()`.
    let s = unsafe { spl::splhigh() };
    clock_boottime_update(new_time);
    // SAFETY: the clock interrupt is held off, so the store is atomic
    // against it, as the C's was.
    unsafe { TIME = new_time };
    // SAFETY: the clock interrupt is held off, so the store is atomic against
    // it, as the C's was; the update writes the mapped page's clock
    // fields.
    update_mapped_time(unsafe { TIME });
    resettodr();
    // SAFETY: `s` is the level `splhigh()` returned.
    unsafe { spl::splx(s) };

    // SAFETY: `thread` is the live current thread and the null is the C
    // `PROCESSOR_NULL`, the unbind the C performed.
    unsafe { thread_bind(thread, ptr::null_mut()) };

    Ok(())
}

/// The body of `host_adjust_time64()` in `kern/mach_clock.c`: bind to the
/// master CPU, then read and rewrite the gradual-adjustment globals at
/// `splclock()`, answering the outstanding adjustment.
pub(crate) fn adjust_time(
    host: *mut c_void,
    new_adjustment: TimeValue64,
) -> Result<TimeValue64, KernError> {
    if host.is_null() {
        return Err(KernError::InvalidHost);
    }

    let thread = per_cpu::thread();
    let boot = processor::boot_processor();
    // SAFETY: `thread` is the live current thread and `boot` the live
    // boot processor; `thread_bind()` only stores the pairing under the
    // thread lock.
    unsafe { thread_bind(thread, boot) };

    if per_cpu::processor().as_ptr() != boot {
        // SAFETY: the thread is bound to `boot`, so the block resumes
        // there; the C passed `thread_no_continuation`, a null continuation.
        unsafe { thread_block(None) };
    }

    // SAFETY: `splclock()` is the real asm routine, and its return value is
    // only handed back to `splx()`.
    let s = unsafe { spl::splclock() };

    // SAFETY: the clock interrupt is held off, so `timedelta` cannot change
    // under this read.
    let timedelta = unsafe { TIMEDELTA };
    let old = TimeValue64 {
        seconds: i64::from(timedelta / MICROSECONDS_IN_ONE_SECOND),
        nanoseconds: i64::from(timedelta % MICROSECONDS_IN_ONE_SECOND) * 1000,
    };

    if new_adjustment.nanoseconds != MACH_ADJTIME_NSECS_OMIT {
        // SAFETY: the clock interrupt is held off, so `timedelta` cannot
        // change under this read; the tuning globals and the clock
        // lock below it belong to the master CPU.
        unsafe {
            let mut ndelta = new_adjustment
                .seconds
                .wrapping_mul(i64::from(MICROSECONDS_IN_ONE_SECOND))
                .wrapping_add(new_adjustment.nanoseconds / 1000);

            if TIMEDELTA == 0 {
                if ndelta > i64::from(BIGADJ)
                    || ndelta < i64::from(BIGADJ.wrapping_neg())
                {
                    // The C product is `unsigned`; the assignment narrows it
                    // to the `int` tickdelta, which the cast spells.
                    TICKDELTA = TICKADJ.wrapping_mul(10) as c_int;
                } else {
                    TICKDELTA = TICKADJ as c_int;
                }
            }

            let tickdelta = i64::from(TICKDELTA);
            if ndelta % tickdelta != 0 {
                ndelta = ndelta / tickdelta * tickdelta;
            }
            // The C assignment narrows `int64_t` to the `int` timedelta,
            // which the cast spells.
            TIMEDELTA = ndelta as c_int;
        }
    }

    // SAFETY: `s` is the level `splclock()` returned.
    unsafe { spl::splx(s) };

    // SAFETY: `thread` is the live current thread and the null is the C
    // `PROCESSOR_NULL`, the unbind the C performed.
    unsafe { thread_bind(thread, ptr::null_mut()) };

    Ok(old)
}

/// `mapable_time_init()` in `kern/mach_clock.c`.
pub(crate) fn mapable_time_init() {
    // SAFETY: `kernel_map` is the live kernel map this boot step runs on.
    let map = unsafe { NonNull::new_unchecked(KERNEL_MAP) };
    let Ok(page) = vm_kern::kmem_alloc_wired(map, crate::vm::types::PAGE_SIZE)
    else {
        kpanic!("mapable_time_init", "mapable_time_init");
    };

    // SAFETY: `page` is the wired page just allocated, so zeroing it and
    // recording it is what the C `memset()` and assignment did.
    unsafe {
        (page as *mut u8).write_bytes(0, crate::vm::types::PAGE_SIZE);
        MTIME = page as *mut MappedTimeValue;
    }
    // SAFETY: the page is live, and this boot step is its only writer.
    update_mapped_time(unsafe { TIME });
    // SAFETY: the page is live, and this boot step is its only writer.
    update_mapped_uptime(unsafe { UPTIME });
}

/// `timeout()` in `kern/mach_clock.c`: hand out a preallocated element from
/// the pool.
///
/// # Safety
///
/// `param` is passed to `fcn` at expiry; the pool element stays at its
/// address until it expires or is cancelled.
pub(crate) unsafe fn timeout(
    fcn: Option<unsafe fn(*mut c_void)>,
    param: *mut c_void,
    interval: c_int,
) -> *mut Timeout {
    // SAFETY: `splhigh()` is the real asm routine, and its value is only
    // handed back to `splx()`.
    let s = unsafe { spl::splhigh() };
    TIMEOUT_LOCK.lock();

    let mut selected: *mut Timeout = ptr::null_mut();
    // SAFETY: the pool is a live static, and the lock above serializes every
    // claim.
    unsafe {
        for i in 0..NTIMERS {
            let t = addr_of_mut!(TIMEOUT_TIMERS).cast::<Timeout>().add(i);
            if (*t).set & TIMEOUT_ACTIVE == 0 {
                selected = t;
                break;
            }
        }
    }
    if selected.is_null() {
        kpanic!("timeout", "more than NTIMERS timeouts");
    }

    // SAFETY: `selected` was free under the lock, and this caller now owns
    // it.
    unsafe {
        (*selected).set |= TIMEOUT_ALLOC;
        (*selected).fcn = fcn;
        (*selected).param = param;
    }
    TIMEOUT_LOCK.unlock();
    // SAFETY: `s` is the level `splhigh()` returned.
    unsafe { spl::splx(s) };

    // SAFETY: `selected` is a live element the caller now owns, and the C
    // converted the `int` interval to the unsigned parameter.
    unsafe { set_timeout(selected, interval as c_uint) };
    selected
}

/// The wall clock `clock_interrupt()` maintains: `time` of `kern/mach_clock.c`.
///
/// # Safety
///
/// The caller must hold the clock interrupt off, as `splhigh()` does, or
/// accept a torn reading as the C did.
pub(crate) unsafe fn wallclock() -> TimeValue64 {
    unsafe { TIME }
}

/// Replace the wall clock: what `model_dep.rs`'s `set_wallclock()` does
/// under `splhigh()`.
///
/// # Safety
///
/// The caller must hold the clock interrupt off, as `splhigh()` does.
pub(crate) unsafe fn set_wallclock(value: TimeValue64) {
    unsafe { TIME = value };
}

/// The mapped time page: `mtime` of `kern/mach_clock.c`.
///
/// # Safety
///
/// The page is live only after `mapable_time_init()` ran at boot.
pub(crate) unsafe fn mapped_time_page() -> *mut MappedTimeValue {
    unsafe { MTIME }
}

/// The ticks since boot: `elapsed_ticks` of `kern/mach_clock.c`.
///
/// # Safety
///
/// The value is updated by the master CPU's clock interrupt, so a reader
/// sees a snapshot.
pub(crate) unsafe fn elapsed_ticks() -> usize {
    unsafe { ELAPSED_TICKS }
}

const _: () = {
    assert!(size_of::<Timeout>() == 48);
    assert!(offset_of!(Timeout, chain) == 0);
    assert!(offset_of!(Timeout, fcn) == 16);
    assert!(offset_of!(Timeout, param) == 24);
    assert!(offset_of!(Timeout, t_time) == 32);
    assert!(offset_of!(Timeout, set) == 40);
};
