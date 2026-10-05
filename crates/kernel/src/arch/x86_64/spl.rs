// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/spl.S and x86_64/spl.S:
//   Copyright (c) 1995 Shantanu Goel
//   All Rights Reserved.
//
//   Permission to use, copy, modify and distribute this software and its
//   documentation is hereby granted, provided that both the copyright
//   notice and this permission notice appear in all copies of the
//   software, derivative works or modified versions, and any portions
//   thereof, and that both notices appear in supporting documentation.
//
//   THE AUTHOR ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
//   CONDITION.  THE AUTHOR DISCLAIMS ANY LIABILITY OF ANY KIND FOR
//   ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt-masking entries.
//!
//! Levels 1 through 6 all collapse into [`SPL7`], so `spl1` to `spl6` and the
//! named aliases share one body: they mask interrupts and raise the current
//! level to 7, returning the level they replaced.  The interrupt flag, the
//! flags word [`sploff`] and [`splon`] carry, and the `lock add` fence are the
//! only instructions Rust cannot spell; the current level itself is a plain
//! per-CPU read and write.

use crate::arch::x86_64::clock_platform::softclock;
use crate::arch::x86_64::ioapic::CURR_IPL;
use crate::arch::x86_64::per_cpu;
use core::arch::asm;
use core::ffi::{c_int, c_ulong};
use core::sync::atomic::{AtomicI32, Ordering};

/// The level with interrupts open.
const SPL0: c_int = 0;

/// The level with interrupts blocked.
const SPL7: c_int = 7;

/// Nonzero while `softclock()` is owed a call.
///
/// The C's word is a plain `long`; Rust reaches it through an atomic
/// because a setter on one CPU can meet a drain on another.
static SOFTCLK_PENDING: AtomicI32 = AtomicI32::new(0);

/// A full barrier that names this CPU's own stack word, which no other CPU has
/// cached.
fn serializing_fence() {
    // SAFETY: The locked add names the word at the stack pointer and adds
    // zero to it, so it neither pushes nor reaches the red zone and
    // `nostack` holds.
    unsafe {
        asm!("lock; addl $0, (%rsp)", options(att_syntax, nostack));
    }
}

fn interrupts_disable() {
    // SAFETY: CLI changes only the interrupt flag, which this module owns
    // while it runs.
    unsafe { asm!("cli", options(nostack)) };
}

fn interrupts_enable() {
    // SAFETY: STI changes only the interrupt flag, which this module owns
    // while it runs.
    unsafe { asm!("sti", options(nostack)) };
}

fn current_ipl() -> c_int {
    // SAFETY: The `cpu_id()` call names a live CPU, so its slot is inside
    // `CURR_IPL`, and no other CPU writes that slot while this one runs.
    unsafe { ipl_slot().read() }
}

fn set_current_ipl(level: c_int) {
    // SAFETY: As `current_ipl()`; each CPU reaches only its own slot.
    unsafe { ipl_slot().write(level) };
}

fn ipl_slot() -> *mut c_int {
    let cpu = per_cpu::cpu_id();
    // SAFETY: `cpu_id()` is below `MAX_NCPUS`, the array's length, so the
    // element the offset reaches is inside the array.
    unsafe { (&raw mut CURR_IPL).cast::<c_int>().add(cpu.as_usize()) }
}

/// Masks interrupts and raises the current level to [`SPL7`], returning the
/// level it replaced.
fn raise_to_spl7() -> c_int {
    serializing_fence();
    interrupts_disable();
    let old = current_ipl();
    set_current_ipl(SPL7);
    old
}

/// Opens the interrupt gates, running a pending softclock first.
///
/// # Safety
///
/// The caller must be in kernel mode with `%gs` based at the running CPU's
/// per-CPU block, and must not hold a lock that `softclock()` could want.
pub(crate) unsafe fn spl0() -> c_int {
    serializing_fence();
    let old = current_ipl();
    interrupts_disable();
    // Relaxed: The flag guards no other data, and the swap only settles
    // which CPU runs the pending softclock.
    if SOFTCLK_PENDING.swap(0, Ordering::Relaxed) != 0 {
        let _ = unsafe { spl1() };
        softclock();
        interrupts_disable();
    }
    if current_ipl() != SPL0 {
        set_current_ipl(SPL0);
    }
    interrupts_enable();
    old
}

/// Defines the `splsoftclock`..`splhi` aliases, which share one body with
/// [`spl7`].
///
/// # Safety
///
/// Each generated entry requires kernel mode with `%gs` based at the running
/// CPU's per-CPU block.
macro_rules! ipl_entry {
    ($($name:ident),+ $(,)?) => {
        $(
            /// Clears the interrupt flag and raises the current level to
            /// [`SPL7`], returning the mask it replaced.
            ///
            /// # Safety
            ///
            /// The caller must be in kernel mode with `%gs` based at the
            /// running CPU's per-CPU block.
            pub unsafe fn $name() -> c_int {
                raise_to_spl7()
            }
        )+
    };
}

ipl_entry!(
    splsoftclock,
    spl1,
    spl2,
    spl3,
    splnet,
    splhdw,
    spl4,
    splbio,
    spldcm,
    spl5,
    spltty,
    splimp,
    splvm,
    spl6,
    splclock,
    splsched,
    splhigh,
    splhi,
);

/// Clears the interrupt flag and raises the current level to [`SPL7`],
/// returning the mask it replaced.  The interrupt entry calls it from
/// assembly.
///
/// # Safety
///
/// The caller must be in kernel mode with `%gs` based at the running CPU's
/// per-CPU block.
pub(crate) unsafe extern "C" fn spl7() -> c_int {
    raise_to_spl7()
}

/// The tail of [`splx`]: sets the current level to `level` and returns the
/// mask it replaced.  Level 7 goes through [`spl7`], which masks interrupts
/// first.
///
/// # Safety
///
/// The caller must be in kernel mode with `%gs` based at the running CPU's
/// per-CPU block.
unsafe fn spl(level: c_int) -> c_int {
    if level == SPL7 {
        return unsafe { spl7() };
    }
    interrupts_disable();
    let old = current_ipl();
    set_current_ipl(level);
    interrupts_enable();
    old
}

/// Lowers the mask to `level` and returns the mask it replaced.
///
/// # Safety
///
/// The caller must be in kernel mode with `%gs` based at the running CPU's
/// per-CPU block, and must not hold a lock that the softclock path could want
/// when `level` is [`SPL0`].
pub(crate) unsafe fn splx(level: c_int) -> c_int {
    if level == SPL0 {
        return unsafe { spl0() };
    }
    let old = current_ipl();
    if level != old {
        return unsafe { spl(level) };
    }
    if level != SPL7 {
        interrupts_enable();
    }
    old
}

/// Like [`splx`], but returns with interrupts disabled and without the old
/// mask.
///
/// # Safety
///
/// The caller must be on an interrupt-return path, so the mask it sets
/// is the one that was active before the interrupt.
pub(crate) unsafe extern "C" fn splx_cli(level: c_int) {
    interrupts_disable();
    // Relaxed: As `spl0()`; the interrupt-return path leans on the same
    // atomic clear.
    if level == SPL0 && SOFTCLK_PENDING.swap(0, Ordering::Relaxed) != 0 {
        let _ = unsafe { spl1() };
        softclock();
        interrupts_disable();
    }
    if current_ipl() != level {
        set_current_ipl(level);
    }
}

/// Returns the interrupt flag and disables interrupts.
///
/// # Safety
///
/// The caller must be in kernel mode; the returned flags must be
/// restored with [`splon`].
pub(crate) unsafe fn sploff() -> c_ulong {
    let flags: c_ulong;
    // SAFETY: The `pushfq`/`popq` pair reads the flags into a register and
    // leaves the stack as it found it.
    unsafe {
        asm!(
            "pushfq",
            "popq {flags}",
            flags = out(reg) flags,
            options(att_syntax),
        );
    }
    interrupts_disable();
    flags
}

/// Restores the interrupt flag a [`sploff`] returned.
///
/// # Safety
///
/// `n` must come from an unmatched [`sploff`] on this CPU.
pub(crate) unsafe fn splon(n: c_ulong) {
    // SAFETY: The `pushq`/`popfq` pair restores the flags word the caller
    // got from `sploff`, and the stack ends where it started.
    unsafe {
        asm!("pushq {n}", "popfq", n = in(reg) n, options(att_syntax));
    }
}

/// Raises the softclock flag [`spl0`] and [`splx_cli`] drain.
pub(crate) fn setsoftclock() {
    // Relaxed: The flag guards no other data; the locked increment is the
    // setter's only claim, and the caller's spl keeps a drain off this CPU.
    SOFTCLK_PENDING.fetch_add(1, Ordering::Relaxed);
}
