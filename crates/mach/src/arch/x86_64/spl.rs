// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The interrupt-masking entries.
//!
//! Levels 1 through 6 all collapse into [`SPL7`], so `spl1` to `spl6` and the
//! named aliases share one body: they mask interrupts and raise the current
//! level to 7, returning the level they replaced.  Each entry opens with a
//! full fence; the current level itself is a plain per-CPU read and write.

use crate::arch::x86_64::clock_platform::softclock;
use crate::arch::x86_64::ioapic::CURR_IPL;
use crate::arch::x86_64::per_cpu;
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering, fence};
use x86_64::instructions::interrupts;

/// The level with interrupts open.
const SPL0: c_int = 0;

/// The level with interrupts blocked.
const SPL7: c_int = 7;

/// Nonzero while `softclock()` is owed a call.
///
/// The C's word is a plain `long`; Rust reaches it through an atomic
/// because a setter on one CPU can meet a drain on another.
static SOFTCLK_PENDING: AtomicI32 = AtomicI32::new(0);

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
    fence(Ordering::SeqCst);
    interrupts::disable();
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
    fence(Ordering::SeqCst);
    let old = current_ipl();
    interrupts::disable();
    // Relaxed: The flag guards no other data, and the swap only settles
    // which CPU runs the pending softclock.
    if SOFTCLK_PENDING.swap(0, Ordering::Relaxed) != 0 {
        let _ = unsafe { spl1() };
        softclock();
        interrupts::disable();
    }
    if current_ipl() != SPL0 {
        set_current_ipl(SPL0);
    }
    interrupts::enable();
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
    interrupts::disable();
    let old = current_ipl();
    set_current_ipl(level);
    interrupts::enable();
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
        interrupts::enable();
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
    interrupts::disable();
    // Relaxed: As `spl0()`; the interrupt-return path leans on the same
    // atomic clear.
    if level == SPL0 && SOFTCLK_PENDING.swap(0, Ordering::Relaxed) != 0 {
        let _ = unsafe { spl1() };
        softclock();
        interrupts::disable();
    }
    if current_ipl() != level {
        set_current_ipl(level);
    }
}

/// Raises the softclock flag [`spl0`] and [`splx_cli`] drain.
pub(crate) fn setsoftclock() {
    // Relaxed: The flag guards no other data; the locked increment is the
    // setter's only claim, and the caller's spl keeps a drain off this CPU.
    SOFTCLK_PENDING.fetch_add(1, Ordering::Relaxed);
}
