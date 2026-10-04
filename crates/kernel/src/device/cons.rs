// SPDX-License-Identifier: CMU-Mach
// Derived from device/cons.c and device/cons.h:
//   Copyright (c) 1988-1994, The University of Utah and
//   the Computer Systems Laboratory (CSL).  All rights reserved.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The console package and the machine's console table, which
//! `device/cons.c` and `i386/i386at/cons_conf.c` used to define and
//! <device/cons.h> declares.

use crate::arch::x86_64::com::{comcngetc, comcninit, comcnprobe, comcnputc};
use crate::arch::x86_64::kd::ConsDev;
use crate::arch::x86_64::kd::console::{
    kdcngetc, kdcninit, kdcnprobe, kdcnputc,
};
use crate::device::dev_name;
use crate::device::kmsg;
use crate::kern::debug::kpanic;
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_short};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// The `constab[]` entries `i386/i386at/cons_conf.c` spelled out, terminator
/// included.
const CONSTAB_COUNT: usize = 3;

/// `constab[]` of `i386/i386at/cons_conf.c`: the console candidates `cninit()`
/// probes in order, terminated by an entry whose `cn_probe` is null.
static CONSTAB: SyncCell<[ConsDev; CONSTAB_COUNT]> =
    SyncCell(UnsafeCell::new([
        ConsDev {
            cn_name: c"kd".as_ptr().cast_mut(),
            cn_probe: Some(kdcnprobe),
            cn_init: Some(kdcninit),
            cn_getc: Some(kdcngetc),
            cn_putc: Some(kdcnputc),
            cn_dev: 0,
            cn_pri: 0,
        },
        ConsDev {
            cn_name: c"com".as_ptr().cast_mut(),
            cn_probe: Some(comcnprobe),
            cn_init: Some(comcninit),
            cn_getc: Some(comcngetc),
            cn_putc: Some(comcnputc),
            cn_dev: 0,
            cn_pri: 0,
        },
        ConsDev {
            cn_name: ptr::null_mut(),
            cn_probe: None,
            cn_init: None,
            cn_getc: None,
            cn_putc: None,
            cn_dev: 0,
            cn_pri: 0,
        },
    ]));

/// `CN_DEAD` of <device/cons.h>: a console that does not exist.
const CN_DEAD: c_short = 0;

/// `CONSBUFSIZE` of <device/cons.h>.
const CONSBUFSIZE: usize = 1024;

/// `cn_inited` of `device/cons.c`.
static CN_INITED: AtomicBool = AtomicBool::new(false);

/// `cn_tab` of `device/cons.c`: the chosen console.
static CN_TAB: AtomicPtr<ConsDev> = AtomicPtr::new(ptr::null_mut());

/// `consbuf`, `consbp` and `consbufused` of `device/cons.c`: the output held
/// until a console is chosen, a ring only the boot CPU fills.
struct PendingOutput {
    buf: [c_char; CONSBUFSIZE],
    /// The slot the next byte goes to, which is also the oldest byte once
    /// the ring has wrapped.
    next: usize,
    used: bool,
}

static PENDING: SyncCell<PendingOutput> =
    SyncCell(UnsafeCell::new(PendingOutput {
        buf: [0; CONSBUFSIZE],
        next: 0,
        used: false,
    }));

/// `cninit()` of `device/cons.c`: find and initialize the console.
///
/// # Safety
///
/// Called once, during the boot, after the device tables and `constab` exist
/// and before any console user runs.
pub(crate) unsafe fn init() {
    if CN_INITED.load(Ordering::Relaxed) {
        return;
    }

    // SAFETY: the table is boot-initialized and only probed from here.
    let constab = CONSTAB.0.get().cast::<ConsDev>();
    let mut cp = constab;
    let mut chosen: *mut ConsDev = ptr::null_mut();
    // SAFETY: `constab` is the table, terminated by an entry whose
    // `cn_probe` is null, which `Option` reads as `None`.
    while let Some(probe) = unsafe { (*cp).cn_probe } {
        // SAFETY: the probe entry is inside `constab` and the probe routine
        // is the entry's own.
        unsafe { probe(cp) };
        // SAFETY: `cp` is the probed entry.
        if unsafe { (*cp).cn_pri } > CN_DEAD
            && (chosen.is_null()
                // SAFETY: `cp` is the probed entry, and `chosen` is
                // non-null in this branch.
                || unsafe { (*cp).cn_pri } > unsafe { (*chosen).cn_pri })
        {
            chosen = cp;
            // The C named the best entry as soon as it saw one.
            CN_TAB.store(cp, Ordering::Relaxed);
        }
        // SAFETY: the probe entry is inside `constab`, whose terminator ends
        // the walk.
        cp = unsafe { cp.add(1) };
    }

    if chosen.is_null() {
        kpanic!("cninit", "can't find a console device")
    }

    // SAFETY: `chosen` is a probed table entry with its `cn_init` filled by
    // the probe.
    if let Some(initialize) = unsafe { (*chosen).cn_init } {
        unsafe { initialize(chosen) };
    }

    // SAFETY: the console's name is a NUL-terminated string in the table.
    let Some((ops, _unit)) = (unsafe { dev_name::lookup((*chosen).cn_name) })
    else {
        kpanic!("cninit", "cninit: dev_name_lookup failed")
    };
    // `minor()` of <sys/types.h>: the low byte of the device number.
    // SAFETY: `chosen` is a live table entry.
    let minor = c_int::from(unsafe { (*chosen).cn_dev } & 0xff);
    // SAFETY: the indirect table is the C's, and `ops` is a live entry point
    // table.
    unsafe {
        dev_name::set_indirection(c"console".as_ptr(), ops.as_ptr(), minor);
    };

    // SAFETY: the console is initialized, so the pending buffer can be
    // flushed through it.
    unsafe { flush_pending() };
    CN_INITED.store(true, Ordering::Relaxed);
}

/// The `consbufused` flush at the end of `cninit()`.
///
/// # Safety
///
/// The console must be initialized; the buffer is this module's and nothing
/// else flushes it concurrently.
unsafe fn flush_pending() {
    // No reference is held across `putc()`: with a console chosen it never
    // reaches the buffer, but the cell is not borrowed while it runs.
    let pending = PENDING.0.get();
    // SAFETY: the caller guarantees nothing else touches the buffer.
    let (used, start) = unsafe { ((*pending).used, (*pending).next) };
    if !used {
        return;
    }
    let mut i = start;
    loop {
        // SAFETY: as above; `i` stays inside the ring.
        let byte = unsafe { (*pending).buf[i] };
        if byte != 0 {
            unsafe { putc(byte) };
        }
        i = (i + 1) % CONSBUFSIZE;
        if i == start {
            break;
        }
    }
    // SAFETY: as above.
    unsafe { (*pending).used = false };
}

/// `cngetc()` and `cnmaygetc()` of `device/cons.c`.
///
/// # Safety
///
/// The console and ROM tables are the machine's; `wait` selects the blocking
/// or polling read, exactly as the C passed `1` or `0`.
pub(crate) unsafe fn getc(wait: c_int) -> c_int {
    // The chosen entry, or null before `cninit()`.
    let tab = CN_TAB.load(Ordering::Relaxed);
    if !tab.is_null() {
        // SAFETY: a chosen console has `cn_getc` filled by its probe.
        if let Some(cn_getc) = unsafe { (*tab).cn_getc } {
            return unsafe { cn_getc((*tab).cn_dev, wait) };
        }
    }
    0
}

/// `cnputc()` of `device/cons.c`.
///
/// # Safety
///
/// The console and ROM tables are the machine's, and the pending buffer is
/// this module's.
pub(crate) unsafe fn putc(c: c_char) {
    if c == 0 {
        return;
    }

    kmsg::putchar(c_int::from(c));

    // The chosen entry, or null before `cninit()`.
    let tab = CN_TAB.load(Ordering::Relaxed);
    if tab.is_null() {
        // SAFETY: the buffer is this module's and no console exists yet, so
        // the C buffered the byte.
        unsafe { buffer_char(c) };
    // SAFETY: a chosen console has `cn_putc` filled by its probe.
    } else if let Some(cn_putc) = unsafe { (*tab).cn_putc } {
        unsafe {
            cn_putc((*tab).cn_dev, c_int::from(c));
            if c == b'\n' as c_char {
                cn_putc((*tab).cn_dev, c_int::from(b'\r'));
            }
        }
    }
}

/// Hold `c` in `consbuf` until a console is chosen, as the `CONSBUFSIZE > 0`
/// arm of `cnputc()` did.
///
/// # Safety
///
/// Nothing else may write the buffer concurrently: the C ran this before any
/// console existed.
unsafe fn buffer_char(c: c_char) {
    // SAFETY: the caller guarantees nothing else touches the buffer.
    let pending = unsafe { &mut *PENDING.0.get() };
    if !pending.used {
        pending.buf = [0; CONSBUFSIZE];
        pending.next = 0;
        pending.used = true;
    }
    pending.buf[pending.next] = c;
    pending.next = (pending.next + 1) % CONSBUFSIZE;
}
