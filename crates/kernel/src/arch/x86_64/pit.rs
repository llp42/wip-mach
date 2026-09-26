// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/pit.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
//   Copyright 1988, 1989 by Intel Corporation, Santa Clara, California.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The 8254 timer, which `i386/i386/pit.c` used to define and
//! `i386/i386/pit.h` declares.

use crate::arch::x86_64::per_cpu::cpu_id;
use crate::arch::x86_64::pio::Port;
use crate::arch::x86_64::spl;
use crate::kern::smp::CpuId;
use core::ffi::c_int;

/// The PIT control port, `PITCTL_PORT` of <i386/pit.h>.
const PITCTL_PORT: Port = Port::new(0x43);
/// Counter 0's data port, `PITCTR0_PORT` of <i386/pit.h>.
const PITCTR0_PORT: Port = Port::new(0x40);
/// Counter 2's data port, `PITCTR2_PORT` of <i386/pit.h>.
const PITCTR2_PORT: Port = Port::new(0x42);
/// The PIT auxiliary port, `PITAUX_PORT` of <i386/pit.h>.
const PITAUX_PORT: Port = Port::new(0x61);
/// The port read for a tiny I/O delay, `POST_PORT` of <i386/pit.h>.
const POST_PORT: Port = Port::new(0x80);

/// Counter 2's gate input in the auxiliary port, `PITAUX_GATE2`.
const PITAUX_GATE2: u8 = 0x01;
/// Counter 2's clock output enable, `PITAUX_OUT2`.
const PITAUX_OUT2: u8 = 0x02;
/// Counter 2's output bit, `PITAUX_VAL`.
const PITAUX_VAL: u8 = 0x20;

/// Select counter 0, `PIT_C0`.
const PIT_C0: u8 = 0x00;
/// Select counter 2, `PIT_C2`.
const PIT_C2: u8 = 0x80;
/// Load the least significant byte, then the most significant one,
/// `PIT_LOADMODE`.
const PIT_LOADMODE: u8 = 0x30;
/// Read or load the least significant byte, then the most significant one,
/// `PIT_READMODE`.
const PIT_READMODE: u8 = 0x30;
/// Square-wave mode, `PIT_SQUAREMODE`.
const PIT_SQUAREMODE: u8 = 0x06;
/// One-shot mode, `PIT_ONESHOTMODE`.
const PIT_ONESHOTMODE: u8 = 0x02;

/// The control byte `clkstart()` programs for counter 0,
/// `PIT_C0|PIT_SQUAREMODE|PIT_READMODE`.
const PIT0_MODE: u8 = PIT_C0 | PIT_SQUAREMODE | PIT_READMODE;

/// The timer input clock, `CLKNUM` of <i386/pit.h>, in ticks per second.
const CLKNUM: u32 = 1_193_182;

/// The longest wait one counter load covers, `MAX_PIT_USEC` of <i386/pit.h>.
const MAX_PIT_USEC: u32 = 54924;

/// Program counter 2 for a one-shot wait of `usec` microseconds.
fn prepare_sleep(usec: u32) {
    let aux = PITAUX_PORT.read_u8();
    let aux = (aux & !PITAUX_OUT2) | PITAUX_GATE2;
    PITAUX_PORT.write_u8(aux);
    PITCTL_PORT.write_u8(PIT_C2 | PIT_LOADMODE | PIT_ONESHOTMODE);
    let count = u64::from(CLKNUM) * u64::from(usec) / 1_000_000;
    // The counter latch is 16 bits wide and `outb` writes one byte, so the C's
    // byte pair is the quotient's low two bytes.
    let lsb = (count & 0xff) as u8;
    let msb = (count >> 8) as u8;
    PITCTR2_PORT.write_u8(lsb);
    let _ = POST_PORT.read_u8();
    PITCTR2_PORT.write_u8(msb);
}

/// Start the one-shot and spin until counter 2 reaches zero.
fn sleep() {
    let aux = PITAUX_PORT.read_u8();
    let low = aux & !PITAUX_GATE2;
    PITAUX_PORT.write_u8(low);
    PITAUX_PORT.write_u8(low | PITAUX_GATE2);
    while PITAUX_PORT.read_u8() & PITAUX_VAL == 0 {}
}

/// Busy-wait for `usec` microseconds, the core of `pit_udelay()`.
pub(crate) fn udelay(mut usec: u32) {
    while usec > MAX_PIT_USEC {
        prepare_sleep(MAX_PIT_USEC);
        sleep();
        usec -= MAX_PIT_USEC;
    }
    prepare_sleep(usec);
    sleep();
}

/// Program counter 0 for the kernel clock.
///
/// # Panics
///
/// Panics if the kernel's `hz` global is zero: the interval conversion divides
/// by it.
pub(crate) fn clkstart() {
    if cpu_id() != CpuId::BOOT {
        return;
    }

    // SAFETY: `sploff()` is the function <i386/spl.h> declares and
    // `src/arch/x86_64/spl.rs` defines.
    let s = unsafe { spl::sploff() };

    PITCTL_PORT.write_u8(PIT0_MODE);

    let hz_rate = crate::kern::mach_clock::CLOCK_HZ;

    // The C computed the interval in `int` and stored it in an `unsigned int`:
    // `(CLKNUM + hz_rate / 2) / hz_rate`.
    let clknumb = ((CLKNUM as c_int) + hz_rate / 2) / hz_rate;
    // The C's `unsigned int` store.
    let clknumb = clknumb as u32;

    // The counter latch is 16 bits wide, so the C's byte pair is the
    // quotient's low two bytes.
    PITCTR0_PORT.write_u8(clknumb as u8);
    PITCTR0_PORT.write_u8((clknumb >> 8) as u8);

    // SAFETY: `s` is the flags word just returned by `sploff()`.
    unsafe { spl::splon(s) };
}
