// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The 8254 timer.

use crate::arch::x86_64::per_cpu::cpu_id;
use crate::arch::x86_64::pio::Port;
use core::ffi::c_int;
use lock::TicketLock;
use mach_thread::smp::CpuId;

/// The PIT control port.
const PITCTL_PORT: Port = Port::new(0x43);
/// Counter 0's data port.
const PITCTR0_PORT: Port = Port::new(0x40);
/// Counter 2's data port.
const PITCTR2_PORT: Port = Port::new(0x42);
/// The PIT auxiliary port.
const PITAUX_PORT: Port = Port::new(0x61);
/// The port read for a tiny I/O delay.
const POST_PORT: Port = Port::new(0x80);

bitflags::bitflags! {
    /// Port B of the system board, the auxiliary port: counter 2's gate and
    /// output, and the speaker it drives.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct PortB: u8 {
        /// Counter 2's gate input, `PITAUX_GATE2`.
        const GATE2 = 0x01;
        /// Drive the speaker from counter 2's output, `PITAUX_OUT2`.
        const SPEAKER = 0x02;
        /// Counter 2's output, `PITAUX_VAL`.
        const OUT2 = 0x20;
        // The bits the timer leaves as it finds them.
        const _ = !0;
    }
}

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

/// The timer input clock, in ticks per second.
const CLKNUM: u32 = 1_193_182;

/// The longest wait one counter load covers.
const MAX_PIT_USEC: u32 = 54924;

/// The timer's ports: the control port is shared by every counter, and a
/// counter is loaded in two writes. No interrupt handler touches them.
static PIT: TicketLock<()> = TicketLock::new(());

/// Program counter 2 for a one-shot wait of `usec` microseconds.
fn prepare_sleep(usec: u32) {
    let aux = PortB::from_bits_retain(PITAUX_PORT.read_u8());
    let aux = (aux & !PortB::SPEAKER) | PortB::GATE2;
    PITAUX_PORT.write_u8(aux.bits());
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
    let aux = PortB::from_bits_retain(PITAUX_PORT.read_u8());
    let low = aux & !PortB::GATE2;
    PITAUX_PORT.write_u8(low.bits());
    PITAUX_PORT.write_u8((low | PortB::GATE2).bits());
    while !PortB::from_bits_retain(PITAUX_PORT.read_u8()).contains(PortB::OUT2)
    {
    }
}

/// Busy-waits for `usec` microseconds.
pub(crate) fn udelay(mut usec: u32) {
    // Counter 2 times one wait at a time.
    let _pit = PIT.lock();
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

    let _pit = PIT.lock();
    PITCTL_PORT.write_u8(PIT0_MODE);

    let hz_rate = mach_sched::sched::CLOCK_HZ;

    // The C computed the interval in `int` and stored it in an `unsigned int`:
    // `(CLKNUM + hz_rate / 2) / hz_rate`.
    let clknumb = ((CLKNUM as c_int) + hz_rate / 2) / hz_rate;
    // The C's `unsigned int` store.
    let clknumb = clknumb as u32;

    // The counter latch is 16 bits wide, so the C's byte pair is the
    // quotient's low two bytes.
    PITCTR0_PORT.write_u8(clknumb as u8);
    PITCTR0_PORT.write_u8((clknumb >> 8) as u8);
}
