// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/smp.c and i386/i386/smp.h:
//   Copyright (C) 2020 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The SMP controller: CPU discovery and the application-processor startup.

use crate::arch::x86_64::{apic, per_cpu, pit};
use crate::kern::console::kprint;
use crate::kern::machine;
use crate::kern::smp as kern_smp;
use crate::kern::smp::CpuId;
use core::arch::asm;
use core::ffi::{c_uint, c_ulong};

/// How far a startup IPI's vector shifts its target address.
const STARTUP_VECTOR_SHIFT: u32 = 20 - 8;
/// The IPI destination shorthand that names the target.
const NO_SHORTHAND: c_uint = 0;
/// The fixed IPI delivery mode.
const FIXED: c_uint = 0;
/// The physical IPI destination mode.
const PHYSICAL: c_uint = 0;
/// The edge IPI trigger mode.
const EDGE: c_uint = 0;
/// The de-asserted IPI level.
const DE_ASSERT: c_uint = 0;
/// The asserted IPI level.
const ASSERT: c_uint = 1;
/// The IPI destination shorthand of every CPU but this one.
const ALL_EXCLUDING_SELF: c_uint = 3;
/// The INIT IPI delivery mode.
const INIT: c_uint = 5;
/// The startup IPI delivery mode.
const STARTUP: c_uint = 6;
/// The remote AST request vector.
const CALL_AST_CHECK: c_uint = 0xfa;
/// The TLB shootdown vector.
const CALL_PMAP_UPDATE: c_uint = 0xfb;

/// The spin-loop hint.
pub(crate) fn pause() {
    // SAFETY: `pause` touches no registers and the stack stays balanced; the
    // memory clobber of the C macro is the default.
    unsafe { asm!("pause", options(nostack, preserves_flags)) };
}

/// The local APIC's `error_status` register.
fn error_status() -> u32 {
    let ptr = apic::lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page, and the read is the C's
    // volatile access.
    unsafe { apic::reg_read(&raw const (*ptr).error_status) }
}

/// Clear the local APIC's `error_status` register.
fn clear_error_status() {
    let ptr = apic::lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page, and the write is the C's
    // volatile access.
    unsafe { apic::reg_write(&raw mut (*ptr).error_status, 0) };
}

/// Records the CPU count and marks every online CPU's machine slot.
fn data_init() {
    let ncpus = apic::ncpus();
    kern_smp::set_ncpus(ncpus);

    for cpu in CpuId::online() {
        // SAFETY: the slot is `cpu`'s own `machine_slot`, which the machine
        // never frees.
        unsafe { (*machine::slot(cpu)).is_cpu = 1 };
    }
}

/// Sends `vector` to `cpu` alone, addressed by the APIC ID its setup
/// recorded.
fn send_ipi(cpu: CpuId, vector: c_uint) {
    let apic_id = per_cpu::per_cpu_at(cpu).apic_id();
    let flags = apic::intr_save();

    while apic::ipi_pending() {
        pause();
    }

    apic::send_ipi(
        NO_SHORTHAND,
        FIXED,
        PHYSICAL,
        ASSERT,
        EDGE,
        vector,
        apic_id,
    );

    apic::intr_restore(flags);
}

/// Waits until the local APIC has sent the pending IPI.
fn wait_for_ipi() {
    while apic::ipi_pending() {
        pause();
    }
}

/// Sends the INIT assert and de-assert IPIs to every other CPU.
fn send_ipi_init(bsp_apic_id: u32) {
    clear_error_status();
    let _ = error_status();

    apic::send_ipi(
        ALL_EXCLUDING_SELF,
        INIT,
        PHYSICAL,
        ASSERT,
        EDGE,
        0,
        bsp_apic_id,
    );
    wait_for_ipi();

    apic::send_ipi(
        ALL_EXCLUDING_SELF,
        INIT,
        PHYSICAL,
        DE_ASSERT,
        EDGE,
        0,
        bsp_apic_id,
    );
    wait_for_ipi();

    let error = error_status();
    if error != 0 {
        kprint!("ESR error upon INIT 0x{:x}\n", error);
    }
}

/// Whether both startup IPIs went out and were accepted.
fn send_ipi_startup_twice(bsp_apic_id: u32, vector: c_uint) -> bool {
    let mut send_err = 0;
    let mut accept_err = 0;

    for _ in 0..2 {
        clear_error_status();
        let _ = error_status();

        apic::send_ipi(
            ALL_EXCLUDING_SELF,
            STARTUP,
            PHYSICAL,
            DE_ASSERT,
            EDGE,
            vector,
            bsp_apic_id,
        );

        pit::udelay(10);
        wait_for_ipi();
        send_err = error_status();

        pit::udelay(10);
        clear_error_status();
        accept_err = error_status() & 0xef;

        if send_err != 0 || accept_err != 0 {
            break;
        }
    }

    if send_err != 0 {
        kprint!("ESR error: DID NOT SEND? 0x{:x}\n", send_err);
    }
    if accept_err != 0 {
        kprint!("ESR error: delivery 0x{:x}\n", accept_err);
    }

    send_err == 0 && accept_err == 0
}

/// Interrupts `cpu` so that it runs the AST check.
pub(crate) fn remote_ast(cpu: CpuId) {
    send_ipi(cpu, CALL_AST_CHECK);
}

/// Interrupts `cpu` so that it flushes its queued pmap updates.
pub(crate) fn pmap_update(cpu: CpuId) {
    send_ipi(cpu, CALL_PMAP_UPDATE);
}

/// Starts the application processors at `start_eip`.
pub(crate) fn startup_cpus(bsp_apic_id: u32, start_eip: c_ulong) {
    // SAFETY: `wbinvd` touches no registers and the stack stays balanced; the
    // memory clobber of the C macro is the default.
    unsafe { asm!("wbinvd", options(nostack, preserves_flags)) };

    kprint!("Sending IPIs from BSP APIC ID {}...\n", bsp_apic_id);

    send_ipi_init(bsp_apic_id);
    // The C passed the shifted address through an `int`; only the vector
    // byte reaches the ICR, and that is what the shift leaves here.
    let vector = (start_eip >> STARTUP_VECTOR_SHIFT) as c_uint;
    if !send_ipi_startup_twice(bsp_apic_id, vector) {
        kprint!("FATAL: APs failed to start\n");
        loop {
            pause();
        }
    }

    kprint!("done\n");
}

/// Discovers the CPUs and starts the application processors.
pub(crate) fn init() {
    data_init();
}
