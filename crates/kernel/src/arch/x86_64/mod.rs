// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `x86_64` kernel's architecture code, mirroring the shared `i386/`
//! headers of the C tree.

pub mod acpi;
pub mod apic;
pub mod ast;
pub mod autoconf;
pub mod biosmem;
pub mod boothdr;
pub mod busses;
pub mod clock_platform;
pub mod com;
pub mod cpuboot;
pub mod cswitch;
pub mod db_interface;
pub mod debug_i386;
pub mod error;
pub mod fpu;
pub mod gdt;
pub mod hardclock;
pub mod idt;
pub mod idt_inittab;
pub mod int_init;
pub mod int_stubs;
pub mod interrupt;
pub mod io_perm;
pub mod io_req;
pub mod ioapic;
pub mod irq;
pub mod kd;
pub mod kd_event;
pub mod kd_mouse;
pub mod ktss;
pub mod ldt;
pub mod locore;
pub mod machine_task;
pub mod mbinfo;
pub mod mem;
pub mod model_dep;
pub mod mp_desc;
pub mod multiboot;
pub mod pcb;
pub mod per_cpu;
pub mod phys;
pub mod pio;
pub mod pit;
pub mod platform;
pub mod pmap;
pub mod rtc;
pub mod seg;
pub mod smp;
pub mod spl;
pub mod trap;
pub mod user_access;
pub mod user_ldt;
