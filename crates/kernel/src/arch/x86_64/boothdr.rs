// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386at/boothdr.S and x86_64/boothdr.S:
//   Copyright (C) 2022 Free Software Foundation
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The Multiboot header and the first-stage entry, which
//! `i386/i386at/boothdr.S` and `x86_64/boothdr.S` used to define.

mod x86_64 {
    use crate::arch::x86_64::apic::{
        APIC_MSR, APIC_MSR_BSP, APIC_MSR_ENABLE, APIC_MSR_X2APIC,
    };
    use crate::arch::x86_64::fpu::{CR0_PG, CR0_WP, CR4_PAE};
    use crate::arch::x86_64::model_dep::c_boot_entry;
    use crate::arch::x86_64::mp_desc::INTSTACK_SIZE;
    use crate::arch::x86_64::pcb::{
        MSR_REG_EFER, MSR_REG_EFER_LONG_MODE_EN, MSR_REG_GSBASE,
        MSR_REG_KGSBASE,
    };
    use crate::arch::x86_64::pmap::{
        INTEL_PTE_PS, INTEL_PTE_VALID, INTEL_PTE_WRITE,
    };
    use crate::arch::x86_64::seg::{ACC_CODE_R, ACC_DATA_W, ACC_P, SZ_64};
    use crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS;
    use core::arch::global_asm;

    /// `MULTIBOOT_MAGIC`, `MULTIBOOT_PAGE_ALIGN` and
    /// `MULTIBOOT_MEMORY_INFO` of <mach/i386/multiboot.h>.
    const MULTIBOOT_MAGIC: u32 = 0x1bad_b002;
    const MULTIBOOT_PAGE_ALIGN: u32 = 0x0000_0001;
    const MULTIBOOT_MEMORY_INFO: u32 = 0x0000_0002;
    /// `MULTIBOOT_FLAGS` of `x86_64/boothdr.S`.
    const MULTIBOOT_FLAGS: u32 = MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO;
    /// The header checksum, `-(MULTIBOOT_MAGIC+MULTIBOOT_FLAGS)`.
    const MULTIBOOT_CHECKSUM: u32 =
        MULTIBOOT_MAGIC.wrapping_add(MULTIBOOT_FLAGS).wrapping_neg();

    /// `BOOT_CS` and `BOOT_DS` of `x86_64/boothdr.S`.
    const BOOT_CS: u32 = 0x8;
    const BOOT_DS: u32 = 0x10;

    /// `~APIC_MSR_X2APIC`: clear the x2APIC bit.
    const APIC_MSR_X2APIC_CLEAR: u32 = !APIC_MSR_X2APIC;

    /// The page-table entry bits the kernel mapping uses.  The bits fit a
    /// 32-bit entry, so the narrowing cannot lose one.
    const PTE_V_W: u32 = (INTEL_PTE_VALID | INTEL_PTE_WRITE) as u32;
    const PTE_V_W_S: u32 =
        (INTEL_PTE_VALID | INTEL_PTE_WRITE | INTEL_PTE_PS) as u32;

    /// `KERNEL_MAP_BASE` and the P4/P3 slots the kernel mapping lands on.
    const KERNEL_MAP_BASE: u64 = VM_MIN_KERNEL_ADDRESS as u64;
    const P4_KERNEL_INDEX: u64 = (KERNEL_MAP_BASE >> 39) & 0x1ff;
    const P3_KERNEL_INDEX: u64 = (KERNEL_MAP_BASE >> 30) & 0x1ff;
    const _: () = assert!(KERNEL_MAP_BASE >= (1 << 39));

    /// `SEG_ACCESS_OFS`, `SEG_FLAGS_OFS` and the two descriptors of
    /// `x86_64/boothdr.S`.
    const SEG_ACCESS_OFS: u64 = 40;
    const SEG_FLAGS_OFS: u64 = 52;
    const BOOT_GDT64_CODE: u64 = ((ACC_P | ACC_CODE_R) as u64)
        << SEG_ACCESS_OFS
        | (SZ_64 as u64) << SEG_FLAGS_OFS;
    const BOOT_GDT64_DATA: u64 = ((ACC_P | ACC_DATA_W) as u64)
        << SEG_ACCESS_OFS
        | (SZ_64 as u64) << SEG_FLAGS_OFS;
    const GDT64_LIMIT: u16 = 3 * 8 - 1;

    global_asm!(
        ".section .boot.text,\"ax\"",
        ".globl boot_start",
        "boot_start:",
        ".code32",
        "jmp boot_entry",
        ".p2align 2",
        "boot_hdr:",
        ".long {multiboot_magic}",
        ".long {multiboot_flags}",
        ".long {multiboot_checksum}",
        ".global _start",
        "_start:",
        "boot_entry:",
        "xorl %eax, %eax",
        "xorl %edx, %edx",
        "movl ${apic_msr}, %ecx",
        "rdmsr",
        "orl ${apic_msr_enable}, %eax",
        "orl ${apic_msr_bsp}, %eax",
        "andl ${apic_msr_x2apic_clear}, %eax",
        "movl ${apic_msr}, %ecx",
        "wrmsr",
        "movl $p3table, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p4table)",
        "movl $p2table, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p3table)",
        "movl $p2table1, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p3table + 8)",
        "movl $p2table2, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p3table + 16)",
        "movl $p2table3, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p3table + 24)",
        "mov $0, %ecx",
        ".Lboot_map_p2_table:",
        "mov $0x200000, %eax",
        "mul %ecx",
        "or ${pte_v_w_s}, %eax",
        "mov %eax, p2table(,%ecx,8)",
        "inc %ecx",
        "cmp $2048, %ecx",
        "jne .Lboot_map_p2_table",
        ".Lboot_kernel_map:",
        "movl $p3ktable, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p4table + (8 * {p4_kernel_index}))",
        "movl $p2ktable1, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p3ktable + (8 * {p3_kernel_index}))",
        "movl $p2ktable2, %eax",
        "or ${pte_v_w}, %eax",
        "movl %eax, (p3ktable + (8 * ({p3_kernel_index} + 1)))",
        "mov $0, %ecx",
        ".Lboot_map_p2k_table:",
        "mov $0x200000, %eax",
        "mul %ecx",
        "or ${pte_v_w_s}, %eax",
        "mov %eax, p2ktable1(,%ecx,8)",
        "inc %ecx",
        "cmp $1024, %ecx",
        "jne .Lboot_map_p2k_table",
        "boot_switch64:",
        "mov %cr4, %eax",
        "or ${cr4_pae}, %eax",
        "mov %eax, %cr4",
        "mov ${msr_reg_efer}, %ecx",
        "rdmsr",
        "or ${msr_efer_long_mode_en}, %eax",
        "wrmsr",
        "mov $p4table, %eax",
        "mov %eax, %cr3",
        "mov %cr0, %eax",
        "or ${cr0_pg}, %eax",
        "or ${cr0_wp}, %eax",
        "mov %eax, %cr0",
        "lgdt gdt64pointer",
        "ljmp ${boot_cs},$boot_entry64",
        ".code64",
        "boot_entry64:",
        "xorl %eax, %eax",
        "movw %ax,%ds",
        "movw %ax,%es",
        "movw %ax,%ss",
        "movw %ax,%fs",
        "movw %ax,%gs",
        "movw ${boot_ds},%ax",
        "movw %ax,%ds",
        "movw %ax,%es",
        "movw %ax,%ss",
        "movq $solid_intstack+{intstack_size}-16, %rax",
        "andq $-16,%rax",
        "movq %rax,%rsp",
        "movq $per_cpu_array, %rdx",
        "movl %edx, %eax",
        "shrq $32, %rdx",
        "movl ${msr_reg_gsbase}, %ecx",
        "wrmsr",
        "xorl %eax, %eax",
        "xorl %edx, %edx",
        "movl ${msr_reg_kgsbase}, %ecx",
        "wrmsr",
        "pushq $0",
        "popfq",
        "movq %rbx,%r8",
        "movq $__rela_iplt_start,%rsi",
        "movq $__rela_iplt_end,%rdi",
        "iplt_cont:",
        "cmpq %rdi,%rsi",
        "jae iplt_done",
        "movq (%rsi),%rbx",
        "movb 4(%rsi),%al",
        "cmpb $42,%al",
        "jnz iplt_next",
        "call *(%rbx)",
        "movq %rax,(%rbx)",
        "iplt_next:",
        "addq $8,%rsi",
        "jmp iplt_cont",
        "iplt_done:",
        "movq %r8,%rdi",
        "call {c_boot_entry}",
        "nop",
        ".code32",
        ".section .boot.data,\"ax\",@progbits",
        ".p2align 12",
        "gdt64:",
        ".quad 0",
        ".quad {boot_gdt64_code}",
        ".quad {boot_gdt64_data}",
        "gdt64end:",
        ".skip 4096 - (gdt64end - gdt64)",
        "gdt64pointer:",
        ".word {gdt64_limit}",
        ".quad gdt64",
        ".section .boot.data,\"ax\",@progbits",
        ".p2align 12",
        "p4table:",
        ".space 4096",
        "p3table:",
        ".space 4096",
        "p2table:",
        ".space 4096",
        "p2table1:",
        ".space 4096",
        "p2table2:",
        ".space 4096",
        "p2table3:",
        ".space 4096",
        "p3ktable:",
        ".space 4096",
        "p2ktable1:",
        ".space 4096",
        "p2ktable2:",
        ".code64",
        ".space 4096",
        multiboot_magic = const MULTIBOOT_MAGIC,
        multiboot_flags = const MULTIBOOT_FLAGS,
        multiboot_checksum = const MULTIBOOT_CHECKSUM,
        boot_cs = const BOOT_CS,
        boot_ds = const BOOT_DS,
        apic_msr = const APIC_MSR,
        apic_msr_bsp = const APIC_MSR_BSP,
        apic_msr_enable = const APIC_MSR_ENABLE,
        apic_msr_x2apic_clear = const APIC_MSR_X2APIC_CLEAR,
        pte_v_w = const PTE_V_W,
        pte_v_w_s = const PTE_V_W_S,
        p4_kernel_index = const P4_KERNEL_INDEX,
        p3_kernel_index = const P3_KERNEL_INDEX,
        cr4_pae = const CR4_PAE,
        msr_reg_efer = const MSR_REG_EFER,
        msr_efer_long_mode_en = const MSR_REG_EFER_LONG_MODE_EN,
        cr0_pg = const CR0_PG,
        cr0_wp = const CR0_WP,
        msr_reg_gsbase = const MSR_REG_GSBASE,
        msr_reg_kgsbase = const MSR_REG_KGSBASE,
        intstack_size = const INTSTACK_SIZE,
        boot_gdt64_code = const BOOT_GDT64_CODE,
        boot_gdt64_data = const BOOT_GDT64_DATA,
        gdt64_limit = const GDT64_LIMIT,
        c_boot_entry = sym c_boot_entry,
        options(att_syntax),
    );
}
