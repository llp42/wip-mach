// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The application-processor boot page.

use crate::arch::x86_64::model_dep::GdtDescrTmp;
use core::ffi::c_char;

unsafe extern "C" {
    /// `apboot` and `apbootend`: the AP boot code `start_other_cpus()` copies
    /// to `APBOOT_ADDR`.
    pub(crate) static apboot: c_char;
    pub(crate) static apbootend: c_char;

    /// `gdt_descr_tmp` and `apboot_jmp_offset`: the realmode GDT pointer
    /// and far jump `machine_init()` relocates.
    pub(crate) static mut gdt_descr_tmp: GdtDescrTmp;
    pub(crate) static mut apboot_jmp_offset: u32;
}

mod x86_64 {
    use crate::arch::vm_param::VM_MIN_KERNEL_ADDRESS;
    use crate::arch::x86_64::apic::{APIC_MSR, ApicBase};
    use crate::arch::x86_64::mp_desc::cpu_ap_main;
    use crate::arch::x86_64::pcb::{
        MSR_REG_EFER, MSR_REG_GSBASE, MSR_REG_KGSBASE,
    };
    use crate::arch::x86_64::per_cpu::PerCpu;
    use crate::arch::x86_64::seg::{Access, KERNEL_CS, KERNEL_DS, SegSize};
    use ::x86_64::registers::control::{Cr0Flags, Cr4Flags};
    use ::x86_64::registers::model_specific::EferFlags;
    use core::arch::global_asm;
    use core::mem::{offset_of, size_of};
    use mach_pmap::pte::Pte;

    /// The kernel load base as the boot code's `u64` immediate.
    const KERNEL_BASE: u64 = VM_MIN_KERNEL_ADDRESS as u64;

    /// The temporary flat selectors of the boot GDT.
    const BOOT_CS: u32 = 0x8;
    const BOOT_DS: u32 = 0x10;

    /// The CR0 bits the boot path sets and clears.  They fit the 32-bit
    /// register it programs, so the narrowing and the complement are
    /// 32-bit.
    const CR0_SET_FLAGS: u32 = Cr0Flags::CACHE_DISABLE
        .union(Cr0Flags::NOT_WRITE_THROUGH)
        .union(Cr0Flags::PROTECTED_MODE_ENABLE)
        .bits() as u32;
    const CR0_CLEAR_FLAGS: u32 = Cr0Flags::PAGING
        .union(Cr0Flags::ALIGNMENT_MASK)
        .union(Cr0Flags::WRITE_PROTECT)
        .union(Cr0Flags::NUMERIC_ERROR)
        .union(Cr0Flags::TASK_SWITCHED)
        .union(Cr0Flags::EMULATE_COPROCESSOR)
        .union(Cr0Flags::MONITOR_COPROCESSOR)
        .bits() as u32;
    const CR0_CLEAR_FLAGS_MASK: u32 = !CR0_CLEAR_FLAGS;

    /// The access and size bytes `gdt_fill()` gives the flat descriptors.
    const BOOT_ACCESS_CODE: u8 =
        Access::PL_K.union(Access::CODE_R).union(Access::P).bits();
    const BOOT_ACCESS_DATA: u8 =
        Access::PL_K.union(Access::DATA_W).union(Access::P).bits();
    const BOOT_SIZE_32: u8 =
        (SegSize::DEFAULT_32.union(SegSize::GRANULARITY).bits() << 4) | 0xf;

    /// `~(APIC_MSR_BSP | APIC_MSR_X2APIC)`, which the AP leaves clear.
    const APIC_MSR_BSP_X2APIC_CLEAR: u32 =
        !ApicBase::BSP.union(ApicBase::X2APIC).bits();

    /// The page-table entry bits the kernel mapping uses.  The bits fit a
    /// 32-bit entry, so the narrowing cannot lose one.
    const PTE_V_W: u32 = Pte::VALID.union(Pte::WRITE).bits() as u32;
    const PTE_V_W_S: u32 =
        Pte::VALID.union(Pte::WRITE).union(Pte::PS).bits() as u32;

    /// `KERNEL_MAP_BASE` and the P4/P3 slots the kernel mapping lands on.
    const KERNEL_MAP_BASE: u64 = VM_MIN_KERNEL_ADDRESS as u64;
    const P4_KERNEL_INDEX: u64 = (KERNEL_MAP_BASE >> 39) & 0x1ff;
    const P3_KERNEL_INDEX: u64 = (KERNEL_MAP_BASE >> 30) & 0x1ff;
    const _: () = assert!(KERNEL_MAP_BASE >= (1 << 39));

    /// The number of entries in the boot GDT.
    const GDT64_DESCR_COUNT: u32 = 14;

    /// `SEG_ACCESS_OFS`, `SEG_FLAGS_OFS` and the two descriptors of the
    /// long-mode GDT.
    const SEG_ACCESS_OFS: u64 = 40;
    const SEG_FLAGS_OFS: u64 = 52;
    const BOOT_GDT64_CODE: u64 =
        (Access::P.union(Access::CODE_R).bits() as u64) << SEG_ACCESS_OFS
            | (SegSize::LONG.bits() as u64) << SEG_FLAGS_OFS;
    const BOOT_GDT64_DATA: u64 =
        (Access::P.union(Access::DATA_W).bits() as u64) << SEG_ACCESS_OFS
            | (SegSize::LONG.bits() as u64) << SEG_FLAGS_OFS;
    const GDT64_DESCR_LIMIT: u16 = (GDT64_DESCR_COUNT * 8) as u16 - 1;

    /// The offset of `cpu_id` within the per-CPU block.
    const PER_CPU_CPU_ID_OFFSET: usize = offset_of!(PerCpu, cpu_id);
    /// The distance from one per-CPU block to the next.
    const PER_CPU_OFFSET: usize = size_of::<PerCpu>();

    global_asm!(
        ".globl apboot, apbootend, gdt_descr_tmp, apboot_jmp_offset",
        ".section .boot.text,\"ax\"",
        ".p2align 12",
        ".code16",
        "apboot:",
        "mov %cs, %dx",
        "mov %dx, %ds",
        "cli",
        "xorl %eax, %eax",
        "movl %eax, %cr3",
        "mov %ax, %es",
        "mov %ax, %fs",
        "mov %ax, %gs",
        "mov %ax, %ss",
        "movl %cr0, %eax",
        "andl ${cr0_clear_flags_mask}, %eax",
        "orl ${cr0_set_flags}, %eax",
        "movl %eax, %cr0",
        "lgdt (gdt_descr_tmp - apboot)",
        "ljmpl *(apboot_jmp_offset - apboot)",
        "apboot32:",
        ".code32",
        "xorl %eax, %eax",
        "movw %ax, %ds",
        "movw %ax, %es",
        "movw %ax, %fs",
        "movw %ax, %gs",
        "movw ${boot_ds}, %ax",
        "movw %ax, %ds",
        "movw %ax, %es",
        "movw %ax, %ss",
        "movl $AP_p3table,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p4table)",
        "movl $AP_p2table,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p3table)",
        "movl $AP_p2table1,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p3table + 8)",
        "movl $AP_p2table2,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p3table + 16)",
        "movl $AP_p2table3,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p3table + 24)",
        "mov $0,%ecx",
        ".Lapboot_map_p2_table:",
        "mov $0x200000,%eax",
        "mul %ecx",
        "or ${pte_v_w_s},%eax",
        "mov %eax,AP_p2table(,%ecx,8)",
        "inc %ecx",
        "cmp $2048,%ecx",
        "jne .Lapboot_map_p2_table",
        ".Lapboot_kernel_map:",
        "movl $AP_p3ktable,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p4table + (8 * {p4_kernel_index}))",
        "movl $AP_p2ktable1,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p3ktable + (8 * {p3_kernel_index}))",
        "movl $AP_p2ktable2,%eax",
        "or ${pte_v_w},%eax",
        "movl %eax,(AP_p3ktable + (8 * ({p3_kernel_index} + 1)))",
        "mov $0,%ecx",
        ".Lapboot_map_p2k_table:",
        "mov $0x200000,%eax",
        "mul %ecx",
        "or ${pte_v_w_s},%eax",
        "mov %eax,AP_p2ktable1(,%ecx,8)",
        "inc %ecx",
        "cmp $1024,%ecx",
        "jne .Lapboot_map_p2k_table",
        "apboot_switch64:",
        "mov %cr4,%eax",
        "or ${cr4_pae},%eax",
        "mov %eax,%cr4",
        "mov ${msr_reg_efer},%ecx",
        "rdmsr",
        "or ${msr_efer_long_mode_en},%eax",
        "wrmsr",
        "mov $AP_p4table,%eax",
        "mov %eax,%cr3",
        "mov %cr0,%eax",
        "or ${cr0_pg},%eax",
        "or ${cr0_wp},%eax",
        "mov %eax,%cr0",
        "movl $apboot_idt_ptr, %eax",
        "lidtl (%eax)",
        "lgdtl apboot_gdt64_descr",
        "ljmpl ${kernel_cs}, $1f",
        "1:",
        ".code64",
        "xorl %eax, %eax",
        "movw %ax, %ds",
        "movw %ax, %es",
        "movw %ax, %fs",
        "movw %ax, %gs",
        "movw ${kernel_ds}, %ax",
        "movw %ax, %ds",
        "movw %ax, %es",
        "movw %ax, %fs",
        "movw %ax, %gs",
        "movw %ax, %ss",
        "movq $1, %rax",
        "cpuid",
        "shrl $24, %ebx",
        "andb %cs:apic_id_mask, %bl",
        "movq $cpu_id_lut, %rdi",
        "movl %cs:(%rdi, %rbx, 4), %ebp",
        "movq $int_stack_top, %rdi",
        "movq (%rdi, %rbp, 8), %rsp",
        "pushq ${kernel_cs}",
        "pushq $(start64 + {kernel_base})",
        "lretq",
        "start64:",
        "xorl %eax, %eax",
        "movw %ax, %ds",
        "movw %ax, %es",
        "movw %ax, %fs",
        "movw %ax, %gs",
        "movw ${kernel_ds}, %ax",
        "movw %ax, %ds",
        "movw %ax, %es",
        "movw %ax, %ss",
        "movl $1, %eax",
        "cpuid",
        "shrl $24, %ebx",
        "andb %cs:apic_id_mask, %bl",
        "movq $cpu_id_lut, %rdi",
        "movl %cs:(%rdi, %rbx, 4), %ebp",
        "movq %rbp, %rax",
        "movq ${per_cpu_offset},%rbx",
        "mul %rbx",
        "addq $per_cpu_array, %rax",
        "movl %ebp, ({per_cpu_cpu_id_offset})(%rax)",
        "movq %rax, %rdx",
        "shrq $32, %rdx",
        "movl ${msr_reg_gsbase}, %ecx",
        "wrmsr",
        "xorl %eax, %eax",
        "xorl %edx, %edx",
        "movl ${msr_reg_kgsbase}, %ecx",
        "wrmsr",
        "xorl %eax, %eax",
        "xorl %edx, %edx",
        "movl ${apic_msr}, %ecx",
        "rdmsr",
        "orl ${apic_msr_enable}, %eax",
        "andl ${apic_msr_bsp_x2apic_clear}, %eax",
        "movl ${apic_msr}, %ecx",
        "wrmsr",
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "movq $int_stack_top, %rdi",
        "movq (%rdi, %rdx, 8), %rsp",
        "andq $-16, %rsp",
        "pushq $0",
        "popfq",
        "call {cpu_ap_main} - {kernel_base}",
        "3:",
        "hlt",
        "jmp 3b",
        ".p2align 4",
        ".word 0",
        "gdt_descr_tmp:",
        ".short 3*8-1",
        ".long (gdt_tmp - apboot)",
        ".p2align 4",
        "gdt_tmp:",
        ".quad 0",
        ".word 0xffff",
        ".word 0x0000",
        ".byte 0x00",
        ".byte {boot_access_code}",
        ".byte {boot_size_32}",
        ".byte 0x00",
        ".word 0xffff",
        ".word 0x0000",
        ".byte 0x00",
        ".byte {boot_access_data}",
        ".byte {boot_size_32}",
        ".byte 0x00",
        ".p2align 4",
        "apboot_jmp_offset:",
        ".long (apboot32 - apboot)",
        ".word {boot_cs}",
        "apbootend:",
        ".section .boot.data,\"ax\",@progbits",
        ".p2align 12",
        "AP_p4table:",
        ".space 4096",
        "AP_p3table:",
        ".space 4096",
        "AP_p2table:",
        ".space 4096",
        "AP_p2table1:",
        ".space 4096",
        "AP_p2table2:",
        ".space 4096",
        "AP_p2table3:",
        ".space 4096",
        "AP_p3ktable:",
        ".space 4096",
        "AP_p2ktable1:",
        ".space 4096",
        "AP_p2ktable2:",
        ".space 4096",
        ".p2align 4",
        "apboot_idt_ptr:",
        ".quad 0",
        ".word 0",
        ".code64",
        ".p2align 4",
        "apboot_gdt64_top:",
        ".long 0",
        ".word 0",
        "apboot_gdt64_descr:",
        ".word {gdt64_descr_limit}",
        "apboot_gdt64_descr_addr:",
        ".quad apboot_gdt64",
        "apboot_gdt64:",
        ".quad 0",
        ".quad {boot_gdt64_code}",
        ".quad {boot_gdt64_data}",
        kernel_base = const KERNEL_BASE,
        boot_cs = const BOOT_CS,
        boot_ds = const BOOT_DS,
        cr0_set_flags = const CR0_SET_FLAGS,
        cr0_clear_flags_mask = const CR0_CLEAR_FLAGS_MASK,
        boot_access_code = const BOOT_ACCESS_CODE,
        boot_access_data = const BOOT_ACCESS_DATA,
        boot_size_32 = const BOOT_SIZE_32,
        apic_msr = const APIC_MSR,
        apic_msr_bsp_x2apic_clear = const APIC_MSR_BSP_X2APIC_CLEAR,
        apic_msr_enable = const ApicBase::ENABLE.bits(),
        pte_v_w = const PTE_V_W,
        pte_v_w_s = const PTE_V_W_S,
        p4_kernel_index = const P4_KERNEL_INDEX,
        p3_kernel_index = const P3_KERNEL_INDEX,
        cr4_pae = const Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits(),
        msr_reg_efer = const MSR_REG_EFER,
        msr_efer_long_mode_en = const EferFlags::LONG_MODE_ENABLE.bits(),
        cr0_pg = const Cr0Flags::PAGING.bits(),
        cr0_wp = const Cr0Flags::WRITE_PROTECT.bits(),
        msr_reg_gsbase = const MSR_REG_GSBASE,
        msr_reg_kgsbase = const MSR_REG_KGSBASE,
        per_cpu_offset = const PER_CPU_OFFSET,
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET,
        kernel_cs = const KERNEL_CS,
        kernel_ds = const KERNEL_DS,
        gdt64_descr_limit = const GDT64_DESCR_LIMIT,
        boot_gdt64_code = const BOOT_GDT64_CODE,
        boot_gdt64_data = const BOOT_GDT64_DATA,
        cpu_ap_main = sym cpu_ap_main,
        options(att_syntax),
    );
}
