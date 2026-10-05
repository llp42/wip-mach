// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/cswitch.S and x86_64/cswitch.S:
//   Copyright (c) 1991,1990 Carnegie Mellon University
//   All Rights Reserved.
//
//   Permission to use, copy, modify and distribute this software and its
//   documentation is hereby granted, provided that both the copyright
//   notice and this permission notice appear in all copies of the
//   software, derivative works or modified versions, and any portions
//   thereof, and that both notices appear in supporting documentation.
//
//   CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
//   CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
//   ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The context switch.

use crate::arch::vm_param::KERNEL_STACK_SIZE;
use crate::arch::x86_64::mp_desc::{INT_STACK_BASE, INTSTACK_SIZE};
use crate::arch::x86_64::pcb::{
    I386ExceptionLink, I386KernelState, KERNEL_STACK,
};
use crate::arch::x86_64::per_cpu::PerCpu;
use crate::kern::processor::Processor;
use crate::kern::sched_prim::thread_dispatch_entry;
use crate::kern::thread::{Continuation, Thread};
use core::arch::naked_asm;
use core::mem::{offset_of, size_of};

/// Where the kernel state starts at the top of a kernel stack.
const IKS_OFFSET: usize = KERNEL_STACK_SIZE - size_of::<I386KernelState>();

/// The `k_ebx` slot measured from a kernel stack's base.
const KSS_EBX_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_ebx);
/// The `k_esp` slot measured from a kernel stack's base.
const KSS_ESP_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_esp);
/// The `k_ebp` slot measured from a kernel stack's base.
const KSS_EBP_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_ebp);
/// The `k_eip` slot measured from a kernel stack's base.
const KSS_EIP_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_eip);
/// The `k_r12` slot measured from a kernel stack's base.
const KSS_R12_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_r12);
/// The `k_r13` slot measured from a kernel stack's base.
const KSS_R13_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_r13);
/// The `k_r14` slot measured from a kernel stack's base.
const KSS_R14_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_r14);
/// The `k_r15` slot measured from a kernel stack's base.
const KSS_R15_OFFSET: usize = IKS_OFFSET + offset_of!(I386KernelState, k_r15);

/// Where the exception link begins at the top of a kernel stack.
const STACK_TOP: usize = KERNEL_STACK_SIZE
    - size_of::<I386KernelState>()
    - size_of::<I386ExceptionLink>();

/// The offset of `kernel_stack` within a [`Thread`].
const TH_KERNEL_STACK_OFFSET: usize = offset_of!(Thread, kernel_stack);
/// The offset of `swap_func` within a [`Thread`].
const TH_SWAP_FUNC_OFFSET: usize = offset_of!(Thread, swap_func);

/// Resumes `new` on this CPU, with no old thread.
///
/// # Safety
///
/// `new` must be a live thread whose kernel stack and saved context are ready
/// to resume, and no other CPU may be running it.  The caller must be in
/// kernel mode with `%gs` based at this CPU's per-CPU block.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn load_context(new: *mut Thread) -> ! {
    naked_asm!(
        "movq %rdi, %rcx",
        "movq {th_kernel_stack_offset}(%rcx), %rcx",
        "leaq {stack_top}(%rcx), %rdx",
        "movl %gs:{cpu_id}, %eax",
        "movq %rcx, %gs:{stack}",
        "movq %rdx, {kernel_stack}(, %rax, 8)",
        "movq {kss_esp_offset}(%rcx), %rsp",
        "movq {kss_ebp_offset}(%rcx), %rbp",
        "movq {kss_ebx_offset}(%rcx), %rbx",
        "movq {kss_r12_offset}(%rcx), %r12",
        "movq {kss_r13_offset}(%rcx), %r13",
        "movq {kss_r14_offset}(%rcx), %r14",
        "movq {kss_r15_offset}(%rcx), %r15",
        "xorl %eax, %eax",
        "jmp *{kss_eip_offset}(%rcx)",
        th_kernel_stack_offset = const TH_KERNEL_STACK_OFFSET,
        stack_top = const STACK_TOP,
        cpu_id = const offset_of!(PerCpu, cpu_id),
        stack = const offset_of!(PerCpu, stack),
        kernel_stack = sym KERNEL_STACK,
        kss_esp_offset = const KSS_ESP_OFFSET,
        kss_ebp_offset = const KSS_EBP_OFFSET,
        kss_ebx_offset = const KSS_EBX_OFFSET,
        kss_r12_offset = const KSS_R12_OFFSET,
        kss_r13_offset = const KSS_R13_OFFSET,
        kss_r14_offset = const KSS_R14_OFFSET,
        kss_r15_offset = const KSS_R15_OFFSET,
        kss_eip_offset = const KSS_EIP_OFFSET,
        options(att_syntax),
    );
}

/// Saves the running thread's kernel context, resumes `new`, and returns `old`
/// in `%rax`.
///
/// The register saves only matter when a thread later resumes with no
/// explicit continuation; it then lands on the return PC saved here.
///
/// # Safety
///
/// `old` must be the running thread and `new` the thread about to run, both
/// live and not running on any other CPU, and `continuation` must be where
/// `old` resumes when it has one.  The caller must be in kernel mode with
/// `%gs` based at this CPU's per-CPU block.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn switch_context(
    old: *mut Thread,
    continuation: Continuation,
    new: *mut Thread,
) -> *mut Thread {
    naked_asm!(
        "movq %gs:{stack}, %rcx",
        "movq %r12, {kss_r12_offset}(%rcx)",
        "movq %r13, {kss_r13_offset}(%rcx)",
        "movq %r14, {kss_r14_offset}(%rcx)",
        "movq %r15, {kss_r15_offset}(%rcx)",
        "movq %rbx, {kss_ebx_offset}(%rcx)",
        "movq %rbp, {kss_ebp_offset}(%rcx)",
        "popq {kss_eip_offset}(%rcx)",
        "movq %rsp, {kss_esp_offset}(%rcx)",
        "movq %rdi, %rax",
        "movq %rcx, {th_kernel_stack_offset}(%rax)",
        "movq %rsi, %rbx",
        "movq %rbx, {th_swap_func_offset}(%rax)",
        "movq %rdx, %rsi",
        "movq {th_kernel_stack_offset}(%rsi), %rcx",
        "leaq {stack_top}(%rcx), %rbx",
        "movl %gs:{cpu_id}, %edx",
        "movq %rsi, %gs:{thread}",
        "movq %rcx, %gs:{stack}",
        "movq %rbx, {kernel_stack}(, %rdx, 8)",
        "movq {kss_esp_offset}(%rcx), %rsp",
        "movq {kss_ebp_offset}(%rcx), %rbp",
        "movq {kss_ebx_offset}(%rcx), %rbx",
        "movq {kss_r12_offset}(%rcx), %r12",
        "movq {kss_r13_offset}(%rcx), %r13",
        "movq {kss_r14_offset}(%rcx), %r14",
        "movq {kss_r15_offset}(%rcx), %r15",
        "jmp *{kss_eip_offset}(%rcx)",
        stack = const offset_of!(PerCpu, stack),
        thread = const offset_of!(PerCpu, thread),
        cpu_id = const offset_of!(PerCpu, cpu_id),
        th_kernel_stack_offset = const TH_KERNEL_STACK_OFFSET,
        th_swap_func_offset = const TH_SWAP_FUNC_OFFSET,
        stack_top = const STACK_TOP,
        kernel_stack = sym KERNEL_STACK,
        kss_ebx_offset = const KSS_EBX_OFFSET,
        kss_ebp_offset = const KSS_EBP_OFFSET,
        kss_r12_offset = const KSS_R12_OFFSET,
        kss_r13_offset = const KSS_R13_OFFSET,
        kss_r14_offset = const KSS_R14_OFFSET,
        kss_r15_offset = const KSS_R15_OFFSET,
        kss_eip_offset = const KSS_EIP_OFFSET,
        kss_esp_offset = const KSS_ESP_OFFSET,
        options(att_syntax),
    );
}

/// Calls the continuation in `%rbx` with the thread in `%rax` as its argument.
///
/// # Safety
///
/// Entered only by a context switch resuming a thread's stack, with `%rax`
/// holding the thread and `%rbx` the continuation it must call.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn thread_continue() {
    naked_asm!(
        "movq %rax, %rdi",
        "xorq %rbp, %rbp",
        "call *%rbx",
        options(att_syntax),
    );
}

/// Saves `thread`'s kernel context, switches to its CPU's interrupt stack,
/// dispatches `thread`, and runs `routine(processor)` there.
///
/// The stack switch leaves both calls 16-byte aligned, as the assembly
/// did, and `thread` is a kernel thread, so it has no FPU state to save.
///
/// # Safety
///
/// `thread` must be a live kernel thread whose processor is being shut down,
/// `routine` must be callable on the interrupt stack, and `processor` must be
/// the argument it expects.  The caller must be in kernel mode with `%gs`
/// based at this CPU's per-CPU block.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn switch_to_shutdown_context(
    thread: *mut Thread,
    routine: Option<unsafe extern "C" fn(*mut Processor)>,
    processor: *mut Processor,
) {
    naked_asm!(
        "movq %gs:{stack}, %rcx",
        "movq %r12, {kss_r12_offset}(%rcx)",
        "movq %r13, {kss_r13_offset}(%rcx)",
        "movq %r14, {kss_r14_offset}(%rcx)",
        "movq %r15, {kss_r15_offset}(%rcx)",
        "movq %rbx, {kss_ebx_offset}(%rcx)",
        "movq %rbp, {kss_ebp_offset}(%rcx)",
        "popq {kss_eip_offset}(%rcx)",
        "movq %rsp, {kss_esp_offset}(%rcx)",
        "movq %rdi, %rax",
        "movq %rcx, {th_kernel_stack_offset}(%rax)",
        "movq $0, {th_swap_func_offset}(%rax)",
        "movq %rsi, %rbx",
        // `thread_dispatch` clobbers caller-saved registers, so the
        // processor waits in `%r12`, which the KSS save above freed.
        "movq %rdx, %r12",
        "movl %gs:{cpu_id}, %ecx",
        "movq {int_stack_base}(, %rcx, 8), %rcx",
        "leaq {int_stack_size}(%rcx), %rsp",
        "movq %rax, %rdi",
        "call {thread_dispatch}",
        "movq %r12, %rdi",
        "call *%rbx",
        "hlt",
        stack = const offset_of!(PerCpu, stack),
        cpu_id = const offset_of!(PerCpu, cpu_id),
        th_kernel_stack_offset = const TH_KERNEL_STACK_OFFSET,
        th_swap_func_offset = const TH_SWAP_FUNC_OFFSET,
        int_stack_base = sym INT_STACK_BASE,
        int_stack_size = const INTSTACK_SIZE,
        thread_dispatch = sym thread_dispatch_entry,
        kss_ebx_offset = const KSS_EBX_OFFSET,
        kss_ebp_offset = const KSS_EBP_OFFSET,
        kss_r12_offset = const KSS_R12_OFFSET,
        kss_r13_offset = const KSS_R13_OFFSET,
        kss_r14_offset = const KSS_R14_OFFSET,
        kss_r15_offset = const KSS_R15_OFFSET,
        kss_eip_offset = const KSS_EIP_OFFSET,
        kss_esp_offset = const KSS_ESP_OFFSET,
        options(att_syntax),
    );
}
