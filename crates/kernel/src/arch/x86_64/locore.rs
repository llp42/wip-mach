// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/locore.S and x86_64/locore.S:
//   Copyright (c) 1993,1992,1991,1990 Carnegie Mellon University
//   Copyright (c) 1991 IBM Corporation
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The low-level entries: the CPU probe, the trap and interrupt entries, the
//! return paths and the system-call entries, plus the forced shutdown.
//!
//! Every label jumped to across functions is a private naked function reached
//! by `sym`; the labels named by address keep their exact names.

use crate::arch::vm_param::KERNEL_STACK_SIZE;
use crate::arch::vm_param::VM_MAX_USER_ADDRESS;
use crate::arch::x86_64::interrupt::interrupt;
use crate::arch::x86_64::mp_desc::{
    INT_STACK_BASE, INT_STACK_TOP, INTSTACK_SIZE,
};
use crate::arch::x86_64::pcb::{
    I386ExceptionLink, I386InterruptState, I386KernelState, I386SavedState,
    KERNEL_STACK,
};
use crate::arch::x86_64::pcb::{MSR_REG_GSBASE, Pcb};
use crate::arch::x86_64::per_cpu::PerCpu;
use crate::arch::x86_64::trap::T_DOUBLE_FAULT;
use crate::arch::x86_64::trap::handle_double_fault_entry;
use crate::arch::x86_64::trap::{
    T_DEBUG, T_GENERAL_PROTECTION, T_INVALID_OPCODE, T_PAGE_FAULT, T_PF_USER,
    T_SEGMENT_NOT_PRESENT,
};
use crate::arch::x86_64::trap::{
    i386_astintr, kernel_trap_entry, user_trap_entry,
};
use crate::kern::ast::AST_ARRAY;
use crate::kern::syscall_sw::{MACH_TRAP_COUNT, MACH_TRAP_TABLE, MachTrap};
use crate::kern::thread::{Continuation, Thread};
use core::arch::{asm, naked_asm};
use core::ffi::{c_char, c_int, c_uint};
use core::mem::{offset_of, size_of};

/// The offset of `cpu_id` within the per-CPU block.
const PER_CPU_CPU_ID_OFFSET: usize = offset_of!(PerCpu, cpu_id);
/// The offset of `thread` within the per-CPU block.
const PER_CPU_THREAD_OFFSET: usize = offset_of!(PerCpu, thread);
/// The offset of `pcb` within a [`Thread`].
const TH_PCB_OFFSET: usize = offset_of!(Thread, pcb);
/// The offset of `iss` within a [`Pcb`].
const PCB_ISS_OFFSET: usize = offset_of!(Pcb, iss);

/// The offset of `eax` within an [`I386SavedState`].
const R_EAX_OFFSET: usize = offset_of!(I386SavedState, eax);
/// The offset of `cr2` within an [`I386SavedState`].
const R_CR2_OFFSET: usize = offset_of!(I386SavedState, cr2);
/// The offset of `trapno` within an [`I386SavedState`].
const R_TRAPNO_OFFSET: usize = offset_of!(I386SavedState, trapno);
/// The offset of `err` within an [`I386SavedState`].
const R_ERR_OFFSET: usize = offset_of!(I386SavedState, err);
/// The offset of `eip` within an [`I386SavedState`].
const R_EIP_OFFSET: usize = offset_of!(I386SavedState, eip);
/// The offset of `cs` within an [`I386SavedState`].
const R_CS_OFFSET: usize = offset_of!(I386SavedState, cs);
/// The offset of `efl` within an [`I386SavedState`].
const R_EFLAGS_OFFSET: usize = offset_of!(I386SavedState, efl);
/// The offset of `uesp` within an [`I386SavedState`].
const R_UESP_OFFSET: usize = offset_of!(I386SavedState, uesp);
/// The offset of `edi` within an [`I386SavedState`].
const R_EDI_OFFSET: usize = offset_of!(I386SavedState, edi);
/// The offset of `esi` within an [`I386SavedState`].
const R_ESI_OFFSET: usize = offset_of!(I386SavedState, esi);
/// The offset of `ebx` within an [`I386SavedState`].
const R_EBX_OFFSET: usize = offset_of!(I386SavedState, ebx);
/// The offset of `edx` within an [`I386SavedState`].
const R_EDX_OFFSET: usize = offset_of!(I386SavedState, edx);
/// The offset of `ebp` within an [`I386SavedState`].
const R_EBP_OFFSET: usize = offset_of!(I386SavedState, ebp);
/// The offset of `r8` within an [`I386SavedState`].
const R_R8_OFFSET: usize = offset_of!(I386SavedState, r8);
/// The offset of `r9` within an [`I386SavedState`].
const R_R9_OFFSET: usize = offset_of!(I386SavedState, r9);
/// The offset of `r10` within an [`I386SavedState`].
const R_R10_OFFSET: usize = offset_of!(I386SavedState, r10);
/// The offset of `r12` within an [`I386SavedState`].
const R_R12_OFFSET: usize = offset_of!(I386SavedState, r12);
/// The offset of `r13` within an [`I386SavedState`].
const R_R13_OFFSET: usize = offset_of!(I386SavedState, r13);
/// The offset of `r14` within an [`I386SavedState`].
const R_R14_OFFSET: usize = offset_of!(I386SavedState, r14);
/// The offset of `r15` within an [`I386SavedState`].
const R_R15_OFFSET: usize = offset_of!(I386SavedState, r15);

/// The offset of `cs` within an [`I386InterruptState`].
const I_CS_OFFSET: usize = offset_of!(I386InterruptState, cs);

/// The CR2 slot measured from the frame's r15.
const R_CR2_MINUS_R_R15: usize = R_CR2_OFFSET - R_R15_OFFSET;

/// The mask that folds a stack pointer to the last byte of its kernel
/// stack.
const KERNEL_STACK_MASK: usize = KERNEL_STACK_SIZE - 1;

/// Where the exception link's saved-state pointer sits, relative to the
/// kernel stack's last byte.
const STACK_IEL_FROM_TOP: isize = -((size_of::<I386KernelState>()
    + size_of::<I386ExceptionLink>()
    - 1) as isize);

/// The mask that folds a stack pointer to its interrupt stack.
const INTSTACK_MASK: isize = -(INTSTACK_SIZE as isize);

/// The shift from a syscall number to its `mach_trap_table` entry.
const MACH_TRAP_SHIFT: u32 = size_of::<MachTrap>().trailing_zeros();
const _: () = assert!(size_of::<MachTrap>() == 1 << MACH_TRAP_SHIFT);

/// The offset of `mach_trap_function` within a [`MachTrap`].
const MACH_TRAP_FUNCTION: usize = offset_of!(MachTrap, mach_trap_function);

/// The `%r12` tag for a return that must not swap `%gs`.
const RETURN_TO_KERN: u32 = 0x7ead_beef;
/// The `%r12` tag for a return that must swap `%gs`.
const RETURN_TO_USER: u32 = 0x6666_6666;

unsafe extern "C" {
    /// The same address as [`thread_exception_return()`], whose entry emits
    /// the label.
    pub(crate) fn thread_bootstrap_return();

    /// The return address of `interrupt()` that `hardclock()` compares
    /// against.  [`all_intrs()`] emits the label right after the call.
    pub(crate) static return_to_iret: c_char;
}

/// CPUID leaf 1's EDX in word 0 and ECX in word 1.
pub static mut CPU_FEATURES: [c_uint; 2] = [0; 2];

/// The CPU family, 3 to 6, and a fill of [`CPU_FEATURES`].
pub(crate) fn discover_x86_cpu_type() -> c_int {
    let (eax, ecx, edx) = cpuid_leaf1();
    // SAFETY: `CPU_FEATURES` is written only here, during the single-threaded
    // boot before any reader runs.
    unsafe {
        let table = core::ptr::addr_of_mut!(CPU_FEATURES).cast::<c_uint>();
        table.write(edx);
        table.add(1).write(ecx);
    }
    // The family is bits 8-11 of EAX; 15 is all four bits can hold, so
    // the conversion loses nothing that matters.
    ((eax >> 8) & 15) as c_int
}

/// CPUID leaf 1, whose EAX holds the family and whose ECX and EDX are the
/// two feature words.
fn cpuid_leaf1() -> (u32, u32, u32) {
    let eax: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: `cpuid` is the CPU's own instruction; the surrounding
    // moves save and restore the `%rbx` LLVM reserves.
    unsafe {
        asm!(
            "mov {scratch:r}, rbx",
            "cpuid",
            "xchg {scratch:r}, rbx",
            scratch = out(reg) _,
            inout("eax") 1u32 => eax,
            lateout("ecx") ecx,
            out("edx") edx,
            options(nostack),
        );
    }
    (eax, ecx, edx)
}

/// The 256-byte zeroed table `cpu_shutdown()` points the IDTR at.
static NULL_IDT: [u8; 8 * 32] = [0; 8 * 32];

/// The IDTR limit for [`NULL_IDT`]: one byte less than its size.
const NULL_IDT_LIMIT: u16 = 8 * 32 - 1;

/// The empty IDT pseudo-descriptor: a limit followed by the base address, with
/// no padding.
///
/// The base is a pointer because a `static` cannot hold a
/// pointer-to-integer cast; the bytes are the same relocation.
#[repr(C, packed)]
#[allow(missing_docs)]
struct NullIdtr {
    limit: u16,
    base: *const u8,
}

// SAFETY: `NULL_IDTR` is immutable and Rust never dereferences its base
// pointer; the only reader is `lidt` itself.
unsafe impl Sync for NullIdtr {}

const _: () = {
    assert!(size_of::<NullIdtr>() == 2 + size_of::<*const u8>());
    assert!(offset_of!(NullIdtr, limit) == 0);
    assert!(offset_of!(NullIdtr, base) == 2);
};

static NULL_IDTR: NullIdtr = NullIdtr {
    limit: NULL_IDT_LIMIT,
    base: core::ptr::addr_of!(NULL_IDT).cast::<u8>(),
};

/// Disables the IDT and divides by zero, which resets the machine.
///
/// # Safety
///
/// The caller must be done: with no handlers left, the divide-by-zero
/// fault does not return.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn cpu_shutdown() -> ! {
    naked_asm!(
        "lidt [{idtr}]",
        "xor ecx, ecx",
        "div ecx",
        idtr = sym NULL_IDTR,
    )
}

/// Reports a GP or NP fault on a user return sequence against the user's
/// instruction.
///
/// # Safety
///
/// Entered by `t_gen_prot`/`t_segnp` with the fault's error code and frame
/// on the stack.
#[unsafe(naked)]
unsafe extern "C" fn trap_check_kernel_exit() {
    // SAFETY: the C label's body; the frame runs on eight-byte slots.
    naked_asm!(
        "testq $2, 24(%rsp)",
        "jnz {alltraps}",
        "cmpq ${kret_iret}, 16(%rsp)",
        "je {fault_iret}",
        "jmp {take_fault}",
        alltraps = sym alltraps,
        kret_iret = sym kret_iret,
        fault_iret = sym fault_iret,
        take_fault = sym take_fault,
        options(att_syntax),
    );
}

/// The `take_fault` tail of the trap-check chain: no return sequence
/// matched, so the fault is a normal trap.
///
/// # Safety
///
/// Entered only by jump from [`trap_check_kernel_exit`] and the
/// [`t_gen_prot`]/[`t_segnp`] entries.
#[unsafe(naked)]
unsafe extern "C" fn take_fault() {
    // SAFETY: the C label's one jump; the frame is the fault's.
    naked_asm!("jmp {alltraps}", alltraps = sym alltraps, options(att_syntax));
}

/// A GP or NP fault on the return path's IRET, where CS or SS is the error.
///
/// # Safety
///
/// Entered only by jump from [`trap_check_kernel_exit`], with the fault's
/// frame on the stack.
#[unsafe(naked)]
unsafe extern "C" fn fault_iret() {
    naked_asm!(
        "movq %rax, 16(%rsp)",
        "popq %rax",
        "movq %rax, 16(%rsp)",
        "popq %rax",
        "movq %rax, 16(%rsp)",
        "popq %rax",
        "jmp {alltraps}",
        alltraps = sym alltraps,
        options(att_syntax),
    );
}

/// The general-protection fault entry.
///
/// # Safety
///
/// Entered only by the CPU through the IDT gate this entry is installed in.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn t_gen_prot() {
    naked_asm!(
        "pushq ${trapno}",
        "jmp {trap_check_kernel_exit}",
        trapno = const T_GENERAL_PROTECTION,
        trap_check_kernel_exit = sym trap_check_kernel_exit,
        options(att_syntax),
    );
}

/// The segment-not-present fault entry.
///
/// # Safety
///
/// Entered only by the CPU through the IDT gate this entry is installed in.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn t_segnp() {
    naked_asm!(
        "pushq ${trapno}",
        "jmp {trap_check_kernel_exit}",
        trapno = const T_SEGMENT_NOT_PRESENT,
        trap_check_kernel_exit = sym trap_check_kernel_exit,
        options(att_syntax),
    );
}

/// The debug trap entry, which continues a system call when single-stepping
/// crossed it.
///
/// # Safety
///
/// Entered only by the CPU through the IDT gate this entry is installed in.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn t_debug() {
    naked_asm!(
        "testq $2, 8(%rsp)",
        "jnz 0f",
        // TODO: implement the system-call case; it is a UD2 for now.
        "ud2",
        "0:",
        "pushq $0",
        "pushq ${trapno}",
        "jmp {alltraps}",
        trapno = const T_DEBUG,
        alltraps = sym alltraps,
        options(att_syntax),
    );
}

/// The page fault entry, which saves `%cr2` in the frame.
///
/// # Safety
///
/// Entered only by the CPU through the IDT gate this entry is installed in.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn t_page_fault() {
    naked_asm!(
        "pushq ${trapno}",
        "pushq %rax",
        "pushq %rcx",
        "pushq %rdx",
        "pushq %rbx",
        "subq $8, %rsp",
        "pushq %rbp",
        "pushq %rsi",
        "pushq %rdi",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "movq %cr2, %rax",
        "movq %rax, {r_cr2}(%rsp)",
        "jmp {trap_push_segs}",
        trapno = const T_PAGE_FAULT,
        r_cr2 = const R_CR2_MINUS_R_R15,
        trap_push_segs = sym trap_push_segs,
        options(att_syntax),
    );
}

/// The common trap-frame builder every exception stub jumps to.
///
/// # Safety
///
/// Entered only by jump from an IDT trap stub, with the CPU's error code
/// and frame on the stack.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn alltraps() {
    naked_asm!(
        "pushq %rax",
        "pushq %rcx",
        "pushq %rdx",
        "pushq %rbx",
        "subq $8, %rsp",
        "pushq %rbp",
        "pushq %rsi",
        "pushq %rdi",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "jmp {trap_push_segs}",
        trap_push_segs = sym trap_push_segs,
        options(att_syntax),
    );
}

/// Saves the segment registers, switches to the kernel's, and joins
/// `trap_set_segs`.
///
/// # Safety
///
/// Entered by jump from [`alltraps`] or [`t_page_fault`], with the general
/// registers already saved.
#[unsafe(naked)]
unsafe extern "C" fn trap_push_segs() {
    // SAFETY: the kernel segments need no loading, so only the `%r12` return
    // tag is set.
    naked_asm!(
        "pushf",
        "cli",
        "pushq %rax",
        "pushq %rcx",
        "pushq %rdx",
        "movl ${msr_gsbase}, %ecx",
        "rdmsr",
        "testl %edx, %edx",
        "js 0f",
        "swapgs",
        "movq ${return_to_user}, %r12",
        "jmp 1f",
        "0:",
        "movq ${return_to_kern}, %r12",
        "1:",
        "popq %rdx",
        "popq %rcx",
        "popq %rax",
        "popf",
        "jmp {trap_set_segs}",
        msr_gsbase = const MSR_REG_GSBASE,
        return_to_user = const RETURN_TO_USER,
        return_to_kern = const RETURN_TO_KERN,
        trap_set_segs = sym trap_set_segs,
        options(att_syntax),
    );
}

/// Clears the direction flag and picks the user or kernel trap path.
///
/// # Safety
///
/// Entered by jump from [`trap_push_segs`], with the kernel segments
/// loaded and the frame on the stack.
#[unsafe(naked)]
unsafe extern "C" fn trap_set_segs() {
    // SAFETY: the C label's body; `R_CS_OFFSET` names the frame's saved code
    // selector.
    naked_asm!(
        "cld",
        "testb $2, {r_cs_offset}(%rsp)",
        "jz {trap_from_kernel}",
        "jmp {trap_from_user}",
        r_cs_offset = const R_CS_OFFSET,
        trap_from_user = sym trap_from_user,
        trap_from_kernel = sym trap_from_kernel,
        options(att_syntax),
    );
}

/// Switches from the PCB stack to the kernel stack and takes the trap.
///
/// # Safety
///
/// Entered by jump from [`trap_set_segs`] with a user-mode frame.
#[unsafe(naked)]
unsafe extern "C" fn trap_from_user() {
    naked_asm!(
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "movq {kernel_stack}(,%rdx,8), %rbx",
        "xchgq %rbx, %rsp",
        "jmp {take_trap}",
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET,
        kernel_stack = sym KERNEL_STACK,
        take_trap = sym take_trap,
        options(att_syntax),
    );
}

/// Calls `user_trap()` with the register save area and acts on its answer.
///
/// # Safety
///
/// Entered by jump from [`trap_from_user`], with `%rbx` holding the PCB
/// stack and the kernel stack in use, or by jump from the system-call
/// fixups with `%rbx` holding the frame.
#[unsafe(naked)]
unsafe extern "C" fn take_trap() {
    naked_asm!(
        "movq %rbx, %rdi",
        "call {user_trap}",
        "movq (%rsp), %rsp",
        "jmp {return_from_trap}",
        user_trap = sym user_trap_entry,
        return_from_trap = sym return_from_trap,
        options(att_syntax),
    );
}

/// Returns from a trap or system call, taking any pending AST first.
///
/// # Safety
///
/// Entered on the PCB stack with a complete register save area on it.
#[unsafe(naked)]
unsafe extern "C" fn return_from_trap() {
    naked_asm!(
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "cmpl $0, {ast_array}(,%rdx,4)",
        "jz {return_to_user}",
        "movq {kernel_stack}(,%rdx,8), %rsp",
        "call {i386_astintr}",
        "popq %rsp",
        "jmp {return_from_trap}",
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET,
        ast_array = sym AST_ARRAY,
        return_to_user = sym return_to_user,
        kernel_stack = sym KERNEL_STACK,
        i386_astintr = sym i386_astintr,
        return_from_trap = sym return_from_trap,
        options(att_syntax),
    );
}

/// Returns to user mode when the AST check found nothing pending.
///
/// # Safety
///
/// Entered only by jump from [`return_from_trap`].
#[unsafe(naked)]
unsafe extern "C" fn return_to_user() {
    // SAFETY: the path falls into `return_from_kernel`.
    naked_asm!(
        "jmp {return_from_kernel}",
        return_from_kernel = sym return_from_kernel,
        options(att_syntax),
    );
}

/// Pops the save area and returns to the interrupted context.
///
/// # Safety
///
/// Entered only by jump from [`return_to_user`] or
/// [`trap_from_kernel`], with the frame on the stack.
#[unsafe(naked)]
unsafe extern "C" fn return_from_kernel() {
    naked_asm!(
        "cmpq ${return_to_user}, %r12",
        "je 0f",
        "cmpq ${return_to_kern}, %r12",
        "je 1f",
        "ud2",
        "0:",
        "swapgs",
        "1:",
        "popq %r15",
        "popq %r14",
        "popq %r13",
        "popq %r12",
        "popq %r11",
        "popq %r10",
        "popq %r9",
        "popq %r8",
        "popq %rdi",
        "popq %rsi",
        "popq %rbp",
        "addq $8, %rsp",
        "popq %rbx",
        "popq %rdx",
        "popq %rcx",
        "popq %rax",
        "addq $16, %rsp",
        "jmp {kret_iret}",
        return_to_user = const RETURN_TO_USER,
        return_to_kern = const RETURN_TO_KERN,
        kret_iret = sym kret_iret,
        options(att_syntax),
    );
}

/// The IRET of the return path.
///
/// # Safety
///
/// Entered only by jump from the return path, with the interrupt frame on
/// top.
#[unsafe(naked)]
unsafe extern "C" fn kret_iret() {
    naked_asm!("iretq", options(att_syntax));
}

/// Calls `kernel_trap()` on the frame and returns.
///
/// # Safety
///
/// Entered by jump from [`trap_set_segs`] with a kernel-mode frame.
#[unsafe(naked)]
unsafe extern "C" fn trap_from_kernel() {
    // SAFETY: the C label's body; `kernel_trap()` takes the frame's
    // address.
    naked_asm!(
        "movq %rsp, %rdi",
        "call {kernel_trap}",
        "jmp {return_from_kernel}",
        kernel_trap = sym kernel_trap_entry,
        return_from_kernel = sym return_from_kernel,
        options(att_syntax),
    );
}

/// Makes the current thread return from the kernel as if from an exception.
///
/// The entry also emits `thread_bootstrap_return`, which the C defined at
/// this same address; `kern/thread.rs`'s clean-point checks compare the two
/// by address.
///
/// # Safety
///
/// The caller must be the current thread's clean-point path, on its kernel
/// stack.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn thread_exception_return() {
    naked_asm!(
        ".globl thread_bootstrap_return",
        "thread_bootstrap_return:",
        "movq %rsp, %rcx",
        "orq ${stack_mask}, %rcx",
        "movq {stack_iel}(%rcx), %rsp",
        "movq ${return_to_user}, %r12",
        "jmp {return_from_trap}",
        stack_mask = const KERNEL_STACK_MASK,
        stack_iel = const STACK_IEL_FROM_TOP,
        return_to_user = const RETURN_TO_USER,
        return_from_trap = sym return_from_trap,
        options(att_syntax),
    );
}

/// Makes the current thread return from the kernel as if from a system call,
/// with `retval` as its answer.
///
/// # Safety
///
/// The caller must be the current thread's clean-point path, on its kernel
/// stack.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn thread_syscall_return(_retval: c_int) -> ! {
    // SAFETY: the C label's body; the first argument travels in `%rdi`.
    naked_asm!(
        "movq %rdi, %rax",
        "movq %rsp, %rcx",
        "orq ${stack_mask}, %rcx",
        "movq {stack_iel}(%rcx), %rsp",
        "movq %rax, {r_eax_offset}(%rsp)",
        "movq ${return_to_user}, %r12",
        "jmp {return_from_trap}",
        stack_mask = const KERNEL_STACK_MASK,
        stack_iel = const STACK_IEL_FROM_TOP,
        r_eax_offset = const R_EAX_OFFSET,
        return_to_user = const RETURN_TO_USER,
        return_from_trap = sym return_from_trap,
        options(att_syntax),
    );
}

/// Drops the current kernel stack and calls `continuation` on a bare one.
///
/// # Safety
///
/// `continuation` must be a live continuation, and the caller must be
/// switching away from the current thread for good.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn call_continuation(
    _continuation: Continuation,
) -> ! {
    // SAFETY: the C label's body; the first argument travels in `%rdi`.
    naked_asm!(
        "movq %rdi, %rax",
        "movq %rsp, %rcx",
        "orq ${stack_mask}, %rcx",
        "addq ${stack_iel}, %rcx",
        "movq %rcx, %rsp",
        "xorq %rbp, %rbp",
        "pushq $0",
        "jmp *%rax",
        stack_mask = const KERNEL_STACK_MASK,
        stack_iel = const STACK_IEL_FROM_TOP,
        options(att_syntax),
    );
}

/// The double-fault entry, installed with IST 1.
///
/// # Safety
///
/// Entered only by the CPU through the IDT gate this entry is installed in.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn t_dbl_fault() {
    naked_asm!(
        "cli",
        "pushq ${trapno}",
        "pushq %rax",
        "pushq %rcx",
        "pushq %rdx",
        "pushq %rbx",
        "subq $8, %rsp",
        "pushq %rbp",
        "pushq %rsi",
        "pushq %rdi",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "movq %cr2, %rax",
        "movq %rax, {r_cr2}(%rsp)",
        "movq %rsp, %rdi",
        "call {handle_double_fault}",
        "jmp {cpu_shutdown}",
        trapno = const T_DOUBLE_FAULT,
        r_cr2 = const R_CR2_MINUS_R_R15,
        handle_double_fault = sym handle_double_fault_entry,
        cpu_shutdown = sym cpu_shutdown,
        options(att_syntax),
    );
}

/// The common interrupt entry, which also emits the `return_to_iret` label
/// `hardclock()` compares against.
///
/// # Safety
///
/// Entered only by jump from an interrupt stub, with the old `%eax` on the
/// stack and the interrupt number in `%eax`/`%rax`.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn all_intrs() {
    // SAFETY: the registers are saved before the return tag is set.
    naked_asm!(
        "pushq %rcx",
        "pushq %rdx",
        "pushq %rsi",
        "pushq %rdi",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %r12",
        "cld",
        "pushf",
        "cli",
        "pushq %rax",
        "pushq %rcx",
        "pushq %rdx",
        "movl ${msr_gsbase}, %ecx",
        "rdmsr",
        "testl %edx, %edx",
        "js 2f",
        "swapgs",
        "movq ${return_to_user}, %r12",
        "jmp 3f",
        "2:",
        "movq ${return_to_kern}, %r12",
        "3:",
        "popq %rdx",
        "popq %rcx",
        "popq %rax",
        "popf",
        "movl %gs:{per_cpu_cpu_id_offset}, %ecx",
        "movq %rsp, %rdx",
        "andq ${intstack_mask}, %rdx",
        "cmpq %ss:{int_stack_base}(,%rcx,8), %rdx",
        "je {int_from_intstack}",
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "movq {int_stack_top}(,%rdx,8), %rcx",
        "xchgq %rcx, %rsp",
        "pushq %rcx",
        "call {interrupt}",
        ".globl return_to_iret",
        "return_to_iret:",
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "popq %rsp",
        "testb $2, {i_cs_offset}(%rsp)",
        "jz 1f",
        "0:",
        "cmpl $0, {ast_array}(,%rdx,4)",
        "jnz {ast_from_interrupt}",
        "1:",
        "cmpq ${return_to_user}, %r12",
        "je 4f",
        "cmpq ${return_to_kern}, %r12",
        "je 5f",
        "ud2",
        "4:",
        "swapgs",
        "5:",
        "popq %r12",
        "popq %r11",
        "popq %r10",
        "popq %r9",
        "popq %r8",
        "popq %rdi",
        "popq %rsi",
        "popq %rdx",
        "popq %rcx",
        "popq %rax",
        "iretq",
        msr_gsbase = const MSR_REG_GSBASE,
        return_to_user = const RETURN_TO_USER,
        return_to_kern = const RETURN_TO_KERN,
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET,
        intstack_mask = const INTSTACK_MASK,
        int_stack_base = sym INT_STACK_BASE,
        int_stack_top = sym INT_STACK_TOP,
        int_from_intstack = sym int_from_intstack,
        interrupt = sym interrupt,
        i_cs_offset = const I_CS_OFFSET,
        ast_array = sym AST_ARRAY,
        ast_from_interrupt = sym ast_from_interrupt,
        options(att_syntax),
    );
}

/// The interrupt already ran on an interrupt stack, so it takes no ASTs.
///
/// # Safety
///
/// Entered only by jump from [`all_intrs`].
#[unsafe(naked)]
unsafe extern "C" fn int_from_intstack() {
    // SAFETY: the C label's body; the return tag is checked before the
    // pops.
    naked_asm!(
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "cmpq {int_stack_base}(,%rdx,8), %rsp",
        "jb {stack_overflowed}",
        "call {interrupt}",
        "cmpq ${return_to_user}, %r12",
        "je 4f",
        "cmpq ${return_to_kern}, %r12",
        "je 5f",
        "ud2",
        "4:",
        "swapgs",
        "5:",
        "popq %r12",
        "popq %r11",
        "popq %r10",
        "popq %r9",
        "popq %r8",
        "popq %rdi",
        "popq %rsi",
        "popq %rdx",
        "popq %rcx",
        "popq %rax",
        "iretq",
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET,
        int_stack_base = sym INT_STACK_BASE,
        stack_overflowed = sym stack_overflowed,
        interrupt = sym interrupt,
        return_to_user = const RETURN_TO_USER,
        return_to_kern = const RETURN_TO_KERN,
        options(att_syntax),
    );
}

/// The kernel's interrupt stack underran, which is unrecoverable.
///
/// # Safety
///
/// Entered only by jump when the check fails; it does not return.
#[unsafe(naked)]
unsafe extern "C" fn stack_overflowed() {
    naked_asm!("ud2", options(att_syntax));
}

/// Turns the interrupt frame into a user trap frame and takes the AST.
///
/// # Safety
///
/// Entered only by jump from [`all_intrs`], with an AST pending and the
/// interrupt frame on the stack.
#[unsafe(naked)]
unsafe extern "C" fn ast_from_interrupt() {
    // SAFETY: the interrupt frame is on the stack; the saved registers are
    // popped, the frame is rebuilt, and the return is marked as one to user
    // mode.
    naked_asm!(
        "popq %r12",
        "popq %r11",
        "popq %r10",
        "popq %r9",
        "popq %r8",
        "popq %rdi",
        "popq %rsi",
        "popq %rdx",
        "popq %rcx",
        "popq %rax",
        "pushq $0",
        "pushq $0",
        "pushq %rax",
        "pushq %rcx",
        "pushq %rdx",
        "pushq %rbx",
        "subq $8, %rsp",
        "pushq %rbp",
        "pushq %rsi",
        "pushq %rdi",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "movl %gs:{per_cpu_cpu_id_offset}, %edx",
        "movq {kernel_stack}(,%rdx,8), %rsp",
        "call {i386_astintr}",
        "popq %rsp",
        "movq ${return_to_user}, %r12",
        "jmp {return_from_trap}",
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET,
        kernel_stack = sym KERNEL_STACK,
        i386_astintr = sym i386_astintr,
        return_to_user = const RETURN_TO_USER,
        return_from_trap = sym return_from_trap,
        options(att_syntax),
    );
}

/// The 64-bit SYSCALL entry, which saves the thread state in its pcb and
/// invokes the system call.
///
/// # Safety
///
/// Entered only by SYSCALL, with the user stack still in `%rsp`.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn syscall64() -> ! {
    naked_asm!(
        "swapgs",
        "shlq $32, %r11",
        "shlq $32, %rax",
        "shrq $32, %rax",
        "orq %r11, %rax",
        "movq %gs:{per_cpu_thread_offset}, %r11",
        "movq {th_pcb_offset}(%r11), %r11",
        "addq ${pcb_iss_offset}, %r11",
        "movq %rsp, {r_uesp_offset}(%r11)",
        "movq %rcx, {r_eip_offset}(%r11)",
        "movq %rbx, {r_ebx_offset}(%r11)",
        "movq %rax, %rbx",
        "shrq $32, %rbx",
        "movq %rbx, {r_eflags_offset}(%r11)",
        "movq %rbp, {r_ebp_offset}(%r11)",
        "movq %r12, {r_r12_offset}(%r11)",
        "movq %r13, {r_r13_offset}(%r11)",
        "movq %r14, {r_r14_offset}(%r11)",
        "movq %r15, {r_r15_offset}(%r11)",
        "cdqe",
        "movq %rax, {r_eax_offset}(%r11)",
        "movq %rdi, {r_edi_offset}(%r11)",
        "movq %rsi, {r_esi_offset}(%r11)",
        "movq %rdx, {r_edx_offset}(%r11)",
        "movq %r10, {r_r10_offset}(%r11)",
        "movq %r8, {r_r8_offset}(%r11)",
        "movq %r9, {r_r9_offset}(%r11)",
        "movq %r11, %rbx",
        "movq %r10, %rcx",
        "movl %gs:{per_cpu_cpu_id_offset}, %r11d",
        "movq {kernel_stack}(,%r11,8), %rsp",
        "sti",
        "negl %eax",
        "jl {syscall64_range}",
        "cmpl {mach_trap_count}, %eax",
        "jg {syscall64_range}",
        "shll ${trap_shift}, %eax",
        "movq {mach_trap_table}(%rax), %r10",
        "subq $6, %r10",
        "jle 3f",
        "movq {r_uesp_offset}(%rbx), %r11",
        "addq $8, %r11",
        "leaq (%r11,%r10,8), %r11",
        "movq ${vm_max_address}, %r12",
        "cmpq %r12, %r11",
        "jae {syscall64_addr_push}",
        "0:",
        "subq $8, %r11",
        ".pushsection mach_recover,\"a\",@progbits",
        ".balign 8",
        ".quad 2f",
        ".quad {fixup}",
        ".popsection",
        "2:",
        "movq (%r11), %r12",
        "pushq %r12",
        "decq %r10",
        "jnz 0b",
        "3:",
        "call *{mach_trap_table}+{trap_function}(%rax)",
        "4:",
        "movl %gs:{per_cpu_cpu_id_offset}, %r11d",
        "cmpl $0, {ast_array}(,%r11,4)",
        "jz {syscall64_restore_state}",
        "pushq %rax",
        "pushq $0",
        "movq %rsp, %rcx",
        "orq ${stack_mask}, %rcx",
        "movq {stack_iel}(%rcx), %rcx",
        "movq %rax, {r_eax_offset}(%rcx)",
        "call {i386_astintr}",
        "popq %rax",
        "popq %rax",
        "jmp 4b",
        per_cpu_thread_offset = const PER_CPU_THREAD_OFFSET,
        th_pcb_offset = const TH_PCB_OFFSET, pcb_iss_offset = const PCB_ISS_OFFSET,
        r_uesp_offset = const R_UESP_OFFSET, r_eip_offset = const R_EIP_OFFSET, r_ebx_offset = const R_EBX_OFFSET,
        r_eflags_offset = const R_EFLAGS_OFFSET, r_ebp_offset = const R_EBP_OFFSET,
        r_r12_offset = const R_R12_OFFSET, r_r13_offset = const R_R13_OFFSET, r_r14_offset = const R_R14_OFFSET,
        r_r15_offset = const R_R15_OFFSET, r_eax_offset = const R_EAX_OFFSET, r_edi_offset = const R_EDI_OFFSET,
        r_esi_offset = const R_ESI_OFFSET, r_edx_offset = const R_EDX_OFFSET, r_r10_offset = const R_R10_OFFSET,
        r_r8_offset = const R_R8_OFFSET, r_r9_offset = const R_R9_OFFSET,
        per_cpu_cpu_id_offset = const PER_CPU_CPU_ID_OFFSET, kernel_stack = sym KERNEL_STACK,
        syscall64_range = sym syscall64_range,
        mach_trap_count = sym MACH_TRAP_COUNT,
        trap_shift = const MACH_TRAP_SHIFT, ast_array = sym AST_ARRAY,
        mach_trap_table = sym MACH_TRAP_TABLE,
        vm_max_address = const VM_MAX_USER_ADDRESS,
        syscall64_addr_push = sym syscall64_addr_push,
        fixup = sym syscall64_addr_push, stack_iel = const STACK_IEL_FROM_TOP,
        trap_function = const MACH_TRAP_FUNCTION,
        syscall64_restore_state = sym syscall64_restore_state,
        stack_mask = const KERNEL_STACK_MASK,
        i386_astintr = sym i386_astintr,
        options(att_syntax),
    );
}

/// Restores the thread's user state and returns through SYSRETQ.
///
/// # Safety
///
/// Entered only by jump from [`syscall64`], with its pcb saved state set
/// and no AST pending.
#[unsafe(naked)]
unsafe extern "C" fn syscall64_restore_state() {
    naked_asm!(
        "cli",
        "movq %gs:{per_cpu_thread_offset}, %r11",
        "movq {th_pcb_offset}(%r11), %r11",
        "addq ${pcb_iss_offset}, %r11",
        "movq {r_edi_offset}(%r11), %rdi",
        "movq {r_esi_offset}(%r11), %rsi",
        "movq {r_edx_offset}(%r11), %rdx",
        "movq {r_r10_offset}(%r11), %r10",
        "movq {r_r8_offset}(%r11), %r8",
        "movq {r_r9_offset}(%r11), %r9",
        "movq {r_uesp_offset}(%r11), %rsp",
        "movq {r_eip_offset}(%r11), %rcx",
        "movq {r_ebx_offset}(%r11), %rbx",
        "movq {r_ebp_offset}(%r11), %rbp",
        "movq {r_r12_offset}(%r11), %r12",
        "movq {r_r13_offset}(%r11), %r13",
        "movq {r_r14_offset}(%r11), %r14",
        "movq {r_r15_offset}(%r11), %r15",
        "movq {r_eflags_offset}(%r11), %r11",
        "swapgs",
        "sysretq",
        per_cpu_thread_offset = const PER_CPU_THREAD_OFFSET,
        th_pcb_offset = const TH_PCB_OFFSET,
        pcb_iss_offset = const PCB_ISS_OFFSET,
        r_edi_offset = const R_EDI_OFFSET,
        r_esi_offset = const R_ESI_OFFSET,
        r_edx_offset = const R_EDX_OFFSET,
        r_r10_offset = const R_R10_OFFSET,
        r_r8_offset = const R_R8_OFFSET,
        r_r9_offset = const R_R9_OFFSET,
        r_uesp_offset = const R_UESP_OFFSET,
        r_eip_offset = const R_EIP_OFFSET,
        r_ebx_offset = const R_EBX_OFFSET,
        r_ebp_offset = const R_EBP_OFFSET,
        r_r12_offset = const R_R12_OFFSET,
        r_r13_offset = const R_R13_OFFSET,
        r_r14_offset = const R_R14_OFFSET,
        r_r15_offset = const R_R15_OFFSET,
        r_eflags_offset = const R_EFLAGS_OFFSET,
        options(att_syntax),
    );
}

/// The argument copy's fault fixup and its bounds check's target.
///
/// # Safety
///
/// Entered by jump from [`syscall64`] or through the `mach_recover` entry
/// it emits, with `%r11` the failing user address and `%rbx` the saved
/// state.
#[unsafe(naked)]
unsafe extern "C" fn syscall64_addr_push() {
    naked_asm!(
        "movq %r11, {r_cr2}(%rbx)",
        "movq ${trapno}, {r_trapno_offset}(%rbx)",
        "movq ${err}, {r_err_offset}(%rbx)",
        "movq ${return_to_user}, %r12",
        "jmp {take_trap}",
        r_cr2 = const R_CR2_OFFSET,
        trapno = const T_PAGE_FAULT,
        r_trapno_offset = const R_TRAPNO_OFFSET,
        err = const T_PF_USER,
        r_err_offset = const R_ERR_OFFSET,
        return_to_user = const RETURN_TO_USER,
        take_trap = sym take_trap,
        options(att_syntax),
    );
}

/// An out-of-range system call becomes an invalid-opcode trap.
///
/// # Safety
///
/// Entered only by jump from [`syscall64`], with `%rbx` the saved state.
#[unsafe(naked)]
unsafe extern "C" fn syscall64_range() {
    naked_asm!(
        "movq ${trapno}, {r_trapno_offset}(%rbx)",
        "movq $0, {r_err_offset}(%rbx)",
        "movq ${return_to_user}, %r12",
        "jmp {take_trap}",
        trapno = const T_INVALID_OPCODE,
        r_trapno_offset = const R_TRAPNO_OFFSET,
        r_err_offset = const R_ERR_OFFSET,
        return_to_user = const RETURN_TO_USER,
        take_trap = sym take_trap,
        options(att_syntax),
    );
}
