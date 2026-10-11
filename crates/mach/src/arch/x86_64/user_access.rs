// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The guarded user accesses: the instruction fetch and the copies in and out.
//!
//! These are the user-memory reads and writes, with every fault fixup
//! carried in the linker's `mach_recover` section and every
//! successful-fault retry in `mach_retry`.

use core::arch::naked_asm;
use core::ffi::{c_int, c_void};

use crate::arch::types::VmOffset;
use crate::arch::vm_param::VM_MAX_USER_ADDRESS;

/// Reads the byte at `eip` with `cs` in `%fs`, or `-1` if the read faults.
///
/// The C ABI's `eip` and `cs` are read in the assembly, and each call emits
/// one `Recovery` pair into `mach_recover`, naming the read and
/// [`inst_fetch_fault`]; `trap.rs` scans the section's link-time bounds.
///
/// The trap entry does not restore `%fs`, and a blocking decode fault can
/// switch to a thread whose `switch_ktss` loads another FS base from the
/// pcb, so the resolved read must re-run the `%fs` load from the top; the
/// body carries the C's `mach_retry` entry for that.
///
/// # Safety
///
/// `cs` must select a user segment, so that the read faults on an
/// unreadable `eip` instead of reaching kernel memory, and the caller
/// must be in kernel mode where `%fs` may be left clobbered.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn inst_fetch(eip: c_int, cs: c_int) -> c_int {
    // The C, and so this, compare the whole 64-bit `%rdi`; an `int`
    // caller may leave the argument's upper half undefined.
    naked_asm!(
        ".pushsection mach_retry,\"a\",@progbits",
        ".balign 8",
        ".quad 2f",
        ".quad 1f",
        ".popsection",
        "1:",
        "movq %rsi, %rax",
        "movw %ax, %fs",
        "movq %rdi, %rax",
        "movq ${vm_max_address}, %rcx",
        "cmpq %rcx, %rax",
        "jae {fixup}",
        ".pushsection mach_recover,\"a\",@progbits",
        ".balign 8",
        ".quad 2f",
        ".quad {fixup}",
        ".popsection",
        "2:",
        "movzbl %fs:(%rax), %eax",
        "ret",
        vm_max_address = const VM_MAX_USER_ADDRESS,
        fixup = sym inst_fetch_fault,
        options(att_syntax),
    );
}

/// The recovery fixup of [`inst_fetch`].  The trap enters it with the fault's
/// stack, whose top is `inst_fetch()`'s return address, so its `ret` returns
/// from the naked `inst_fetch()` with `-1` in `%eax`.
///
/// # Safety
///
/// Entered only through the `mach_recover` pair `inst_fetch()` emits while
/// its `%fs` read faults; it must not be called directly.
#[unsafe(naked)]
unsafe extern "C" fn inst_fetch_fault() -> c_int {
    naked_asm!("movq $-1, %rax", "ret", options(att_syntax));
}

/// A user address a copy could not reach: the access faulted, or the
/// address lies at or above `VM_MAX_USER_ADDRESS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserFault;

/// Copies `kernel.len()` bytes from the user address `user` into `kernel`.
///
/// Any user address is safe to pass: the copy refuses one at or above
/// `VM_MAX_USER_ADDRESS`, a copy that runs past it enters the non-canonical
/// hole that bound starts, and a faulting read recovers, except at address 0,
/// where the page-fault handler panics.
///
/// # Errors
///
/// Returns [`UserFault`] instead of copying when the user read faults.
pub(crate) fn copyin(
    user: VmOffset,
    kernel: &mut [u8],
) -> Result<(), UserFault> {
    // SAFETY: `kernel` is writable kernel memory for its length, and the
    // assembly bounds and recovers the user side.
    if unsafe { copyin_asm(user, kernel.as_mut_ptr().cast(), kernel.len()) }
        == 0
    {
        Ok(())
    } else {
        Err(UserFault)
    }
}

/// The assembly body of [`copyin()`], returning 1 instead of copying when
/// the user read faults.
///
/// Each `rep` carries one `mach_recover` pair, both recovering to
/// [`copyin_fail`], and a `user` at or above `VM_MAX_USER_ADDRESS` is
/// rejected before copying.
///
/// # Safety
///
/// `kernelbuf` must be writable kernel memory for `cn` bytes.
#[unsafe(naked)]
unsafe extern "C" fn copyin_asm(
    user: VmOffset,
    kernelbuf: *mut c_void,
    cn: usize,
) -> c_int {
    naked_asm!(
        "xchgq %rsi, %rdi",
        "movq ${vm_max_address}, %rcx",
        "cmpq %rcx, %rsi",
        "jae {fixup}",
        "movq %rdx, %rcx",
        "shrq $3, %rcx",
        ".pushsection mach_recover,\"a\",@progbits",
        ".balign 8",
        ".quad 2f",
        ".quad {fixup}",
        ".popsection",
        "2:",
        "rep movsq",
        "movq %rdx, %rcx",
        "andq $7, %rcx",
        ".pushsection mach_recover,\"a\",@progbits",
        ".balign 8",
        ".quad 3f",
        ".quad {fixup}",
        ".popsection",
        "3:",
        "rep movsb",
        "xorq %rax, %rax",
        "ret",
        vm_max_address = const VM_MAX_USER_ADDRESS,
        fixup = sym copyin_fail,
        options(att_syntax),
    );
}

/// The `copyin_fail` label of [`copyin_asm`]: return 1.
///
/// # Safety
///
/// Entered only through the `mach_recover` pairs `copyin_asm` emits and its
/// bound-check branch; there is no frame to unwind, and it must not be
/// called directly.
#[unsafe(naked)]
unsafe extern "C" fn copyin_fail() -> c_int {
    naked_asm!("movq $1, %rax", "ret", options(att_syntax));
}

/// Copies `kernel` to the user address `user`.
///
/// Any user address is safe to pass, for the reasons [`copyin()`] gives.
///
/// # Errors
///
/// Returns [`UserFault`] instead of copying when the user write faults.
pub(crate) fn copyout(kernel: &[u8], user: VmOffset) -> Result<(), UserFault> {
    // SAFETY: `kernel` is readable kernel memory for its length, and the
    // assembly bounds and recovers the user side.
    if unsafe { copyout_asm(kernel.as_ptr().cast(), user, kernel.len()) } == 0
    {
        Ok(())
    } else {
        Err(UserFault)
    }
}

/// The assembly body of [`copyout()`], returning 1 instead of copying when
/// the user write faults.
///
/// Every `rep` carries one `mach_recover` pair to [`copyout_fail`], and a
/// `user` at or above `VM_MAX_USER_ADDRESS` is rejected before copying.
///
/// # Safety
///
/// `kernelbuf` must be readable kernel memory for `cn` bytes.
#[unsafe(naked)]
unsafe extern "C" fn copyout_asm(
    kernelbuf: *const c_void,
    user: VmOffset,
    cn: usize,
) -> c_int {
    naked_asm!(
        "xchgq %rsi, %rdi",
        "movq ${vm_max_address}, %rcx",
        "cmpq %rcx, %rdi",
        "jae {fail}",
        "movq %rdx, %rax",
        "movq %rax, %rcx",
        "shrq $3, %rcx",
        ".pushsection mach_recover,\"a\",@progbits",
        ".balign 8",
        ".quad 2f",
        ".quad {fail}",
        ".popsection",
        "2:",
        "rep movsq",
        "movq %rax, %rcx",
        "andq $7, %rcx",
        ".pushsection mach_recover,\"a\",@progbits",
        ".balign 8",
        ".quad 3f",
        ".quad {fail}",
        ".popsection",
        "3:",
        "rep movsb",
        "xorq %rax, %rax",
        "ret",
        vm_max_address = const VM_MAX_USER_ADDRESS,
        fail = sym copyout_fail,
        options(att_syntax),
    );
}

/// The `copyout_fail` label of [`copyout_asm`]: return 1.
///
/// # Safety
///
/// Entered only through the `mach_recover` pairs `copyout_asm()` emits and its
/// bound-check branch; there is no frame to unwind, and it must not be
/// called directly.
#[unsafe(naked)]
unsafe extern "C" fn copyout_fail() -> c_int {
    naked_asm!("movq $1, %rax", "ret", options(att_syntax));
}
