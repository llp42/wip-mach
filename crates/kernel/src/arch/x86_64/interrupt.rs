// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/interrupt.S and x86_64/interrupt.S:
//   Copyright (c) 1995 Shantanu Goel
//   All Rights Reserved.
//
//   Permission to use, copy, modify and distribute this software and its
//   documentation is hereby granted, provided that both the copyright
//   notice and this permission notice appear in all copies of the
//   software, derivative works or modified versions, and any portions
//   thereof, and that both notices appear in supporting documentation.
//
//   THE AUTHOR ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
//   CONDITION.  THE AUTHOR DISCLAIMS ANY LIABILITY OF ANY KIND FOR
//   ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The generic interrupt handler.
//!
//! `all_intrs` enters with the interrupt number in `%eax` and calls
//! [`interrupt`] with the interrupted registers above the frame it builds.

use crate::arch::x86_64::apic::lapic_eoi;
use crate::arch::x86_64::int_init::{CALL_AST_CHECK, CALL_PMAP_UPDATE};
use crate::arch::x86_64::ioapic::{IRQINFO, IUNIT, IVECT, ioapic_irq_eoi};
use crate::arch::x86_64::pmap::pmap_update_interrupt;
use crate::arch::x86_64::spl::{spl7, splx_cli};
use crate::kern::ast::check;
use core::arch::naked_asm;

/// Runs the handler of the interrupt in `%eax` at the highest level,
/// acknowledging the line before or after it as its trigger mode needs, then
/// restores the level.  The AST and pmap-update vectors go to their own
/// handlers, and vector 255 returns at once.
///
/// # Safety
///
/// Only `all_intrs` calls this, with the interrupt number in `%eax`/`%rax`
/// and the frame those entry points build under the return address.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn interrupt() {
    // The frame: the saved level at 0(%rsp), the irq at 8(%rsp), the return
    // address at 16(%rsp) and the interrupted registers from 24(%rsp); the
    // arguments travel in registers.
    naked_asm!(
        "cmpl $255, %eax",
        "jne 1f",
        "ret",
        "1:",
        "subq $16, %rsp",
        "movl %eax, 8(%rsp)",
        "call {spl7}",
        "movl %eax, (%rsp)",
        "movl 8(%rsp), %ecx",
        "cmpl ${call_pmap_update}, %ecx",
        "je 5f",
        "cmpl ${call_ast_check}, %ecx",
        "je 6f",
        "movb {irqinfo}(,%rcx,2), %al",
        "testb $1, %al",
        "jnz 3f",
        "2:",
        "movl %ecx, %edi",
        "call {ioapic_irq_eoi}",
        "movl 8(%rsp), %ecx",
        "movb {irqinfo}(,%rcx,2), %al",
        "testb $1, %al",
        "jnz 4f",
        "3:",
        "movq 0(%rsp), %rsi",
        "movq 16(%rsp), %rdx",
        "movq 24(%rsp), %rcx",
        "movl 8(%rsp), %eax",
        "movl {iunit}(,%rax,4), %edi",
        "movq {ivect}(,%rax,8), %r11",
        "call *%r11",
        "movl 8(%rsp), %ecx",
        "movb {irqinfo}(,%rcx,2), %al",
        "testb $1, %al",
        "jnz 2b",
        "4:",
        "movl 0(%rsp), %edi",
        "call {splx_cli}",
        "addq $16, %rsp",
        "ret",
        "5:",
        "call {lapic_eoi}",
        "call {pmap_update_interrupt}",
        "jmp 4b",
        "6:",
        "call {lapic_eoi}",
        "call {ast_check}",
        "jmp 4b",
        call_pmap_update = const CALL_PMAP_UPDATE,
        call_ast_check = const CALL_AST_CHECK,
        irqinfo = sym IRQINFO,
        iunit = sym IUNIT,
        ivect = sym IVECT,
        ioapic_irq_eoi = sym ioapic_irq_eoi,
        lapic_eoi = sym lapic_eoi,
        pmap_update_interrupt = sym pmap_update_interrupt,
        spl7 = sym spl7,
        splx_cli = sym splx_cli,
        ast_check = sym check,
        options(att_syntax),
    );
}
