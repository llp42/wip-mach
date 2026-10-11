// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine-dependent AST bits of the x86: the machine reason the
//! hardware raises and which of the reasons travel with a thread.

use mach_sched::ast::AstReason;

/// The delayed floating-point exception, an AST reason.  The FPU interrupt
/// posts it on the CPU, not on the thread.
pub(crate) const I386_FP: AstReason = AstReason::from_bits_retain(0x8000_0000);

/// The machine reasons reset at a context switch.
///
/// A thread descheduled before it takes the FP AST drops the reason here,
/// and the error resurfaces when the FPU state reloads.
pub(crate) const MACHINE_PER_THREAD: AstReason = I386_FP;
