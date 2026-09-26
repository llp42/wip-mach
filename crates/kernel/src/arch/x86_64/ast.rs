// SPDX-License-Identifier: CMU-Mach
// SPDX-FileCopyrightText: 1991,1990 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from Mach4 (commit e8a91124a56b72f46c5337679517cb5e4349d766)
//   <https://github.com/openmach/mach4>
// original files: i386/kernel/i386/ast.h

//! The machine-dependent AST bits of the x86: the machine reason the
//! hardware raises and which of the reasons travel with a thread.

use crate::kern::ast::AstReason;

/// The delayed floating-point exception, an AST reason.  The FPU interrupt
/// posts it on the CPU, not on the thread.
pub(crate) const I386_FP: AstReason = AstReason::from_bits(0x8000_0000);

/// The machine reasons reset at a context switch.
///
/// A thread descheduled before it takes the FP AST drops the reason here,
/// and the error resurfaces when the FPU state reloads.
pub(crate) const MACHINE_PER_THREAD: AstReason = I386_FP;
