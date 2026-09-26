// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/locore.S and x86_64/locore.S:
//   Copyright (c) 1993,1992,1991,1990 Carnegie Mellon University
//   Copyright (c) 1991 IBM Corporation
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `INTERRUPT(n)` stubs and `int_entry_table` that
//! `i386/i386/locore.S` and `x86_64/locore.S` used to define; the trap
//! web they feed is [`locore`](crate::arch::x86_64::locore).

use crate::arch::types::VmOffset;
use crate::arch::x86_64::apic::IOAPIC_SPURIOUS_BASE;
use crate::arch::x86_64::int_init::{CALL_AST_CHECK, CALL_PMAP_UPDATE};
use crate::arch::x86_64::locore;
use crate::config::NINTR;
use core::arch::naked_asm;
use core::mem::size_of;

const _: () = assert!(
    size_of::<Option<unsafe extern "C" fn()>>() == size_of::<VmOffset>()
);

/// The `INTERRUPT(n)` macro of `i386/i386/locore.S` and `x86_64/locore.S`:
/// each stub enters `all_intrs` with its own vector.
macro_rules! interrupt_stub {
    ($($vector:expr => $name:ident),+ $(,)?) => {
        $(
            /// # Safety
            ///
            /// Entered only by the CPU through the gate whose vector
            /// names this stub.
            #[unsafe(naked)]
            unsafe extern "C" fn $name() {
                naked_asm!(
                    "pushq %rax",
                    "movq ${vector}, %rax",
                    "jmp {all_intrs}",
                    vector = const $vector,
                    all_intrs = sym locore::all_intrs,
                    options(att_syntax),
                );
            }
        )+
    };
}

interrupt_stub! {
    0 => int_0,
    1 => int_1,
    2 => int_2,
    3 => int_3,
    4 => int_4,
    5 => int_5,
    6 => int_6,
    7 => int_7,
    8 => int_8,
    9 => int_9,
    10 => int_10,
    11 => int_11,
    12 => int_12,
    13 => int_13,
    14 => int_14,
    15 => int_15,
    16 => int_16,
    17 => int_17,
    18 => int_18,
    19 => int_19,
    20 => int_20,
    21 => int_21,
    22 => int_22,
    23 => int_23,
    24 => int_24,
    25 => int_25,
    26 => int_26,
    27 => int_27,
    28 => int_28,
    29 => int_29,
    30 => int_30,
    31 => int_31,
    32 => int_32,
    33 => int_33,
    34 => int_34,
    35 => int_35,
    36 => int_36,
    37 => int_37,
    38 => int_38,
    39 => int_39,
    40 => int_40,
    41 => int_41,
    42 => int_42,
    43 => int_43,
    44 => int_44,
    45 => int_45,
    46 => int_46,
    47 => int_47,
    48 => int_48,
    49 => int_49,
    50 => int_50,
    51 => int_51,
    52 => int_52,
    53 => int_53,
    54 => int_54,
    55 => int_55,
    56 => int_56,
    57 => int_57,
    58 => int_58,
    59 => int_59,
    60 => int_60,
    61 => int_61,
    62 => int_62,
    63 => int_63,
    CALL_AST_CHECK => int_ast_check,
    CALL_PMAP_UPDATE => int_pmap_update,
    IOAPIC_SPURIOUS_BASE => int_spurious,
}

/// The table's length: the `NINTR` interrupt lines plus the AST,
/// pmap-update and spurious entries.
const INT_ENTRY_TABLE_LEN: usize = NINTR + 3;

/// `int_entry_table[]` of `i386/i386/locore.S` and `x86_64/locore.S`: the
/// interrupt entry points `int_fill()` installs, the `NINTR` lines first
/// and the AST, pmap-update and spurious vectors after them.
pub(crate) static INT_ENTRY_TABLE: [Option<unsafe extern "C" fn()>;
    INT_ENTRY_TABLE_LEN] = [
    Some(int_0),
    Some(int_1),
    Some(int_2),
    Some(int_3),
    Some(int_4),
    Some(int_5),
    Some(int_6),
    Some(int_7),
    Some(int_8),
    Some(int_9),
    Some(int_10),
    Some(int_11),
    Some(int_12),
    Some(int_13),
    Some(int_14),
    Some(int_15),
    Some(int_16),
    Some(int_17),
    Some(int_18),
    Some(int_19),
    Some(int_20),
    Some(int_21),
    Some(int_22),
    Some(int_23),
    Some(int_24),
    Some(int_25),
    Some(int_26),
    Some(int_27),
    Some(int_28),
    Some(int_29),
    Some(int_30),
    Some(int_31),
    Some(int_32),
    Some(int_33),
    Some(int_34),
    Some(int_35),
    Some(int_36),
    Some(int_37),
    Some(int_38),
    Some(int_39),
    Some(int_40),
    Some(int_41),
    Some(int_42),
    Some(int_43),
    Some(int_44),
    Some(int_45),
    Some(int_46),
    Some(int_47),
    Some(int_48),
    Some(int_49),
    Some(int_50),
    Some(int_51),
    Some(int_52),
    Some(int_53),
    Some(int_54),
    Some(int_55),
    Some(int_56),
    Some(int_57),
    Some(int_58),
    Some(int_59),
    Some(int_60),
    Some(int_61),
    Some(int_62),
    Some(int_63),
    Some(int_ast_check),
    Some(int_pmap_update),
    Some(int_spurious),
];
