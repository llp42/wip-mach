// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Machine scalar and page-geometry modules, mirrored from
//! `crates/kernel/src/arch`.

#[path = "../../../../crates/kernel/src/arch/types.rs"]
pub mod types;

#[path = "../../../../crates/kernel/src/arch/vm_param.rs"]
pub mod vm_param;

pub mod x86_64;
