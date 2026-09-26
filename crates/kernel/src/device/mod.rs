// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The Rust home of the C `device/` tree, the machine-independent device
//! layer.

pub mod chario;
pub mod cirbuf;
pub mod cons;
pub mod dev_lookup;
pub mod dev_lookup_ffi;
pub mod dev_name;
pub mod dev_pager;
pub mod device_init;
pub mod ds_routines;
pub mod ds_routines_ffi;
pub mod intr;
pub mod kmsg;
pub mod net_io;
pub mod r#return;
pub mod subrs;
