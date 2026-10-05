// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Virtual memory; mirrors `vm/`.

pub mod error;
pub mod memory_object;
pub mod memory_object_proxy;
pub mod types;
pub mod vm_debug;
pub mod vm_external;
pub mod vm_fault;
pub mod vm_init;
pub mod vm_kern;
pub mod vm_map;
pub mod vm_object;
pub mod vm_page;
pub mod vm_pageout;
pub mod vm_resident;
pub mod vm_user;
