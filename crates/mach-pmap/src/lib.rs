// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `x86_64` physical map.
//!
//! Each physical map is a four-level page-table tree. The pv lists record
//! every mapping of each managed physical page, so a page's mappings can be
//! found, lowered or removed, and its modify and reference bits read. A
//! change to a map active on other CPUs queues an invalidation for each and
//! interrupts them. The kernel map's bootstrap builds the first tables and
//! fixes the layout of the kernel address space.
//!
//! Everything this crate asks of the rest of the kernel arrives through
//! [`Platform`](platform::Platform). VM reaches the physical map through
//! its own platform, which the kernel implements by calling this crate.

#![no_std]
// These routines mirror the C's integer and pointer conversions one for
// one: the widths and alignments are known at each site, and the
// truncations, sign changes and wraps are deliberate.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss
)]

pub mod bootstrap;
mod cell;
pub mod cpu_set;
mod lock;
pub mod param;
pub mod phys;
pub mod platform;
pub mod pmap;
pub mod pte;
pub mod pv;
pub mod shootdown;
pub mod state;
pub mod types;
mod window;
