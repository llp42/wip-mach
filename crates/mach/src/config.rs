// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Build-wide constants of the Rust half.

/// The version string this kernel reports.
pub const KERNEL_VERSION: &str =
    concat!("WIP Mach ", env!("CARGO_PKG_VERSION"));

/// The bytes a `kernel_version_t` holds.
pub const KERNEL_VERSION_MAX: usize = 512;

/// The processor capacity the build was configured with, which the
/// scheduler sizes its per-CPU arrays by.
pub use mach_thread::smp::MAX_NCPUS;

/// The serial-port count the build was configured with; the ABI gate pins it
/// at 2, as it pins `MAX_NCPUS`.
pub const NCOM: usize = 2;

/// The interrupt lines the I/O APIC build addresses.
pub const NINTR: usize = 64;
