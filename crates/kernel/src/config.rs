// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Build-wide constants of the Rust half.

/// The version string this kernel reports.
pub const KERNEL_VERSION: &str =
    concat!("WIP Mach ", env!("CARGO_PKG_VERSION"));

/// The bytes a `kernel_version_t` holds.
pub const KERNEL_VERSION_MAX: usize = 512;

/// The processor capacity the build was configured with.
///
/// It is the CPU capacity, not the live count: per-CPU arrays hold this
/// many entries, and [`CpuId`](crate::kern::smp::CpuId) is bounded by it;
/// [`ncpus()`](crate::kern::smp::ncpus) reports how many the machine
/// brought up, and [`CpuId::online()`](crate::kern::smp::CpuId::online)
/// iterates them.
///
/// The ABI gate pins it at 2.  `--enable-ncpus` changes it, and the Rust
/// half then has to carry the same number here.
///
/// At least one, for the boot CPU: `kern/smp.rs` asserts it, since
/// `CpuId::BOOT` names block 0.  At most 64: the per-CPU state that keeps
/// one bit per CPU in a machine word, `kern/rcu.rs`'s `QS_PENDING` (which
/// asserts `MAX_NCPUS <= usize::BITS`) and `arch/x86_64/pmap.rs`'s `CpuSet`
/// (`1isize << cpu`).  `kern/host.rs` asserts the looser
/// `MAX_NCPUS <= HOST_INFO_MAX` for the `host_info()` slots.
pub const MAX_NCPUS: usize = 2;

/// The serial-port count the build was configured with; the ABI gate pins it
/// at 2, as it pins `MAX_NCPUS`.
pub const NCOM: usize = 2;

/// The interrupt lines the I/O APIC build addresses.
pub const NINTR: usize = 64;
