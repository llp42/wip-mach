// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The fakes the Mach crates' integration tests run over.
//!
//! [`Fake`] implements the `Platform` of `mach-vm`, `mach-ipc` and
//! `mach-gsync` at once, with [`Host`] as its lock platform: heap caches,
//! boxed pmaps, `kalloc` over the global allocator and a thread record per
//! host thread.  It carries only what the tests reach; every other function
//! panics with its name.  [`FakeScreen`] is the text screen `mach-kd`'s
//! terminal draws on.  Only tests depend on this crate.

mod fake;
mod gsync;
mod heap;
mod host;
mod ipc;
mod screen;
mod types;
mod vm;

pub use fake::Fake;
pub use heap::HostHeap;
pub use host::Host;
pub use screen::FakeScreen;
pub use types::{FakePmap, PmapCounts};
pub use vm::PMAPS;
