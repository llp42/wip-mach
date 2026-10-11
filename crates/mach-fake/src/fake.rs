// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`Fake`]: the platform of the Mach crates' host tests.

/// The platform of the host tests: VM's, IPC's and gsync's at once, with
/// the services the tests reach; every other function panics with its
/// name.
pub struct Fake;
