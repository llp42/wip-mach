// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The gsync calls' early exits, over the fake platform.

use core::ptr;
use mach_fake::Fake;
use mach_gsync::error::Error;
use mach_gsync::{Flags, Gsync};

static GSYNC: Gsync<Fake> = Gsync::new();

#[test]
fn an_unaligned_address_is_refused_before_any_lookup() {
    // SAFETY: the address check fails before the map is read.
    unsafe {
        assert_eq!(
            GSYNC.wait(ptr::null_mut(), 0x1002, 0, 0, 0, Flags::empty()),
            Err(Error::InvalidAddress)
        );
        assert_eq!(
            GSYNC.wake(ptr::null_mut(), 0x1001, 0, Flags::empty()),
            Err(Error::InvalidAddress)
        );
    }
}

#[test]
fn a_wake_without_a_map_finds_no_address() {
    // SAFETY: a null map is never dereferenced.
    unsafe {
        assert_eq!(
            GSYNC.wake(ptr::null_mut(), 0x1000, 7, Flags::MUTATE),
            Err(Error::InvalidAddress)
        );
    }
}
