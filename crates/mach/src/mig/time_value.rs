// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The clock page the user side maps, beside the time records of the Mach
//! interface, which `mach-task` and `mach-host` define.

use core::ffi::c_int;
use core::mem::offset_of;

pub use mach_host::time::MACH_ADJTIME_NSECS_OMIT;
pub use mach_sched::time_value::{TimeValue, TimeValue64};

/// `mapped_time_value_t`: the clock page the user side maps, read with a
/// double check: each `check_*` copy is written before its value and read
/// after it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MappedTimeValue {
    /// `seconds`: the microsecond clock's seconds.
    pub seconds: c_int,
    /// `microseconds`: the microsecond clock's fraction.
    pub microseconds: c_int,
    /// `check_seconds`: a reader's copy of `seconds`.
    pub check_seconds: c_int,
    /// `time_value`: the wall-clock time.
    pub time_value: TimeValue64,
    /// `check_seconds64`: a reader's copy of `time_value.seconds`.
    pub check_seconds64: i64,
    /// `uptime_value`: the time since boot.
    pub uptime_value: TimeValue64,
    /// `check_upseconds64`: a reader's copy of `uptime_value.seconds`.
    pub check_upseconds64: i64,
}

const _: () = {
    assert!(size_of::<MappedTimeValue>() == 64);
    assert!(offset_of!(MappedTimeValue, seconds) == 0);
    assert!(offset_of!(MappedTimeValue, microseconds) == 4);
    assert!(offset_of!(MappedTimeValue, check_seconds) == 8);
    assert!(offset_of!(MappedTimeValue, time_value) == 16);
    assert!(offset_of!(MappedTimeValue, check_seconds64) == 32);
    assert!(offset_of!(MappedTimeValue, uptime_value) == 40);
    assert!(offset_of!(MappedTimeValue, check_upseconds64) == 56);
};
