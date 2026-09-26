// SPDX-License-Identifier: CMU-Mach AND GPL-2.0-or-later
// SPDX-FileCopyrightText: 1993,1992,1991,1990,1989 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from Mach4 (commit e8a91124a56b72f46c5337679517cb5e4349d766)
//   <https://github.com/openmach/mach4>
// original files: include/mach/processor_info.h

//! The basic and scheduling information `processor_set_info()` reports, and
//! the conversions that fill them from the kernel's processor-set record.

use crate::kern::processor::ProcessorSet;
use core::ffi::{c_int, c_long, c_uint};
use core::mem::{offset_of, size_of};

/// The basic information `processor_set_info()` reports for a processor set.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessorSetBasicInfo {
    pub processor_count: c_int,
    pub task_count: c_int,
    pub thread_count: c_int,
    /// `load_average`: the scaled load average.
    pub load_average: c_int,
    /// `mach_factor`: the scaled mach factor.
    pub mach_factor: c_int,
}

impl ProcessorSetBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

/// The scheduling information `processor_set_info()` reports for a processor
/// set.
// struct processor_set_sched_info {
// 	integer_t	policies;	/* allowed policies */
// 	integer_t	max_priority;	/* max priority for new threads */
// };
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessorSetSchedInfo {
    pub policies: c_int,
    /// `max_priority`: the maximum priority for new threads.
    pub max_priority: c_int,
}

impl ProcessorSetSchedInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

/// Narrow a processor-set `c_long` field to the record's `c_int` member.
const fn narrow_long(value: c_long) -> c_int {
    value as c_int
}

impl From<&ProcessorSet> for ProcessorSetBasicInfo {
    /// Takes the set's `lock` for the reads.
    fn from(pset: &ProcessorSet) -> Self {
        pset.lock.lock();
        let info = Self {
            processor_count: pset.processor_count,
            task_count: pset.task_count,
            thread_count: pset.thread_count,
            load_average: narrow_long(pset.load_average),
            mach_factor: narrow_long(pset.mach_factor),
        };
        pset.lock.unlock();
        info
    }
}

impl From<&ProcessorSet> for ProcessorSetSchedInfo {
    /// Takes the set's `lock` for the reads.
    fn from(pset: &ProcessorSet) -> Self {
        pset.lock.lock();
        let info = Self {
            policies: pset.policies,
            max_priority: pset.max_priority,
        };
        pset.lock.unlock();
        info
    }
}

// struct processor_set_basic_info {
//  integer_t  processor_count;  /* How many processors */
//  integer_t  task_count;       /* How many tasks */
//  integer_t  thread_count;     /* How many threads */
//  integer_t  load_average;     /* Scaled */
//  integer_t  mach_factor;      /* Scaled */
// };
const _: () = assert!(size_of::<ProcessorSetBasicInfo>() == 20);
const _: () = assert!(offset_of!(ProcessorSetBasicInfo, processor_count) == 0);
const _: () = assert!(offset_of!(ProcessorSetBasicInfo, task_count) == 4);
const _: () = assert!(offset_of!(ProcessorSetBasicInfo, thread_count) == 8);
const _: () = assert!(offset_of!(ProcessorSetBasicInfo, load_average) == 12);
const _: () = assert!(offset_of!(ProcessorSetBasicInfo, mach_factor) == 16);

// struct processor_set_sched_info {
//  integer_t  policies;      /* allowed policies */
//  integer_t  max_priority;  /* max priority for new threads */
// };
const _: () = assert!(size_of::<ProcessorSetSchedInfo>() == 8);
const _: () = assert!(offset_of!(ProcessorSetSchedInfo, policies) == 0);
const _: () = assert!(offset_of!(ProcessorSetSchedInfo, max_priority) == 4);
