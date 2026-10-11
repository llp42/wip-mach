// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The basic information `processor_info()` reports, and the conversion that
//! fills it from the kernel's processor record.

use crate::machine;
use crate::platform::Platform;
use core::ffi::{c_int, c_uint};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::Ordering;
use mach_thread::processor::{Processor, boot_processor};
use mach_thread::types::ProcessorState;
use zerocopy::{Immutable, IntoBytes};

/// The basic information `processor_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct ProcessorBasicInfo {
    /// The CPU type.
    pub cpu_type: c_int,
    /// The CPU subtype.
    pub cpu_subtype: c_int,
    /// Whether the processor runs.
    pub running: c_int,
    /// `slot_num`: the CPU's [`Processor::cpu_id`].
    pub slot_num: c_int,
    /// Whether this is the boot processor.
    pub is_master: c_int,
}

impl ProcessorBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

impl<P: Platform> From<&Processor<P>> for ProcessorBasicInfo {
    fn from(processor: &Processor<P>) -> Self {
        let cpu_id = processor.cpu_id;
        let machine = machine::slot(cpu_id);

        let state = processor.state.load(Ordering::Acquire);
        let running = state != ProcessorState::Shutdown
            && state != ProcessorState::OffLine;
        let is_boot = ptr::eq(processor, boot_processor());

        Self {
            cpu_type: machine.cpu_type.load(Ordering::Relaxed),
            cpu_subtype: machine.cpu_subtype.load(Ordering::Relaxed),
            running: c_int::from(running),
            slot_num: cpu_id.bits() as c_int,
            is_master: c_int::from(is_boot),
        }
    }
}

// struct processor_basic_info {
// 	cpu_type_t              cpu_type;	    /* type of cpu */
// 	cpu_subtype_t           cpu_subtype;  /* subtype of cpu */
//  /*boolean_t*/integer_t  running;      /* is processor running */
// 	integer_t               slot_num;     /* slot number */
//  /*boolean_t*/integer_t  is_master;    /* is this the master processor */
// };
const _: () = assert!(size_of::<ProcessorBasicInfo>() == 20);
const _: () = assert!(offset_of!(ProcessorBasicInfo, cpu_type) == 0);
const _: () = assert!(offset_of!(ProcessorBasicInfo, cpu_subtype) == 4);
const _: () = assert!(offset_of!(ProcessorBasicInfo, running) == 8);
const _: () = assert!(offset_of!(ProcessorBasicInfo, slot_num) == 12);
const _: () = assert!(offset_of!(ProcessorBasicInfo, is_master) == 16);
