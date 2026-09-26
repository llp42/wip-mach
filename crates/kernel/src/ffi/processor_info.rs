// SPDX-License-Identifier: CMU-Mach AND GPL-2.0-or-later
// SPDX-FileCopyrightText: 1993,1992,1991,1990,1989 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from Mach4 (commit e8a91124a56b72f46c5337679517cb5e4349d766)
//   <https://github.com/openmach/mach4>
// original files: include/mach/processor_info.h

//! The basic information `processor_info()` reports, and the conversion that
//! fills it from the kernel's processor record.

use crate::kern::machine;
use crate::kern::processor::{Processor, ProcessorState, boot_processor};
use core::ffi::{c_int, c_uint};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::Ordering;

/// The basic information `processor_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessorBasicInfo {
    pub cpu_type: c_int,
    pub cpu_subtype: c_int,
    pub running: c_int,
    /// `slot_num`: the CPU's [`Processor::cpu_id`].
    pub slot_num: c_int,
    pub is_master: c_int,
}

impl ProcessorBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

impl From<&Processor> for ProcessorBasicInfo {
    fn from(processor: &Processor) -> Self {
        let cpu_id = processor.cpu_id;
        // SAFETY: the record's init stored a live CPU's number, so its
        // machine slot is one the probe filled, and the two fields read are
        // plain integers.
        let machine = unsafe { &*machine::slot(cpu_id) };

        let state = processor.state.load(Ordering::Acquire);
        let running = state != ProcessorState::Shutdown
            && state != ProcessorState::OffLine;
        let is_boot = ptr::eq(processor, boot_processor());

        Self {
            cpu_type: machine.cpu_type,
            cpu_subtype: machine.cpu_subtype,
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
