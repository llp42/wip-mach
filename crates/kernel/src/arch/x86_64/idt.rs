// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/idt.c:
//   Copyright (c) 1994 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt descriptor table.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::idt_inittab::IDT_INITTAB;
use crate::arch::x86_64::mp_desc::{self, IDTSZ, RealGate};
use crate::arch::x86_64::seg;
use core::ffi::{c_int, c_ulong, c_ushort};
use core::mem::size_of;
use core::ptr;

/// The boot CPU's table, which the other CPUs get copies of through
/// `MP_DESC_TABLE`.
pub(crate) static mut IDT: [RealGate; IDTSZ] = [RealGate::ZERO; IDTSZ];

/// One entry of the table [`idt_fill`] installs.
///
/// The entrypoint is the Rust spelling of the C's `unsigned long`: an
/// `Option<unsafe extern "C" fn()>` is pointer-sized, and the null
/// terminator is the `None` the `idt_fill()` walk stops on.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct IdtInitEntry {
    entrypoint: Option<unsafe extern "C" fn()>,
    vector: c_ushort,
    type_: c_ushort,
    /// `ist`: the 1-based Interrupt Stack Table index the gate switches
    /// to, or 0 to leave the stack unchanged.
    ist: c_ushort,
    pad_0: c_ushort,
}

const _: () = {
    assert!(size_of::<IdtInitEntry>() == 16);
    assert!(align_of::<IdtInitEntry>() == align_of::<c_ulong>());
    assert!(core::mem::offset_of!(IdtInitEntry, entrypoint) == 0);
    assert!(core::mem::offset_of!(IdtInitEntry, vector) == 8);
    assert!(core::mem::offset_of!(IdtInitEntry, type_) == 10);
    assert!(core::mem::offset_of!(IdtInitEntry, ist) == 12);
    assert!(core::mem::offset_of!(IdtInitEntry, pad_0) == 14);
};

impl IdtInitEntry {
    /// An ordinary gate.
    pub(crate) const fn new(
        entrypoint: unsafe extern "C" fn(),
        vector: c_ushort,
        access: c_ushort,
    ) -> Self {
        Self {
            entrypoint: Some(entrypoint),
            vector,
            type_: access,
            ist: 0,
            pad_0: 0,
        }
    }

    /// The double-fault gate, the one gate with an IST.
    pub(crate) const fn with_ist(
        entrypoint: unsafe extern "C" fn(),
        vector: c_ushort,
        access: c_ushort,
        ist: c_ushort,
    ) -> Self {
        Self {
            entrypoint: Some(entrypoint),
            vector,
            type_: access,
            ist,
            pad_0: 0,
        }
    }

    /// The all-zero entry ending the table.
    pub(crate) const fn terminator() -> Self {
        Self {
            entrypoint: None,
            vector: 0,
            type_: 0,
            ist: 0,
            pad_0: 0,
        }
    }
}

/// The `limit` of the pseudo-descriptor [`idt_fill`] loads, a 16-bit field.
const IDT_LIMIT: usize = IDTSZ * size_of::<RealGate>() - 1;

const _: () = assert!(IDT_LIMIT <= u16::MAX as usize);

/// Fills `myidt` from the init table and loads it.
///
/// # Safety
///
/// `myidt` must be valid for `IDTSZ` gates.
unsafe fn idt_fill(myidt: *mut RealGate) {
    let mut iie = ptr::addr_of!(IDT_INITTAB).cast::<IdtInitEntry>();

    loop {
        // SAFETY: the table is an array terminated by a null entrypoint,
        // and the walk starts at its first element.
        let entry = unsafe { iie.read() };
        let Some(entrypoint) = entry.entrypoint else {
            break;
        };

        // The C passed the 16-bit field into an `unsigned char` parameter,
        // and the hardware keeps the IST in the low three bits.
        let ist = entry.ist as u8;

        // The table's `type` is the access byte, an `unsigned short` the C
        // passed to a parameter that is an `unsigned char`; the generated
        // values fit.
        let access = entry.type_ as u8;

        unsafe {
            seg::fill_idt_gate(
                myidt,
                c_int::from(entry.vector),
                entrypoint as VmOffset,
                seg::KERNEL_CS,
                access,
                ist,
            );
        }
        // SAFETY: the walk stops at the terminated table's sentinel before
        // this pointer leaves it.
        iie = unsafe { iie.add(1) };
    }

    let pdesc = seg::PseudoDescriptor {
        limit: IDT_LIMIT as c_ushort,
        linear_base: myidt as VmOffset as c_ulong,
    };
    seg::lidt(&pdesc);
}

/// Loads the boot CPU's table.
pub(crate) fn idt_init() {
    // SAFETY: `idt` is the boot CPU's table, valid for `IDTSZ` gates.
    unsafe { idt_fill(ptr::addr_of_mut!(IDT).cast::<RealGate>()) };
}

/// Loads the table of the application processor `cpu`.
pub(crate) fn ap_idt_init(cpu: c_int) {
    // SAFETY: `mp_desc_init()` stored this CPU's table before any CPU ran
    // `ap_idt_init()` on it.
    let table =
        unsafe { (*ptr::addr_of!(mp_desc::MP_DESC_TABLE))[cpu as usize] };
    // SAFETY: `table` is this CPU's full table.
    unsafe { idt_fill(ptr::addr_of_mut!((*table).idt).cast::<RealGate>()) };
}
