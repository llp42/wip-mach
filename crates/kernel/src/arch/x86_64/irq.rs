// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/irq.c:
//   Copyright (C) 1995 Shantanu Goel
//   Copyright (C) 2020 Free Software Foundation, Inc
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt vector accessors and the per-line disable counts.
//!
//! The [`IrqDev`] table and the [`UserIntr`] entries are the device interrupt
//! layer's.

use crate::arch::x86_64::ioapic::{self, InterruptHandler};
use crate::arch::x86_64::platform::MachPlatform;
use crate::config::NINTR;
use collections::simple_queue::{self, SimpleQueue};
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use lock::IrqSpinLock;

/// One interrupt controller's table.
#[repr(C)]
#[allow(missing_docs)]
pub struct IrqDev {
    pub name: *mut c_char,
    /// `ack`: the controller's per-line end-of-interrupt hook. A caller
    /// invoking it must pass this table's own live address as `self` and a
    /// line number inside its `irq` table; the call may run at interrupt
    /// level.
    pub irqdev_ack: Option<unsafe fn(*mut Self, c_int)>,
    pub intr_queue: *mut UserIntrQueue,
    pub tot_num_intr: c_int,
    pub irq: [c_uint; NINTR],
}

/// One userland interrupt registration.
#[repr(C)]
#[allow(missing_docs)]
pub struct UserIntr {
    pub chain: simple_queue::Link,
    pub interrupts: c_int,
    pub n_unacked: c_int,
    pub dst_port: *mut c_void,
    pub id: c_int,
}

simple_queue::adapter!(
    /// The adapter for a registration's `chain` in an interrupt queue.
    pub UserIntrAdapter = UserIntr { chain }
);

/// A queue of registrations, in the order they were made.
pub type UserIntrQueue = SimpleQueue<'static, UserIntrAdapter>;

// The offsets below pin the layout of `IrqDev` and `UserIntr`.
const _: () = {
    assert!(size_of::<IrqDev>() == 288);
    assert!(align_of::<IrqDev>() == 8);
    assert!(offset_of!(IrqDev, name) == 0);
    assert!(offset_of!(IrqDev, irqdev_ack) == 8);
    assert!(offset_of!(IrqDev, intr_queue) == 16);
    assert!(offset_of!(IrqDev, tot_num_intr) == 24);
    assert!(offset_of!(IrqDev, irq) == 28);

    assert!(size_of::<UserIntr>() == 32);
    assert!(align_of::<UserIntr>() == 8);
    assert!(offset_of!(UserIntr, chain) == 0);
    assert!(offset_of!(UserIntr, interrupts) == 8);
    assert!(offset_of!(UserIntr, n_unacked) == 12);
    assert!(offset_of!(UserIntr, dst_port) == 16);
    assert!(offset_of!(UserIntr, id) == 24);
};

/// One line's disable count in its own lock.  Each entry takes a whole cache
/// line.  An irq spin lock, since an interrupt handler may disable its line.
#[repr(C, align(64))]
#[allow(missing_docs)]
struct NestedIrq {
    ndisabled: IrqSpinLock<c_int, MachPlatform>,
}

const _: () = assert!(size_of::<NestedIrq>() == 64);

static NESTED_IRQS: [NestedIrq; NINTR] = [const {
    NestedIrq {
        ndisabled: IrqSpinLock::new(0),
    }
}; NINTR];

/// The line map of [`IRQTAB`]: each line maps to itself.
const fn irq_map() -> [c_uint; NINTR] {
    let mut table = [0; NINTR];
    let mut irq = 0;
    while irq < NINTR {
        // NINTR is 64, so the narrowing loses nothing.
        table[irq] = irq as c_uint;
        irq += 1;
    }
    table
}

/// Acknowledges the line behind `dev`.
///
/// # Safety
///
/// `dev` must be a live, initialized [`IrqDev`], such as [`IRQTAB`].
unsafe fn irq_eoi(dev: *mut IrqDev, id: c_int) {
    let Ok(index) = usize::try_from(id) else {
        return;
    };
    // SAFETY: `dev` is the live `IRQTAB`, and `index` addresses one of its
    // NINTR `irq` entries.
    let Some(irq) = (unsafe { (*dev).irq.get(index) }) else {
        return;
    };
    let Ok(pin) = c_int::try_from(*irq) else {
        return;
    };
    ioapic::irq_eoi(pin);
}

/// The interrupt controller table of the I/O APIC lines.
pub static mut IRQTAB: IrqDev = IrqDev {
    name: c"irq".as_ptr().cast_mut(),
    irqdev_ack: Some(irq_eoi),
    intr_queue: &raw mut crate::device::intr::MAIN_INTR_QUEUE,
    tot_num_intr: 0,
    irq: irq_map(),
};

/// The `NINTR`-bounded index of `irq`, or [`None`] outside the table.
fn index_of(irq: c_int) -> Option<usize> {
    let index = usize::try_from(irq).ok()?;
    if index < NINTR { Some(index) } else { None }
}

/// The handler of the line `irq`.
pub(crate) fn handler(irq: c_int) -> InterruptHandler {
    let index = index_of(irq)?;
    // SAFETY: `index` is inside `IVECT`, which the interrupt entry reads by
    // its symbol.
    unsafe {
        *(&raw const ioapic::IVECT)
            .cast::<InterruptHandler>()
            .add(index)
    }
}

/// Sets the handler of the line `irq`.
pub(crate) fn set_handler(irq: c_int, handler: InterruptHandler) {
    let Some(index) = index_of(irq) else {
        return;
    };
    // SAFETY: `index` is inside `ivect`; nothing else writes that entry while
    // the caller adjusts the vector.
    unsafe {
        (&raw mut ioapic::IVECT)
            .cast::<InterruptHandler>()
            .add(index)
            .write(handler);
    };
}

/// The unit the handler of the line `irq` is called with.
pub(crate) fn unit(irq: c_int) -> c_int {
    let Some(index) = index_of(irq) else {
        return 0;
    };
    // SAFETY: `index` is inside `iunit`, the array
    // `src/arch/x86_64/interrupt.rs` reads.
    unsafe { *(&raw const ioapic::IUNIT).cast::<c_int>().add(index) }
}

/// Sets the unit the handler of the line `irq` is called with.
pub(crate) fn set_unit(irq: c_int, unit: c_int) {
    let Some(index) = index_of(irq) else {
        return;
    };
    // SAFETY: `index` is inside `iunit`.
    unsafe { *(&raw mut ioapic::IUNIT).cast::<c_int>().add(index) = unit };
}

/// Raises the line's disable count and masks it on the first disable.
fn disable(irq: c_uint) {
    let Ok(pin) = c_int::try_from(irq) else {
        return;
    };
    let Ok(index) = usize::try_from(irq) else {
        return;
    };
    let Some(nested) = NESTED_IRQS.get(index) else {
        return;
    };

    let mut ndisabled = nested.ndisabled.lock();
    *ndisabled = ndisabled.wrapping_add(1);
    if *ndisabled == 1 {
        ioapic::mask(pin);
    }
}

/// Lowers the line's disable count and unmasks it on the last enable.
fn enable(irq: c_uint) {
    let Ok(pin) = c_int::try_from(irq) else {
        return;
    };
    let Ok(index) = usize::try_from(irq) else {
        return;
    };
    let Some(nested) = NESTED_IRQS.get(index) else {
        return;
    };

    let mut ndisabled = nested.ndisabled.lock();
    *ndisabled = ndisabled.wrapping_sub(1);
    if *ndisabled == 0 {
        ioapic::unmask(pin);
    }
}

/// Sets up nothing: the tables are statically initialized.
///
/// The C zeroed each entry's lock and count; the constructor above already
/// leaves every `NESTED_IRQS` entry in that state, so nothing is left to do.
pub(crate) const fn init_irqs() {}

/// Disables the line `irq`, counting nested disables.
pub(crate) fn __disable_irq(irq: c_uint) {
    disable(irq);
}

/// Enables the line `irq` once every disable is undone.
pub(crate) fn __enable_irq(irq: c_uint) {
    enable(irq);
}
