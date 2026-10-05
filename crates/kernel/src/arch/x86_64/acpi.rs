// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2018 Juan Bosco Garcia
// SPDX-FileCopyrightText: 2019 2020 Almudena Garcia Jurado-Centurion
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: i386/i386at/acpi_parse_apic.c

//! The CPUs, I/O APICs, interrupt overrides and HPET the ACPI tables
//! describe, recorded in `apic`.
//!
//! The `acpi` crate reads the tables through [`BootMemory`]; this module
//! maps the register windows they name and builds the APIC tables.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::apic::{
    self, ApicIoUnit, ApicLocalUnit, IoApicData, IrqOverrideData,
};
use crate::config::MAX_NCPUS;
use crate::kern::console::kprint;
use crate::vm::types::VmProt;
use crate::vm::vm_kern::{self, KERNEL_MAP, VM_MIN_KERNEL_ADDRESS};
use crate::vm::vm_map::VmMap;
use ::acpi::{Hpet, Madt, MadtEntry, PhysicalMemory, Root};
use core::mem::size_of;
use core::ops::Deref;
use core::ptr::{self, NonNull};
use core::slice;

/// The physical memory below this address is always in the direct map.
const LOW_MEMORY_END: VmOffset = 0x10_0000;
/// The bytes of the HPET register block the kernel maps.
const HPET_WINDOW: VmSize = 1024;

/// Why the ACPI tables gave no usable APIC description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcpiError {
    /// The firmware tables were rejected.
    Tables(::acpi::Error),
    /// The root table lists no MADT.
    NoApic,
    /// The local APIC could not be mapped.
    NoLapic,
    /// The MADT named no CPU or no I/O APIC, or the CPU list could not be
    /// allocated.
    ApicFailure,
    /// The CPU list could not be shrunk to the CPUs found.
    FitFailure,
}

impl From<::acpi::Error> for AcpiError {
    fn from(error: ::acpi::Error) -> Self {
        Self::Tables(error)
    }
}

/// The kernel virtual address of the physical address `phys`.
const fn phystokv(phys: VmOffset) -> VmOffset {
    phys.wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// Maps the `size` bytes at physical address `phys` into the kernel map
/// with `mode`, until `kmem_unmap_aligned_table` takes them back.
fn map_physical<T>(
    phys: VmOffset,
    size: VmSize,
    mode: VmProt,
) -> Option<NonNull<T>> {
    // SAFETY: `KERNEL_MAP` is the boot kernel map, built before any ACPI
    // caller.
    let map = unsafe { NonNull::new_unchecked(KERNEL_MAP.cast::<VmMap>()) };
    vm_kern::kmem_map_aligned_table(map, phys, size, mode.bits())
        .map(NonNull::cast::<T>)
}

/// Physical memory as boot sees it: the low MiB through the direct map,
/// anything above through a read-only mapping made for the reader.
#[derive(Debug)]
struct BootMemory;

/// A range [`BootMemory`] made readable.
///
/// # Invariants
///
/// `base..base + len` is mapped readable while the window lives: the
/// direct map covers the low MiB for good, and a `mapped` window is
/// unmapped only when it drops.
#[derive(Debug)]
struct Window {
    base: NonNull<u8>,
    len: usize,
    /// The range came from [`map_physical`] and is unmapped on drop.
    mapped: bool,
}

impl Deref for Window {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the type's invariant keeps the range mapped, and nothing
        // writes firmware tables or the BIOS areas while the reader holds
        // them.
        unsafe { slice::from_raw_parts(self.base.as_ptr(), self.len) }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if self.mapped {
            // SAFETY: `map_physical` mapped this range into the live
            // `KERNEL_MAP`, and no slice of the window outlives it.
            unsafe {
                vm_kern::kmem_unmap_aligned_table(
                    &mut *KERNEL_MAP.cast::<VmMap>(),
                    self.base.as_ptr().expose_provenance(),
                    self.len,
                );
            }
        }
    }
}

impl PhysicalMemory for BootMemory {
    type Region<'a> = Window;

    fn map(&self, phys: u64, len: usize) -> Option<Window> {
        let phys = phys as VmOffset;
        if phys.checked_add(len)? <= LOW_MEMORY_END {
            let base = NonNull::new(ptr::with_exposed_provenance_mut::<u8>(
                phystokv(phys),
            ))?;
            return Some(Window {
                base,
                len,
                mapped: false,
            });
        }
        let base = map_physical::<u8>(phys, len, VmProt::READ)?;
        Some(Window {
            base,
            len,
            mapped: true,
        })
    }
}

/// Finds the MADT and the HPET in the ACPI tables and builds the APIC
/// tables.
///
/// # Errors
///
/// Returns the [`AcpiError`] that stopped the parse.
#[expect(
    clippy::too_many_lines,
    reason = "one boot sequence, each step used once"
)]
pub(crate) fn init() -> Result<(), AcpiError> {
    let memory = BootMemory;
    let rsdp = ::acpi::find_rsdp(&memory)?;
    let root = Root::new(&memory, rsdp)?;
    kprint!("ACPI:\n");
    kprint!(" rsdp = 0x{:x}\n", rsdp.address());
    kprint!(
        " {} = 0x{:x} (n = {})\n",
        if rsdp.is_extended() { "xsdt" } else { "rsdt" },
        rsdp.root(),
        root.len(),
    );

    if let Some(address) = root.find(*b"HPET")? {
        match Hpet::new(&memory, address) {
            Ok(hpet) => {
                let window = map_physical::<u32>(
                    hpet.base_address() as VmOffset,
                    HPET_WINDOW,
                    VmProt::READ | VmProt::WRITE,
                );
                apic::publish_hpet(
                    window.map_or(ptr::null_mut(), NonNull::as_ptr),
                );
                kprint!(
                    "HPET at physical address 0x{:x}\n",
                    hpet.base_address()
                );
            }
            Err(error) => kprint!("HPET table rejected: {}\n", error),
        }
    }

    let madt_address = root.find(*b"APIC")?.ok_or(AcpiError::NoApic)?;
    let madt = Madt::new(&memory, madt_address)?;

    if !apic::data_init() {
        return Err(AcpiError::ApicFailure);
    }

    let lapic = map_physical::<ApicLocalUnit>(
        madt.local_apic_address() as VmOffset,
        size_of::<ApicLocalUnit>(),
        VmProt::READ | VmProt::WRITE,
    )
    .ok_or(AcpiError::NoLapic)?;
    apic::publish_lapic(lapic.as_ptr());
    apic::fix_id_mask();

    for entry in madt.entries() {
        match entry? {
            MadtEntry::LocalApic {
                apic_id,
                enabled,
                online_capable,
            } => {
                if (enabled || online_capable)
                    && usize::from(apic::ncpus()) < MAX_NCPUS
                {
                    apic::add_cpu(u16::from(apic_id & apic::id_mask()));
                }
            }
            MadtEntry::IoApic {
                id,
                address,
                gsi_base,
            } => {
                let Some(unit) = map_physical::<ApicIoUnit>(
                    address as VmOffset,
                    size_of::<ApicIoUnit>(),
                    VmProt::READ | VmProt::WRITE,
                ) else {
                    continue;
                };
                // SAFETY: `unit` is the IOAPIC register window just mapped.
                let ngsis = unsafe { apic::ioapic_entry_count(unit.as_ptr()) };
                apic::add_ioapic(IoApicData {
                    apic_id: id,
                    ngsis,
                    addr: address,
                    gsi_base,
                    ioapic: unit.as_ptr(),
                });
            }
            MadtEntry::InterruptOverride {
                bus,
                source,
                gsi,
                flags,
            } => apic::add_irq_override(IrqOverrideData {
                bus,
                irq: source,
                gsi,
                flags,
            }),
            MadtEntry::Other { kind } => {
                kprint!("Unhandled APIC entry type 0x{:x}\n", kind);
            }
        }
    }

    let ncpus = apic::ncpus();
    if ncpus == 0 || apic::num_ioapics() == 0 || MAX_NCPUS < usize::from(ncpus)
    {
        return Err(AcpiError::ApicFailure);
    }
    if usize::from(ncpus) < MAX_NCPUS && !apic::refit_cpulist() {
        return Err(AcpiError::FitFailure);
    }

    apic::generate_cpu_id_lut();
    apic::print_info();
    Ok(())
}
