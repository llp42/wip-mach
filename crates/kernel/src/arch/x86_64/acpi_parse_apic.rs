// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386at/acpi_parse_apic.c:
//   Copyright (C) 2018 Juan Bosco Garcia
//   Copyright (C) 2019 2020 Almudena Garcia Jurado-Centurion
//   Written by Juan Bosco Garcia and Almudena Garcia Jurado-Centurion
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ACPI-MADT parser, which `i386/i386at/acpi_parse_apic.c` used to define
//! and `i386/i386at/acpi_parse_apic.h` declares, with the packed ACPI table
//! mirrors of that header.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::apic::{
    self, ApicIoUnit, ApicLocalUnit, IoApicData, IrqOverrideData,
};
use crate::config::MAX_NCPUS;
use crate::kern::console::kprint;
use crate::vm::types::VmProt;
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_kern::{self, VM_MIN_KERNEL_ADDRESS};
use crate::vm::vm_map::VmMap;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::slice;

/// `ACPI_RSDP_ALIGN` of <`i386at/acpi_parse_apic.h`>.
const ACPI_RSDP_ALIGN: usize = 16;
/// `ACPI_RSDP_SIG`: the RSDP signature.
const ACPI_RSDP_SIG: [u8; 8] = *b"RSD PTR ";
/// `ACPI_RSDT_SIG`.
const ACPI_RSDT_SIG: [u8; 4] = *b"RSDT";
/// `ACPI_XSDT_SIG`.
const ACPI_XSDT_SIG: [u8; 4] = *b"XSDT";
/// `ACPI_APIC_SIG`.
const ACPI_APIC_SIG: [u8; 4] = *b"APIC";
/// `ACPI_HPET_SIG`.
const ACPI_HPET_SIG: [u8; 4] = *b"HPET";

/// `ACPI_LAPIC_FLAG_ENABLED`.
const ACPI_LAPIC_FLAG_ENABLED: u32 = 1 << 0;
/// `ACPI_LAPIC_FLAG_CAPABLE`.
const ACPI_LAPIC_FLAG_CAPABLE: u32 = 1 << 1;

/// `ACPI_APIC_ENTRY_LAPIC`.
const ACPI_APIC_ENTRY_LAPIC: u8 = 0;
/// `ACPI_APIC_ENTRY_IOAPIC`.
const ACPI_APIC_ENTRY_IOAPIC: u8 = 1;
/// `ACPI_APIC_ENTRY_IRQ_OVERRIDE`.
const ACPI_APIC_ENTRY_IRQ_OVERRIDE: u8 = 2;

/// The byte count the C searches between `0xe0000` and `0x100000`.
const BIOS_SEARCH_LENGTH: u32 = 0x0010_0000 - 0xe0000;

/// A 32-bit table field as a `usize`; `usize` holds every `u32`, so the
/// widening loses nothing.
const fn from_u32(value: u32) -> usize {
    value as usize
}

/// The `ACPI_RETURN` codes of <`i386at/acpi_parse_apic.h`> this parser returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i8)]
enum AcpiError {
    BadChecksum = -1,
    NoRsdp = -3,
    NoRsdt = -4,
    NoApic = -6,
    NoLapic = -7,
    ApicFailure = -8,
    FitFailure = -9,
}

impl AcpiError {
    /// The `int` the C entry point returns.
    const fn code(self) -> c_int {
        self as c_int
    }
}

/// `struct acpi_rsdp` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiRsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_addr: u32,
}

/// `struct acpi_rsdp2` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiRsdp2 {
    /// `v1`: the ACPI 1.0 RSDP this ACPI 2.0+ table extends.
    v1: AcpiRsdp,
    length: u32,
    xsdt_addr: u64,
    checksum: u8,
    reserved: [u8; 3],
}

/// `struct acpi_dhdr` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiDhdr {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: [u8; 4],
    creator_revision: u32,
}

/// `struct acpi_rsdt` of <`i386at/acpi_parse_apic.h>`: the header and the C's
/// trailing `entry[0]`, one `u32` per table.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiRsdt {
    header: AcpiDhdr,
    entry: [u32; 0],
}

/// `struct acpi_xsdt` of <`i386at/acpi_parse_apic.h>`: the header and the C's
/// trailing `entry[0]`, one `u64` per table.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiXsdt {
    header: AcpiDhdr,
    entry: [u64; 0],
}

/// `struct acpi_address` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiAddress {
    is_io: u8,
    reg_width: u8,
    reg_offset: u8,
    reserved: u8,
    addr64: u64,
}

/// `struct acpi_apic_dhdr` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiApicDhdr {
    type_: u8,
    length: u8,
}

/// `struct acpi_apic` of <`i386at/acpi_parse_apic.h>`: the MADT itself, whose
/// trailing `entry[0]` holds one [`AcpiApicDhdr`] per interrupt controller.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiApic {
    header: AcpiDhdr,
    lapic_addr: u32,
    flags: u32,
    entry: [AcpiApicDhdr; 0],
}

/// `struct acpi_apic_lapic` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiApicLapic {
    header: AcpiApicDhdr,
    processor_id: u8,
    apic_id: u8,
    flags: u32,
}

/// `struct acpi_apic_ioapic` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiApicIoapic {
    header: AcpiApicDhdr,
    apic_id: u8,
    reserved: u8,
    addr: u32,
    gsi_base: u32,
}

/// `struct acpi_apic_irq_override` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiApicIrqOverride {
    header: AcpiApicDhdr,
    bus: u8,
    irq: u8,
    gsi: u32,
    flags: u16,
}

/// `struct acpi_hpet` of <`i386at/acpi_parse_apic.h`>.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
struct AcpiHpet {
    header: AcpiDhdr,
    id: u32,
    address: AcpiAddress,
    sequence: u8,
    minimum_tick: u16,
    flags: u8,
}

const _: () = {
    assert!(size_of::<AcpiRsdp>() == 20);
    assert!(align_of::<AcpiRsdp>() == 1);
    assert!(offset_of!(AcpiRsdp, signature) == 0);
    assert!(offset_of!(AcpiRsdp, checksum) == 8);
    assert!(offset_of!(AcpiRsdp, oem_id) == 9);
    assert!(offset_of!(AcpiRsdp, revision) == 15);
    assert!(offset_of!(AcpiRsdp, rsdt_addr) == 16);

    assert!(size_of::<AcpiRsdp2>() == 36);
    assert!(align_of::<AcpiRsdp2>() == 1);
    assert!(offset_of!(AcpiRsdp2, v1) == 0);
    assert!(offset_of!(AcpiRsdp2, length) == 20);
    assert!(offset_of!(AcpiRsdp2, xsdt_addr) == 24);
    assert!(offset_of!(AcpiRsdp2, checksum) == 32);
    assert!(offset_of!(AcpiRsdp2, reserved) == 33);

    assert!(size_of::<AcpiDhdr>() == 36);
    assert!(align_of::<AcpiDhdr>() == 1);
    assert!(offset_of!(AcpiDhdr, signature) == 0);
    assert!(offset_of!(AcpiDhdr, length) == 4);
    assert!(offset_of!(AcpiDhdr, revision) == 8);
    assert!(offset_of!(AcpiDhdr, checksum) == 9);
    assert!(offset_of!(AcpiDhdr, oem_id) == 10);
    assert!(offset_of!(AcpiDhdr, oem_table_id) == 16);
    assert!(offset_of!(AcpiDhdr, oem_revision) == 24);
    assert!(offset_of!(AcpiDhdr, creator_id) == 28);
    assert!(offset_of!(AcpiDhdr, creator_revision) == 32);

    assert!(size_of::<AcpiRsdt>() == 36);
    assert!(align_of::<AcpiRsdt>() == 1);
    assert!(offset_of!(AcpiRsdt, entry) == 36);
    assert!(size_of::<AcpiXsdt>() == 36);
    assert!(align_of::<AcpiXsdt>() == 1);
    assert!(offset_of!(AcpiXsdt, entry) == 36);

    assert!(size_of::<AcpiAddress>() == 12);
    assert!(align_of::<AcpiAddress>() == 1);
    assert!(offset_of!(AcpiAddress, is_io) == 0);
    assert!(offset_of!(AcpiAddress, reg_width) == 1);
    assert!(offset_of!(AcpiAddress, reg_offset) == 2);
    assert!(offset_of!(AcpiAddress, reserved) == 3);
    assert!(offset_of!(AcpiAddress, addr64) == 4);

    assert!(size_of::<AcpiApicDhdr>() == 2);
    assert!(align_of::<AcpiApicDhdr>() == 1);
    assert!(offset_of!(AcpiApicDhdr, type_) == 0);
    assert!(offset_of!(AcpiApicDhdr, length) == 1);

    assert!(size_of::<AcpiApic>() == 44);
    assert!(align_of::<AcpiApic>() == 1);
    assert!(offset_of!(AcpiApic, header) == 0);
    assert!(offset_of!(AcpiApic, lapic_addr) == 36);
    assert!(offset_of!(AcpiApic, flags) == 40);
    assert!(offset_of!(AcpiApic, entry) == 44);

    assert!(size_of::<AcpiApicLapic>() == 8);
    assert!(align_of::<AcpiApicLapic>() == 1);
    assert!(offset_of!(AcpiApicLapic, header) == 0);
    assert!(offset_of!(AcpiApicLapic, processor_id) == 2);
    assert!(offset_of!(AcpiApicLapic, apic_id) == 3);
    assert!(offset_of!(AcpiApicLapic, flags) == 4);

    assert!(size_of::<AcpiApicIoapic>() == 12);
    assert!(align_of::<AcpiApicIoapic>() == 1);
    assert!(offset_of!(AcpiApicIoapic, header) == 0);
    assert!(offset_of!(AcpiApicIoapic, apic_id) == 2);
    assert!(offset_of!(AcpiApicIoapic, reserved) == 3);
    assert!(offset_of!(AcpiApicIoapic, addr) == 4);
    assert!(offset_of!(AcpiApicIoapic, gsi_base) == 8);

    assert!(size_of::<AcpiApicIrqOverride>() == 10);
    assert!(align_of::<AcpiApicIrqOverride>() == 1);
    assert!(offset_of!(AcpiApicIrqOverride, header) == 0);
    assert!(offset_of!(AcpiApicIrqOverride, bus) == 2);
    assert!(offset_of!(AcpiApicIrqOverride, irq) == 3);
    assert!(offset_of!(AcpiApicIrqOverride, gsi) == 4);
    assert!(offset_of!(AcpiApicIrqOverride, flags) == 8);

    assert!(size_of::<AcpiHpet>() == 56);
    assert!(align_of::<AcpiHpet>() == 1);
    assert!(offset_of!(AcpiHpet, header) == 0);
    assert!(offset_of!(AcpiHpet, id) == 36);
    assert!(offset_of!(AcpiHpet, address) == 40);
    assert!(offset_of!(AcpiHpet, sequence) == 52);
    assert!(offset_of!(AcpiHpet, minimum_tick) == 53);
    assert!(offset_of!(AcpiHpet, flags) == 55);
};

/// `hpet_addr` of <i386/apic.h>: the mapped HPET register window.
pub(crate) static mut HPET_ADDR: *mut u32 = ptr::null_mut();

/// `lapic_addr` of `i386/i386at/acpi_parse_apic.c`: the local-APIC address
/// the MADT named.
pub(crate) static mut LAPIC_ADDR: c_uint = 0;

/// `phystokv()` of <`i386/vm_param.h`>.
const fn phystokv(phys: VmOffset) -> VmOffset {
    phys.wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// The mapped table of type `T` at physical address `phys`.
fn map_table<T>(
    phys: VmOffset,
    size: VmSize,
    mode: VmProt,
) -> Option<NonNull<T>> {
    // SAFETY: `kernel_map` is the boot kernel map, built before any ACPI
    // caller.
    let map = unsafe { NonNull::new_unchecked(KERNEL_MAP.cast::<VmMap>()) };
    vm_kern::kmem_map_aligned_table(map, phys, size, mode.bits())
        .map(NonNull::cast::<T>)
}

/// `acpi_checksum()` in C: the wrapping byte sum of `bytes`.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

/// `acpi_checksum()` in C over the mapped table at `addr`.
///
/// # Safety
///
/// `addr..addr + length` must be mapped readable.
unsafe fn checksum_table(addr: *const u8, length: u32) -> u8 {
    let bytes = unsafe { slice::from_raw_parts(addr, from_u32(length)) };
    checksum(bytes)
}

/// The packed `header.length` of a descriptor header.
///
/// # Safety
///
/// `header` must be a mapped descriptor header.
const unsafe fn header_length(header: *const AcpiDhdr) -> u32 {
    unsafe { ptr::read_unaligned(ptr::addr_of!((*header).length)) }
}

/// The packed `header.signature` of a descriptor header.
///
/// # Safety
///
/// As [`header_length()`].
const unsafe fn header_signature(header: *const AcpiDhdr) -> [u8; 4] {
    // SAFETY: the caller promises the header is mapped; the packed read is
    // unaligned.
    unsafe { ptr::read_unaligned(header.cast::<[u8; 4]>()) }
}

/// `rsdt->entry[index]` in C, past the packed header.
///
/// # Safety
///
/// `index` must be below the entry count `get_rsdt()` computed, and the
/// mapped table must cover the entry.
const unsafe fn rsdt_entry(rsdt: *const AcpiRsdt, index: usize) -> VmOffset {
    let entry = unsafe {
        ptr::read_unaligned(
            ptr::addr_of!((*rsdt).entry).cast::<u32>().add(index),
        )
    };
    from_u32(entry)
}

/// `xsdt->entry[index]` in C, past the packed header.
///
/// # Safety
///
/// As [`rsdt_entry()`], against the count `get_xsdt()` computed.
const unsafe fn xsdt_entry(xsdt: *const AcpiXsdt, index: usize) -> VmOffset {
    let entry = unsafe {
        ptr::read_unaligned(
            ptr::addr_of!((*xsdt).entry).cast::<u64>().add(index),
        )
    };
    // The C passes the `uint64_t` entry to a `phys_addr_t` parameter; both
    // are 64 bits here, so the conversion is exact.
    entry as VmOffset
}

/// `acpi_check_rsdp()` in C: the ACPI version and the RSDT/XSDT physical base
/// the RSDP at `addr` records, when its signature and checksum are good.
fn check_rsdp(addr: VmOffset) -> Option<(u8, VmOffset)> {
    // SAFETY: the caller only probes the EBDA and BIOS ranges, which the
    // kernel maps, and every candidate is 16-byte aligned.
    let rsdp = unsafe {
        ptr::read_unaligned(ptr::with_exposed_provenance::<AcpiRsdp2>(addr))
    };

    if rsdp.v1.signature != ACPI_RSDP_SIG {
        return None;
    }

    match rsdp.v1.revision {
        0 => {
            kprint!("ACPI v1.0\n");
            // SAFETY: the caller only probes the EBDA and BIOS ranges,
            // which the kernel maps; the v1 checksum covers the 20-byte
            // table.
            let bytes = unsafe {
                slice::from_raw_parts(
                    ptr::with_exposed_provenance::<u8>(addr),
                    size_of::<AcpiRsdp>(),
                )
            };
            if checksum(bytes) != 0 {
                return None;
            }
            Some((1, from_u32(rsdp.v1.rsdt_addr)))
        }
        2 => {
            kprint!("ACPI >= v2.0\n");
            // SAFETY: the caller only probes the EBDA and BIOS ranges,
            // which the kernel maps; the v2 checksum covers the 36-byte
            // table.
            let bytes = unsafe {
                slice::from_raw_parts(
                    ptr::with_exposed_provenance::<u8>(addr),
                    size_of::<AcpiRsdp2>(),
                )
            };
            if checksum(bytes) != 0 {
                return None;
            }
            // The C assigns the `uint64_t` to a `phys_addr_t`; both are 64
            // bits here, so the conversion is exact.
            Some((2, rsdp.xsdt_addr as VmOffset))
        }
        _ => None,
    }
}

/// `acpi_search_rsdp()` in C: the first valid RSDP in `addr..addr + length`.
fn search_rsdp(addr: VmOffset, length: u32) -> Option<(u8, VmOffset)> {
    let end = addr.wrapping_add(from_u32(length));
    let mut cursor = addr;
    while cursor < end {
        if let Some(found) = check_rsdp(cursor) {
            return Some(found);
        }
        cursor = cursor.wrapping_add(ACPI_RSDP_ALIGN);
    }
    None
}

/// `acpi_get_rsdp()` in C: the RSDP physical base and whether it is ACPI 2.0.
fn get_rsdp() -> Option<(bool, VmOffset)> {
    // SAFETY: 0x040e is the EBDA paragraph word in the low memory the kernel
    // keeps mapped, and it is 2-byte aligned.
    let paragraph = unsafe {
        ptr::read(ptr::with_exposed_provenance::<u16>(phystokv(0x040e)))
    };
    let base = phystokv(VmOffset::from(paragraph) << 4);

    if base & (ACPI_RSDP_ALIGN - 1) != 0 {
        return None;
    }

    search_rsdp(base, 1024)
        .or_else(|| search_rsdp(phystokv(0xe0000), BIOS_SEARCH_LENGTH))
        .map(|(version, sdt)| (version == 2, sdt))
}

/// `acpi_get_rsdt()` in C: the mapped RSDT and its entry count.
fn get_rsdt(rsdp_phys: VmOffset) -> Option<(NonNull<AcpiRsdt>, c_int)> {
    let rsdt =
        map_table::<AcpiRsdt>(rsdp_phys, size_of::<AcpiRsdt>(), VmProt::READ)?;

    // SAFETY: `map_table` mapped a full descriptor header at `rsdt`.
    let signature = unsafe { header_signature(rsdt.as_ptr().cast()) };
    if signature != ACPI_RSDT_SIG {
        return None;
    }

    // SAFETY: `map_table` mapped a full descriptor header at `rsdt`.
    let length = unsafe { header_length(rsdt.as_ptr().cast()) };
    let entries = from_u32(length).wrapping_sub(size_of::<AcpiRsdt>())
        / size_of::<u32>();
    // The C assigns the `size_t` quotient to an `int`, so a malformed length
    // truncates the same way.
    Some((rsdt, entries as c_int))
}

/// `acpi_get_xsdt()` in C: the mapped XSDT and its entry count.
fn get_xsdt(rsdp_phys: VmOffset) -> Option<(NonNull<AcpiXsdt>, c_int)> {
    let xsdt =
        map_table::<AcpiXsdt>(rsdp_phys, size_of::<AcpiXsdt>(), VmProt::READ)?;

    // SAFETY: `map_table` mapped a full descriptor header at `xsdt`.
    let signature = unsafe { header_signature(xsdt.as_ptr().cast()) };
    if signature != ACPI_XSDT_SIG {
        return None;
    }

    // SAFETY: `map_table` mapped a full descriptor header at `xsdt`.
    let length = unsafe { header_length(xsdt.as_ptr().cast()) };
    let entries = from_u32(length).wrapping_sub(size_of::<AcpiXsdt>())
        / size_of::<u64>();
    // The C assigns the `size_t` quotient to an `int`, so a malformed length
    // truncates the same way.
    Some((xsdt, entries as c_int))
}

/// Examine one RSDT/XSDT entry: remember the MADT it names, or map the HPET
/// it names.
fn inspect_entry(phys: VmOffset, madt: &mut Option<NonNull<AcpiApic>>) {
    let Some(header) =
        map_table::<AcpiDhdr>(phys, size_of::<AcpiDhdr>(), VmProt::READ)
    else {
        return;
    };

    // SAFETY: `map_table` mapped a full descriptor header at `header`.
    let signature = unsafe { header_signature(header.as_ptr()) };
    if signature == ACPI_APIC_SIG {
        *madt = Some(header.cast::<AcpiApic>());
    }

    if signature == ACPI_HPET_SIG {
        // SAFETY: the mapped descriptor header begins the packed HPET table,
        // whose `address.addr64` field the C reads the same way.
        let hpet = header.cast::<AcpiHpet>();
        // SAFETY: the mapped descriptor header begins the packed HPET table,
        // whose `address.addr64` field the C reads the same way.
        let address = unsafe {
            ptr::read_unaligned(ptr::addr_of!((*hpet.as_ptr()).address.addr64))
        };
        // The C passes the `uint64_t` address to `kmem_map_aligned_table`;
        // both are 64 bits here, so the conversion is exact.
        let mapped = map_table::<u32>(
            address as VmOffset,
            1024,
            VmProt::READ | VmProt::WRITE,
        );
        // SAFETY: `hpet_addr` is the C global, written only from this loop.
        unsafe {
            HPET_ADDR = mapped.map_or(ptr::null_mut(), NonNull::as_ptr);
        };
        kprint!("HPET at physical address 0x{:x}\n", address);
    }
}

/// `acpi_get_apic()` in C: the MADT one of the RSDT entries names.
fn get_apic(
    rsdt: NonNull<AcpiRsdt>,
    count: c_int,
) -> Option<NonNull<AcpiApic>> {
    let count = usize::try_from(count).unwrap_or(0);
    let mut madt = None;
    for i in 0..count {
        // SAFETY: `i` is below the entry count `get_rsdt()` computed, and
        // the mapped table covers the entries.
        let phys = unsafe { rsdt_entry(rsdt.as_ptr(), i) };
        inspect_entry(phys, &mut madt);
    }
    madt
}

/// `acpi_get_apic2()` in C: the MADT one of the XSDT entries names.
fn get_apic2(
    xsdt: NonNull<AcpiXsdt>,
    count: c_int,
) -> Option<NonNull<AcpiApic>> {
    let count = usize::try_from(count).unwrap_or(0);
    let mut madt = None;
    for i in 0..count {
        // SAFETY: `i` is below the entry count `get_xsdt()` computed, and
        // the mapped table covers the entries.
        let phys = unsafe { xsdt_entry(xsdt.as_ptr(), i) };
        inspect_entry(phys, &mut madt);
    }
    madt
}

/// `acpi_apic_add_lapic()` in C: record one enabled or capable CPU.
fn add_lapic(entry: AcpiApicLapic) {
    if entry.flags & (ACPI_LAPIC_FLAG_ENABLED | ACPI_LAPIC_FLAG_CAPABLE) != 0 {
        apic::add_cpu(u16::from(entry.apic_id & apic::id_mask()));
    }
}

/// `acpi_apic_add_ioapic()` in C: map one IOAPIC and record it.
fn add_ioapic(entry: AcpiApicIoapic) {
    let Some(unit) = map_table::<ApicIoUnit>(
        from_u32(entry.addr),
        size_of::<ApicIoUnit>(),
        VmProt::READ | VmProt::WRITE,
    ) else {
        return;
    };

    // SAFETY: `unit` is the mapped IOAPIC register window.
    let ngsis = unsafe { apic::ioapic_entry_count(unit.as_ptr()) };

    apic::add_ioapic(IoApicData {
        apic_id: entry.apic_id,
        ngsis,
        addr: entry.addr,
        gsi_base: entry.gsi_base,
        ioapic: unit.as_ptr(),
    });
}

/// `acpi_apic_add_irq_override()` in C: record one IRQ override.
fn add_irq_override(entry: AcpiApicIrqOverride) {
    apic::add_irq_override(IrqOverrideData {
        bus: entry.bus,
        irq: entry.irq,
        gsi: entry.gsi,
        flags: entry.flags,
    });
}

/// `acpi_apic_parse_table()` in C: walk the MADT entries.
fn parse_table(apic: NonNull<AcpiApic>) {
    // SAFETY: the caller passes the mapped MADT.
    let length = unsafe { header_length(apic.as_ptr().cast()) };
    let start = apic.as_ptr().cast::<u8>();
    // SAFETY: the first entry follows the 44-byte packed MADT header, which
    // the mapping covers.
    let mut entry =
        unsafe { ptr::addr_of_mut!((*apic.as_ptr()).entry).cast::<u8>() };
    let end = start as usize + from_u32(length);

    kprint!(
        "APIC entry=0x{:x} end=0x{:x}\n",
        entry.expose_provenance(),
        end,
    );

    let mut ncpus = apic::ncpus();
    while (entry as usize) < end {
        // SAFETY: `entry` is inside the mapped MADT; the descriptor's two
        // fields are packed.
        let type_ = unsafe { ptr::read(entry) };
        // SAFETY: `entry` is inside the mapped MADT; the descriptor's two
        // fields are packed.
        let entry_length = unsafe { ptr::read(entry.add(1)) };

        kprint!(
            "APIC entry=0x{:x} end=0x{:x}\n",
            entry.expose_provenance(),
            end,
        );

        match type_ {
            ACPI_APIC_ENTRY_LAPIC => {
                if usize::from(ncpus) < MAX_NCPUS {
                    // SAFETY: the entry is inside the mapped MADT.
                    let lapic_entry = unsafe {
                        ptr::read_unaligned(entry.cast::<AcpiApicLapic>())
                    };
                    add_lapic(lapic_entry);
                }
            }
            ACPI_APIC_ENTRY_IOAPIC => {
                // SAFETY: the entry is inside the mapped MADT.
                let ioapic_entry = unsafe {
                    ptr::read_unaligned(entry.cast::<AcpiApicIoapic>())
                };
                add_ioapic(ioapic_entry);
            }
            ACPI_APIC_ENTRY_IRQ_OVERRIDE => {
                // SAFETY: the entry is inside the mapped MADT.
                let override_entry = unsafe {
                    ptr::read_unaligned(entry.cast::<AcpiApicIrqOverride>())
                };
                add_irq_override(override_entry);
            }
            _ => {
                kprint!("Unhandled APIC entry type 0x{:x}\n", type_);
            }
        }

        // SAFETY: `entry_length` advances inside the mapping the C walks.
        entry = unsafe { entry.add(usize::from(entry_length)) };
        ncpus = apic::ncpus();
    }
}

/// `acpi_apic_setup()` in C: map the local APIC, parse the MADT and build the
/// ID tables.
fn setup(apic: NonNull<AcpiApic>) -> Result<(), AcpiError> {
    // SAFETY: the caller passes the mapped MADT, and `lapic_addr` sits inside
    // its packed header.
    let address = unsafe {
        ptr::read_unaligned(ptr::addr_of!((*apic.as_ptr()).lapic_addr))
    };
    // SAFETY: `lapic_addr` is the C global <i386at/acpi_parse_apic.h>
    // declares, written once at boot.
    unsafe { LAPIC_ADDR = address };

    let Some(unit) = map_table::<ApicLocalUnit>(
        from_u32(address),
        size_of::<ApicLocalUnit>(),
        VmProt::READ | VmProt::WRITE,
    ) else {
        return Err(AcpiError::NoLapic);
    };

    apic::publish_lapic(unit.as_ptr());
    apic::fix_id_mask();
    parse_table(apic);

    let ncpus = apic::ncpus();
    let nioapics = apic::num_ioapics();
    if ncpus == 0 || nioapics == 0 || MAX_NCPUS < usize::from(ncpus) {
        return Err(AcpiError::ApicFailure);
    }

    if usize::from(ncpus) < MAX_NCPUS && !apic::refit_cpulist() {
        return Err(AcpiError::FitFailure);
    }

    apic::generate_cpu_id_lut();
    Ok(())
}

/// `acpi_apic_init()` in C: find the MADT in the ACPI tables and build the
/// APIC tables.
fn init() -> Result<(), AcpiError> {
    let Some((is_64bit, rsdp)) = get_rsdp() else {
        return Err(AcpiError::NoRsdp);
    };

    let (madt, tables, count) = if is_64bit {
        let Some((xsdt, count)) = get_xsdt(rsdp) else {
            return Err(AcpiError::NoRsdt);
        };
        // SAFETY: `get_xsdt` mapped a full descriptor header at `xsdt`, and
        // the checksum walks that mapped table.
        let checksum = unsafe {
            checksum_table(
                xsdt.as_ptr().cast(),
                header_length(xsdt.as_ptr().cast()),
            )
        };
        if checksum != 0 {
            return Err(AcpiError::BadChecksum);
        }
        let Some(madt) = get_apic2(xsdt, count) else {
            return Err(AcpiError::NoApic);
        };
        (madt, xsdt.as_ptr().cast::<c_void>(), count)
    } else {
        let Some((rsdt_table, count)) = get_rsdt(rsdp) else {
            return Err(AcpiError::NoRsdt);
        };
        // SAFETY: `get_rsdt` mapped a full descriptor header at `rsdt_table`,
        // and the checksum walks that mapped table.
        let checksum = unsafe {
            checksum_table(
                rsdt_table.as_ptr().cast(),
                header_length(rsdt_table.as_ptr().cast()),
            )
        };
        if checksum != 0 {
            return Err(AcpiError::BadChecksum);
        }
        let Some(madt) = get_apic(rsdt_table, count) else {
            return Err(AcpiError::NoApic);
        };
        (madt, rsdt_table.as_ptr().cast::<c_void>(), count)
    };

    // SAFETY: `get_apic` and `get_apic2` mapped a full descriptor header at
    // the MADT address, and the checksum walks that mapped table.
    let checksum = unsafe {
        checksum_table(
            madt.as_ptr().cast(),
            header_length(madt.as_ptr().cast()),
        )
    };
    if checksum != 0 {
        return Err(AcpiError::BadChecksum);
    }

    print_info(rsdp, tables, count);

    if !apic::data_init() {
        return Err(AcpiError::ApicFailure);
    }

    setup(madt)?;
    apic::print_info();
    Ok(())
}

/// Report the physical RSDP address, the mapped RSDT or XSDT address and the
/// number of entries the table holds.
fn print_info(rsdp: VmOffset, rsdt_table: *mut c_void, acpi_rsdt_n: c_int) {
    kprint!("ACPI:\n");
    kprint!(" rsdp = 0x{:x}\n", rsdp as u64);
    kprint!(
        " rsdt/xsdt = 0x{:x} (n = {})\n",
        rsdt_table.expose_provenance(),
        acpi_rsdt_n,
    );
}

/// The ACPI MADT parser, which `acpi_apic_init()` in C ran at boot.
pub(crate) fn acpi_apic_init() -> c_int {
    match init() {
        Ok(()) => 0,
        Err(error) => error.code(),
    }
}
