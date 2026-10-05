# `acpi` — the ACPI static-table reader

The reader finds the root system description pointer, walks the root
table it names, and decodes the two tables the kernel reads: the MADT,
for the local APICs, I/O APICs and interrupt overrides, and the HPET
description table, for the timer block's address. It never touches
memory itself: a caller supplies a `PhysicalMemory` that maps physical
ranges, and every table is mapped whole and checksummed before a field of
it is read. Everything here is original MIT code designed from the ACPI
and IA-PC HPET specifications (ADR 0010); the crate has no `unsafe`.

## What it provides

| Item | Purpose |
|---|---|
| `PhysicalMemory` | the caller's mapper of physical ranges |
| `find_rsdp` | find the root pointer in the EBDA or the BIOS area |
| `Rsdp` | where the root pointer and its root table are, RSDT or XSDT |
| `Root` | the RSDT or XSDT, mapped, searched by table signature |
| `Madt` | the local-APIC address and the entry iterator |
| `MadtEntries` | the iterator over the MADT's entries |
| `MadtEntry` | a local APIC, an I/O APIC, an interrupt override, or `Other` |
| `Hpet` | the physical address of the HPET registers |
| `Error` | why a table was rejected |

## Implementing `PhysicalMemory`

`map(phys, len)` returns a region of exactly `len` bytes, or `None` when
the range cannot be mapped; the reader turns `None` into
`Error::Unmapped`. Dropping the region may unmap it: `Root` and `Madt`
hold theirs for as long as they live, and every other mapping is dropped
before the call that made it returns. The ranges are firmware tables and
the BIOS areas below 1 MiB, which nothing writes while they are mapped.

```text
let rsdp = acpi::find_rsdp(&memory)?;
let root = acpi::Root::new(&memory, rsdp)?;
if let Some(address) = root.find(*b"HPET")? {
    let hpet = acpi::Hpet::new(&memory, address)?;
    /* map hpet.base_address() */
}
let madt = acpi::Madt::new(&memory, root.find(*b"APIC")?.ok_or(..)?)?;
for entry in madt.entries() {
    match entry? {
        acpi::MadtEntry::LocalApic { apic_id, enabled, online_capable } => {}
        acpi::MadtEntry::IoApic { id, address, gsi_base } => {}
        acpi::MadtEntry::InterruptOverride { bus, source, gsi, flags } => {}
        acpi::MadtEntry::Other { kind } => {}
    }
}
```

`find_rsdp` searches the first KiB of the EBDA, then the BIOS read-only
area from `0xe0000` to 1 MiB, on 16-byte boundaries. Revision 0 names an
RSDT; revision 2 names an XSDT and must pass both checksums. A malformed
MADT entry, whether zero-length, running past the table or shorter than
its type's layout, yields one `Error::Corrupted` and ends the walk.
Entry types the kernel does not use come back as `Other { kind }`.

## Not rust-osdev's `acpi`

The ecosystem crate of the same name does this job and more, and its
allocator-free API would cover what the kernel reads. It is not used
(ADR 0023):

- its 6.x releases set `#![feature(allocator_api)]` unconditionally, so
  they build only on nightly (ADR 0004);
- 6.1.1 checks neither the root table's signature and checksum nor any
  found table's checksum, and reads root entries through misaligned
  pointers, which the kernel's `dev` profile turns into a panic;
- it brings six runtime dependencies, and its `Handler` trait asks for
  port I/O, PCI configuration and timing services a table walk never
  calls;
- its zero-length MADT entry loops forever;
- its main extra, the AML interpreter, is what ADR 0019 keeps out of the
  kernel.

## Tests

`cargo test -p acpi --target x86_64-unknown-linux-gnu` (`mise run
test::acpi`) runs the host tests against a sparse in-memory physical
memory. `mise run cov::acpi` holds the crate at 100% lines, regions and
functions.
