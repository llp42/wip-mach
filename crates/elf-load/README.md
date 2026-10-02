# `elf-load` — the ELF executable parser

The parser recognizes an ELF image and reports the `PT_LOAD` segments
the caller has to place, plus the entry point and the stack protection
the image asks for. It never touches memory itself: a caller supplies
an [`ElfImage`] that reads file bytes, and `parse` walks the headers
and returns an `ExecInfo` whose `segments` iterator yields one
`Segment` per loadable segment.

The 64-bit reader lives in `src/x86_64.rs`. `parse` reads the `e_ident`
bytes, rejects anything that is not a little-endian `ELFCLASS64` ELF
and hands the image to the reader; the reader owns the `EM_X86_64`
machine check, the program-header walk and the segment iterator.
`ELFCLASS32` is rejected as `WrongArch` (ADR 0003). Everything here is
original MIT code designed from the ELF format (ADR 0010).

## What it provides

| Item | Purpose |
|---|---|
| `parse` | recognize an image and report the segments to place |
| `ElfImage` | the caller's source of file bytes |
| `ExecInfo` | entry point, stack protection, and the segment iterator |
| `Segment` | one `PT_LOAD` segment: offset, lengths, address, wants |
| `Segments` | the iterator over an image's loadable segments |
| `ExecSectype` | read/write/execute, allocate, load |
| `Prot` | the protection bits a segment or the stack wants |
| `ElfParserError` | why an image was rejected |
| `types` (private) | the format's class-independent types: `e_ident`, file type, machine, segment type, permissions |
| `consts` (private) | the numbers the ELF format defines |

## Implementing `ElfImage`

`read_at` has `FileExt::read_at`'s buffer-filling shape: it fills
`buf` with up to `buf.len()` bytes at `offset` and returns how many
were read. A short read is not an error (the parser classifies it).
`parse` reads the whole program-header table before it returns, so a
mangled image is rejected before the caller places anything.

`ExecInfo::segments` re-reads the program headers through the same
`ElfImage`: each item is `Ok(segment)` for a `PT_LOAD` header or
`Err(ElfParserError::Corrupted)` when the image no longer covers a
header, in which case the iteration ends. `Segment` carries the file
offset, the file and memory lengths, the address already rebased for a
position-independent image, and the `ExecSectype` it wants.

```text
match elf_load::parse(&image) {
    Ok(info) => {
        for segment in info.segments(&image) {
            /* segment.offset(), segment.addr(), segment.sectype() */
        }
        /* info.entry(), info.stack_prot() */
    }
    Err(err) => { /* ElfParserError::{NotElf,WrongArch,Corrupted} */ }
}
```

## Tests

`cargo test -p elf-load --target x86_64-unknown-linux-gnu` (`mise run
test::elf-load`) runs the host tests against an in-memory image.
`mise run cov::elf-load` holds the crate at 100% lines, regions and
functions.
