# `elf-load` — the ELF executable loader

The loader recognizes an ELF image and places its `PT_LOAD` segments.
It never touches memory itself: a caller supplies an [`ElfImage`] that
reads file bytes and places one segment, and `load` walks the
program headers and reports what it found.

The 32-bit and 64-bit readers are separate modules
(`src/x86.rs` and `src/x86_64.rs`). `load` matches `EI_CLASS` through `EiClass` (`1` =
x86, `2` = x86_64) and hands the image to one
path immediately. Each path then owns its magic, byte-order, machine
and program-header walk (`p_flags` sits in different places in the 32-
and 64-bit headers). Everything here is original MIT code designed
from the ELF format (ADR 0010).

## What it provides

| Item | Purpose |
|---|---|
| `load` | recognize an image and place its `PT_LOAD` segments |
| `ElfImage` | the caller's source of file bytes and segment sink |
| `ExecInfo` | entry point and stack protection the image asks for |
| `ExecSectype` | read/write/execute, allocate, load |
| `Prot` | the protection bits a segment or the stack wants |
| `ExecError` | why an image was rejected, or the caller's own error |

## Implementing `ElfImage`

One object plays both roles. `read_at(offset, len)` returns a borrowed
slice of the image — not a copy — of up to `len` bytes; a short slice
is not an error (the loader classifies it). `place` receives one
segment: the `file_len` bytes at `offset` land at `addr`, the
trailing `mem_len - file_len` bytes read as zero, and `sectype` says
what the segment wants.

```text
match elf_load::load(&mut image) {
    Ok(info) => { /* info.entry(), info.stack_prot() */ }
    Err(err) => { /* ExecError::{NotExecutable,WrongArch,Corrupt,Image} */ }
}
```

## Tests

`cargo test -p elf-load --target x86_64-unknown-linux-gnu` (`mise run
test::elf-load`) runs the host tests against an in-memory image that
records every `place`. `mise run cov::elf-load` holds the crate at 100%
lines, regions and functions.
