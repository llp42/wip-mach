# Removing the slab's rbtree: benefits and problems

> **Status (2026-10): research note, a decision aid.** It follows
> `RESEARCH-slab-rbtree.md` (why the tree exists, and how six other kernels
> map a buffer to its slab) and asks what taking `active_slabs` out of
> `kern/slab.rs` would give this kernel and cost it. Nothing here is decided
> or landed. It changes no code, no ADR and no `DEBT.md` entry.
>
> **Decision (2026-10-01, maintainer):** tag every page of a slab, the
> FreeBSD UMA `vtoslab()` and x15 shape, not only the first page as
> section 5 recommends. The reason given was that the tree's insert and
> remove cost goes away and the interior-address lookup comes back; no
> further analysis was done. The tag cost at create and destroy (P6) was
> not measured in the kernel. The sections below are the analysis from
> before that decision.

Facts carry `path:line @ revision`. Statements that are my reading rather
than a quote say "inference"; things I did not or could not reach say "not
checked". Paths are under `crates/kernel/src` unless they start with `docs/`,
`crates/` or name a root file. The earlier note's section 1 (what the tree
does) and section 4 (other kernels) are not repeated; "the earlier note"
means that file.

## Sources and their limits

- **wip-mach** at `d379b8f` (2026-10-01) **plus an uncommitted working tree**
  that is moving while I read it (section 1 below). Line numbers of
  `kern/slab.rs` are the working tree's (blob `d2a92c4`); the committed file
  has 23 more lines, so HEAD numbers differ by up to that. The diff touches
  only the tree plumbing, so every non-tree cite is the same text at HEAD.
- **x15** at `~/Codebases/x15`, `c08b3ff` (2019-08-19): `kern/kmem.c`,
  `vm/vm_page.{c,h}`, `arch/x86/machine/pmap.c`.
- **GNU Mach** C: `git show 97cae82e:kern/slab.c` and `kern/slab.h`
  (2025-05-07), `include/mach_debug/slab_info.h`.
- **Linux** `551c722f4` (2026-09-29): `mm/slab.h`, `mm/internal.h`.
- **Benchmark**: written for this note, outside the repo, in the session
  scratchpad (`slabbench/`, not committed, ephemeral). It links
  `crates/collections` by path at `d379b8f` (the crate has no uncommitted
  change). It runs in user space on an i7-11800H (L1d 48 KiB per core, L2
  1.25 MiB per core, L3 24 MiB), pinned to one core, release build, three
  runs that agree within 5 ns except the page-walk row at n = 65536 (58 to
  70 ns). Section 4 says what it does not model.
- **Memory notes** (`~/.claude/projects/.../memory/rb-tree-benchmark-findings.md`,
  not part of the repo): the tree's own descent and insert measurements and
  the benchmark pitfalls (a replayed key sequence is memorised by the branch
  predictor at small n; a reseed can insert duplicate keys). I used them to
  design the harness (fresh random picks every operation, 4M operations per
  size, no replay) and I re-measured nothing about the tree's internals.
- **Not checked**: any in-kernel measurement (no boot was run); the live
  buffer count of any cache in a running system; the sizes of the typed
  caches beyond those named in section 3; NetBSD, OpenBSD, FreeBSD, XNU and
  Zircon (the earlier note holds them, I did not re-read them).

## 0. The working tree already touches this question

`git diff` (HEAD `d379b8f`) shows an uncommitted migration of both trees from
`intrusive-collections` to `collections::rb_tree`: `kern/slab.rs`,
`vm/vm_map.rs`, `crates/kernel/Cargo.toml` (the `intrusive-collections` line
is deleted), `Cargo.lock`, and `DEBT.md` (the entries "The kernel's trees do
not use `collections::rb_tree`" and the `intrusive-collections` half of
"Third-party runtime crates" are deleted, and "`KmemCache` hot fields left
the first cache line" is added). It does not remove the slab's tree; it keeps
it and changes its type. Consequences for this question:

- **The `intrusive-collections` dependency is no longer a reason to remove
  the slab tree.** The migration consumes it (`DEBT.md:151-156` @ worktree).
  The earlier note's section 6 item 4 (page tagging "retires" the
  dependency) was written before this and no longer applies.
- **The earlier note's "No ordered `collections` shape" entry does not exist
  at HEAD either**; HEAD's entry is "The kernel's trees do not use
  `collections::rb_tree`" (`git show HEAD:DEBT.md`, line 165). The migration
  deletes it.
- **The migration made the slab tree cost more bytes.** `rb_tree` is a
  three-word head (ADR 0051, Consequences), so `RbTree<KmemSlabTreeAdapter>`
  is 24 bytes where the `intrusive-collections` head was 8
  (`slab.rs:239` @ worktree). Every `KmemCache` field after `active_slabs`
  moved up 16 bytes, which is the new DEBT entry (`DEBT.md:158-168`
  @ worktree; offsets `slab.rs:281-306`). Removing the tree is one way to
  close that entry (section 2).
- **The migration is the same shape as the tree's remaining need**: `insert_ptr`,
  `remove_ptr`, `upper_bound`, `clear` (`slab.rs:469, 691, 770-771, 796,
  896-897`). `vm_map.rs` uses all four too, so no `rb_tree` operation, test or
  benchmark row retires with the slab's use (inference from the diff).

## 1. The design to port, and what it takes

### 1.1 x15 today (`c08b3ff`)

- **Which caches register.** `kmem_cache_registration_required()` is
  `SLAB_EXTERNAL || VERIFY || slab_size != PAGE_SIZE` (`kern/kmem.c:642-648`);
  the one-page embedded slab is found by address arithmetic
  (`kmem_cache_buf_to_slab`, `:631-640`). The general caches are the same 13
  as ours, 32 bytes to 128 KiB (`:102-106`), so x15 registers up to 32 pages
  per slab.
- **How a slab registers.** `kmem_cache_register()` loops over the
  `slab_size` range, one page at a time; a slab larger than a page is
  "virtual" (`kmem_pagealloc_is_virtual`, `size > PAGE_SIZE`, `:240-243`) and
  each page goes through `pmap_kextract(va)` (a four-level software walk,
  `arch/x86/machine/pmap.c:1105-1134`, which stops at a large PTE), then
  `vm_page_lookup(pa)` (a scan of the zone array, `vm/vm_page.c:759-773`),
  asserts the page type and `priv == NULL` (`:676-678`), and calls
  `vm_page_set_priv(page, slab)` (`kern/kmem.c:651-682`;
  `vm/vm_page.h:143-155`). A direct-mapped slab uses `vm_page_direct_pa`
  instead of the walk.
- **When.** In `kmem_cache_grow()`, after the slab is created and linked, with
  the cache lock held (`:748-762`).
- **Lookup.** `kmem_cache_lookup()` redoes the walk for any address inside the
  slab, returns NULL if the page is not a kernel page, and asserts the address
  lies in the slab (`:684-722`). `kmem_cache_free_to_slab()` calls it under
  the cache lock when the arithmetic returns NULL (`:830-834`);
  `kmem_cache_free_verify()` calls it too (`:983`).
- **No unregister, because there is no destroy.** The only `kmem_pagefree`
  calls are on slab-create failure (`:322`) and on the large-allocation path
  of `kmem_free` (`:1377`); there is no reap. So `priv` is set once and the
  assert `priv == NULL` at register (`:678`) is never at risk. `vm_page_init`
  zeroes the struct once at boot (`vm/vm_page.c:166-177`). **Our slab does
  reap** (`slab_collect`, `slab.rs:1690-1726`), so x15 gives no precedent for
  the untag half.
- **Linux does the same split differently.** `virt_to_slab` is `page_slab(
  virt_to_page(addr))` (`mm/slab.h:208-211 @ 551c722f4`) and `page_slab()`
  goes through `compound_head()` (`:174-181`). The tail-to-head pointers are
  written by the page allocator when it builds the compound page
  (`prep_compound_tail`, `mm/internal.h:794-800`), not by SLUB, and SLUB slabs
  are physically contiguous, so `virt_to_page` is arithmetic (see the earlier
  note, 4.5). Neither x15's walk nor a per-slab registration is needed
  there. Our multi-page slabs are virtually contiguous (`pagealloc_virtual`,
  `slab.rs:1345-1358`), which is why the walk is needed.

### 1.2 What exists in our kernel

| Piece the design needs | Where | Reading |
|---|---|---|
| A tag field | `VmPage.priv_`, `vm/vm_page.rs:64` (offset 32, `:79`) | Written only by the slab (`slab.rs:1082, 1175`), read only by the slab (`:767`); zeroed once at boot (`vm_page.rs:773-780`); `vm_resident::grab`/`alloc_flags` never touch it. No other user (grep over `crates/kernel/src`). |
| Virtual to physical | `kvtophys`, `arch/x86_64/phys.rs:41-53`: `pmap_pte` on the kernel pmap, no lock | Generic over any kernel-pmap address (`pte_of`, `pmap.rs:837-852`), but it **does not check the last PTE's valid bit**: an unmapped address under a present table returns `addr & 0xfff`. `lookup_pa` then finds no page for it (segments start at 64 KiB or above, `biosmem.rs:37, 954-956`). |
| Physical to page | `vm_page::lookup_pa`, `vm/vm_page.rs:2241-2258` | A scan over at most `VM_PAGE_MAX_SEGS` = 4 segments (`:489`), no lock. Same as x15's. |
| A `vm_page` for every page a slab can sit on | `PHYSMEM` slabs: `vm_resident::grab` (`vm_resident.rs:945-961`). Virtual slabs: `kmem_alloc_wired` -> `alloc_pages` (`vm_kern.rs:161-166, 673-742`) takes pages from the kernel object with `alloc_flags`, wires them, `pmap_enter`s them. | Yes, both are real descriptors. Not checked: slabs from `kmem_alloc_aligned` with `align > PAGE_SIZE` go the same way (`vm_kern.rs:584-664`) and no cache asks for it. |
| Stable mapping for the slab's life | Wired kernel-object pages mapped at one address until `kmem_free` (`vm_kern.rs:243-249`). Kernel page tables are never freed: `pmap_collect` returns at once for the kernel pmap (`pmap.rs:2403-2407`). | So a lock-free walk of a live buffer's address cannot race a table free (inference). |
| Direct map is 4 KiB PTEs | `pmap.rs:1134-1150` builds it with 4 KiB entries | `pte_of` has no large-page case (`INTEL_PTE_PS` is used only by the boot headers), so none is needed (inference). |

**Callers of `kvtophys` today pass direct-map addresses only**: the
`USE_PAGE` sites (`slab.rs:761, 1073, 1172, 1368`) and `pmap.rs:589, 1413,
1425, 2016` act on `PHYSMEM` pages and pmap tables. No caller I found passes a
`kmem_alloc_wired` address, so **the walk on a `kernel_map` address has never
run in this kernel** (not checked at run time; the code is generic).

### 1.3 The observation that shrinks the port: one buffer per multi-page slab

The earlier note's sweep (1.3) is the key and I re-ran it with the working
tree's 72-byte `KmemSlab` and with the 48 bytes that remain once the 24-byte
link goes (script in the scratchpad, `sweep.py`, a transcription of
`compute_properties`, `slab.rs:511-583`):

- **No multi-page slab holds more than one buffer** for any buffer size from 8
  to 300000 in steps of 8 under default init flags, for either header size.
- **With `NOOFFSLAB` and no `PHYSMEM`**, buffer sizes 4032 to 4056 (72-byte
  header) or 4056 to 4072 (48-byte header) get a two-page slab holding two
  buffers. The only `NOOFFSLAB` caller outside `slab_init` is `vm_map_entry`,
  with `PHYSMEM` (`vm_map.rs:699`), and it is one page.
- **The buffer always starts in the slab's first page.** `addr = slab_buf +
  color` (`slab.rs:1111`) and `color_max >= PAGE_SIZE` is zeroed
  (`:547-549`), so `color < PAGE_SIZE`. This matters because multi-page slabs
  with a non-zero colour are the norm, not the exception: of 36988 swept
  sizes that need a multi-page slab, 36268 (72-byte header) or 36484
  (48-byte header) are embedded with a non-zero `color_max`, and 576 or 360
  are off-slab with one.
- **Inference**: since `kmem_cache_free` is always handed the buffer start,
  tagging **only the first page** is enough for every cache that exists, and
  `bufs_per_slab == 1` can be asserted in `compute_properties` for a
  multi-page slab. That turns "register N pages" (x15; N up to 32) into "tag
  one page" (what `USE_PAGE` already does, `slab.rs:1071-1083`), and the
  per-slab cost of section 3 item 2 vanishes. A cache that breaks the
  invariant (a `NOOFFSLAB` typed cache of 4032..4056 bytes) would need all
  pages tagged or a panic at init.

### 1.4 Sketch of the change (inference)

- `compute_properties`: every cache that is not `DIRECT` gets `USE_PAGE`; the
  `PHYSMEM`-must-be-one-page panic (`:555-566`) becomes "multi-page implies one
  buffer".
- `KmemSlab::create`: the tag moves out of the `SLAB_EXTERNAL` branch
  (`:1071-1083`) so embedded multi-page slabs are tagged too; `destroy` untags
  before `pagefree` for the same reason (`:1171-1186`): after
  `pagefree_virtual` the mapping is gone and `kvtophys` can no longer name the
  page.
- `alloc_from_slab`, `free_to_slab`, `free_verify`, the struct fields, the
  adapter and three `USE_TREE` assignments lose their tree code (about 21
  lines mention it, `grep` over `slab.rs`).
- The lookup can move **before** `lock()` in `free()` (it reads data that is
  stable while the buffer is live); the current `USE_PAGE` code does it under
  the lock (`:760-767`).

## 2. Benefits and problems

Sizes are mine and marked (B) for the benchmark of section 4, (A) for
arithmetic on `slab.rs` offsets, (C) for a count of lines.

| # | Effect | Direction | Size and evidence |
|---|---|---|---|
| B1 | `KmemCache` loses the 24-byte head; `flags` returns to offset 48 and `bufctl_dist` to 56 | benefit | Removes the cause named in `DEBT.md:158-168` "hot fields left the first cache line": `flags` 72 to 48, `bufctl_dist` 80 to 56 (A, `slab.rs:289-290` minus 24), both back on line 0, one better than HEAD, where the 8-byte `intrusive-collections` head left `flags` at 56 and pushed `bufctl_dist` to 64 (HEAD diff). `slab_size`, `bufs_per_slab`, `nr_objs`, `nr_free_slabs` and `ctor` start at 64 and later, so they stay on line 1 (A); whether that matters is the entry's own "or the line split is measured not to matter". |
| B2 | `KmemSlab` 72 to 48 bytes | benefit | Each off-slab slab record is 24 bytes smaller; the `kmem_slab` cache goes from 55 to 84 records per page ((4096-72)/72 and (4096-48)/48; A, `slab.rs:198, 1630`). An embedded cache gains header room: 32-byte buffers 125 to 126 per page, 64-byte 62 to 63, the 128 and 256 caches unchanged, 512 and up unchanged (sweep, 1.3). `host_slab_info` reports `bufs_per_slab`, so those two numbers change; the ABI suite checks only plausibility (`module-mach-debug-abi` strings: `bufs_per_slab > 0`, `slab_size` a page multiple). |
| B3 | Per free of a tree-cache buffer: lookup | benefit from n = 4, loss below | Floor 7 to 104 ns (n 1 to 65536) against walk plus `priv_` read 12.6 to 70 ns, loop overhead of about 7.7 ns included in both (B, table in section 4). Hot break-even between n = 2 and n = 4; at n = 1 the tree is faster by about 6 ns. |
| B4 | Per alloc/free pair of a one-buffer slab: tree edits | benefit | Every alloc of a one-buffer slab inserts (`slab.rs:687-692`, `nr_refs == 1`) and every free removes (`:793-797`). Floor+remove+insert 8.5 ns at n = 1, 38.5 at 16, 88 at 4096, 155 at 65536, against 12.6, 12.6, 23.8 and 70 ns for the tagged lookup, and **nothing** on alloc (B). Ahead from n = 2. |
| B5 | Lock hold time on a tree cache | benefit | The tagged lookup needs no cache lock, so the critical section of `free` shrinks to the list edits; the tree version holds the lock for floor+remove (or insert) (inference; B3, B4 give the removed work). |
| B6 | No tree on a path that has no per-CPU pool | benefit | `SLAB_USE_CPU_POOLS` is 0 (earlier note 1.2), so every free reaches this code; the five `kalloc` caches of 8 KiB and up take it for every packet buffer (`device/net_io.rs:1225-1240, 2342-2343`, earlier note 1.3). |
| B7 | Code, types, unsafe | benefit, small | `KmemSlab.tree_node`, `KmemSlabTreeAdapter`, `USE_TREE`, the `rb_tree` and `Bound` imports, the asserts at `slab.rs:202, 233-234, 239, 288`, one `unsafe { insert_ptr }` and one `remove_ptr` block (`:691, 796`), and the `free_verify` lock round trip. About 21 lines mention the tree (C). The tag path adds no new `unsafe` site: the write and read of `priv_` exist (`:1082, 767, 1175`). ADR 0005 surface: two blocks fewer, none more. |
| B8 | `free_verify` loses a race | benefit (dead code) | It drops the cache lock at `:899` and then dereferences the slab it found (`:901-914`), so a concurrent last-free could free the slab record under it. A tag lookup has no such window for a live buffer. `VERIFY` is dead (earlier note 1.1), so this is hygiene. |
| B9 | Divergence from GNU Mach is already the direction | neutral | The tree is not observable at the ABI; `host_slab_info.flags` carries the `KMEM_CF_*` bits (`slab.rs:1025`), including `USE_TREE` (0x08), whose meaning the header does not define (`include/mach_debug/slab_info.h @ 97cae82e` has no flag constants). ADR 0013 says nothing answers to the upstream layout, and `f6c5ce9` dropped the same kind of layout assert on `Thread`. The `slab.rs` offset asserts at `:197-206, 281-306` mirror the C record and have no reader outside the file (inference; not checked for the MIG seam). |
| P1 | Page-table walk on every free of a tree cache | problem, bounded | About 5 ns above a bare slab touch when everything is cached; four dependent loads plus a scan of at most 4 segments plus the `vm_page` line (B). **Not modelled: TLB misses**, and `vm_page` descriptors are 96 bytes (`vm_page.rs:42-44, 75-79`), 48 MB for the 2047 MB the ABI runner gives QEMU, so on a busy system the descriptor line is cold. |
| P2 | First run of `kvtophys` on a `kernel_map` address | problem | No caller does it today (1.2). The code is generic, but a bug (for instance the unchecked last PTE, below) would show as a wrong slab, not a panic. |
| P3 | A wrong or stale tag is silent corruption | problem | `free_to_slab` reads `priv_` and uses it unchecked (`slab.rs:767-786`): a NULL tag derefs, another cache's tag corrupts that cache. The tree path could only return this cache's own slabs. The C asserted `buf >= slab->addr` and `buf + buf_size <= trunc_page(slab->addr + slab_size)` (`kern/slab.c:1024-1026 @ 97cae82e`); the Rust has no such check on any path. x15 checks the page type and asserts the range (`kern/kmem.c:714-721`). Cheap guards: `slab.cache == self`, the range, `priv_` non-NULL. |
| P4 | Untag order and the reap path | problem, local | `destroy` must untag before `pagefree_virtual`, and `slab_collect` is also called from `kmem_alloc_aligned`'s retry (`vm_kern.rs:647`), i.e. from inside an allocation. Untagging reads only the kernel page tables, so it adds no lock (inference). A stale tag left on a freed page would be seen by the next slab that lands on it; x15 asserts `priv == NULL` at register for that (`kern/kmem.c:678`). |
| P5 | Interior-address lookup is lost for multi-page slabs | problem, unused | Only `free_verify` asks (`:893-977`), and `VERIFY` is passed by no caller (earlier note 1.1). With first-page tags a verify cache of one-page slabs still works (`DIRECT` or `USE_PAGE` give the slab for any address in the page), and a multi-page verify cache would reject a non-first-page address as `Invalid`, which is what it should do for a buffer start. The debugger consumer is gone (ADR 0021). |
| P6 | Tag cost at create/destroy | problem, small | With the one-buffer invariant: one tag and one untag per slab, 15 ns together hot (B, section 4). Even the literal x15 version (all pages) is 202 ns for a 32-page slab (B), against `alloc_pages`, which per page takes the object lock, `alloc_flags`, the queue lock, `wire`, `pmap_enter` and a second object lock (`vm_kern.rs:684-741`). |
| P7 | The hardware-dependent members of the tree set | problem for sizing | `i386_fpsave_state` is `offset_of(save) + xfp_save_size()` bytes (`arch/x86_64/fpu.rs:1055-1058`), and XCR0 is set to every state component the CPU reports (`:963-967`). Inference: on a CPU with a large XSAVE area (AMX state alone is several KiB) that cache has multi-page buffers and every thread's FP save area allocates from the tree path; under the ABI runner's `-cpu core2duo-v1` there is probably no XSAVE (inference from the model name; the fixed struct is 640 bytes, `fpu.rs:243`), so the test suites would not exercise it. The XSAVE size on real hardware was not measured. `i386_task_iopb` is 8192 bytes (`machine_task.rs:44, 102`), also a tree cache. |
| P8 | No automatic test of `slab.rs` | problem | `host-tests` mirrors twelve files, none of them `slab.rs` (`crates/host-tests/src/**/mod.rs`); ADR 0024 puts `kernel` under "proven by booting": the ABI suite (only `host_slab_info` plausibility) and the Hurd smoke. A wrong tag would surface only as a boot or smoke failure. |
| P9 | Hardening is optional and so can be dropped by accident | problem | The tree version of `free_to_slab` has no range check either, so the guards of P3 are an addition, not a loss; a reviewer should require them (inference). |

## 3. Alternatives that the table makes visible

Beyond the earlier note's four options (keep; page tagging; hash; drop only
`VERIFY`):

- **Tag first page only (recommended in section 5, inference).** Needs the
  one-buffer assertion of 1.3.
- **Tag every page (x15 literal).** Costs 3.2 ns per page per tag (B) and a
  loop on create and destroy; needed only for a cache the sweep says does not
  exist. It is the form that supports interior-address lookup.
- **Stop slab-caching the large kalloc sizes.** `kalloc` already sends sizes
  above 128 KiB straight to `pagealloc_virtual` (`slab.rs:1514-1518, 1543-1548`),
  so the five tree caches (8 KiB to 128 KiB) hold only one-buffer slabs that
  are a cache of virtual allocations. Setting `KALLOC_NR_CACHES` to 9 would
  delete the tree *and* the tag, at the price of a `kernel_map` insert and a
  page grab per packet buffer instead of a free-list hit
  (`kmem_alloc_wired`, `vm_kern.rs:135-157`; `kmem_free` -> `VmMap::remove`),
  and the slab no longer retains and reaps them. `IOPB_CACHE` and a
  multi-page `ifps` would need another answer. Not measured; this is a
  performance regression risk on the network path.
- **Physically contiguous multi-page slabs** (Linux, x15's direct-map slabs):
  `va - VM_MIN_KERNEL_ADDRESS` replaces the walk. GNU Mach moved these slabs
  to kernel virtual memory on purpose (`e3cdb6f6`, 2016-02-20, "large
  objects are rare... compatible with kernel virtual memory", earlier note
  2.1), and `pagealloc_physmem` ignores its size argument today
  (`slab.rs:1322`). Not recommended; it reverses a decision with a stated
  reason.
- **Hash:** as the earlier note, no.

## 4. Closing the earlier note's section 6 item 5

| Gap | Result |
|---|---|
| Lookup cost of the page walk against tree depth | Measured in a model, below. |
| How many live buffers the tree caches hold (the tree's n) | **Not checked** (no boot, no `host_slab_info` dump). Bounds from the code: the `kalloc_8192` cache holds the packet buffers, whose number is capped by `net_kmsg_max` (`want_more`, `net_io.rs:1207-1215`), which starts at `net_queue_free_min` = 3 (`:1117, 2347-2350`) and is adjusted by each receive filter's queue limit (decrement at `:2262`; the increment side I did not find, not checked), so probably small (inference). Large IPC messages use `ikm_alloc` -> `kalloc` for every size (`ipc/ipc_kmsg.rs:1181-1184`), so any in-flight message above `PAGE_SIZE - IKM_OVERHEAD` also lands in a tree cache and is bounded only by queue limits. The benchmark covers n = 1 to 65536. |
| Sizes of the typed caches beyond `kalloc` | Partly. Known above one page: `i386_task_iopb`, 8192 bytes (`machine_task.rs:44, 102`); `i386_fpsave_state` on large-XSAVE CPUs (P7). Small: `Pcb` 488 (`pcb.rs:393`), `Task` 336 (`task.rs:133`), `VmMapEntry` 136 (`vm_map.rs:171`), `io_buf_ptr_inband` 128 and `io_req` 2048 (`ds_routines.rs:110, 116`). The ABI log reports 51 caches (`target/abi-logs/test-mach-debug-abi.log:58`), 13 of them `kalloc`; I did not obtain per-cache sizes (the test prints only the count). The remaining ~35 typed sizes: not checked. |
| `vm_page` reuse rules for `kernel_map` pages | `priv_` is never reset by the page allocator, release or free (it is memset once in `init_pa`, `vm_page.rs:773-780`); `release` and `alloc_flags` do not write it. A page freed with a tag keeps the tag, which is why untag-before-free is a hard rule (P4). The kernel pages are VM_PT_KERNEL either way (`vm_resident.rs:703, 947`), so the page type does not tell a slab page from another kernel page (x15 uses two types for that, `kern/kmem.c:676-677`). |
| How `kmem_alloc_wired` pages interact with `lookup_pa` | They are ordinary managed descriptors from the highmem or directmap segment (`vm_kern.rs:165`, flag `VM_PAGE_HIGHMEM`), so `lookup_pa(kvtophys(va))` finds them; the walk reads the kernel pmap tables, which are never collected (`pmap.rs:2405`). First runtime exercise is P2. |
| `pmap_extract` lock order | Not needed: `kvtophys` takes no lock, `pmap_extract` takes the pmap lock at `splvm` (`pmap.rs:2368-2385`) and would be a lock-order question under the cache lock; the tag path uses `kvtophys` and never reaches it. |

### The benchmark

`slabbench` models one-buffer slabs at stride 8192 in a kernel-map-like
span, a four-level table (PML4 to PT, each table page-aligned), two segments
(directmap 1 MiB to 896 MiB, highmem to 2 GiB), 96-byte `vm_page` descriptors
for 2 GiB (48 MB), physical pages drawn at random from the highmem segment,
slab records packed densely (72 bytes for the tree variant, 48 for the tagged
one). Each operation picks a random live slab and its result feeds the next
pick, so the loads are a dependent chain, not overlapped. "Control" is the
pick plus one slab touch, so subtract about 7.7 ns (8.9 at 4096, 16 at 65536)
from the others to read the lookup alone. Times in ns per operation, run 3
of 3 (runs 1 and 2 agree within 2 ns):

| n live slabs | control | tree floor | tree floor+remove+insert | page walk + `priv_` |
|---:|---:|---:|---:|---:|
| 1 | 7.7 | 6.9 | 8.5 | 12.6 |
| 2 | 7.7 | 11.1 | 16.1 | 12.5 |
| 4 | 7.7 | 12.9 | 23.9 | 12.5 |
| 8 | 7.6 | 12.8 | 30.5 | 12.7 |
| 16 | 7.7 | 17.4 | 38.5 | 12.6 |
| 64 | 7.7 | 20.2 | 46.3 | 13.0 |
| 256 | 7.8 | 24.4 | 54.3 | 13.9 |
| 1024 | 7.8 | 31.2 | 68.6 | 17.6 |
| 4096 | 8.9 | 43.7 | 88.3 | 23.8 |
| 65536 | 16.0 | 103.7 | 155.2 | 69.6 |

Tag and untag of every page of a slab (the x15 shape), hot: 1 page 15 ns,
2 pages 24 ns, 8 pages 64 ns, 32 pages 202 ns per slab (3.2 to 7.4 ns per
page-tag).

Reading (inference): the page walk is flat in n (4 dependent loads, a segment
scan and one descriptor line), the tree grows with log n and with cache
misses on the nodes. Per alloc/free pair the tagged design is ahead from n =
2, by 3 to 4 times as measured between n = 16 and n = 4096 (5 to 6 times
with the loop overhead subtracted); per free alone it is ahead from n = 4,
by 1.4 times at n = 16 and 1.8 times at n = 4096. In absolute terms the saving is tens of nanoseconds per
buffer, against a packet or a message that costs microseconds, so the gain is
real but not large. What it does **not** model: TLB misses on the page-table
pages and the 48 MB descriptor array (the kernel walks tables through the
direct map), interrupts, other CPUs' cache traffic on the cache lock, and any
in-kernel instruction mix. The tree side uses the `d379b8f` `rb_tree`
(cached ends, ADR 0051), whose ascending-insert and floor behaviour the
memory notes describe; my harness re-inserts a removed slab at its own key, a
random position, which is neither the ascending case the cached ends speed
up nor a worst case; the real order of slab addresses and frees is not
measured. A repeat inside a booted
kernel with `rdtsc` around `kfree` of a `kalloc_8192` buffer would settle it
(section 5, item 3).

## 5. Recommendation (inference), staged plan, and what to verify

**Verdict.** Removing the tree is feasible, small, and closes nothing that an
ADR demands; its benefits are real but modest (tens of ns per large-buffer
free, 24 bytes per slab, the cache-line DEBT entry, about 21 lines, two
`unsafe` blocks). Its risks are a first-ever use of `kvtophys` on a
`kernel_map` address, a lookup with no cross-check, and no automatic test.
The 2016 GNU Mach commit `b325f426`, x15 `80f72c0`, and Linux, FreeBSD and
XNU all took this direction (earlier note 5); OpenBSD and NetBSD still use a
tree. The tree is not wrong, it is just the more expensive of two workable
designs. It is also the cheaper one to keep **if the slab is about to be
rewritten**: `DEBT.md:69-74` says the slab is derived from GNU Mach and must
become a non-derived rewrite (ADR 0017: designed from Bonwick, no derived
code), so the better home for this change is the rewrite's design, not a
patch on the translation.

**Staged plan.**

1. **Land the in-flight migration** (section 0) as it is: it consumes
   `intrusive-collections` and the "trees do not use `rb_tree`" entry, and it
   keeps the slab tree for now.
2. **Verify** (list below). One boot instrumented, no merge.
3. **One change** that (a) makes every non-`DIRECT` cache `USE_PAGE` with the
   first-page tag, asserting "multi-page implies one buffer" in
   `compute_properties`; (b) moves tag/untag out of the `SLAB_EXTERNAL` branch
   and untags before `pagefree`; (c) adds the three guards of P3; (d) hoists
   the lookup out of the cache lock; (e) deletes `tree_node`, `active_slabs`,
   `USE_TREE`, the adapter and the asserts, and decides `VERIFY`'s fate
   (either `free_verify` becomes the tag lookup plus an exact check, or
   `VERIFY` is deleted with its dead call sites); (f) deletes the DEBT entry
   "`KmemCache` hot fields left the first cache line" or rewrites it to the
   remaining `slab_size`..`ctor` line-1 spill, and fixes the `KmemCache` doc
   comment (`slab.rs:249-253`). Per ADR 0012 the change closes a gap and
   deletes its entry; it opens none unless it leaves `VERIFY` half-done.
4. **Fold into the slab rewrite**, if that goes ahead: the rewrite starts
   from this lookup, not from the tree.

**ADR or not.** No ADR currently governs how a slab finds its buffer, so no
ADR is needed to *do* this; one is worth writing only if the rule should bind
the rewrite ("a buffer finds its slab through the page descriptor, never an
ordered map"), as a paragraph in ADR 0017 or a new ADR. Whether to is the
maintainer's call. The change is one commit and one `DEBT.md` edit, not two.

**Verify before acting (all not done here).**

1. Boot once with a temporary print of `host_slab_info` per cache after the
   Hurd smoke: n (`nr_objs`) and `slab_size` for every cache above one page,
   including `i386_task_iopb` and `i386_fpsave_state`.
2. In `KmemSlab::create` for a virtual slab, check at runtime that
   `lookup_pa(kvtophys(slab_buf))` is `Some`, that its `phys_addr` equals the
   `kvtophys` result's page, and that `priv_` is NULL, on QEMU `-cpu
   core2duo-v1` and a CPU with AVX-512 (first use of P2).
3. Time `kfree` of a `kalloc_8192` buffer with `rdtsc`, tree against tag, in
   the same boot (closes the benchmark's TLB and descriptor-line gap).
4. Confirm the assert "multi-page implies one buffer" holds at every
   `kmem_cache_init` of a boot (it holds for the sizes in section 1.3; the
   typed sizes beyond those named here are not checked).
5. Run the gates of ADR 0024: ABI suite and Hurd smoke on `dev` and `release`;
   `slab.rs` has no host test, so add a boot-time self-test or a kernel-side
   check if the maintainer wants coverage beyond a boot.
