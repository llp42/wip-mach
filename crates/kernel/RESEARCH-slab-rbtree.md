# Slab buffer lookup: why the rbtree?

Why does `KmemCache.active_slabs` in `kern/slab.rs` hold a red-black tree,
what design evidence supports it, and do FreeBSD, NetBSD, DragonFly BSD,
OpenBSD, Linux and Zircon map a freed buffer to its slab the same way? Facts
carry `path:line @ revision` (or a paper section). Statements that are my
reading rather than a quote say "inference"; things I did not or could not
reach say "not checked". The note is evidence for the DEBT.md entry "No
ordered `collections` shape"; it changes no code and no ADR.

## Sources and their limits

- **wip-mach Rust kernel** at `66ed047` (2026-09-27). `HEAD` moved from
  `cd872ba` to `66ed047` while I worked; I read the working tree, whose
  `kern/slab.rs` (uncommitted at `cd872ba`) is what `66ed047` committed, and
  the cited lines are unchanged. Primary source for section 1.
- **GNU Mach at ~/Codebases/gnumach** (`daaf5391`, 2026-09-26, a fork of
  upstream `v1.8+git20260224`; the working tree has no `.c` files). For the
  C behaviour I read `git show 97cae82e:kern/slab.c` and `kern/slab.h`
  (2025-05-07, the last full-C snapshot, same approach as
  `crates/kmem/RESEARCH.md`). The only change to `kern/slab.{c,h}` between
  `97cae82e` and the fork's Rust-port commits (`a1e28c7d` and later,
  2026-09-18 on) is `da3b48eb` (2026-03-01, 11 deleted lines, none about the
  tree), so `97cae82e` is the C the Rust port started from. History back to
  the import is `7bc54a62` (2011-12-13), read with `git show REV:path` and
  `git log -S`.
- **Design papers**, fetched from the USENIX legacy archive and read as
  text: Bonwick, "The Slab Allocator: An Object-Caching Kernel Memory
  Allocator", USENIX Summer 1994
  (`usenix.org/legacy/publications/library/proceedings/bos94/full_papers/bonwick.a`);
  Bonwick and Adams, "Magazines and Vmem", USENIX 2001
  (`usenix.org/legacy/publications/library/proceedings/usenix01/full_papers/bonwick/bonwick_html/index.html`).
  Cited by section; line numbers of my local copies mean nothing.
- **illumos-gate** `7e802e8` (2026-09-09), shallow and sparse clone
  (`usr/src/uts/common/{os,sys}`).
- **x15** at `~/Codebases/x15`, `c08b3ff` (2019-08-19), including its git
  history for `kern/kmem.c`.
- **FreeBSD** `1e8708d` (2026-09-23), `sys/vm` only, shallow sparse clone of
  github.com/freebsd/freebsd-src.
- **NetBSD** at `~/Codebases/netbsd`, `cc2030c15` (2026-09-29).
- **OpenBSD** `ebc3947` (2026-09-30), `sys/{kern,sys,uvm}`, shallow sparse
  clone of github.com/openbsd/src.
- **DragonFly BSD** at `~/Codebases/DragonFlyBSD`, `d1f4fb94` (2026-09-26).
- **Linux** at `~/Codebases/linux`, `551c722f4` (2026-09-29), `Makefile`
  says 7.3.0-rc5.
- **Zircon** in Fuchsia `1a0ae36a` (2026-09-30), shallow `--filter=tree:0`
  clone of fuchsia.googlesource.com/fuchsia, sparse checkout of
  `zircon/kernel/{lib,vm}` and `zircon/system/ulib/fbl`.
- **XNU** at `~/Codebases/xnu`, `xnu-12377.1.9` (`f6217f891`).
- **Mailing lists**: bug-hurd archive at lists.gnu.org, 2011-11 (messages
  140, 145, 146), 2011-12 (23, 46), 2016-01 (5, 6, 7, 14), 2016-02 (118).
  None of them mentions the tree (section 2.1).
- **Not checked**: the pre-GNU-Mach origin of the slab code (the 2011-11
  thread names only the `slabinfo` tool's repository), debbugs, the
  debian-hurd list, Linux `mm/slab.c` (SLAB, removed from mainline; my clone's
  history did not show the removal, so I did not use it), the history of
  `RegionList` in Zircon, the history of the `phtree` code in NetBSD and
  OpenBSD and of the hash-vs-`vtoslab` split in UMA, and any measurement of
  lookup cost.

Four starting assumptions turned out wrong or incomplete, listed here so
they are not missed:

1. **Zircon has slab allocators in the kernel** (`lib/object_cache` and
   `PageSlabAllocator`); it is the general heap that is not slab-based.
2. **Zircon's VMAR children are no longer a `fbl::WAVLTree`**: at `1a0ae36a`
   they are a `btree::BTree`. `WAVLTree` is still used elsewhere.
3. **NetBSD's `pr_phtree` is a splay tree**, not a red-black tree and not a
   hash, although a comment in the same file still says "hash table".
4. **In our build the `VERIFY` path that needs a floor lookup is dead**; the
   tree is reached only by caches with slabs larger than a page (1.3).

## 1. What our slab does with the tree

The claims I started from hold. Checked against `crates/kernel/src/kern/slab.rs @ 66ed047`:

- A slab carries the link (`tree_node: RBTreeLink`, `:190`), and a cache
  holds the head (`active_slabs: RBTree<KmemSlabTreeAdapter>`, `:280`; built
  at `:445`, reset with `fast_clear()` at `:488`). The key is the slab's
  buffer base `KmemSlab.addr` (`:223-228`), which includes the colour offset.
- Insert: when a buffer is handed out and `nr_refs` becomes 1, if `USE_TREE`
  is set (`:706-712`). Remove: when `nr_refs` returns to 0 (`:813-820`). So the
  tree holds only slabs with at least one live buffer.
- `free_to_slab` (`:775-800`) finds the slab three ways: `DIRECT` is address
  arithmetic (`slab_from_direct`, `:1250`), `USE_PAGE` reads `priv_` of the
  `vm_page` at `lookup_pa(kvtophys(buf))` (`:780-787`), and anything else is
  `active_slabs.upper_bound(Bound::Included(&addr))` (`:789-792`), the
  greatest slab base at or below `addr`. `free_verify` uses the same floor
  lookup (`:915-920`).
- The flags come from `compute_properties` (`:574-601`): `VERIFY` implies
  `USE_TREE`; an off-slab cache gets `USE_PAGE` if `PHYSMEM` and `USE_TREE`
  otherwise; an embedded cache gets `DIRECT` if `slab_size == PAGE_SIZE` and
  `USE_TREE` otherwise. Since `PHYSMEM` with a multi-page slab panics
  (`:579-584`), the tree is used exactly for multi-page slabs (and
  `VERIFY`).

The starting conclusion, "the tree is the fallback buffer to slab map", is
confirmed against the C (section 2.2). Three corrections and additions:

### 1.1 `VERIFY` is dead code in our build

`CacheInitFlags::VERIFY` is defined (`slab.rs:90`) and read (`:477`), but no
call site in `crates/` passes it (`grep -rn 'InitFlags::VERIFY' crates/`
finds only `:477`). The C had the same shape: `SLAB_VERIFY` was
hard-coded to 0 (`configfrag.ac:127 @ 97cae82e`, later deleted by
`a1e28c7d`), and `KMEM_CACHE_VERIFY` appears only in its own definition and
test (`kern/slab.h:203`, `kern/slab.c:826 @ 97cae82e`). The second C
consumer of a floor lookup, the debugger command `db_whatis_slab`
(`kern/slab.c:1504-1529 @ 97cae82e`, added by `42bdb9e4` in 2023), sat
under `#if MACH_KDB` (`:1496`) and went with `9b51c5b4`. So today nothing
asks the tree a question about an interior address that is not a buffer
start. Whether we keep that capability is a choice, not a constraint.

### 1.2 No per-CPU pools, so every free reaches the slab layer

`SLAB_USE_CPU_POOLS` is 0 (`configfrag.ac:130`, `kern/slab.h:154 @ 97cae82e`:
"Currently, SLAB_USE_CPU_POOLS is not defined"), and the Rust has no pool
layer (the only `cpu_pool` hit is `info.cpu_pool_size = 0`, `slab.rs:1048`).
Every `kfree` of a tree cache therefore takes the cache lock and does an
O(log n) lookup, and the first and last buffer of a slab also pay an insert
and a remove under that lock.

### 1.3 Which caches use the tree, and they are not rare

- **Inference (derived by running the `compute_properties` loop, not read
  off a table)**: with `PAGE_SIZE` 4096 and `size_of::<KmemSlab>()` 72
  (asserted at `slab.rs:197`), the 13 `kalloc` caches (`KALLOC_FIRST_SHIFT`
  5, `KALLOC_NR_CACHES` 13, `slab.rs:51-55`) come out as:

  | cache sizes | slab layout | lookup |
  |---|---|---|
  | 32, 64, 128, 256 | embedded, one page | `DIRECT` |
  | 512, 1024, 2048, 4096 | off-slab, one page | `USE_PAGE` |
  | 8192 to 131072 (5 caches) | off-slab, `slab_size == buf_size`, one buffer | `USE_TREE` |

- **Inference**: the same sweep over every buffer size from 8 to 300000 in
  steps of 8 found **no** multi-page slab holding more than one buffer under
  default init flags. (With `NOOFFSLAB` and no `PHYSMEM`, buffer sizes 4032
  to 4056 would get two; no caller asks for that combination, and
  `vm_map.rs:729` pairs `NOOFFSLAB` with `PHYSMEM`.) In a one-buffer slab
  the buffer starts at `slab.addr`, so for every non-`VERIFY` tree cache the
  floor lookup always lands on an exact key.
- The tree is on a real data path. A received network packet is
  `kalloc(NET_KMSG_SIZE)` where `size_of::<NetRcvMsg>()` is 4216
  (`device/net_io.rs:1068`), rounded to a page multiple
  (`net_io.rs:2342-2343`), so 8192 bytes: the `kalloc_8192` cache
  (`net_io.rs:1227`, freed at `:1240`). Inference: any IPC message whose body
  exceeds `PAGE_SIZE - IKM_OVERHEAD` (`ipc/ipc_kmsg.rs:48`, `:1181-1182`,
  `:1289`) also lands in a tree cache. Not checked: the typed
  (`KmemCache`) caches other than these; I did not compute their
  `size_of`s, so a typed cache above about 4 KiB would also use the tree.

## 2. Why GNU Mach does (C evidence and commit history)

### 2.1 Where the design is written down

The reason is stated once, in the file's own header comment, and it has been
there since the import. `kern/slab.c:54-64 @ 97cae82e`:

> The per-cache self-scaling hash table for buffer-to-bufctl conversion,
> described in 3.2.3 "Slab Layout for Large Objects", has been replaced by
> a red-black tree storing slabs, sorted by address. [...] Unlike a hash
> table, a BST provides a "lookup nearest" operation, so obtaining the slab
> data [...] from a buffer address simply consists of a "lookup nearest
> towards 0" tree search. Finally, a self-balancing tree is a true
> self-scaling data structure, whereas a hash table requires periodic
> maintenance and complete resizing, which is expensive. The only drawback
> is that releasing a buffer to the slab layer takes logarithmic time
> instead of constant time.

The 2011 text (`7bc54a62:kern/slab.c:31-46`) had two more reasons that
`e3cdb6f6` (2016-02-20) deleted: "Storing slabs instead of buffers also
considerably reduces the number of elements to retain", and that the
logarithmic cost is acceptable "because the CPU pool layer services most
requests, avoiding many accesses to the slab layer". The second no longer
holds (1.2).

Timeline, from `git log -S'rbtree' -- kern/slab.c` and the messages:

| Commit | Date | Relevance |
|---|---|---|
| `7bc54a62` "Import the slab allocator" | 2011-12-13 | The tree is there from the first commit. `KMEM_CF_DIRECT` meant "embedded and `slab_size == PAGE_SIZE`" (`:744`), `kmem_slab_use_tree()` was `!DIRECT \|\| VERIFY` (`:525-527`). So every off-slab cache (512 B to 4 KiB buffers included) and every multi-page cache used the tree. |
| `d25bd66f` "Import utility files" | 2011-12-17 | Adds `kern/rbtree.{c,h}`, `rbtree_i.h`, `list.h`. (`7bc54a62` was authored 2011-12-13 but committed 2011-12-17 22:12, six minutes after this one, so the slab import was rebased onto the rbtree import.) |
| `5e9f6f52` | 2016-02-02 | Slabs now come straight from the physical allocator, power-of-two sized. |
| `0b07275f` | 2016-02-06 | "use the lowest possible size for its slabs"; inference: slab sizes are then any page multiple (the loop adds `PAGE_SIZE`, `kern/slab.c:770 @ 97cae82e`), not powers of two. |
| `e3cdb6f6` | 2016-02-20 | Larger-than-page slabs go back to kernel virtual memory to avoid fragmentation failures: "large objects are rare, and their use infrequent, which is compatible with the use of kernel virtual memory". Trims the header comment. |
| `b325f426` "Optimize slab lookup on the free path" | 2016-02-22 | "Caches that use external slab data but allocate slabs from the direct physical mapping can look up slab data in constant time by associating the slab data directly with the underlying page." Adds `vm_page_{set,get}_priv` (`vm/vm_page.h:386-397 @ 97cae82e`) and leaves the tree for virtual-memory slabs only. |

Mailing lists: Braun's announcement (bug-hurd 2011-12 msg00023, 2011-12-17)
and Thibault's test report (msg00046) say nothing about lookup. The
2011-11 thread (msg00140, 145, 146) gives his stated merits of the slab
allocator over the zone allocator: reduced fragmentation, clean maintainable
code, debugging features. No thread I
reached cites or debates the tree; the header comment and the commit messages
above are the whole record. `doc/` has no text on the slab (`git grep -i slab
97cae82e -- doc` is empty) and `NEWS` mentions the slab twice (`:39`, `:98`),
neither about lookup. The `NEWS` line about a red-black tree (`:9`) is about
`vm_map`, not the slab.

### 2.2 The requirement, from the C

1. **Which frees carry no slab hint.** `kmem_cache_free(cache, obj)`
   (`kern/slab.c:1215`) knows the cache and nothing else; `kfree(data, size)`
   (`:1427-1447`) derives the cache from `size` (`kalloc_get_index`) and calls
   `kmem_cache_free`. Both reach `kmem_cache_free_to_slab(cache, buf)`
   (`:999`), which must recover the `kmem_slab` (free list, `nr_refs`,
   list links) from `buf`. The search space is one cache's slabs
   (`cache->active_slabs`, per cache), not the whole heap. There is no
   `free(ptr)` without cache or size in this allocator. That is a difference
   from Linux `kfree(ptr)` (4.5) and DragonFly `kfree(ptr, type)` (4.3), which
   are given neither cache nor size and so need a map valid for the whole
   heap.
2. **What makes `DIRECT` unavailable.** `DIRECT` computes the slab trailer as
   the end of the `slab_size`-aligned block holding the buffer
   (`P2END(buf, slab_size) - 1`, `:1004-1007`, asserting
   `slab_size == PAGE_SIZE`). That only works for one-page slabs.
   Bonwick says the same about multi-page slabs: "with large (multi-page)
   slabs we lose the ability to determine the slab data address from the
   buffer address" (§3.2.3). Inference: after `0b07275f` a multi-page
   `slab_size` is the smallest page multiple that fits, not a power of two, and
   `kmem_pagealloc_virtual` (`:397-414`) only asks for page alignment
   (`kmem_alloc_wired`) or `align`-alignment (`kmem_alloc_aligned`, where
   `align` is the buffer alignment, not `slab_size`), so a buffer address
   does not reveal where the slab ends.
3. **What makes `USE_PAGE` unavailable.** `USE_PAGE` stores the slab pointer
   in the `priv` field of the `vm_page` under the slab's first page
   (`:492-497`, read back at `:1008-1013`). It is set only for `PHYSMEM`
   caches, which are forced to one page (`:781-792`, panic otherwise), and the
   commit that added it restricts it to "the direct physical mapping"
   (`b325f426`). Multi-page slabs come from `kernel_map`
   (`kmem_pagealloc_virtual`), and the tag goes on the first page only.
   Nothing in the C tags the other pages of a virtual slab; x15 does (3.4).
4. **Which caches set `USE_TREE`** (`:794-807`): `VERIFY` caches, off-slab
   caches that are not `PHYSMEM`, and embedded caches whose `slab_size` is not
   one page. In the shipped configuration that is the `kalloc` caches of 8 KiB
   and up plus any other cache with such buffers (1.3).
5. **Why a floor.** The key is `slab->addr` (`kmem_slab_cmp_lookup`,
   `:583-596`) and a freed buffer is the slab base plus a multiple of
   `buf_size`; the comparison has to find the last slab base at or below the
   buffer. `rbtree_lookup_nearest(..., RBTREE_LEFT)` is that
   (`:1018-1019`; `kern/rbtree.h:137-140` defines it as a lookup that, on a
   miss, returns the neighbour). The range check follows
   (`:1024-1027`). The verify path needs it more: it is handed a possibly bogus
   address, finds the candidate slab by floor, then rejects it if it is past
   `slabend` or not on a `buf_size` boundary (`:1163-1178`). Bonwick's
   debug section has the same idea for the hash (§6.2, quoted in 3.1), and
   `KMEM_CF_VERIFY` implies `USE_TREE` (`:208-209`).
   For the non-`VERIFY` tree caches the floor is not needed (1.3, inference).

## 3. Design literature (Bonwick 1994/2001, illumos, x15)

### 3.1 Bonwick 1994

- §3.2.2 "Slab Layout for Small Objects" (objects under 1/8 page): one page,
  slab data at its end, so the slab is found by address arithmetic. This is
  GNU Mach's `DIRECT`.
- §3.2.3 "Slab Layout for Large Objects": "with large (multi-page) slabs we
  lose the ability to determine the slab data address from the buffer
  address"; slab and bufctl structures come from their own caches; "A
  per-cache self-scaling hash table provides buffer-to-bufctl conversion."
  The hash is **confirmed**. It maps each *allocated buffer* (exact key) to
  its bufctl, whose back-pointer names the slab (§3.2.1).
- §6.2 "Freed-Address Verification": "if the hash lookup in
  kmem_cache_free() fails, then the caller must be attempting to free a bogus
  address", and verification of all frees is obtained by setting the
  large-object threshold to zero. GNU Mach's "`VERIFY` implies `USE_TREE`"
  is this design with a tree in place of the hash.

What GNU Mach changed: bufctls live inside the buffers (`kern/slab.h:92-100`),
so only the slab has to be found, and the map has one element per *active
slab* instead of one per allocated buffer. That is what the dropped sentence
about "the number of elements to retain" meant.

### 3.2 Bonwick and Adams 2001

The paper keeps the slab layer and adds magazines and vmem. A text search
finds no `bufctl` and no slab-side lookup structure. Its hash is in vmem:
"boundary tags for allocated segments [...] are also linked into an
allocated-segment hash table" (§4.4, Figure 4.4), used so that
`vmem_free()` "looks up the segment's boundary tag in the allocated-segment
hash table" in constant time, with a free sanity check (§4.4.2). Footnote 4
names "a size-sorted tree" of free segments only as an alternative that "could
be used". So the 2001 paper supports the hash for exact-address frees and
says nothing in favour of an ordered map for slabs.

### 3.3 illumos `kmem.c`: the hash, confirmed

`usr/src/uts/common/os/kmem.c @ 7e802e8`:

- A cache gets `KMF_HASH` unless its chunk is smaller than
  `vm_quantum / KMEM_VOID_FRACTION` (1/8 page, `sys/kmem_impl.h:100`) or it
  is created `KMC_NOHASH`; `KMC_NOTOUCH` and audit caches, and the firewall
  arena, always get it (`kmem.c:3880-3925`).
- Allocation links the bufctl into a chain at
  `KMEM_HASH(cp, buf)` (`kmem.c:1654-1662`); free walks that chain for
  `bcp->bc_addr == buf` and takes `sp = bcp->bc_slab` (`:1786-1800`). The
  bucket is `(buf >> cache_hash_shift) & cache_hash_mask`
  (`sys/kmem_impl.h:236-240`). The key is exact, never a floor.
- The table is resized by a periodic task (`kmem_hash_rescale`,
  `kmem.c:3325-3395`, triggered when `cache_buftotal` leaves the range
  `[mask/2, 2*mask]`). This is the "periodic maintenance and complete
  resizing" that the GNU Mach comment avoids.
- Small-object caches use `KMEM_SLAB(cp, buf)`, `P2END(buf, slabsize) - 1`
  (`sys/kmem_impl.h:174-175`), the same arithmetic as `DIRECT`.

### 3.4 x15: the same author dropped the tree in 2012

`~/Codebases/x15 @ c08b3ff`, `kern/kmem.c`:

- Its header comment keeps the paragraph but says the hash "has been replaced
  with a constant time buffer-to-slab lookup that relies on the VM system"
  (`:26-28`).
- `80f72c0` (2012-12-07) "kern/kmem: rework buffer-to-slab lookup": "Instead
  of using a red-black tree, rely on the VM system to store kmem specific
  private data." The diff deletes `kmem_slab_cmp_lookup/insert`, the
  `rbtree_node`, and `rbtree_init`. Its new comment names the price: the
  method "needs to walk the low level page tables, but it's expected that
  these have already been cached by the CPU".
- Today's code: a one-page embedded slab is found by
  `vm_page_end(buf) - 1` (`:631-640`); every other slab is **registered in
  every one of its pages**: `kmem_cache_register()` loops over the
  `slab_size` range, turns each address into a physical address
  (`pmap_kextract` for virtual slabs, `vm_page_direct_pa` for direct-map
  ones) and calls `vm_page_set_priv(page, slab)` (`:650-682`).
  `kmem_cache_lookup()` does the reverse for any address inside the slab
  (`:683-722`), and `kmem_cache_free_to_slab()` calls it when the address
  arithmetic returns NULL (`:825-834`). `kmem_cache_free_verify()` uses the
  same lookup, then checks the offset (`:975-990`).
- `80f72c0` wrote `page->slab_priv` directly; the `vm_page_{set,get}_priv`
  accessors the current code uses came with `436cf12` (2017-01-11).

So the author of the GNU Mach slab built the tree first (2011), tried the
page-metadata replacement in his own kernel a year later (2012), and in
GNU Mach moved the direct-mapped half of the problem to page metadata
(2016) but left the virtual-memory slabs on the tree. Nothing I read says
why GNU Mach did not finish the job; the commit messages are silent, so the
reason (effort, risk, or the page-table walk per free) is not checked.

## 4. Other kernels

### 4.1 FreeBSD UMA (`sys/vm/uma_core.c @ 1e8708d`)

Verdict: **no tree.** Three mechanisms, chosen per keg. (a) Slab header
inside the page: address arithmetic, `mem = item & ~UMA_SLAB_MASK`, then
`mem + keg->uk_pgoff` (`uma_core.c:4931-4936`, `uma_int.h:133-135`).
(b) `UMA_ZFLAG_VTOSLAB`: `vtoslab(va)` is
`PHYS_TO_VM_PAGE(pmap_kextract(va))->plinks.uma.slab` (`uma_int.h:618-624`;
`vm_page.h:227-230`), with every page of a slab tagged at creation
(`uma_core.c:1823-1826`, `vsetzoneslab`). (c) `UMA_ZFLAG_HASH`: a hash of
slab base address, `hash_sfind()` exact match on the page base
(`uma_int.h:200-207, 603-616`; `uma_core.c:4933-4934, 5816-5820`), grown by
`hash_expand` (`uma_core.c:1286`, called from `:1212`). The comment on the
flag: "Use a hash table instead of caching information in the vm_page"
(`uma_int.h:151-155`), and on the table: "Only zones with memory not
touchable by the allocator use the hash table. Otherwise slabs are found with
vtoslab()" (`uma_int.h:200-203`). The flag selection (`uma_core.c:2454-2460`)
reads: off-page header, or items not all starting in the first page, means
`HASH` if the zone is `NOTPAGE` and `VTOSLAB` otherwise; the source
comment above it (`:2450-2452`) says "We could solve the latter case with
vaddr alignment, but we don't". Similarity to our tree: none in structure;
the `VTOSLAB` path is the x15 method, the `HASH` path is Bonwick's with
slab-base keys.

### 4.2 NetBSD pool (`sys/kern/subr_pool.c @ cc2030c15`)

Verdict: **a tree, and a floor lookup in one case.** The assumption of a
page-header tree is confirmed with a correction: the tree is a **splay tree**
(`SPLAY_HEAD(phtree, pool_item_header)`, `sys/sys/pool.h:107`; member
`pr_phtree`, `pool.h:179`; `SPLAY_PROTOTYPE/GENERATE`, `subr_pool.c:589-590`),
and only for pools with off-page headers (`SPLAY_INIT` at `:938`, insert at
`:1494`). The comment at `:924-927` still says "Off-page page headers go on a
hash table", which the code contradicts. `pr_find_pagehead()` (`:614-635`)
has three cases: `PR_PHINPAGE` (header at the page start, address arithmetic
through `POOL_OBJ_TO_PAGE`, `:337-338, 622-625`), off-page with an aligned
backend (exact `SPLAY_FIND` on the page base, `:626-628`), and `PR_NOALIGN`
(`pr_find_pagehead_noalign`, `:593-609`), which does a **floor** lookup: the
comparator orders larger `ph_page` first ("unnatural ordering is for the
benefit of pr_find_pagehead", `:578-579`), `SPLAY_FIND` misses, and the next
node is taken. `PR_NOALIGN` is set for items bigger than a page
(`:840-844`, `pool.h:159`), i.e. the same population as our multi-page
slabs. This is the closest precedent for what we have.

### 4.3 DragonFly BSD (`sys/kern/kern_slaballoc.c`, `kern_objcache.c @ d1f4fb94`)

Verdict: **no tree, no hash.** Zones are `ZoneSize`-aligned, so `kfree()` does
`z = (SLZone *)((uintptr_t)ptr & ZoneMask)` and checks a magic
(`kern_slaballoc.c:1465-1472`; `ZoneMask` at `:308`; zones come from
`kmem_slab_alloc(ZoneSize, ZoneSize, ...)` at `:1064`). Oversized allocations
are told apart by a per-page field: `btokup(ptr)` is
`&pmap_kvtom(ptr)->ku_pagecnt` (`:136`, `vm/vm_page.h:193`), read at
`:1424-1425` (positive means a multi-page allocation, negative means a zone).
`kfree(ptr, type)` has no size, and the source says so: "XXX we really
should require that a size be passed to free() instead of this nonsense"
(`:1419-1420`). `kern_objcache.c` has no buffer-to-slab map at all; it is a
magazine layer over allocators, and its malloc-backed flavour calls
`kmalloc`/`kfree` (`kern_objcache.c:571-598`).

### 4.4 OpenBSD pool (`sys/kern/subr_pool.c @ ebc3947`)

Verdict: **the same design as ours**: a red-black tree of page headers keyed
by base address, searched by floor. The assumption is confirmed. `RBT_ENTRY ph_node`
("off-page page headers", `:145-146`); `phtree_compare` orders descending and
says "the compares in this order are important for the NFIND to work"
(`:277-295`); `pr_find_pagehead()` returns `page + pr_phoffset` by mask when
the header is in the page (`POOL_INPGHDR`, `:301-311`) and otherwise does
`RBT_NFIND` on the free address, then `KASSERT(ph->ph_page <= v)` and a range
panic (`:313-322`), which is a floor lookup plus a range check just like
`slab.rs:789-800`. Insertion is at `:1033`. The choice is explained at
`:386-390`: "Off-page page headers go into an RB tree, so we can match a
returned item with its header based on the page address." `pool_do_put()`
calls it for every free (`:835-842`). Not checked: whether OpenBSD's default allocators'
alignment (`POOL_ALLOC_ALIGNED`, `:240-258`) makes the floor strictly
necessary there or only convenient.

### 4.5 Linux SLUB (`mm/slab.h`, `mm/slub.c @ 551c722f4`, 7.3.0-rc5)

Verdict: **per-page metadata, no search structure.** `struct slab`
(`mm/slab.h:116`) is an overlay on `struct page`/folio ("Reuses the bits in
struct page", checked by `SLAB_MATCH`/`static_assert(sizeof(struct slab) <=
sizeof(struct page))`, `:136-147`). `virt_to_slab(addr)` is
`page_slab(virt_to_page(addr))` (`:208-211`), where `virt_to_page` on x86 is
`pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)` (`arch/x86/include/asm/page.h:62`)
and `page_slab` does `compound_head` and a `page_type` test (`:174-181`), so
any page of a multi-page slab reaches the head. `kfree(ptr)` has neither
cache nor size and does exactly that (`slub.c:6780-6802`), as does
`kmem_cache_free` (`:6615-6620`). `slub.c` contains no `rbtree`/`rb_node`
(searched). SLAB: not checked.

### 4.6 Zircon (Fuchsia `1a0ae36a`)

Verdict: **no tree in any slab-like allocator.** The assumption "no slab
allocator in the kernel" is wrong in detail; the general heap is not slab
based, but two slab allocators exist.

- Heap: `lib/heap/cmpctmalloc`, boundary tags; `cmpct_free()` does
  `(header_t *)payload - 1` (`cmpctmalloc.cc:1037`; layout described at
  `:68-72`). Not a slab.
- `lib/object_cache` ("ObjectCache is a power of two slab allocator",
  `object_cache.h:45`): slabs are power-of-two aligned and
  `Slab::FromAllocatedPointer` is `pointer & ~kSlabAddrMask`
  (`:218-219, 500-508`). Address arithmetic.
- `vm/PageSlabAllocator` (`page_slab_allocator.h:20-24`: "Simple slab
  allocator that uses a vm_page_t as its slab [...] All per-slab metadata is
  stored in the vm_page_t itself"): `AllocToSlab(ptr)` is
  `PaddrToPage(physmap_to_paddr(ptr))` with `state() == SLAB` asserted
  (`:96-99`). Per-page metadata. Used by `vm_page_list.cc:34`.
- `fbl::SlabAllocator` (`fbl/slab_allocator.h:26`) is a utility class; each
  object keeps a `slab_origin_` back-pointer (`:408, 788-789`), no lookup. I
  found no use of it under `zircon/kernel` (only `PageSlabAllocator` and
  `IdSlabAllocator` match the name).
- Address-space map, which is relevant to `vm_map.rs`, not the slab:
  `RegionList` is an ordered map by base address, now
  `btree::BTree<vaddr_t, RefPtr<T>, ...>` (`vm_address_region.h:268-271`),
  with `upper_bound(base)` then step back for the preceding region
  (`:366, 373-376`): a floor query. `fbl::WAVLTree` is still used for
  `PageRequest`, the scheduler run queues and `lib/page-map`
  (`page_source.h:385`, `sched/run-queue.h:36`, `page-map.h:120`).
  The assumption that VMAR children are a WAVL tree is out of date; when it
  changed is not checked.

### 4.7 Bonus: XNU (`osfmk/kern/zalloc.c @ xnu-12377.1.9`)

Verdict: **per-page metadata in a flat array.** `zone_meta_from_addr(addr)`
is `zone_info.zi_meta_base[addr >> PAGE_SHIFT]` via `zone_pva_from_addr`
(`zalloc.c:856-861, 883-887`), and `zone_index_from_ptr` reads
`zm_index` from it (`:889-893`). No tree, no hash.

### 4.8 Asides on address-space maps (for `vm_map.rs`)

Each of the six kernels asked about keeps its address-space map in an
ordered structure:
FreeBSD a splay tree (`sys/vm/vm_map.c:1125-1170`, `vm_map.h:187 @ 1e8708d`),
NetBSD an `rb_tree` (`sys/uvm/uvm_map.h:219 @ cc2030c15`), DragonFly an
`RB_HEAD` (`sys/vm/vm_map.h:337-341 @ d1f4fb94`), OpenBSD an `RBT`
(`sys/uvm/uvm_map.c:5381 @ ebc3947`), Linux the maple tree
(`include/linux/mm_types.h:1192 @ 551c722f4`), Zircon a B-tree (4.6). I read
only the declarations, not the lookup operations.

## 5. Comparison table

"Floor" means the greatest key at or below the address; "exact" means the key
is the slab or bufctl address itself; "arith" is address arithmetic with no
search.

| Kernel | Structure that maps buffer to slab | Key | Lookup | File @ rev |
|---|---|---|---|---|
| GNU Mach, wip-mach | per-cache RB tree of active slabs, only for multi-page (and `VERIFY`) caches; `DIRECT` arith and `vm_page.priv` otherwise | `slab->addr` | floor | `kern/slab.c:999-1040 @ 97cae82e`; `slab.rs:775-820 @ 66ed047` |
| Bonwick 1994, illumos | per-cache hash of allocated bufctls for large objects; arith for small | buffer address | exact | `kmem.c:1786-1800`, `sys/kmem_impl.h:174,236-240 @ 7e802e8`; Bonwick §3.2.3 |
| x15 (same author, 2012+) | `vm_page.priv` set in every page of a slab; arith for one-page embedded | page frame of address | exact, any interior address | `kern/kmem.c:631-722 @ c08b3ff`; `80f72c0` |
| FreeBSD UMA | arith (in-page header); `vm_page.plinks.uma.slab` (`VTOSLAB`); hash of slabs (`HASH`, non-page zones) | page frame; page base | arith; exact; exact | `uma_core.c:4925-4937, 5811-5820`, `uma_int.h:603-624 @ 1e8708d` |
| NetBSD pool | arith (`PR_PHINPAGE`); splay tree `pr_phtree` of off-page headers | `ph_page` | exact if aligned; **floor** for `PR_NOALIGN` | `subr_pool.c:574-635 @ cc2030c15` |
| OpenBSD pool | arith (in-page header); RB tree `phtree` of off-page headers | `ph_page` | **floor** (`RBT_NFIND`) | `subr_pool.c:277-323 @ ebc3947` |
| DragonFly | arith (`ptr & ZoneMask`); per-page `ku_pagecnt` marks oversized | zone base; page | arith | `kern_slaballoc.c:1424-1472 @ d1f4fb94` |
| Linux SLUB | `struct slab` overlaying `struct page`, via `virt_to_page` and `compound_head` | pfn | arith into the memmap | `mm/slab.h:116,208-211`, `mm/slub.c:6780-6802 @ 551c722f4` |
| Zircon | arith (`object_cache`, power-of-two slabs); `vm_page_t` by paddr (`PageSlabAllocator`); boundary tag (`cmpctmalloc`) | slab mask; paddr; header before payload | arith / page lookup | `object_cache.h:500-508`, `page_slab_allocator.h:96-99`, `cmpctmalloc.cc:1037 @ 1a0ae36a` |
| XNU zalloc | flat per-page metadata array | `addr >> PAGE_SHIFT` | arith into the array | `zalloc.c:856-887 @ xnu-12377.1.9` |

Ordered tree with floor lookup keyed by slab or page-header base, as a
deliberate answer to "multi-page or off-page header": GNU Mach (RB), OpenBSD
(RB), NetBSD (splay, only when the backend is unaligned). Hash: Bonwick and
illumos for every large-object cache, FreeBSD for non-page zones only.
Everything else, and x15 after 2012, uses page metadata or address
arithmetic.

## 6. What this implies for DEBT.md "No ordered collections shape" (inference)

Everything in this section is inference from sections 1 to 5.

1. **Is the tree justified by precedent?** Yes as a design, weakly as the
   current best one. Its rationale is sound (a floor lookup turns any interior
   address into its slab, one node per active slab, no resizing) and has
   independent precedents in OpenBSD and NetBSD. But the only other design in
   the same lineage that I could read, x15, replaced it with page metadata;
   Linux, FreeBSD (for page-backed zones), XNU and Zircon's page-based
   allocators use page metadata; and GNU Mach itself already moved its
   direct-mapped slabs to page metadata in 2016 (`b325f426`).
2. **The slab's need from an ordered shape is small.** Insert, remove by node
   address, floor lookup, no ceiling, no duplicate keys (DEBT.md lists
   ceiling lookups and duplicate keys for the `vm_map.rs` trees; the slab
   uses only the floor).
   Today that need comes from five `kalloc` caches and whatever other caches
   exceed a page (1.3), with `VERIFY` dead (1.1). Inference from the sweep in
   1.3: for those caches the key is always an exact match, so even the floor
   is unused.
3. **Options for `KmemCache.active_slabs`:**
   - **Keep an ordered tree.** Cheapest to port (translation stays
     one-to-one), and the shape it needs is a subset of what `vm_map.rs`
     needs, so it costs nothing extra if `collections` gets an ordered shape
     anyway. Cost: an O(log n) lookup and tree edits under the cache lock on
     every free of a tree cache, with no per-CPU pool to hide them (1.2), and
     a network packet on that path (1.3).
   - **Replace it with page metadata for virtual slabs (the x15/Linux/FreeBSD
     `VTOSLAB` way).** Tag every page of a multi-page slab with
     `priv_`, look up with `lookup_pa(kvtophys(buf))`, untag at destroy. The
     pieces already exist: `USE_PAGE` does it for the first page
     (`slab.rs:1093-1105, 1193-1198`); `kvtophys` walks the kernel page table
     for any mapped address (`arch/x86_64/phys.rs:41-53`, same as C
     `i386/i386/phys.c:180-186 @ 97cae82e`), not only the direct map;
     `priv_` has no other user in the Rust kernel (defined `vm_page.rs:64`,
     cleared at `:778`, written only in `slab.rs`); and the same lookup
     handles any interior address, so `free_verify` would not need a floor.
     It removes the `RBTree` from `KmemSlab` and `KmemCache`, and the insert
     and remove from `alloc`/`free_to_slab`. Risks, all not checked: the
     per-free page-table walk (x15 accepts it in a comment, but it is not
     measured here); whether wired `kernel_map` pages keep stable `vm_page`
     structures for the life of the slab; and lock order if a lookup ever
     used `pmap_extract`, which takes the pmap lock at `splvm`
     (`pmap.rs:2368-2388`) whereas `kvtophys` does not lock.
   - **Replace it with a hash (Bonwick/illumos).** Not recommended: it needs
     resizing machinery that `collections` does not have and that the
     original author rejected in writing, and our bufctls live in the buffers
     (there is no per-buffer external record to hash).
   - **Drop `USE_TREE` only for the dead `VERIFY` case.** Safe on its own
     (1.1), but it leaves the multi-page caches unsolved, so it does not
     close the DEBT entry.
4. **What this means for the DEBT entry.** If the aim is to remove
   `intrusive-collections`, the slab does not have to be one of the tree's
   customers; page tagging retires it. `vm_map.rs` then remains the only
   ordered-shape user, and it is well precedented (4.8: each of the six
   kernels asked about keeps its address-space map in an ordered structure).
   Whether to split the entry, reword "those three trees", or keep the
   slab's tree for a literal translation is the maintainer's call; the
   evidence favours page metadata for the slab and an ordered shape for
   `vm_map.rs`.
5. **Not checked, and worth checking before acting:** lookup cost of the page
   walk against the tree depth; how many live buffers the tree caches hold in
   a busy system (the tree's n); the sizes of the typed caches beyond
   `kalloc`; `vm_page` reuse rules for `kernel_map` pages; how a slab's pages
   from `kmem_alloc_wired` interact with `lookup_pa`.
