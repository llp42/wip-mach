# kmem research: what the kernel allocates

Inventory of every kernel heap allocation site, to decide which fallible
owning types `crates/kmem` needs (ADR 0017). Facts carry `file:line`
evidence; counts come from `grep` over the trees named below. Where a
statement is an inference rather than a read, it says so.

## Sources and their limits

- **wip-mach Rust kernel** (`crates/kernel/src`) is the primary source:
  27 `kalloc(` call sites and about 38 `kfree` sites outside
  `kern/slab.rs` and `kern/kheap.rs`, 36 `KmemCache` statics (37 typed
  caches, since `ipc_object.rs:38` holds an array of two), 13 `kalloc`
  size-class caches, and `alloc::` use in 8 kernel files plus
  `main.rs:23` (`extern crate alloc`).
- **GNU Mach at /home/leonardo/Git/gnumach**: the working tree holds no
  `.c` files (`git ls-files | grep -c '\.c$'` is 0). Only headers with
  allocation macros remain (`ipc/ipc_kmsg.h:137,180`,
  `device/net_io.h:97-98`, `device/io_req.h:126,131`, `ipc/ipc_entry.h:89`,
  `ipc/ipc_object.h:83`, `ipc/ipc_space.h:82`), and `rust/src` is an
  older revision of the same port (145 hits for `kalloc`, `kfree`,
  `kmem_cache_*`, `alloc::`). For the C behaviour I read the last
  full-C snapshot, commit `97cae82e` (2025-05-07, 354 `.c` files),
  extracted to a scratch directory: 34 `kalloc` and 46 `kfree` sites
  outside Xen, 6 `kalloc` in `xen/`, 38 `kmem_cache_init` calls, 0
  `kget` (the name does not exist in this tree).
- **Other crates**: `lock`, `clock`, `collections` do not use `alloc` in
  library code. The `Box` in `clock/src/*.rs` and `lock/src/test_support.rs`
  is test-only (`Box::leak(Box::new(..))`, `Box::pin`).
- Not read line by line: `vm/`, `device/` cache-only paths beyond the
  cache init and one alloc/free per cache.

## 1. Allocation sites by shape

Shapes: (a) fixed-size typed object, (b) run-time-sized array of T,
(c) byte buffer, (d) grow-by-copy or size-retry list, (e) freed by raw
address+size across the MIG/IPC seam, (f) typed slab cache, (g) other.

### (a) Fixed-size typed object via `kalloc` (3 alloc sites)

| Site | Object | Freed | Notes |
|---|---|---|---|
| `arch/x86_64/io_perm.rs:208` | `IoPerm` | `io_perm.rs:177` (destroy notification) and `:218` (error path), both `size_of::<IoPerm>()` | fails to `ResourceShortage`; thread context, no lock held at the call |
| `device/intr.rs:366` | `IntrList` node | never freed (`USER_INTR_HANDLERS` list is append-only) | failure returns `DeviceError::NoMemory`; allocated before `lock_irq()` at `:375` |
| `vm/vm_map.rs:4636` | `VmMapCopyinArgs` (continuation args) | `vm_map.rs:4750`, `size_of::<VmMapCopyinArgs>()` | `kpanic!` on failure (`:4638`); pointer lives in a thread continuation across a block |

- Freer knows the size: yes, `size_of::<T>()` at every site.
- Alignment above 8: no.
- Under a spin lock or at interrupt level: none found. `io_perm` create
  runs with no lock held; `intr.rs:366` runs before the irq lock.
- Failure handling: two return an error, one panics.

### (a') Fixed-size typed object via `alloc::Box` + `try_box` (kheap.rs)

| Site | Type | Ownership shape |
|---|---|---|
| `device/ds_routines.rs:651,662` (`io_req_alloc`/`io_req_free`); `into_raw` at `:1305,1461,1528,1724,1796` | `IoReq` | `try_box(ior)` then `Box::into_raw`; freed by `Box::from_raw`; linked in intrusive `LinkedList<IoReqAdapter>` (`chario.rs:1207`) and passed to drivers as `*mut IoReq` |
| `device/intr.rs:251,272` | `UserIntr` | `try_box` then `Box::leak` into an intrusive list (`UnsafeRef::from_raw`), never freed |
| `kern/rcu.rs:484-673` | `RcuBox<T>` (`head: RcuHead`, `value: T`) | `try_box(..).map(Box::into_raw)` (`:538`), freed in a grace-period callback via `Box::from_raw(head.cast())` (`:496`) and in `Drop` (`:673`); one user, `vm/memory_object.rs:1219,1339` |
| `kern/bootstrap.rs:85,114,133,166` | `MultibootModule` | infallible `Box::new`, `into_raw` into `thread.saved.other`, `from_raw` in the bootstrap thread; boot only |

Every one of these round-trips through a raw pointer (`into_raw`,
`leak`, `from_raw`). None needs `Box<dyn Trait>` or unsizing.

### (a'') `IoReq` also lives in a slab cache

`IO_TRAP_CACHE` (`ds_routines.rs:599,2288,2301,2369,2462`, size
`IOTRAP_REQSIZE` = 2048) holds `io_req` objects for the device-trap
path, while the `Box` path above holds the same struct. Two allocators
serve one type; `IO_INBAND_CACHE` (`:595`, 128 bytes) holds a raw
`io_buf_ptr_inband_t` byte buffer.

### (b) Run-time-sized array of T via `kalloc`

| Site | Element | Notes |
|---|---|---|
| `arch/x86_64/apic.rs:514` | `u16` x `MAX_NCPUS` | boot; returns `false` on failure |
| `arch/x86_64/apic.rs:653` | `u16` x `ncpus` | shrink-by-copy of the boot table; old freed at `:669` with the old size |
| `ipc/ipc_marequest.rs:147` | `IpcMarequestBucket` x `size` | boot; `kpanic!` on failure; never freed |
| `ipc/ipc_table.rs:107` | `IpcTableSize` x `IPC_TABLE_DNREQUESTS_SIZE` | boot; `kpanic!`; never freed; used as a static lookup table |
| `ipc/ipc_table.rs:141` via `ipc/ipc_port.rs:140` | `IpcPortRequest` x `its_size` | the dead-name request table, see (d) |
| `kern/ipc_tt.rs:706` | `VmOffset` x 4 (`TASK_PORT_REGISTER_MAX`) | `mach_ports_lookup`; allocated with no lock held, freed on the inactive-task path (`:714`) |
| `kern/host.rs:93` | `*mut c_void` x `processor_count` | allocated **with the pset lock held** (`host.rs:80` locks, `:93` allocs, `:94-95` unlock on failure) |
| `kern/host.rs:154` | `VmOffset` x cpus | `host_processors`; no lock held |
| `ffi/mach_debug.rs:329` | `CacheInfo` x `nr_caches` | `host_slab_info`; retry loop `:327-372`, frees at `:343,367,409` |

### (c) Byte buffer

| Site | Buffer | Notes |
|---|---|---|
| `device/cirbuf.rs:240,262` | tty ring, sizes `TTY_INQ_SIZE`/`TTY_OUTQ_SIZE` (4096/2048 per the file comment at `:246`) | size recovered from `c_end - c_start`; alloc failure leaves null pointers, unchecked by callers (`chario.rs:1211,1225`) |
| `device/net_io.rs:1199,1212` | network kmsg buffer, `NET_KMSG_SIZE` (page-rounded, written once at `:1114`) | the pool is filled from thread context in `kmsg_more` (`:1354-1368`); `kmsg_get` (`:1222`) only dequeues, so the receive path allocates nothing at interrupt level |
| `device/ds_routines.rs:1834` | `IO_INBAND_CACHE` object | 128-byte inband data |

### (d) Grow-by-copy and size-retry patterns

Four functions share one pattern, written out by hand each time:
guess size, drop the lock, `kalloc`, retake the lock, re-read the count,
retry if too small; take references on each element while the lock is
held; then allocate a smaller buffer, `memcpy`, and free the larger one.

| Function | Alloc sites | Free sites | Lock around the count |
|---|---|---|---|
| `task_threads` `kern/task.rs` | `:978`, `:1023` (shrink) | `:973`, `:996`, `:1032`, `:1041` | task lock |
| `processor_set_stack_usage`-style thread list `kern/thread.rs` | `:2690` | `:2686`, `:2772` | pset lock |
| `processor_set_things` `kern/processor.rs` | `:1188`, `:1260` (shrink) | `:1183`, `:1230`, `:1265`, `:1273` | pset lock |
| `host_processor_sets` `kern/host.rs` | `:222`, `:251` (shrink) | `:219`, `:259`, `:268` | `all_psets` lock |

Element type is a pointer-sized handle (`VmOffset`, `*mut c_void`)
holding one reference each. On a shrink-alloc failure the code drops
every reference it took (`host.rs:255`, `task.rs:1030`), so
the buffer needs per-element release on error.

Other grow-by-copy sites:

- `ipc/ipc_port.rs:190-285` `dngrow`: allocates a bigger table with the
  port unlocked (`:222`), retakes the lock, checks the table is
  unchanged (`:236`), copies the old prefix (`:254`), threads a free list
  through the new tail, frees the old (`:276`); frees the new one when
  the check fails (`:283`). The size comes from a static size-record
  chain, not from the buffer.
- `kern/syscall_emulation.rs:257-306`: the same alloc-outside-the-lock,
  recheck, free-the-loser loop for the emulation vector.
- `arch/x86_64/user_ldt.rs:171-265`: the same loop, with the pcb lock
  and a leftover `new_ldt` freed at `:264`.

### (e) Freed by raw address + size across the MIG/IPC seam

| Object | Alloc | Free | Where the size lives |
|---|---|---|---|
| `IpcKmsg` (`ikm`) header+body | `ipc_kmsg.rs:1182` (`size + IKM_OVERHEAD`) | `:1150` (`ikm_free`), `:1172` (`free`) | the header (`kmsg.size()`); `IKM_SIZE_NETWORK` (`usize::MAX`, `:42`) routes to `net_io::kmsg_put`; the C tests a truncated `integer_t` (`:1146`) |
| OOL port array inside a message | `ipc_kmsg.rs:2275` | `kfree_addr` (`:850`, called at e.g. `:3664`) | `length` recomputed from the type descriptor in the message body |
| `mach_ports_register` argument | MIG-side | `ffi/mach.rs:696`, `count * size_of::<VmOffset>()` | argument count |
| Result arrays of (b)/(d) | the (d) functions | the IPC copyout path frees them, not the producer | descriptor in the reply message |

- The freer knows the size only because the size travels with the
  object (header field or descriptor), not because it is a type.
- `kalloc`ed arrays leave a Rust function as `(NonNull<T>, count)`
  (`ipc_tt.rs:697`, `task.rs` return `Ok((Some(NonNull), actual))`), so
  the owner at the seam is a raw pair.
- `ikm` is filled by `copyin` from user memory (`ipc_kmsg.rs:1293,1322`
  allocate, then copy in). OOL port arrays are filled by `copyinmap`
  (`:2275` onward).
- `mach-mig-sys` contains no allocation code (its only `alloc` hits are
  `*_deallocate` prototypes in `mig/include/mig_shim.h:471-478`).

### (f) Typed slab caches (stay in the kernel crate)

37 typed caches, all `init`ed once at boot with `(name, size, align, ctor=None, flags)`:

`pcb` (align 16 = `KERNEL_STACK_ALIGN`, `pcb.rs:36,794`), `thread`,
`thread_stack` (size = align = `PAGE_SIZE`, `thread.rs:412`, `vm_param.rs:28`),
`task`, `ipc_port` and `ipc_pset` (`ipc_object.rs:853,861`), `ipc_space`,
`ipc_entry`, `ipc_marequest`, `processor_set`, `vm_page`, `vm_object`,
`vm_map`, `vm_map_entry` (`NOOFFSLAB | PHYSMEM`, `vm_map.rs:729`),
`vm_map_copy`, `vm_external`, `small_existence_map` (16 B),
`large_existence_map`, `vm_fault_state`, `memory_object_proxy`,
`rdxtree_node`, `i386_fpsave_state` (align `align_of::<I386FpSaveState>()`, a
`repr(align(64))` type at `fpu.rs:160`), `iopb` (`machine_task.rs:48`),
`mach_device`, `dev_pager`, `dev_pager_entry`, `dev_device_entry`,
`net_rcv_port`, `net_hash_entry`, `io_inband`, `io_req` (trap), and six
pmap caches `pmap`, `pt`, `pd`, `pdpt`, `l4`, `pv_list` (`pmap.rs:492-507`;
the page-table ones are page-sized and `PHYSMEM`).

Usage counts: about 90 `.alloc()`/`.free()`/`cache_alloc`/
`kmem_cache_alloc`/`kmem_cache_free` call sites outside `slab.rs`. All
objects are initialised in place after `alloc()` (raw memory, then field
writes): the shape ADR 0017 forbids (`Consequences`, second bullet).
GNU Mach C at `97cae82e` has 38 `kmem_cache_init` calls; the C-only
`act_cache` (`kern/act.c:70`, inside an `#if`) has no Rust cache, and I did not
diff the remaining names one by one.

Special properties that the cache API, not kmem's box/vec, must carry:
alignment above 8 (pcb 16, ifps 64, thread_stack and pmap tables page),
`PHYSMEM` (direct-mapped pages), `NOOFFSLAB`, and statistics for
`host_slab_info` (`slab.rs:1739`, `mach_debug.rs:329`).

### (g) Other

- `kalloc` itself: 13 size-class caches 32 B to 128 KiB
  (`slab.rs:42,45`, `kalloc_init`), then `pagealloc_physmem` for
  `size <= PAGE_SIZE` beyond the caches and `pagealloc_virtual`
  (`kmem_alloc_wired`) above that (`slab.rs:1496-1523`). `size == 0`
  returns `None`. Every buffer is 8-aligned only (`KMEM_ALIGN_MIN`,
  `slab.rs:45`; slab colouring means even 4 KiB is not page-aligned,
  `kheap.rs:31`).
- **Blocking**: `pagealloc_physmem` loops on `vm_page::wait(None)`
  (`slab.rs:1325-1345`), so `kalloc` can sleep. `DEBT.md:77-83` records
  this; ADR 0017 wants immediate failure.
- `kmem_alloc*`/`kmem_free` (page-granular kernel-map memory): used by
  `syscall_emulation.rs:361`, `user_ldt.rs:491`, `vm_user.rs:687`,
  `ipc/mach_debug.rs:102`, `ffi/mach_debug.rs:362`, `mach_clock.rs:970`,
  `pmap.rs:1266`, and `slab.rs:1354`. These are not heap objects and are
  not a kmem type; the pageable ones feed `vm_map_copyin`.

## 2. Per-shape answers

| Shape | Freer knows size | Align > 8 | Spin lock / irq level | Failure |
|---|---|---|---|---|
| (a) typed `kalloc` | yes, `size_of::<T>()` | no | none found | 2 return error, 1 `kpanic!` |
| (a') `Box` | yes, type | none found among Box'd types (checked by `repr(align)` grep: the `align(64)` types are statics or slab objects) | none found | `try_box` returns the value; `bootstrap.rs:85` is infallible, boot only |
| (b) array | from count or table record | no | one: `host.rs:93` under the pset lock | error, or `kpanic!` at boot (`ipc_marequest.rs:147`, `ipc_table.rs:107`) |
| (c) byte buffer | from stored end pointer or a global | page-rounded net buffer; no alignment stated | net pool refilled outside irq; `cirbuf` at first tty open | `cirbuf` failure unchecked |
| (d) retry list | tracked in a local `size` | no | alloc always after dropping the lock; count read under the lock | `ResourceShortage`, after releasing taken references |
| (e) seam | header field or descriptor | no | none found | `SEND_INVALID_MEMORY` / `SEND_NO_BUFFER` |
| (f) caches | fixed by cache | yes, see above | `pv_list` refilled outside the pmap lock (`pmap.rs:2264-2276`); others not surveyed | `fpu`/`pmap` handle, several `kpanic!` |
| (g) large kalloc | yes | page-aligned virtual for `> 128 KiB`? not verified | n/a | `None` |

Interrupt level: I found no kernel heap allocation at interrupt level.
The design already keeps net receive on a pre-filled pool
(`net_io.rs:1222-1270`), and interrupts hand off through
`deliver_user_intr` (`intr.rs:225`) to a thread.

## 3. `alloc::` uses in the Rust kernel

| File:line | Type | What it needs |
|---|---|---|
| `arch/x86_64/multiboot.rs:23,213,274-287` | `Vec<MultibootModule>`, `CString` | `Vec::with_capacity(count)`, `push`; `CString::from(&CStr)` (owned NUL-terminated copy); boot only, infallible today |
| `arch/x86_64/model_dep.rs:39,77,81` | `Vec<MultibootModule>` | return value; `Vec::new()` |
| `kern/bootstrap.rs:41-44,85,464-526` | `Box`, `CString`, `format!`, `Vec` | `modules.remove(0)`, `.is_empty()`, `.len()`, `[i]`, `.iter()`; `Vec<u8>` with `with_capacity`, `push`, `clear`, `Vec::from(&[u8])`; `CString::new(Vec<u8>)`; `format!("{port}")` used once (`:526`) to render a `u32` |
| `kern/boot_script.rs:20-21,149-201,247-660` | `Vec<Command>`, `Vec<Symbol>`, `Vec<Arg>`, `Vec<Builtin>`, `CString` (x8 fields), `Vec<Vec<u8>>`, `Vec<*const c_char>` | `push` (already behind `try_reserve` at `:265,600,603,612,655`), `drain(..)` (`:582`), `clear` (`:589`), `iter().position`, `extend_from_slice`, `len`; `CString::new(&[u8])` returning `Err` on interior NUL; `CString::default()`; `as_ptr()` for C `argv`; `as_bytes()` |
| `device/intr.rs:33,251,272` | `Box<UserIntr>` | `try_box`, `Box::leak` |
| `device/ds_routines.rs:51,651-662,1305...` | `Box<IoReq>` | `try_box`, `into_raw`, `from_raw` |
| `kern/rcu.rs:44,484-673` | `Box<RcuBox<T>>` | `try_box`, `into_raw`, `from_raw`, generic over `T` |
| `kern/kheap.rs` | `Box<MaybeUninit<T>>` | `try_box_uninit` for "allocate before the value exists"; ZST shortcut at `:130` |
| `main.rs:23` | `extern crate alloc` | needed only for the above |

Not found in the kernel: `Box<dyn Trait>` (the `&mut dyn Host` in
`boot_script.rs:331,369,407,442,495,576,593,647` is a borrow, not an
owner), `Arc`, `Rc`, `Weak`, `String`, `BTreeMap`, `VecDeque`,
`into_boxed_slice`, `to_vec`, `to_owned`, `retain`, `sort`, `dedup`,
`insert`, `extend` (other than `extend_from_slice`), `truncate`.
`format!` appears once.

## 4. Reference counting

All counting is by hand: an integer in the object, lock-protected,
with `*_reference`/`*_deallocate`-style functions. No type implements
`Clone` for a counted object (`grep 'impl Clone'` is empty in
`crates/kernel`; the only `Drop` impls are `Mapping`, `ManagerPort`,
`ModuleImage`, `RcuGuard`, `Rcu<T>`). `DEBT.md:85-92` records this as
debt.

| Object | Count field | Functions | Freed by |
|---|---|---|---|
| port / port set | `IpcObject.references: u32` (`ipc/mod.rs:74`), under the object lock | `ipc_object::reference`/`release` (`ipc_object.rs:188,202`); `IpcPort::reference`/`release` (`ipc/mod.rs:1250,1260`); `increment_references`/`decrement_references` (`:218,231,745,1195`) | `IPC_OBJECT_CACHES` slab, on last release after explicit death |
| task | `ref_count: c_int` (`task.rs:90,241`), under the task lock | `task::reference` (`:639`), `task::deallocate` (`:583`) | last count: machine teardown, `syscall_emulation::task_deallocate`, pset removal, map and space release, `TASK_CACHE.free` |
| thread | `ref_count: c_int` (`thread.rs:233`), spl + thread lock | `Thread::reference` (`:516`), `Thread::deallocate` (`:1661`); the count is bumped back to 1 mid-teardown (`:1673`) | reaper path, `THREAD_CACHE` and stack cache |
| processor set | `ref_count` (`processor.rs:369`) | `reference`/`deallocate` (`:708,715`) | `PSET_CACHE` |
| vm map | `ref_count: UnsafeCell<c_int>` (`vm_map.rs:387`) | `VmMap::reference`/`deallocate` (`:656,670`) | `map_cache` |
| vm object | `ref_count` (`vm_object.rs:386,598,615`) | `vm_object::reference`/`deallocate` (`:592,609`), shadow chain walked at `:642` | `VM_OBJECT_CACHE` |
| ipc space | `is_references` in a record with `ref_lock` (`ipc_space.rs:223,256`) | `ipc_space::reference`/`release` (`:181,196`) | `IPC_SPACE_CACHE` |
| device | `ref_count` (`dev_lookup.rs:106,241,255`) | `dev_lookup::reference`/`deallocate` (`:238,252`), `ref_count = 1` reset at `:260` | `DEV_HDR_CACHE` |
| dev pager | `ref` (`dev_pager.rs:229,243`) | `reference`/`deallocate` | `DEV_PAGER_CACHE` |
| io_perm | via its port (`io_perm.rs:149,177`) | `deallocate` | `kfree` of the `kalloc` object |
| emulation vector | `ref_count` inside the table (`syscall_emulation.rs:125-135`) | `task_deallocate` | `kfree(size from disp_count)`; a header + trailing array |

Back-pointers and cycles (facts, then inference):

- Ports point back at kernel objects: `port.kobject()` cast to `Task`
  (`ipc_tt.rs:746`), `kotype()` check, plus `is_active()`. The lookup
  takes a reference under the port lock (`:748`) only when the port is
  still active. That is a `Weak::upgrade` shape (a raw pointer valid only
  while the port is live). The reverse edge exists too: `task.itk_self`
  holds a port reference. So task and port reference each other; the
  break is explicit death (`task::terminate`, ADR 0016), which clears the
  kobject. Inference: a `Weak`-like type is not needed if every such
  edge stays a raw kobject pointer checked under the port lock, but
  ADR 0016 has not decided the type of the counted reference itself.
- `thread.task` (`thread.rs:1565`) is an uncounted back-pointer: no
  `task::reference` call in `thread.rs`. The thread deallocate path
  reads `(*thread).task` and locks it (`:1689-1690`), so the task must
  outlive its threads; the guarantee is the task's thread list plus
  `terminate`, not a count.
- `thread.processor_set` is counted (`(*pset).reference()` at
  `thread.rs:737,1489,1522,2337`); `task.processor_set` is counted
  (`task.rs:614-615`).
- Task holds its map and its space (`task.rs:625-630`); neither points
  back at the task by a counted edge that I found.
- vm object: `shadow` chain is counted downward (`vm_object.rs:642`);
  `copy` and pager-request pointers not read. **Not checked**: cycles
  between an object and its pager/request ports.
- Any `Weak` in the code: none found. `Arc`/`Rc`: none found.

## 5. Intrusive and list containers already covered

- `crates/collections` provides four intrusive shapes: `SinglyList`,
  `List`, `SimpleQueue`, `TailQueue` (`collections/src/lib.rs:12-16`).
  They never allocate or free; nodes are caller-owned; ADR 0043-0049.
- The kernel still uses `intrusive-collections =0.10.3` in 4 files
  (`Cargo.toml`): `RBTree` and `Bound` in `vm_map.rs` and `slab.rs`, and
  `LinkedListLink` for the legacy timeout wheel in `mach_clock.rs` and
  `ioapic.rs`. Every other list goes through `collections`' `_ptr` pushes:
  a `Box`'d `UserIntr` enters its queue as
  `push_back_ptr(NonNull::from(Box::leak(..)))` (`intr.rs`).
- `rdxtree.rs` (`RDXTREE_NODE_CACHE`) is an in-kernel radix tree over a
  slab cache, not a `collections` shape.

kmem must not duplicate list shapes. What the owning-pointer side
needs from them is an owning `into_raw`/`from_raw`-style handoff so a
`KBox` can enter a `collections` head and come back.

## 6. Feature needs

| Need | Evidence |
|---|---|
| Zeroed allocation | `syscall_emulation.rs:270` (`write_bytes(.., 0, new_size)` after `kalloc`), `user_ldt` fills from a template; `mach_debug.rs:388` zero-pads a page tail. 36 `zeroed()` calls exist for statics (not heap). Not general |
| Alignment above 8 for heap objects | none found in `kalloc` callers or `Box` types. Caches alone need it (pcb 16, ifps 64, stack/pmap page). `kheap.rs:52-58` implements over-allocation for `alloc` users; no user found |
| Page-sized or page-aligned buffers | slab caches and `kmem_alloc*`, not `kalloc` callers. `NET_KMSG_SIZE` is `round_page`, not aligned |
| Uninitialised memory filled by `copyin` | `ikm` (`ipc_kmsg.rs:1293,1322`), OOL port arrays (`:2275`), `user_ldt` header + descriptors, `host_slab_info` (filled by `collect`). Needs `MaybeUninit` slices with a `set_len`-after-fill or `assume_init` |
| Realloc in place | none found: every grow is alloc-new, copy, free-old (all of section (d)); shrink is also alloc-new+copy |
| ZSTs | `try_box_uninit` special-cases size 0 (`kheap.rs:130`); no ZST allocation found at a real site |
| Header + trailing array (one allocation, size in header) | `IpcKmsg`, `UserLdt` (`user_ldt.rs:125`), `EmlDispatch` (`syscall_emulation.rs`) |
| Refcounted allocation | emulation vector (own count); all other counted objects are slab objects |
| Take a `Result` from a constructor with the value | ADR 0017; `try_box(value) -> Result<Box<T>, T>` is the existing shape |

## 7. Table: shape to candidate kmem type

Counts are Rust-kernel call sites outside `slab.rs`/`kheap.rs`.

| Shape | Sites | Candidate kmem type | Notes |
|---|---|---|---|
| (a) typed object, freed by `size_of` | 3 `kalloc` (`io_perm`, `IntrList`, copyin args) | `KBox<T>` | `into_raw`/`from_raw`/`leak` needed by all 3 |
| (a') `Box` | 4 sites (IoReq, UserIntr, RcuBox, bootstrap module) | `KBox<T>` | `try_new(value) -> Result<KBox<T>, T>`; `into_raw`, `from_raw`, `leak` |
| (b) fixed-once array | 6: apic x2, marequest, ipc_table x2, `ports_lookup` | `KBoxedSlice<T>` or `KVec<T>` with a `try_with_len` | boot tables never freed; `ports_lookup` crosses the seam |
| (c) byte buffer | 3: cirbuf x2 (in/out), net kmsg | `KBoxedSlice<u8>` or `KVec<u8>` | net buffer is raw, page-rounded, pooled |
| (d) size-retry array of handles | 4 functions, 8 alloc sites | `KVec<T>` with `try_reserve_exact`, `try_extend` and `shrink_to_fit`, or a `KBoxedSlice` | element type `*mut`/`VmOffset`; must release elements on error |
| (d') table grow-by-copy | 3: dnrequests, emulation vector, user_ldt | `KBoxedSlice<T>` + `try_clone_prefix`/copy; alloc-outside-lock idiom | none needs in-place realloc |
| (e) seam raw address+size | ~10 (`ikm` x2 alloc, OOL ports x2, plus the frees) | none as owner; `into_raw_parts`/`from_raw_parts` on `KBoxedSlice` and a header+DST type for `ikm` | the seam keeps raw `(addr, size)` per ADR 0016 |
| (f) typed slab cache | 37 caches, ~90 alloc/free sites | cache handle with `try_alloc(value) -> Result<CacheBox<T>, T>` (in kernel crate per the brief) | holds `T`; constructor takes the value (ADR 0017) |
| header + trailing array | 3: `ikm`, `user_ldt`, emulation vector | a single-allocation header+`[T]` type | size stored in header |
| `CString` | 12 uses (bootstrap x3, boot_script x8, multiboot x1) | `KCString` (or `KVec<u8>` + NUL check) | `new(&[u8])` erring on NUL, `from(&CStr)`, `as_ptr`, `as_bytes`, `default` |
| `format!` | 1 (`bootstrap.rs:526`) | none; write into a `[u8; 11]` (a `u32` in decimal); `boot_script.rs:247 push_decimal` already does this by hand | |

## 8. Open design questions

1. `KBox<T>` handoff: `into_raw`/`from_raw`/`leak` are used at every
   `Box` site and into `collections`/`intrusive-collections`. Does kmem
   expose them as `unsafe` methods, or as a smaller safe adapter
   for intrusive heads?
2. Is `KVec<T>` one type serving (d) (a bounded scratch that leaves as a
   raw pair) and (c) (`Vec<u8>` byte building in boot_script), or does
   the kernel want `KBoxedSlice<T>` for everything that never grows
   after construction? Section (d) needs `try_reserve_exact` plus a
   shrink that reallocates, which `Vec` lacks as a single call.
3. The four (d) functions all drop the lock, allocate, retake the
   lock, and retry; two of them (`host.rs:93`, and `dngrow`'s recheck)
   do it differently. Does ADR 0017's "allocation is legal under a
   spin lock" remove the retry loop (allocate at the locked count,
   fail on shortage), or is that loop the intended caller-waits
   protocol (a caller that may sleep waits for free pages and retries)?
4. What is the seam owner for an array that leaves as `(ptr, count)`
   (`ipc_tt.rs:697`)? The IPC copyout path frees by `(addr, size)`.
   Should `KBoxedSlice` have `into_raw_parts` and a matching free-by-raw
   API that the seam calls, or does the seam get its own type?
5. Header + trailing array (`ikm`, `user_ldt`, emulation table):
   is that one generic type, three hand-written `unsafe` wrappers, or
   three typed-cache-less wrappers over `KBoxedSlice<u8>`? `ikm` also
   has a per-CPU one-entry cache and a network variant sized by a runtime
   global (`NET_KMSG_SIZE`).
6. Do the counted objects need `KArc<T>` in kmem, or does the reference
   type of ADR 0016 belong beside the slab caches in the kernel crate,
   since every counted object is a slab object (section 4)? No object
   outside slab caches is counted except the emulation vector.
7. Does any counted edge need a weak reference? Section 4 found
   `port.kobject` (upgrade-if-alive under the port lock) and the
   uncounted `thread.task`. If the design keeps these as raw pointers
   guarded by explicit death, no `KWeak` is needed. That is a decision,
   not something I verified as safe.
8. Failure policy at boot: `ipc_marequest.rs:147`, `ipc_table.rs:107`,
   `vm_map.rs:4638` `kpanic!`, and `bootstrap`/`boot_script` `expect`s.
   Do boot-time allocations keep a panicking convenience (`expect_boot`),
   given ADR 0017's "no infallible path"?
9. `try_box` on a `T` with alignment above 8 goes through
   `KernelAllocator`'s over-allocation. No user found; does kmem drop
   support for it or keep a guard (`const` assert on `align_of::<T>() <=
   8`) for `KBox`?
10. `kalloc` currently sleeps (`slab.rs:1343`) and `kfree` of a size
    above the caches calls `kmem_free`. ADR 0017 wants
    fail-immediately for both; what does kmem's free-by-size contract say
    for sizes over 128 KiB?
11. Is `IO_TRAP_CACHE` vs `Box<IoReq>` (same struct, two allocators,
    `ds_routines.rs:595,651`) resolved to one before or after kmem?
12. `cirbuf` and `IntrList` use `kalloc` without checking or freeing;
    are those callers converted to `KBox`/`KBoxedSlice` and their
    failure paths added in the same change?

## 9. Not needed (from the survey)

- `Box<dyn Trait>`, unsizing coercion (`CoerceUnsized`): no owned trait
  object anywhere.
- `Arc`, `Rc`, `Weak`, `String`, `BTreeMap`, `HashMap`, `VecDeque`: no
  use.
- A general `format!`/`String`: one use, replaceable with a fixed
  buffer.
- In-place `realloc`: every grow and shrink allocates, copies and frees.
- `Vec` operations beyond `new`, `with_capacity`, `push`,
  `extend_from_slice`, `clear`, `drain(..)`, `remove(0)`, `len`,
  `is_empty`, `iter`, indexing, `as_ptr` (the complete set in
  `boot_script.rs`, `bootstrap.rs`, `multiboot.rs`).
- Heap allocation at interrupt level: none found.
- Heap alignment above 8: no heap `Box`/`kalloc` user found (only slab
  caches and statics).
- Page-aligned heap buffers: only slab caches and `kmem_alloc*` need
  them.
- List containers: `crates/collections` and `intrusive-collections`
  already cover them.
- Zero-sized allocation at a real site: none found.
- GNU Mach's `kget`: does not exist in this tree.
