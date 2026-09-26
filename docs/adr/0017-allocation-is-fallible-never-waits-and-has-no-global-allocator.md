# Allocation is fallible, never waits, and has no global allocator

The kernel image links no `alloc` crate and has no
`#[global_allocator]`. Heap memory comes from an allocator trait of
our own, `Alloc`, defined in the `kmem` crate together with the fallible
owning types over it: `KBox`, `KVec`, `KBoxSlice` and `KRawBuf` — plus
other containers only when a caller needs them. The kernel implements
`Alloc` over its slab caches and general sized allocator, which stay in
the `kernel` crate: they are coupled to the page allocator and the VM
map, and `host_slab_info` exposes their statistics (ADR 0002). Each
owner stores its allocator, so a zero-sized one costs nothing and one
that points at a cache can be shared by many.

Every constructor takes a complete value and returns a `Result`; there
is no infallible path to hide behind a lint, and none for boot code. A
failed constructor drops the value it was given. A caller that must keep
a value across a failure reserves first (`KBox::try_new_uninit`,
`KVec::try_reserve`) and writes afterwards, when nothing can fail.

Allocation never waits. When memory is short it fails at once, and a
caller that may sleep waits for free pages itself and retries.
Allocating is therefore legal under a spin lock, and "may this sleep"
never hides inside an allocation call (ADR 0001). Interrupt handlers
never allocate: they work from memory set aside in advance, so the
cache locks are plain spin locks, not irq spin locks.

The slab and the general allocator are designed from Bonwick, *The Slab
Allocator* (USENIX 1994), and Bonwick and Adams, *Magazines and Vmem*
(USENIX 2001), and carry no code derived from GNU Mach (ADR 0010).
`kmem` is MIT (ADR 0010).

## Considered Options

- **`alloc` with a global allocator**, clippy blocking the infallible
  methods: the infallible API still exists, `Box::try_new` needs
  nightly, and a global allocator cannot say which cache to use or
  whether it may wait.
- **Typed caches only**, no `Box` or `Vec`: every variable-size buffer
  becomes a hand-paired `kalloc`/`kfree`.
- **A wait flag on every call** (Linux's `GFP_KERNEL`/`GFP_ATOMIC`): a
  block point hidden in a call that reads like arithmetic.
- **Rust-for-Linux's route**: it too left `alloc`'s types for its own
  `KBox` and `KVec`, but builds with unstable features enabled through
  `RUSTC_BOOTSTRAP`, which ADR 0004 rules out; `kmem` uses stable Rust
  only, which is why its types carry their own allocator parameter and
  cannot coerce to `dyn`. It also takes their `K` prefix, which keeps
  the names apart from `alloc`'s in host tests.
- **The slab inside `kmem`**: the crate would need the page allocator
  and the VM map behind more traits than the types themselves are worth.
- **Constructors that hand the value back** (`Result<_, (AllocError,
  T)>`): every error grows by `T`. Reserve-then-write gives the same
  guarantee at the call sites that need it.

## Consequences

- No `format!`, and no third-party crate that needs `alloc`
  (ADR 0023).
- An object enters memory whole, through a constructor that takes the
  value; nothing is filled in field by field over raw or recycled
  memory.
- Freeing never blocks either (ADR 0016).
