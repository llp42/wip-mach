# wip-mach

A Mach kernel in Rust that reproduces GNU Mach's userspace ABI, so a
stock GNU Hurd userland runs on it.

## Language

**Mach ABI**:
The userspace-visible Mach interface surface — traps, message formats,
and type sizes — that GNU Hurd observes.
_Avoid_: syscall ABI, calling convention

**ABI name**:
An identifier the Mach ABI publishes — a type, constant, trap, RPC or
MIG subsystem name — kept with its upstream spelling, `i386` included.
_Avoid_: C name, header name

**Upstream internal name**:
A GNU Mach identifier outside the Mach ABI, such as a source file,
function or internal struct; cited only in an ADR's reasoning.

**GNU Mach**:
The C kernel whose Mach ABI this kernel reproduces: a behaviour
reference, not a source the project tracks.
_Avoid_: Mach, CMU Mach (unless meaning the historical release),
upstream (unless meaning a provenance pin)

**Hurd / GNU Hurd**:
The current stock Debian GNU/Hurd userspace that defines ABI
compatibility; the thing that must boot and run.
_Avoid_: userland, GNU

**Userspace driver**:
A Hurd server that drives hardware the kernel does not, such as a disk
or network card.
_Avoid_: user-mode driver, kernel driver

**Debt entry**:
A record in the debt register of one gap between the code and the
target the ADRs describe: which ADR, where, and what closes it. Work in
progress is a debt entry too.
_Avoid_: TODO, known issue, plan

**MIG**:
The Mach Interface Generator that produces RPC stubs from `.defs`
interfaces.
_Avoid_: RPC generator

**MIG seam**:
The one place where C-visible symbols live: the MIG-generated C calls
the kernel there, and the kernel calls the generated C.
_Avoid_: FFI layer, glue

**Shim header**:
A hand-written C header at the MIG seam that declares types only.
_Avoid_: C header, glue header

**Hurd reference image**:
The pinned Debian GNU/Hurd snapshot whose scripted boot shows that a
stock Hurd runs.
_Avoid_: test image, Debian image

**Checked build**:
The kernel built with debug assertions and overflow checks on, booted by
the ABI suite like any other build.
_Avoid_: debug build

## Kernel objects

**Reference**:
An owning claim on a kernel object's memory: taken by cloning, released
by dropping; the last release frees the object. Not a port right.
_Avoid_: handle, refcount

**Death**:
The explicit, synchronous end of a kernel object's life as Mach sees it,
such as a port losing its receive right or a task terminating; after it
the object is only memory that references hold.
_Avoid_: destroy, deallocate, free

## Code shape

**Platform trait**:
The seam a portable crate uses to receive kernel- and
machine-specific services as a type parameter or stored value.
_Avoid_: backend, HAL, arch hook, machine layer, hooks

**Modular backend**:
An implementation of a portable crate's `Platform` trait.
_Avoid_: driver, provider

**`wip-mach` crate**:
The machine-independent Mach core — IPC, VM, tasks, threads,
scheduling — that receives the machine through its `Platform` trait.
Not the repository, and not the bootable kernel.
_Avoid_: core, mach crate, MI layer

**Provenance header**:
The `// Derived from …` block pinning the upstream project, commit,
and original files of a derived file.

**Non-preemptible**:
A thread leaves its CPU in kernel mode only by blocking; there are no
kernel preemption points.
_Avoid_: preemptive, no-preempt

## Locks

**Irq-quiet section**:
A CPU-local region in which no local interrupt handler runs; whether by
masking or by deferral is the platform's choice.
_Avoid_: spl, splhigh, interrupts-off, critical section, no-preempt
section

**Spin lock**:
A lock whose waiters spin and whose holder must not sleep.
_Avoid_: simple lock, slock

**Irq spin lock**:
A spin lock whose holder is in an irq-quiet section; the only lock
interrupt handlers may share with threads.
_Avoid_: irq lock, simple_lock_irq

**Mutex**:
A sleeping lock with one owner, who is recorded in the lock.
_Avoid_: mutex lock, kmutex, adaptive mutex, complex lock

**RwLock**:
A sleeping shared/exclusive lock whose waiters are served in arrival
order; it can downgrade and never upgrade.
_Avoid_: complex lock, lock_t, sx, rwsem

**Lock class**:
The set of locks built at one construction site; the unit the order
checker reasons about, and a thread holds at most one lock of a class at
a time.
_Avoid_: witness, lock name

**Guard**:
The value that holds a lock for its scope and is the only way to its
data; it unlocks when dropped.
_Avoid_: lock handle, locked ref

**Raw lock**:
A lock with no data, locked and unlocked through `&self`, whose unlock
may come in another function than its lock; the guard's layer is built
on it.
_Avoid_: bare lock, simple lock

**Wait table**:
The hashed table, keyed by lock address, where parked threads queue.
_Avoid_: sleep queue, turnstile, wait list

**Handoff**:
Releasing a contended lock by making its first waiter the new owner
before waking it, so no running thread can take the lock in between.
_Avoid_: direct grant, transfer

**Barging**:
Taking a just-released lock ahead of the threads already waiting for it;
handoff rules it out for contended locks.
_Avoid_: lock stealing
