// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! An interrupt that takes an irq spin lock while the thread it interrupts
//! records a mutex hold.
//!
//! The x86 trap flag stands in for the interrupt: while it is set, the CPU
//! traps after every instruction, and the `SIGTRAP` handler takes an irq
//! spin lock on the interrupted thread's record, as an interrupt handler
//! does in the kernel.  The platform's irq-quiet section clears the flag,
//! as the kernel's masks interrupts.  So the handler runs at every
//! instruction boundary of a mutex acquisition outside those sections.
//!
//! The record claimed the hold's slot, then wrote its kind before its lock
//! address.  A handler in between found its own lock's address, left in
//! the slot by its last release, beside the mutex's kind, and panicked
//! with a recursive acquisition of a lock it did not hold.

#[cfg(all(target_arch = "x86_64", target_os = "linux", debug_assertions))]
mod traced {
    use core::cell::Cell;
    use core::ffi::c_int;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use lock::{
        Bucket, HeldLocks, IrqSpinLock, Mutex, Platform, ThreadRef, WaitTable,
    };

    use x86_64::registers::rflags::{self, RFlags};

    /// The test's one thread, whose record its `SIGTRAP` handler shares.
    struct Thread {
        held: HeldLocks,
        /// How many irq-quiet sections the thread is in.
        quiet: Cell<usize>,
        /// Whether the outermost section found the trap flag set.
        traced: Cell<bool>,
    }

    // SAFETY: only the main thread and its signal handler reach it.
    unsafe impl Sync for Thread {}

    static THREAD: Thread = Thread {
        held: HeldLocks::new(),
        quiet: Cell::new(0),
        traced: Cell::new(false),
    };

    static BUCKETS: [Bucket; 1] = [Bucket::new()];
    static WAITS: WaitTable = WaitTable::new(&BUCKETS);

    /// The lock the thread takes, outside any irq-quiet section.
    static MUTEX: Mutex<(), Host> = Mutex::new(());
    /// The lock the handler takes, as an interrupt takes the timer wheel's.
    static SPIN: IrqSpinLock<(), Host> = IrqSpinLock::new(());
    /// How many times the handler ran.
    static TRAPS: AtomicUsize = AtomicUsize::new(0);

    /// Sets or clears the trap flag, leaving the other flags.
    fn set_trap_flag(on: bool) {
        // SAFETY: only the trap flag changes, which no compiled code reads.
        unsafe { rflags::update(|flags| flags.set(RFlags::TRAP_FLAG, on)) };
    }

    /// The test thread's platform: irq-quiet sections clear the trap flag.
    struct Host;

    // SAFETY: the one thread is always running and never waits, and the
    // sections mask the only interrupt there is.
    unsafe impl Platform for Host {
        fn current() -> ThreadRef {
            ThreadRef::new(NonNull::from(&THREAD).cast())
        }

        fn is_running(_: ThreadRef) -> bool {
            true
        }

        fn irq_quiet_enter() {
            let traced = rflags::read().contains(RFlags::TRAP_FLAG);
            set_trap_flag(false);
            let depth = THREAD.quiet.get();
            if depth == 0 {
                THREAD.traced.set(traced);
            }
            THREAD.quiet.set(depth + 1);
        }

        unsafe fn irq_quiet_exit() {
            let depth = THREAD.quiet.get() - 1;
            THREAD.quiet.set(depth);
            if depth == 0 && THREAD.traced.get() {
                set_trap_flag(true);
            }
        }

        fn park() {
            unreachable!("the one thread never waits");
        }

        fn unpark(_: ThreadRef) {}

        fn wait_table() -> &'static WaitTable {
            &WAITS
        }

        fn held_locks() -> &'static HeldLocks {
            &THREAD.held
        }
    }

    /// The interrupt: takes and releases the irq spin lock.
    extern "C" fn interrupt(_: c_int) {
        drop(SPIN.lock());
        let _ = TRAPS.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn run() {
        // SAFETY: the action is zeroed before its handler is set, and the
        // handler only takes and releases a lock.
        unsafe {
            let mut action: libc::sigaction = core::mem::zeroed();
            let handler: extern "C" fn(c_int) = interrupt;
            action.sa_sigaction = handler as libc::sighandler_t;
            assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
            assert_eq!(
                libc::sigaction(
                    libc::SIGTRAP,
                    &raw const action,
                    ptr::null_mut()
                ),
                0,
            );
        }

        set_trap_flag(true);
        drop(MUTEX.lock());
        set_trap_flag(false);

        // The handler ran at each instruction of the acquisition and the
        // release, not once.
        assert!(TRAPS.load(Ordering::Relaxed) > 100);
    }
}

fn main() {
    #[cfg(all(
        target_arch = "x86_64",
        target_os = "linux",
        debug_assertions
    ))]
    traced::run();
}
