// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`PmapState`]: the physical map's global state whose types name the
//! platform.
//!
//! A Rust `static` cannot be generic, so the platform declares the one
//! `PmapState` and returns it from [`Platform::pmap_state`].

use crate::cell::SyncCell;
use crate::platform::Platform;
use crate::types::{PmapUpdateList, PvEntry};
use core::cell::UnsafeCell;
use lock::irq_spin_lock;
use lock::{IrqSpinLock, TicketLock};
use mach_page::smp::MAX_NCPUS;

/// The physical map's global state whose types name the platform.
pub struct PmapState<P: Platform> {
    /// One lock per managed page, guarding that page's pv list and attribute
    /// byte; `pmap_init()` fills it in before any pv list is used.
    pv_locks: SyncCell<&'static [TicketLock<()>]>,
    /// Each CPU's queued invalidations; the TLB-shootdown interrupt takes
    /// its own CPU's, so the locks are irq spin locks.
    pub(crate) update_lists: [IrqSpinLock<PmapUpdateList, P::Lock>; MAX_NCPUS],
}

impl<P: Platform> PmapState<P> {
    /// `pmap_init()` carves the locks out right after the pv head table.
    const LAYOUT: () =
        assert!(align_of::<TicketLock<()>>() <= align_of::<PvEntry>());

    /// The state before boot: no pv locks.
    #[must_use]
    pub const fn new() -> Self {
        let () = Self::LAYOUT;
        Self {
            pv_locks: SyncCell(UnsafeCell::new(&[])),
            update_lists: [const {
                irq_spin_lock!("pmap update", PmapUpdateList::new())
            }; MAX_NCPUS],
        }
    }

    /// The pv locks, one per managed page.
    pub(crate) fn pv_locks(&self) -> &'static [TicketLock<()>] {
        // SAFETY: `pmap_init()` writes the table once, before any pv list is
        // used, and it is only read from then on.
        unsafe { *self.pv_locks.0.get() }
    }

    /// Publishes the pv locks.
    ///
    /// # Safety
    ///
    /// Once, from `pmap_init()`, before any pv list is used.
    pub(crate) unsafe fn set_pv_locks(
        &self,
        locks: &'static [TicketLock<()>],
    ) {
        // SAFETY: the caller publishes the table before anyone reads it.
        unsafe { *self.pv_locks.0.get() = locks };
    }
}

impl<P: Platform> Default for PmapState<P> {
    fn default() -> Self {
        Self::new()
    }
}
