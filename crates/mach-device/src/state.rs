// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The device service's records whose types name the platform.

use crate::cell::SyncCell;
use crate::dev_lookup::{NDEVHASH, NumberBucket};
use crate::dev_name::DevIndirect;
use crate::dev_pager::{DEV_HASH_COUNT, DeviceBucket, PagerBucket};
use crate::ds_routines::{DevOps, DeviceEmulationOps, MachDevice};
use crate::io_req::IoReqQueue;
use crate::platform::Platform;
use lock::irq_spin_lock;
use lock::{IrqSpinLock, TicketLock};
use mach_vm::vm_map::VmMap;

/// The state of the device service of one platform. The kernel keeps the one
/// value in a static and hands it out through [`Platform::device_state`].
pub struct DeviceState<P: Platform> {
    /// The machine's device table: the drivers each device name opens.
    pub(crate) devices: &'static [DevOps<P>],
    /// The names that stand for another device, such as the console.
    pub(crate) indirect: &'static [DevIndirect<P>],
    /// The native Mach device emulation every device lookup installs.
    pub(crate) emulation: SyncCell<DeviceEmulationOps>,
    /// The map every device I/O buffer is mapped through.
    pub(crate) io_map: SyncCell<VmMap<P>>,
    /// The requests the io-done thread still has to complete.
    pub(crate) io_done_list: SyncCell<IoReqQueue<P>>,
    /// Guards `io_done_list`.  An irq spin lock, since requests complete from
    /// interrupt handlers.
    pub(crate) io_done_lock: IrqSpinLock<(), P::Lock>,
    /// The open devices, one bucket per device-number hash.
    pub(crate) number_hash: SyncCell<[NumberBucket<P>; NDEVHASH]>,
    /// Serializes `number_hash`, and is held before any device's `ref_lock`.
    pub(crate) number_lock: TicketLock<()>,
    /// The device pagers by pager port, one bucket per hash.
    pub(crate) pager_hash: SyncCell<[PagerBucket<P>; DEV_HASH_COUNT]>,
    /// Serializes `pager_hash`.
    pub(crate) pager_hash_lock: TicketLock<()>,
    /// The device pagers by device and offset, one bucket per hash.
    pub(crate) device_hash: SyncCell<[DeviceBucket<P>; DEV_HASH_COUNT]>,
    /// Serializes `device_hash`.
    pub(crate) device_hash_lock: TicketLock<()>,
}

impl<P: Platform> DeviceState<P> {
    /// The state before boot, over the machine's device table `devices` and
    /// its indirect names `indirect`.
    #[must_use]
    pub const fn new(
        devices: &'static [DevOps<P>],
        indirect: &'static [DevIndirect<P>],
    ) -> Self {
        let () = DevOps::<P>::LAYOUT;
        let () = DevIndirect::<P>::LAYOUT;
        let () = MachDevice::<P>::LAYOUT;
        Self {
            devices,
            indirect,
            emulation: SyncCell::new(DeviceEmulationOps::mach::<P>()),
            io_map: SyncCell::new(VmMap::zeroed()),
            io_done_list: SyncCell::new(IoReqQueue::new()),
            io_done_lock: irq_spin_lock!("device io done", ()),
            number_hash: SyncCell::new(
                [const { NumberBucket::new() }; NDEVHASH],
            ),
            number_lock: TicketLock::new(()),
            pager_hash: SyncCell::new(
                [const { PagerBucket::new() }; DEV_HASH_COUNT],
            ),
            pager_hash_lock: TicketLock::new(()),
            device_hash: SyncCell::new(
                [const { DeviceBucket::new() }; DEV_HASH_COUNT],
            ),
            device_hash_lock: TicketLock::new(()),
        }
    }
}
