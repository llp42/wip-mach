// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! [`Probe`]: what looking an address up in a task's map found — the VM
//! object behind it and the offset into it.

use crate::error::Error;
use crate::platform::Platform;
use crate::types::{Flags, Key};
use core::ptr::NonNull;
use lock::lock_api::RawMutex as _;
use mach_vm::param::{VM_MIN_KERNEL_ADDRESS, VmOffset};
use mach_vm::types::{PAGE_SIZE, VmInherit, VmObject, VmProt};
use mach_vm::vm_map::{EnterRequest, VmMap, trunc_page};

/// The object and offset a lookup found.
pub struct Probe {
    /// The object behind the address, locked by the lookup.
    pub object: *mut VmObject,
    /// The address's offset into `object`.
    pub offset: VmOffset,
}

impl Probe {
    /// Looks `addr` up in `map`, readable and, with [`Flags::MUTATE`],
    /// writable.  On success the map stays read-locked and the object
    /// locked, as the C's `keep_map_locked` argument asked.
    pub fn lookup<P: Platform>(
        map: *mut VmMap<P>,
        addr: VmOffset,
        flags: Flags,
    ) -> Result<Self, Error> {
        let mut prot = VmProt::READ;
        if flags.contains(Flags::MUTATE) {
            prot |= VmProt::WRITE;
        }

        let Some(mut map) = NonNull::new(map) else {
            return Err(Error::InvalidAddress);
        };
        // SAFETY: the caller's task holds the live map, and the lookup takes
        // its read lock and returns the object locked.
        match VmMap::lookup(&mut map, addr, prot, true) {
            Ok(found) => {
                if found.protection.contains(prot) {
                    return Ok(Self {
                        object: found.object,
                        offset: found.offset,
                    });
                }
                // SAFETY: the lookup left the map read-locked and the
                // object locked; the C released both on this path.
                unsafe {
                    (*map.as_ptr()).lock.unlock();
                    (*found.object).lock.unlock();
                }
                Err(Error::InvalidAddress)
            }
            Err(_) => Err(Error::InvalidAddress),
        }
    }

    /// The key a wait on `addr` in `map` is filed under: the object and
    /// offset for [`Flags::SHARED`], the map and address otherwise.
    pub fn key<P: Platform>(
        &self,
        map: *mut VmMap<P>,
        addr: VmOffset,
        flags: Flags,
    ) -> Key {
        if flags.contains(Flags::SHARED) {
            Key::Shared {
                object: self.object as usize,
                offset: self.offset,
            }
        } else {
            Key::Local {
                map: map as usize,
                addr,
            }
        }
    }

    /// Maps `addr`'s page into the kernel with `prot`, or returns zero when
    /// the mapping fails.
    pub fn map_page<P: Platform>(
        &self,
        addr: VmOffset,
        prot: VmProt,
    ) -> VmOffset {
        let mut paddr = VM_MIN_KERNEL_ADDRESS;
        let offset = self
            .offset
            .wrapping_sub(addr.wrapping_sub(trunc_page(addr)));
        let request = EnterRequest {
            address: &mut paddr,
            size: PAGE_SIZE,
            mask: 0,
            anywhere: true,
            object: self.object,
            offset,
            needs_copy: false,
            cur_protection: prot,
            max_protection: VmProt::ALL,
            inheritance: VmInherit::COPY,
        };
        // SAFETY: `kernel_map` is the live kernel map, and the lookup
        // returned the object locked and the caller referenced it.  The C
        // zeroed the address on failure.
        match unsafe { (*P::state().kernel_map()).enter(request) } {
            Ok(()) => paddr,
            Err(_) => 0,
        }
    }
}
