// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from ipc/mach_debug.c and vm/vm_debug.c, and from
// mach_debug/vm_info.h and mach_debug/hash_info.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// Derived from kern/thread.c:
//   Copyright (c) 1994-1987 Carnegie Mellon University.
//   Copyright (c) 1993-1987 Carnegie Mellon University.
// Derived from kern/slab.c and kern/slab.h:
//   Copyright (c) 2011 Free Software Foundation.
//   Copyright (c) 2010, 2011 Richard Braun.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <`mach_debug/mach_debug.defs`> server entries, all 12 routines, which
//! `kern/mach_debug.srv` presents.
//!
//! The cores are in [`crate::ipc::mach_debug`], [`crate::kern::thread`],
//! [`crate::kern::slab`] and [`crate::vm::vm_debug`].

use crate::arch::types::{VmOffset, VmSize};
use crate::ipc::mach_debug;
use crate::ipc::{HashInfoBucket, IpcSpace};
use crate::kern::error::Error;
use crate::kern::host::Host;
use crate::kern::processor::ProcessorSet;
use crate::kern::slab::{self, CacheInfo};
use crate::mig::code::KERN_SUCCESS;
use crate::vm::types::VmObject;
use crate::vm::vm_debug::{
    self, VmObjectInfo, VmPageInfo, VmPagePhysInfo, VmRegionInfo,
};
use crate::vm::vm_kern;
use crate::vm::vm_map::{VmMap, round_page};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::slice;

/// Reports how many send rights exist for the receive right `name`.
///
/// # Safety
///
/// `space` must be null or a live `ipc_space`; `srightsp` must be writable
/// storage for one right count, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_get_srights(
    space: *mut c_void,
    name: c_uint,
    srightsp: *mut c_uint,
) -> c_int {
    match unsafe { mach_debug::get_srights(IpcSpace::new(space), name) } {
        Ok(srights) => {
            unsafe { srightsp.write(srights) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports the buckets of the msg-accepted request table.
///
/// # Safety
///
/// `host` must be null or the live host pointer the generated server
/// converted the request port into; `maxp` and `countp` must be writable
/// storage for one count, and `infop` for one bucket-array pointer.  The
/// caller permits an allocation and a kernel-map copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_ipc_marequest_info(
    host: *mut Host,
    maxp: *mut c_uint,
    infop: *mut *mut HashInfoBucket,
    countp: *mut c_uint,
) -> c_int {
    match unsafe {
        mach_debug::marequest_info(NonNull::new(host), maxp, infop, countp)
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Reports the size and use of the dead-name request table of `name`.
///
/// # Safety
///
/// `space` must be null or a live `ipc_space`; `totalp` and `usedp` must be
/// writable storage for one count each, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_dnrequest_info(
    space: *mut c_void,
    name: c_uint,
    totalp: *mut c_uint,
    usedp: *mut c_uint,
) -> c_int {
    match unsafe { mach_debug::dnrequest_info(IpcSpace::new(space), name) } {
        Ok((total, used)) => {
            unsafe {
                totalp.write(total);
                usedp.write(used);
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports the kernel stacks' usage.
///
/// # Safety
///
/// `host` must be null or the live host the MIG stub converted, and every out
/// pointer must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_stack_usage(
    host: *mut c_void,
    reservedp: *mut VmSize,
    totalp: *mut c_uint,
    spacep: *mut VmSize,
    residentp: *mut VmSize,
    maxusagep: *mut VmSize,
    maxstackp: *mut VmOffset,
) -> c_int {
    let usage = match unsafe { crate::kern::thread::host_stack_usage(host) } {
        Ok(usage) => usage,
        Err(error) => return c_int::from(error),
    };

    unsafe {
        reservedp.write(0);
        totalp.write(usage.total);
        spacep.write(usage.space);
        residentp.write(usage.space);
        maxusagep.write(usage.maxusage);
        maxstackp.write(usage.maxstack);
    }
    0
}

/// Reports the kernel stacks' usage, for `pset`.
///
/// # Safety
///
/// `pset` must be null or point at a live processor set, and the caller must
/// hold no locks: the routine allocates.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_stack_usage(
    pset: *mut ProcessorSet,
    totalp: *mut c_uint,
    spacep: *mut VmSize,
    residentp: *mut VmSize,
    maxusagep: *mut VmSize,
    maxstackp: *mut VmOffset,
) -> c_int {
    let usage = match unsafe {
        crate::kern::thread::processor_set_stack_usage(pset)
    } {
        Ok(usage) => usage,
        Err(error) => return c_int::from(error),
    };

    unsafe {
        totalp.write(usage.total);
        spacep.write(usage.space);
        residentp.write(usage.space);
        maxusagep.write(usage.maxusage);
        maxstackp.write(usage.maxstack);
    }
    0
}

/// Reports the buckets of the virtual-to-physical table.
///
/// # Safety
///
/// `host` must be null or the live host pointer the generated server
/// converted the request port into; `infop` and `countp` must be writable
/// storage, and the caller permits an allocation and a kernel-map copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_virtual_physical_table_info(
    host: *mut Host,
    infop: *mut *mut HashInfoBucket,
    countp: *mut c_uint,
) -> c_int {
    match unsafe {
        vm_debug::virtual_physical_table_info(
            NonNull::new(host),
            infop,
            countp,
        )
    } {
        Ok(()) => KERN_SUCCESS,
        Err(error) => c_int::from(error),
    }
}

/// Reports the type and address of the kernel object `name` names.
///
/// # Safety
///
/// `space` must be null or a live `ipc_space`; `typep` must be writable
/// storage for one kobject type and `addrp` for one address, both written
/// only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_kernel_object(
    space: *mut c_void,
    name: c_uint,
    typep: *mut c_uint,
    addrp: *mut VmOffset,
) -> c_int {
    match unsafe {
        mach_debug::mach_port_kernel_object(IpcSpace::new(space), name)
    } {
        Ok((object_type, object_addr)) => {
            unsafe {
                typep.write(object_type);
                addrp.write(object_addr);
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports the region of `map` at `address`, and its object's port.
///
/// # Safety
///
/// `map` must be null or a live, unlocked map; `regionp` and `portp` must be
/// writable storage, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_vm_region_info(
    map: *mut VmMap,
    address: VmOffset,
    regionp: *mut VmRegionInfo,
    portp: *mut *mut c_void,
) -> c_int {
    match unsafe { vm_debug::region_info(map, address) } {
        Ok((info, port)) => {
            unsafe {
                regionp.write_unaligned(info);
                portp.write(port);
            }
            KERN_SUCCESS
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports `object`'s information, and its shadow and copy.
///
/// # Safety
///
/// `object` must be null or a live object; `infop`, `shadowp` and `copyp`
/// must be writable storage, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_vm_object_info(
    object: *mut VmObject,
    infop: *mut VmObjectInfo,
    shadowp: *mut *mut c_void,
    copyp: *mut *mut c_void,
) -> c_int {
    match unsafe { vm_debug::object_info(object) } {
        Ok((info, shadow, copy)) => {
            unsafe {
                infop.write_unaligned(info);
                shadowp.write(shadow);
                copyp.write(copy);
            }
            KERN_SUCCESS
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports `object`'s resident pages.
///
/// # Safety
///
/// `object` must be null or a live object; `pagesp` must be writable storage
/// for one array pointer and `countp` for one count; the caller permits an
/// allocation and a kernel-map copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_vm_object_pages(
    object: *mut VmObject,
    pagesp: *mut *mut VmPageInfo,
    countp: *mut c_uint,
) -> c_int {
    match unsafe {
        vm_debug::object_pages_info(
            object,
            pagesp.cast::<*mut c_void>(),
            countp,
        )
    } {
        Ok(()) => KERN_SUCCESS,
        Err(error) => c_int::from(error),
    }
}

/// `host_slab_info()` in <`mach_debug/mach_debug.defs`>.
///
/// # Safety
///
/// `info` must point at writable storage for one pointer, `info_cnt` at
/// writable storage for one count, and when `*info` is not used it must be
/// the caller's to overwrite.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_slab_info(
    host: *mut c_void,
    info: *mut *mut CacheInfo,
    info_cnt: *mut c_uint,
) -> c_int {
    if host.is_null() {
        return c_int::from(Error::InvalidHost);
    }

    let (Some(info), Some(info_cnt)) =
        (NonNull::new(info), NonNull::new(info_cnt))
    else {
        return c_int::from(Error::InvalidArgument);
    };

    loop {
        let nr_caches = slab::nr_caches();
        let info_size = nr_caches as usize * size_of::<CacheInfo>();

        // `kalloc` reports a zero-size request as failure.
        let Some(base) = slab::kalloc(info_size) else {
            return c_int::from(Error::ResourceShortage);
        };

        // SAFETY: the allocation holds `nr_caches` records.
        let out = unsafe {
            slice::from_raw_parts_mut(
                base.as_ptr().cast::<CacheInfo>(),
                nr_caches as usize,
            )
        };

        let Some(count) = slab::collect(nr_caches, out) else {
            // SAFETY: `base` is the live allocation from above.
            unsafe { slab::kfree(base, info_size) };
            continue;
        };

        let room = unsafe { info_cnt.as_ptr().read() };

        if count <= room {
            unsafe {
                let dst = info.as_ptr().read();
                ptr::copy_nonoverlapping(
                    base.as_ptr(),
                    dst.cast::<u8>(),
                    info_size,
                );
            }
        } else {
            // SAFETY: `ipc_kernel_map` is the live kernel IPC map.
            let map = unsafe { &mut *crate::ipc::ipc_init::ipc_kernel_map() };

            let info_addr = match vm_kern::kmem_alloc_pageable(map, info_size)
            {
                Ok(addr) => addr,
                Err(error) => {
                    // SAFETY: `base` is the live allocation from above.
                    unsafe { slab::kfree(base, info_size) };
                    return c_int::from(error);
                }
            };

            // SAFETY: the pageable region is `info_size` bytes long, as is
            // the allocation.
            unsafe {
                ptr::copy_nonoverlapping(
                    base.as_ptr(),
                    with_exposed_provenance_mut::<u8>(info_addr),
                    info_size,
                );
            }

            let total_size = round_page(info_size);

            if info_size < total_size {
                // SAFETY: the region is `total_size` bytes, and the range
                // starts at `info_size`.
                unsafe {
                    ptr::write_bytes(
                        with_exposed_provenance_mut::<u8>(
                            info_addr + info_size,
                        ),
                        0,
                        total_size - info_size,
                    );
                }
            }

            let copy = map.copyin(info_addr, info_size, true);

            unsafe {
                info.as_ptr().write(copy.map_or(ptr::null_mut(), |copy| {
                    copy.cast::<CacheInfo>().as_ptr()
                }));
            }
        }

        unsafe { info_cnt.as_ptr().write(count) };
        // SAFETY: `base` is the live allocation from above.
        unsafe { slab::kfree(base, info_size) };

        return KERN_SUCCESS;
    }
}

/// Reports `object`'s resident pages with their physical addresses.
///
/// # Safety
///
/// `object` must be null or a live object; `pagesp` must be writable storage
/// for one array pointer and `countp` for one count; the caller permits an
/// allocation and a kernel-map copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_vm_object_pages_phys(
    object: *mut VmObject,
    pagesp: *mut *mut VmPagePhysInfo,
    countp: *mut c_uint,
) -> c_int {
    match unsafe {
        vm_debug::object_pages_phys(
            object,
            pagesp.cast::<*mut c_void>(),
            countp,
        )
    } {
        Ok(()) => KERN_SUCCESS,
        Err(error) => c_int::from(error),
    }
}
