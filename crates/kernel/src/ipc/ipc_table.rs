// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_table.c and ipc/ipc_table.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The IPC table sizing and allocation, which `ipc/ipc_table.c` used to define
//! and `ipc/ipc_table.h` declares.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::ipc::IpcPortRequest;
use crate::kern::debug::kpanic;
use crate::kern::slab::{kalloc, kfree};
use core::ffi::c_uint;
use core::mem::offset_of;
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::slice;

/// `struct ipc_table_size` of <`ipc/ipc_table.h>`: one table size.
#[repr(C)]
#[allow(missing_docs)]
pub struct IpcTableSize {
    pub its_size: c_uint,
}

const _: () = assert!(size_of::<IpcTableSize>() == 4);
const _: () = assert!(align_of::<IpcTableSize>() == 4);
const _: () = assert!(offset_of!(IpcTableSize, its_size) == 0);

/// `ipc_table_dnrequests_size` in `ipc/ipc_table.c`: how many sizes
/// [`ipc_table_init()`] allocates for.
const IPC_TABLE_DNREQUESTS_SIZE: usize = 64;

/// The byte size of `struct ipc_port_request`, which every table size counts.
pub(crate) const IPC_PORT_REQUEST_SIZE: VmSize = size_of::<IpcPortRequest>();

/// `ipc_port_dngrow()` in `ipc/ipc_port.c` reads the C symbol and walks the
/// table it points at; nothing else touches it.
pub static mut IPC_TABLE_DNREQUESTS: *mut IpcTableSize = ptr::null_mut();

/// Fill `its` with the sizes of the tables the C `ipc_table_fill()` describes:
/// powers of two up to the page size, then page-sized increments that double
/// up to eight pages.
///
/// # Panics
///
/// Halts through [`kpanic!`] when `elemsize` is zero, which the C would
/// divide by.
fn fill(its: &mut [IpcTableSize], min: c_uint, elemsize: VmSize) {
    let Some(elemsize) = NonZeroUsize::new(elemsize) else {
        kpanic!("ipc_table_fill", "ipc_table_fill: zero element size")
    };
    let elemsize = elemsize.get();

    // The C's `minsize = min * elemsize` is unsigned arithmetic and wraps;
    // `min` widens to `usize` exactly on both kernels.
    let minsize = (min as usize).wrapping_mul(elemsize);

    let mut index = 0;

    let mut size = 1;
    while index < its.len() && size < PAGE_SIZE {
        if size >= minsize {
            let Some(entry) = its.get_mut(index) else {
                return;
            };
            // The C stores a `vm_size_t` quotient into the `unsigned int`
            // `its_size`, a deliberate truncation.
            entry.its_size = (size / elemsize) as c_uint;
            index += 1;
        }
        size = size.wrapping_shl(1);
    }

    let mut incrsize = PAGE_SIZE;
    while index < its.len() {
        let mut period = 0;
        while period < 15 && index < its.len() {
            if size >= minsize {
                let Some(entry) = its.get_mut(index) else {
                    return;
                };
                // The C's deliberate truncation, as above.
                entry.its_size = (size / elemsize) as c_uint;
                index += 1;
            }
            period += 1;
            size = size.wrapping_add(incrsize);
        }
        if incrsize < PAGE_SIZE << 3 {
            incrsize = incrsize.wrapping_shl(1);
        }
    }
}

/// `ipc_table_init()` in C.
///
/// # Safety
///
/// Must be called once, from the IPC bootstrap, after `kalloc_init()` and
/// before any port grows its dead-name request table.
pub(crate) unsafe fn ipc_table_init() {
    let bytes = size_of::<IpcTableSize>() * IPC_TABLE_DNREQUESTS_SIZE;
    // The caller promises the allocator is up, and the size is a small
    // multiple of the record.
    let Some(table) = kalloc(bytes).map(NonNull::cast::<IpcTableSize>) else {
        kpanic!(
            "ipc_table_init",
            "ipc_table_init: cannot allocate dnrequests table"
        )
    };

    // SAFETY: this is the only writer, and it runs before any reader.
    unsafe { *ptr::addr_of_mut!(IPC_TABLE_DNREQUESTS) = table.as_ptr() };

    // SAFETY: `table` is a fresh allocation of `IPC_TABLE_DNREQUESTS_SIZE`
    // entries, so the whole slice is writable and unshared.
    let its = unsafe {
        slice::from_raw_parts_mut(table.as_ptr(), IPC_TABLE_DNREQUESTS_SIZE)
    };

    let Some(head) = its.get_mut(..IPC_TABLE_DNREQUESTS_SIZE - 1) else {
        return;
    };
    fill(head, 2, IPC_PORT_REQUEST_SIZE);

    if let Some(last) = its.last_mut() {
        last.its_size = 0;
    }
}

/// `ipc_table_alloc()` in C.
///
/// # Safety
///
/// `kalloc_init()` must have run; the caller owns the returned allocation and
/// releases it with [`ipc_table_free()`].
pub(crate) unsafe fn ipc_table_alloc(size: VmSize) -> VmOffset {
    // The caller promises the allocator is up.
    kalloc(size).map_or(0, |buf| buf.as_ptr().addr())
}

/// `ipc_table_free()` in C.
///
/// # Safety
///
/// `table` must be a live allocation of `size` bytes from
/// [`ipc_table_alloc()`] that nothing references afterwards.
pub(crate) unsafe fn ipc_table_free(size: VmSize, table: VmOffset) {
    if let Some(table) = NonNull::new(with_exposed_provenance_mut::<u8>(table))
    {
        unsafe { kfree(table, size) };
    }
}
