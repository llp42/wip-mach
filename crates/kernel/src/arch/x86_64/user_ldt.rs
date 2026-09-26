// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/user_ldt.c:
//   Copyright (c) 1994,1993,1992,1991 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The per-thread LDT and user GDT entries, which `i386/i386/user_ldt.c` used
//! to define and `i386/i386/user_ldt.h` and the MIG `mach_i386` interface
//! declare.
//!
//! The `extern "C"` edge is in [`user_ldt_ffi`].

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::ldt;
use crate::arch::x86_64::pcb::{self, RealDescriptor, UserLdt};
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::seg;
use crate::ipc::ipc_init;
use crate::kern::slab::{kalloc, kfree};
use crate::kern::thread::Thread;
use crate::vm::error::{
    Error as VmError, KERN_INVALID_ARGUMENT, KERN_NO_SPACE,
    KERN_RESOURCE_SHORTAGE,
};
use crate::vm::types::VmProt;
use crate::vm::vm_kern;
use crate::vm::vm_map::{self, VmMapCopy};
use core::ffi::{c_int, c_uint};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// The `switch` labels of `i386_set_ldt()` accepted in a user descriptor, the
/// C's `case` values.
const ACCESS_CALL_GATE: u8 = seg::ACC_P | seg::ACC_CALL_GATE;
const ACCESS_DATA: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_DATA;
const ACCESS_DATA_W: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_DATA_W;
const ACCESS_DATA_E: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_DATA_E;
const ACCESS_DATA_EW: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_DATA_EW;
const ACCESS_CODE: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_CODE;
const ACCESS_CODE_R: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_CODE_R;
const ACCESS_CODE_C: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_CODE_C;
const ACCESS_CODE_CR: u8 = seg::ACC_P | seg::ACC_PL_U | seg::ACC_CODE_CR;
const ACCESS_CALL_GATE_16: u8 =
    seg::ACC_P | seg::ACC_PL_U | seg::ACC_CALL_GATE_16;

/// The C's `template` local: an empty descriptor with only the present bit.
const TEMPLATE: RealDescriptor = RealDescriptor {
    limit_low_base_low: 0,
    access_and_base_high: (seg::ACC_P as u32) << 8,
};

/// `struct descriptor` of <`mach/i386/mach_i386_types.h`>, the MIG view of a
/// descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct Descriptor {
    pub low_word: c_uint,
    pub high_word: c_uint,
}

const _: () = {
    assert!(size_of::<Descriptor>() == 8);
    assert!(align_of::<Descriptor>() == align_of::<c_uint>());
    assert!(core::mem::offset_of!(Descriptor, low_word) == 0);
    assert!(core::mem::offset_of!(Descriptor, high_word) == 4);
};

/// `sel_idx()` of <i386/seg.h> on a signed selector.
const fn sel_idx(selector: c_int) -> c_int {
    selector >> 3
}

/// The failures `i386_set_ldt()` and `i386_get_ldt()` report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// `KERN_INVALID_ARGUMENT`.
    InvalidArgument,
    /// `KERN_NO_SPACE`.
    NoSpace,
    /// `KERN_RESOURCE_SHORTAGE`.
    ResourceShortage,
    /// A failure of the VM map operations.
    Vm(VmError),
}

impl Error {
    /// The `kern_return_t` the C caller sees.
    pub(crate) const fn as_kern_return(self) -> c_int {
        match self {
            Self::InvalidArgument => KERN_INVALID_ARGUMENT,
            Self::NoSpace => KERN_NO_SPACE,
            Self::ResourceShortage => KERN_RESOURCE_SHORTAGE,
            Self::Vm(error) => error.as_kern_return(),
        }
    }
}

/// The `Error` a VM failure stands for.
const fn kern_error(error: VmError) -> Error {
    Error::Vm(error)
}

/// The descriptors of the kernel's IPC map, used as the source for the
/// copyout of an out-of-line descriptor list.
fn ipc_kernel_map() -> *mut vm_map::VmMap {
    ipc_init::ipc_kernel_map()
}

/// `user_ldt_free()` of <`i386/user_ldt.h`>.
///
/// # Safety
///
/// `user_ldt` must be a live LDT allocation from [`set_ldt()`], given up by
/// this call.
pub(crate) unsafe fn free(user_ldt: *mut UserLdt) {
    let size = usize::from(unsafe { (*user_ldt).desc.limit_low() })
        + 1
        + size_of::<RealDescriptor>();
    // SAFETY: the object came from `kalloc()` with that size.
    unsafe { kfree(NonNull::new_unchecked(user_ldt.cast::<u8>()), size) };
}

/// `i386_set_ldt()` of `i386/i386/user_ldt.c`.
///
/// # Safety
///
/// `thread` must be a live thread; `desc_list` must point at `count`
/// writable descriptors when `desc_list_inline` is true, and at a live
/// `vm_map_copy` the caller owns when it is false.
pub(crate) unsafe fn set_ldt(
    thread: NonNull<Thread>,
    first_selector: c_int,
    desc_list: *mut RealDescriptor,
    count: c_uint,
    desc_list_inline: bool,
) -> Result<(), Error> {
    let min_selector = if thread.as_ptr() == per_cpu::thread() {
        seg::LDTSZ as c_uint
    } else {
        0
    };
    // The C stored the signed shift in an `unsigned`, so a negative selector
    // becomes a large index and fails the bound below.
    let first_desc = sel_idx(first_selector) as c_uint;
    if first_desc < min_selector || first_desc > 8191 {
        return Err(Error::InvalidArgument);
    }
    // The MIG count is at most `0x7fffffff`, so the C's unsigned sum cannot
    // wrap before this check rejects the large values.
    if first_desc + count >= 8192 {
        return Err(Error::InvalidArgument);
    }

    let (desc_list, copy_object, copyin_addr) =
        unsafe { copyin_ldt_list(desc_list, count, desc_list_inline) }?;

    let descriptors: &mut [RealDescriptor] = if count == 0 {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(desc_list, count as usize) }
    };
    // SAFETY: `descriptors` is the live, writable list just assembled.
    if let Err(error) = unsafe { validate_descriptors(descriptors) } {
        free_copy(copyin_addr, copy_object, count);
        return Err(error);
    }

    let ldt_size_needed =
        size_of::<RealDescriptor>() * (first_desc + count) as usize;
    let pcb = unsafe { (*thread.as_ptr()).pcb };
    let mut new_ldt: Option<NonNull<UserLdt>> = None;

    loop {
        unsafe { (*pcb).lock.lock() };
        let old_ldt = NonNull::new(unsafe { (*pcb).ims.ldt });
        let too_small = old_ldt.is_none_or(|old| {
            // SAFETY: `old` is the live LDT the pcb names.
            usize::from(unsafe { (*old.as_ptr()).desc.limit_low() }) + 1
                < ldt_size_needed
        });

        if too_small {
            let Some(new) = new_ldt else {
                // SAFETY: this CPU took the pcb lock above.
                unsafe { (*pcb).lock.unlock() };
                let Some(buf) =
                    kalloc(ldt_size_needed + size_of::<RealDescriptor>())
                else {
                    return Err(Error::ResourceShortage);
                };
                let new = buf.as_ptr().cast::<UserLdt>();
                // The C wrote the self descriptor field by field; a
                // `fill_descriptor()` would shift the wrapped
                // `ldt_size_needed - 1` of the zero-length case.  The size
                // is at most 8192 descriptors, so the `u32` cast is exact.
                //
                // SAFETY: the allocation holds the struct and the descriptor
                // table `ldt_size_needed` bytes long; `kvtolin()` is the
                // identity.
                unsafe {
                    let base = ptr::addr_of_mut!((*new).ldt) as VmOffset;
                    let desc = &mut (*new).desc;
                    desc.limit_low_base_low =
                        (ldt_size_needed as u32).wrapping_sub(1) & 0xffff
                            | (((base & 0xffff) as u32) << 16);
                    desc.access_and_base_high = ((base >> 16) & 0xff) as u32
                        | (u32::from(seg::ACC_P | seg::ACC_LDT) << 8)
                        | (((base >> 24) & 0xff) as u32) << 24;
                }
                new_ldt = NonNull::new(new);
                continue;
            };

            if let Some(old) = old_ldt {
                // SAFETY: both LDTs are live allocations, and the old
                // one's own size covers the bytes copied.
                unsafe {
                    ptr::copy_nonoverlapping(
                        ptr::addr_of!((*old.as_ptr()).ldt).cast::<u8>(),
                        ptr::addr_of_mut!((*new.as_ptr()).ldt).cast::<u8>(),
                        usize::from((*old.as_ptr()).desc.limit_low()) + 1,
                    );
                }
            } else {
                // SAFETY: `new` is the live allocation the branch above
                // made.
                let entries = unsafe {
                    ptr::addr_of_mut!((*new.as_ptr()).ldt)
                        .cast::<RealDescriptor>()
                };
                for i in 0..first_desc as usize {
                    // SAFETY: the index is below `LDTSZ` only in the
                    // first arm; the default LDT covers it there.
                    let entry = if i < seg::LDTSZ {
                        // SAFETY: `i` is below `LDTSZ` in this arm; the
                        // default LDT covers it.
                        unsafe { ldt::entry(i) }
                    } else {
                        TEMPLATE
                    };
                    // SAFETY: the allocation holds `ldt_size_needed`
                    // descriptors and `first_desc` is inside that count.
                    unsafe { entries.add(i).write(entry) };
                }
            }

            // SAFETY: `new` is the live allocation the branch above made,
            // and this CPU holds the pcb lock.
            unsafe { (*pcb).ims.ldt = new.as_ptr() };
            new_ldt = old_ldt;
            if thread.as_ptr() == per_cpu::thread() {
                unsafe { pcb::switch_ktss(pcb) };
            }
        }

        // SAFETY: the branch above made the pcb's LDT non-null and at
        // least `ldt_size_needed` bytes, and `count` ends inside that size.
        unsafe {
            install_descriptors(pcb, descriptors, first_desc, count);
        }
        break;
    }

    // SAFETY: `new_ldt` is the loop's leftover allocation, from `kalloc()`.
    unsafe { free_replaced_ldt(new_ldt) };
    free_copy(copyin_addr, copy_object, count);

    Ok(())
}

/// The pieces an out-of-line descriptor list copyout produces: the kernel
/// address, the emptied copy object, and that address when one was copied.
type LdtList = (
    *mut RealDescriptor,
    Option<NonNull<VmMapCopy>>,
    Option<VmOffset>,
);

/// Copy an out-of-line descriptor list into the kernel's IPC map, as the
/// C's `vm_map_copyout` did.
///
/// # Safety
///
/// `desc_list` must be the caller's live `vm_map_copy` when
/// `desc_list_inline` is false, and the kernel IPC map must be unlocked.
/// The returned address and copy must go to [`free_copy()`].
unsafe fn copyin_ldt_list(
    desc_list: *mut RealDescriptor,
    count: c_uint,
    desc_list_inline: bool,
) -> Result<LdtList, Error> {
    if desc_list_inline {
        return Ok((desc_list, None, None));
    }
    let copy =
        unsafe { NonNull::new_unchecked(desc_list.cast::<VmMapCopy>()) };
    // SAFETY: the kernel's IPC map is a live map.
    let map = unsafe { &mut *ipc_kernel_map() };
    let dst = match unsafe { map.copyout(VmMapCopy::duplicate(copy)) } {
        Ok(dst) => dst,
        Err(error) => return Err(kern_error(error)),
    };
    // The C ignores the pageable result.
    let _ = map.pageable(
        dst,
        dst + count as usize * size_of::<RealDescriptor>(),
        VmProt::READ | VmProt::WRITE,
        true,
        true,
    );
    Ok((
        ptr::with_exposed_provenance_mut::<RealDescriptor>(dst),
        Some(copy),
        Some(dst),
    ))
}

/// Validate the access bits of an `i386_set_ldt()` descriptor list,
/// replacing the kernel call gate and rejecting unsupported kinds.
///
/// # Safety
///
/// `descriptors` must be the live, writable list the caller assembled.
unsafe fn validate_descriptors(
    descriptors: &mut [RealDescriptor],
) -> Result<(), Error> {
    for dp in descriptors.iter_mut() {
        match dp.access() & !seg::ACC_A {
            0
            | seg::ACC_P
            | ACCESS_DATA
            | ACCESS_DATA_W
            | ACCESS_DATA_E
            | ACCESS_DATA_EW
            | ACCESS_CODE
            | ACCESS_CODE_R
            | ACCESS_CODE_C
            | ACCESS_CODE_CR
            | ACCESS_CALL_GATE_16 => (),
            ACCESS_CALL_GATE => {
                // SAFETY: the default LDT's first entry is the syscall gate.
                *dp = unsafe { ldt::entry(seg::sel_idx(seg::USER_SCALL)) };
            }
            _ => return Err(Error::InvalidArgument),
        }
    }
    Ok(())
}

/// Copy `descriptors` into the pcb's LDT and release the pcb lock.
///
/// # Safety
///
/// The caller must hold `pcb`'s lock, the pcb's LDT must be live and cover
/// `count` descriptors at `first_desc`, and `descriptors` must be the live
/// list to copy.
unsafe fn install_descriptors(
    pcb: *mut pcb::Pcb,
    descriptors: &[RealDescriptor],
    first_desc: c_uint,
    count: c_uint,
) {
    unsafe {
        let target = (*pcb).ims.ldt;
        ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            ptr::addr_of_mut!((*target).ldt)
                .cast::<RealDescriptor>()
                .add(first_desc as usize),
            count as usize,
        );
        (*pcb).lock.unlock();
    }
}

/// Free the LDT a failed or replaced growth left behind, if any.
///
/// # Safety
///
/// A `Some` must be an allocation from `kalloc()` with the size its own
/// descriptor limit names.
unsafe fn free_replaced_ldt(new_ldt: Option<NonNull<UserLdt>>) {
    if let Some(new) = new_ldt {
        // SAFETY: `new` is the allocation the loop replaced or never used.
        let size = usize::from(unsafe { (*new.as_ptr()).desc.limit_low() })
            + 1
            + size_of::<RealDescriptor>();
        unsafe { kfree(new.cast::<u8>(), size) };
    }
}

/// Discard the kernel-mapped copy an out-of-line descriptor list was copied
/// out to, and the emptied copy object it came from.
fn free_copy(
    copyin_addr: Option<VmOffset>,
    copy_object: Option<NonNull<VmMapCopy>>,
    count: c_uint,
) {
    if let Some(addr) = copyin_addr {
        // SAFETY: `addr` came from `vm_map_copyout` on the kernel map.
        let _ = vm_kern::kmem_free(
            unsafe { &mut *ipc_kernel_map() },
            addr,
            count as usize * size_of::<RealDescriptor>(),
        );
    }
    if let Some(copy) = copy_object {
        // SAFETY: the caller owns the live copy, emptied by `duplicate()`.
        unsafe { VmMapCopy::discard(copy) };
    }
}

/// `i386_get_ldt()` of `i386/i386/user_ldt.c`.
///
/// # Safety
///
/// `thread` must be a live thread, and `out` must be the caller's writable
/// descriptor storage.
pub(crate) unsafe fn get_ldt(
    thread: NonNull<Thread>,
    first_selector: c_int,
    selector_count: c_int,
    out: Option<&mut [RealDescriptor]>,
) -> Result<(c_uint, Option<NonNull<VmMapCopy>>), Error> {
    let first_desc = sel_idx(first_selector);
    if !(0..=8191).contains(&first_desc) {
        return Err(Error::InvalidArgument);
    }
    if first_desc.wrapping_add(selector_count) >= 8192 {
        return Err(Error::InvalidArgument);
    }

    let capacity = out.as_ref().map_or(0, |list| list.len());
    let pcb = unsafe { (*thread.as_ptr()).pcb };
    let mut addr: Option<VmOffset> = None;
    let mut size: VmSize = 0;

    let (user_ldt, ldt_count, ldt_size) = loop {
        unsafe { (*pcb).lock.lock() };
        let user_ldt = unsafe { (*pcb).ims.ldt };
        if user_ldt.is_null() {
            // SAFETY: this CPU took the pcb lock above.
            unsafe { (*pcb).lock.unlock() };
            if let Some(addr) = addr {
                // SAFETY: `addr` is this call's live kernel allocation.
                let _ = vm_kern::kmem_free(
                    unsafe { &mut *ipc_kernel_map() },
                    addr,
                    size,
                );
            }
            return Ok((0, None));
        }

        // The C compared the unsigned count against the signed selector
        // count, so a negative one becomes large here.
        // SAFETY: `user_ldt` is the live LDT read above.
        let mut ldt_count =
            (u32::from(unsafe { (*user_ldt).desc.limit_low() }) + 1)
                / size_of::<RealDescriptor>() as u32;
        ldt_count = ldt_count.wrapping_sub(first_desc as u32);
        if ldt_count > selector_count as u32 {
            ldt_count = selector_count as u32;
        }
        let ldt_size =
            (ldt_count as usize).wrapping_mul(size_of::<RealDescriptor>());

        if ldt_count as usize <= capacity {
            break (user_ldt, ldt_count, ldt_size);
        }

        let size_needed = vm_map::round_page(ldt_size);
        if size_needed <= size {
            break (user_ldt, ldt_count, ldt_size);
        }

        // SAFETY: this CPU took the pcb lock above.
        unsafe { (*pcb).lock.unlock() };
        if let Some(addr) = addr {
            // SAFETY: `addr` is this call's live kernel allocation.
            let _ = vm_kern::kmem_free(
                unsafe { &mut *ipc_kernel_map() },
                addr,
                size,
            );
        }
        size = size_needed;

        // SAFETY: the kernel IPC map is live and unlocked here.
        let map = unsafe { NonNull::new_unchecked(ipc_kernel_map()) };
        match vm_kern::kmem_alloc(map, size) {
            Ok(allocated) => addr = Some(allocated),
            Err(_) => return Err(Error::ResourceShortage),
        }
    };

    // SAFETY: `user_ldt` is the live LDT the loop's lock held.
    let source = unsafe { ptr::addr_of!((*user_ldt).ldt) }
        .cast::<RealDescriptor>()
        .wrapping_add(first_desc as usize);
    match addr {
        Some(addr) => {
            // SAFETY: the loop's allocation is at least `ldt_size` bytes, and
            // `ldt_count` is inside it.
            unsafe {
                ptr::copy_nonoverlapping(
                    source,
                    ptr::with_exposed_provenance_mut::<RealDescriptor>(addr),
                    ldt_count as usize,
                );
            }
        }
        None => {
            if let Some(out) = out {
                // The loop only breaks into this arm when the caller's
                // storage covers the count.
                let Some(dst) = out.get_mut(..ldt_count as usize) else {
                    // SAFETY: this CPU holds the pcb lock here.
                    unsafe { (*pcb).lock.unlock() };
                    return Err(Error::InvalidArgument);
                };
                // SAFETY: both sides hold `ldt_count` descriptors.
                unsafe {
                    ptr::copy_nonoverlapping(
                        source,
                        dst.as_mut_ptr(),
                        ldt_count as usize,
                    );
                }
            }
        }
    }
    // SAFETY: this CPU holds the pcb lock here.
    unsafe { (*pcb).lock.unlock() };

    // SAFETY: `addr` is this call's live kernel allocation, and the kernel
    // IPC map is unlocked.
    let copy = unsafe { copy_out_ldt(addr, size, ldt_size) }?;

    Ok((ldt_count, copy))
}

/// Trim, page-pad, and copy this call's kernel buffer into a fresh
/// `vm_map_copy`, as the C's `vm_map_copyin` path did.
///
/// # Safety
///
/// `addr` must be this call's live kernel allocation of `size` bytes, and
/// `ldt_size` the used bytes at its front.
unsafe fn copy_out_ldt(
    addr: Option<VmOffset>,
    size: VmSize,
    ldt_size: VmSize,
) -> Result<Option<NonNull<VmMapCopy>>, Error> {
    let Some(addr) = addr else {
        return Ok(None);
    };
    let size_used = vm_map::round_page(ldt_size);
    if size_used != size {
        // SAFETY: `addr` is this call's live kernel allocation of
        // `size` bytes.
        let _ = vm_kern::kmem_free(
            unsafe { &mut *ipc_kernel_map() },
            addr + size_used,
            size - size_used,
        );
    }
    let size_left = size_used - ldt_size;
    if size_left > 0 {
        // SAFETY: the allocation reaches `size_used` bytes.
        unsafe {
            ptr::write_bytes(
                ptr::with_exposed_provenance_mut::<u8>(addr + ldt_size),
                0,
                size_left,
            );
        }
    }

    // SAFETY: `addr` is this call's live kernel allocation, and the map
    // is unlocked.
    let map = unsafe { &mut *ipc_kernel_map() };
    // The C copied the kernel buffer, not the caller's list, into the
    // copy object; the port keeps that.
    match map.copyin(addr, size_used, true) {
        Ok(memory) => Ok(Some(memory)),
        Err(error) => Err(kern_error(error)),
    }
}

/// `i386_set_gdt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be a live thread.  On return `selector` is written
/// when it was `-1` and a slot was free.
pub(crate) unsafe fn set_gdt(
    thread: NonNull<Thread>,
    selector: *mut c_int,
    descriptor: Descriptor,
) -> Result<(), Error> {
    let pcb = unsafe { (*thread.as_ptr()).pcb };
    let user_gdt = unsafe { &mut (*pcb).ims.user_gdt };
    let selector_value = unsafe { *selector };
    let idx;

    if selector_value == -1 {
        let Some(free) = user_gdt
            .iter()
            .position(|entry| entry.access() & seg::ACC_P == 0)
        else {
            return Err(Error::NoSpace);
        };
        idx = free;
        // The slot index is below `USER_GDT_SLOTS`, so this widens exactly.
        let selector_int = free as c_int + sel_idx(seg::USER_GDT);
        unsafe { *selector = (selector_int << 3) | seg::SEL_PL_U };
    } else if (selector_value & (seg::SEL_LDT | seg::SEL_PL)) != seg::SEL_PL_U
        || sel_idx(selector_value) < sel_idx(seg::USER_GDT)
        || sel_idx(selector_value)
            >= sel_idx(seg::USER_GDT) + seg::USER_GDT_SLOTS as c_int
    {
        return Err(Error::InvalidArgument);
    } else {
        let index = sel_idx(selector_value) - sel_idx(seg::USER_GDT);
        // The bound above keeps the index inside `USER_GDT_SLOTS`.
        idx = index as usize;
    }

    let desc = RealDescriptor {
        limit_low_base_low: descriptor.low_word,
        access_and_base_high: descriptor.high_word,
    };
    if desc.access() & seg::ACC_P == 0 {
        user_gdt[idx] = RealDescriptor::ZERO;
    } else if (desc.access() & (seg::ACC_TYPE_USER | seg::ACC_PL))
        != (seg::ACC_TYPE_USER | seg::ACC_PL_U)
        || desc.granularity() & seg::SZ_64 != 0
    {
        return Err(Error::InvalidArgument);
    } else {
        user_gdt[idx] = desc;
    }

    if thread.as_ptr() == per_cpu::thread() {
        unsafe { pcb::switch_ktss(pcb) };
    }
    Ok(())
}

/// `i386_get_gdt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be a live thread, and `descriptor` writable.
pub(crate) unsafe fn get_gdt(
    thread: NonNull<Thread>,
    selector: c_int,
    descriptor: *mut Descriptor,
) -> Result<(), Error> {
    if (selector & (seg::SEL_LDT | seg::SEL_PL)) != seg::SEL_PL_U
        || sel_idx(selector) < sel_idx(seg::USER_GDT)
        || sel_idx(selector)
            >= sel_idx(seg::USER_GDT) + seg::USER_GDT_SLOTS as c_int
    {
        return Err(Error::InvalidArgument);
    }

    let pcb = unsafe { (*thread.as_ptr()).pcb };
    let index = (sel_idx(selector) - sel_idx(seg::USER_GDT)) as usize;
    // SAFETY: the bound check above keeps the index inside `user_gdt`.
    let entry = unsafe { (*pcb).ims.user_gdt[index] };
    unsafe {
        *descriptor = Descriptor {
            low_word: entry.limit_low_base_low,
            high_word: entry.access_and_base_high,
        };
    }
    Ok(())
}
