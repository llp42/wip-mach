// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from ipc/copy_user.c:
//   Copyright (C) 2023 Free Software Foundation
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel's copy of a user message, which `ipc/copy_user.c` used to
//! define and `ipc/copy_user.h` declared.
//!
//! Both configured builds leave `USER32` undefined, so the file's only live
//! definition was the LP64 kernel's `copyinmsg()`; the i386 kernel takes that
//! same entry point from `src/arch/x86_64/user_access.rs`.

use crate::arch::x86_64::user_access;
use crate::ipc::MachMsgHeader;
use core::ffi::c_void;
use core::mem::size_of;

/// The C's `msgh_*_port &= 0xFFFFFFFF`: the pointer-wide unions carry a
/// 32-bit port name.
const PORT_NAME_MASK: usize = 0xFFFF_FFFF;

/// A `copyinmsg()` that did not copy the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyError {
    /// `copyin()` faulted on the user buffer.
    UserFault,
    /// The user size names fewer bytes than a message header.
    TooSmall,
}

/// `copyinmsg()` of `ipc/copy_user.c`: copies the whole user message into the
/// kernel buffer and narrows the header fields the kernel widened.
///
/// # Safety
///
/// `user` must be readable for `size` bytes, and `kernel` must point at a
/// writable buffer of `size` bytes holding at least one [`MachMsgHeader`].
pub(crate) unsafe fn copy_in(
    user: *const c_void,
    kernel: *mut MachMsgHeader,
    size: usize,
) -> Result<(), CopyError> {
    if size < size_of::<MachMsgHeader>() {
        return Err(CopyError::TooSmall);
    }

    if unsafe { user_access::copyin(user, kernel.cast(), size) } != 0 {
        return Err(CopyError::UserFault);
    }

    // SAFETY: the successful copy initialized the whole buffer, and `size` is
    // at least one header.
    let header = unsafe { &mut *kernel };
    // The C stores the low 32 bits of the `size_t` argument into the 32-bit
    // `msgh_size`; every in-tree caller passes a `mach_msg_size_t`.
    header.set_size(size as u32);
    // The user wrote 32-bit port names into the pointer-wide unions, so only
    // their low half is meaningful.
    header.set_remote(header.remote() & PORT_NAME_MASK);
    header.set_local(header.local() & PORT_NAME_MASK);
    Ok(())
}
