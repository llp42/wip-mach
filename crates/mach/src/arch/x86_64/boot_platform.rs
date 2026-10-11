// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The bootstrap's platform: what the first user tasks ask of the `x86_64`
//! machine.

use crate::arch::vm_param::VM_MAX_USER_ADDRESS;
use crate::arch::x86_64::multiboot::MultibootModule;
use crate::arch::x86_64::pcb;
use crate::arch::x86_64::platform::MachPlatform;
use crate::kern::printf;
use core::ffi::CStr;
use mach_boot::platform::{Module, Platform};
use mach_vm::param::{VmOffset, VmSize};

impl Module for MultibootModule {
    fn command_line(&self) -> &CStr {
        Self::command_line(self)
    }

    fn image(&self) -> &[u8] {
        Self::image(self)
    }
}

// SAFETY: each item keeps its documented contract: the module is the
// loader's, user space ends at the machine's limit, the registers are the
// current thread's, and the line comes from the console.
unsafe impl Platform for MachPlatform {
    type Module = MultibootModule;

    const USER_ADDRESS_END: VmOffset = VM_MAX_USER_ADDRESS;

    unsafe fn set_user_regs(
        stack_base: VmOffset,
        stack_size: VmSize,
        entry: VmOffset,
        arg_size: VmSize,
    ) -> VmOffset {
        // SAFETY: the caller runs on the current thread, whose pcb is live.
        unsafe { pcb::set_user_regs(stack_base, stack_size, entry, arg_size) }
    }

    fn read_line(line: &mut [u8]) {
        printf::read_line(line);
    }
}
