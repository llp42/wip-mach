// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/trap.c:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
// Derived from i386/i386/trap.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University
// Derived from i386/include/mach/i386/trap.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The hardware trap and fault handlers, from the low-level entries the
//! assembly stubs call up to the exception and VM-fault handoff.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::ast::I386_FP;
use crate::arch::x86_64::fpu;
use crate::arch::x86_64::pcb::I386SavedState;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::spl;
use crate::arch::x86_64::user_access;
use crate::kern::ast;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::exception as exception_core;
use crate::kern::thread::Thread;
use crate::mig;
use crate::vm::error::Error;
use crate::vm::types::VmProt;
use crate::vm::vm_fault;
use crate::vm::vm_kern;
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_map::{VmMap, trunc_page};
use core::arch::asm;
use core::ffi::{CStr, c_int, c_long, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};

/// The trap number of a divide error.
const T_DIVIDE_ERROR: c_ulong = 0;
/// The trap number of a debug exception.
pub(crate) const T_DEBUG: c_ulong = 1;
/// The trap number of the `int3` breakpoint.
const T_INT3: c_ulong = 3;
/// The trap number of an overflow.
const T_OVERFLOW: c_ulong = 4;
/// The trap number of a bounds-check fault.
const T_OUT_OF_BOUNDS: c_ulong = 5;
/// The trap number of an invalid opcode.
pub(crate) const T_INVALID_OPCODE: c_ulong = 6;
/// The trap number of a missing coprocessor.
const T_NO_FPU: c_ulong = 7;
/// The trap number of a double fault.
pub(crate) const T_DOUBLE_FAULT: c_ulong = 8;
/// The trap number of a coprocessor overrun.
const T_FPU_FAULT: c_ulong = 9;
/// The trap number of a segment-not-present fault.
pub(crate) const T_SEGMENT_NOT_PRESENT: c_ulong = 11;
/// The trap number of a stack fault.
const T_STACK_FAULT: c_ulong = 12;
/// The trap number of a general protection fault.
pub(crate) const T_GENERAL_PROTECTION: c_ulong = 13;
/// The trap number of a page fault.
pub(crate) const T_PAGE_FAULT: c_ulong = 14;
/// The trap number of an x87 floating-point error.
const T_FLOATING_POINT_ERROR: c_ulong = 16;
/// The page-fault error bit marking a write.
const T_PF_WRITE: c_ulong = 0x2;
/// The page-fault error bit marking an access from user state.
pub(crate) const T_PF_USER: c_ulong = 0x4;
/// The flags bit marking a context interrupted in virtual 8086 mode.
pub(crate) const EFL_VM: c_long = 0x0002_0000;

/// The exception code for an inaccessible memory reference.
const EXC_BAD_ACCESS: c_int = 1;
/// The exception code for an illegal or unsupported instruction.
const EXC_BAD_INSTRUCTION: c_int = 2;
/// The exception code for an arithmetic fault.
const EXC_ARITHMETIC: c_int = 3;
/// The exception code for a fault the kernel attributes to software.
const EXC_SOFTWARE: c_int = 5;
/// The exception code for a breakpoint.
const EXC_BREAKPOINT: c_int = 6;

/// The x86 subcode of a divide error.
const EXC_I386_DIV: c_int = 1;
/// The x86 subcode of a single-step trap.
const EXC_I386_SGL: c_int = 1;
/// The x86 subcode of an `int3` breakpoint.
const EXC_I386_BPT: c_int = 2;
/// The x86 subcode of an `into` overflow.
const EXC_I386_INTO: c_int = 2;
/// The x86 subcode of a `bound` range fault.
const EXC_I386_BOUND: c_int = 7;
/// The x86 subcode of an invalid opcode.
const EXC_I386_INVOP: c_int = 1;
/// The x86 subcode of an invalid-TSS fault.
const EXC_I386_INVTSSFLT: c_int = 10;
/// The x86 subcode of a segment-not-present fault.
const EXC_I386_SEGNPFLT: c_int = 11;
/// The x86 subcode of a stack fault.
const EXC_I386_STKFLT: c_int = 12;
/// The x86 subcode of a general protection fault.
const EXC_I386_GPFLT: c_int = 13;
/// The x86 subcode of a page fault.
const EXC_I386_PGFLT: c_int = 14;

/// Where the kernel's linear address range begins.
const LINEAR_MIN_KERNEL_ADDRESS: VmOffset = vm_kern::VM_MIN_KERNEL_ADDRESS;

/// One fault-address/recovery-address pair from the linker's `mach_recover`
/// or `mach_retry` section.
///
/// Both fields hold a full-width offset, the same width as the trap frame's
/// instruction pointer.
#[repr(C)]
#[allow(missing_docs)]
pub struct Recovery {
    fault_addr: c_ulong,
    recover_addr: c_ulong,
}

const _: () = {
    assert!(size_of::<Recovery>() == 16);
    assert!(align_of::<Recovery>() == 8);
    assert!(offset_of!(Recovery, fault_addr) == 0);
    assert!(offset_of!(Recovery, recover_addr) == 8);
};

/// The descriptive name of each trap number, in hardware order.
static TRAP_TYPE: [&CStr; 17] = [
    c"Divide error",
    c"Debug trap",
    c"NMI",
    c"Breakpoint",
    c"Overflow",
    c"Bounds check",
    c"Invalid opcode",
    c"No coprocessor",
    c"Double fault",
    c"Coprocessor overrun",
    c"Invalid TSS",
    c"Segment not present",
    c"Stack bounds",
    c"General protection",
    c"Page fault",
    c"(reserved)",
    c"Coprocessor error",
];

/// Returns the descriptive name registered for a trap number, if any.
fn trap_type(trapnum: c_ulong) -> Option<&'static CStr> {
    let index = usize::try_from(trapnum).ok()?;
    TRAP_TYPE.get(index).copied()
}

/// Returns the name of `trapnum`, or `"(unknown)"` for an unnamed number.
pub(crate) fn trap_name(trapnum: c_uint) -> &'static CStr {
    trap_type(c_ulong::from(trapnum)).unwrap_or(c"(unknown)")
}

/// Maps a linear kernel address into the kernel virtual range.
const fn lintokv(lin: VmOffset) -> VmOffset {
    lin.wrapping_sub(LINEAR_MIN_KERNEL_ADDRESS)
        .wrapping_add(vm_kern::VM_MIN_KERNEL_ADDRESS)
}

/// Scans a recovery table for `regs.eip`; on a hit, redirects it to the
/// recovery address.
fn retry(
    regs: &mut I386SavedState,
    mut entry: *const Recovery,
    end: *const Recovery,
) -> bool {
    while entry < end {
        // SAFETY: the tables are `Recovery` arrays ending at `end`.
        let recovery = unsafe { &*entry };
        if regs.eip == recovery.fault_addr {
            regs.eip = recovery.recover_addr;
            return true;
        }
        entry = entry.wrapping_add(1);
    }
    false
}

/// Fetches the byte at `eip + offset` and narrows it to the opcode byte
/// the callers compare.
fn fetch_byte(eip: c_ulong, cs: c_ulong, offset: c_ulong) -> u8 {
    // The frame's 64-bit values narrow to the `int` parameters
    // `inst_fetch()` takes.
    // SAFETY: both values come from the live trap frame, and
    // `inst_fetch()`'s own `mach_recover` entry handles an unreadable
    // address.
    let fetched = unsafe {
        user_access::inst_fetch(eip.wrapping_add(offset) as c_int, cs as c_int)
    };
    (fetched & 0xff) as u8
}

/// Returns the debug status register.
fn get_dr6() -> c_ulong {
    let value: c_ulong;
    // SAFETY: `mov r, dr6` reads the debug status register and touches no
    // memory; the stack stays balanced.
    unsafe {
        asm!(
            "mov {value}, dr6",
            value = out(reg) value,
            options(nostack, preserves_flags, readonly),
        );
    }
    value
}

/// Loads the debug status register.
fn set_dr6(value: c_ulong) {
    // SAFETY: `mov dr6, r` writes the debug status register and touches no
    // memory; the stack stays balanced.
    unsafe {
        asm!(
            "mov dr6, {value}",
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Delivers an exception to the current thread's handler; never returns.
///
/// # Safety
///
/// Called on the trap or FPU path with nothing locked.
pub(crate) unsafe fn i386_exception(
    exc: c_int,
    code: c_int,
    subcode: c_long,
) -> ! {
    // SAFETY: `splsched()` and `splx()` are the real asm routines.
    let s = unsafe { spl::splsched() };
    ast::off(per_cpu::cpu_id(), I386_FP);
    // SAFETY: `splx()` is the real asm routine.
    let _ = unsafe { spl::splx(s) };

    unsafe { exception_core::exception(exc, code, subcode) }
}

/// Services the AST a CPU posted to itself: the FPU AST takes the FPU
/// path, any other AST the scheduler path.
///
/// # Safety
///
/// Called from the interrupt path with this CPU's AST set by an IPI.
pub(crate) unsafe fn astintr() {
    // SAFETY: `splsched()` is the real asm routine.
    let _ = unsafe { spl::splsched() };
    let mycpu = per_cpu::cpu_id();

    if ast::needed(mycpu).intersects(I386_FP) {
        ast::off(mycpu, I386_FP);
        // SAFETY: `spl0()` is the real asm routine.
        let _ = unsafe { spl::spl0() };
        // SAFETY: the FPU path runs on the trap stack with nothing locked.
        unsafe { fpu::fpexterrflt() };
    } else {
        // SAFETY: `taken()` runs on this CPU's trap stack.
        unsafe { ast::taken() };
    }
}

/// Reports an unhandled kernel trap and halts the kernel.
fn bad_trap(regs: &I386SavedState, type_: c_ulong, code: c_ulong) -> ! {
    kprint!("Kernel ");
    match trap_type(type_) {
        Some(name) => kprint!("{} trap", CStrArg::from(name)),
        None => kprint!("trap {}", type_),
    }
    kprint!(
        ", eip 0x{:x}, code {:x}, cr2 {:x}\n",
        regs.eip,
        code,
        regs.cr2
    );
    // SAFETY: `splhigh()` is the real asm routine.
    let _ = unsafe { spl::splhigh() };
    kprint!("kernel trap, type {}, code = {:x}\n", type_, code);
    // SAFETY: `regs` is the live trap frame.
    unsafe { crate::arch::x86_64::debug_i386::dump_ss(regs) };
    kpanic!("kernel_trap", "trap")
}

/// Recovers the general-protection fault, shared with the page-fault
/// fall-through.
fn general_protection(
    regs: &mut I386SavedState,
    thread: *mut Thread,
    type_: c_ulong,
    code: c_ulong,
) {
    if retry(
        regs,
        ptr::addr_of!(mig::__start_mach_recover),
        ptr::addr_of!(mig::__stop_mach_recover),
    ) {
        return;
    }

    // SAFETY: the trap path runs on a live thread.
    if unsafe { (*thread).recover } != 0 {
        // SAFETY: the thread is live, and its recovery address is set only by
        // the `copyin`/`copyout` paths this trap resumes through.
        unsafe {
            regs.eip = (*thread).recover as c_ulong;
            (*thread).recover = 0;
        }
        return;
    }

    bad_trap(regs, type_, code);
}

/// Handles a kernel-mode page fault.
fn page_fault(
    regs: &mut I386SavedState,
    thread: Option<NonNull<Thread>>,
    type_: c_ulong,
    code: c_ulong,
) {
    // `VmOffset` and the frame's register are the same width, so CR2 is
    // the fault address.
    let mut subcode = regs.cr2 as VmOffset;

    let map = if lintokv(subcode) == 0 || subcode >= LINEAR_MIN_KERNEL_ADDRESS
    {
        // SAFETY: `KERNEL_MAP` is the map the boot path set up and never
        // frees.
        let map = unsafe { KERNEL_MAP }.cast::<VmMap>();
        subcode = lintokv(subcode);

        let image_start = ptr::addr_of!(mig::_start).addr();
        let image_end = ptr::addr_of!(mig::etext).addr();
        if trunc_page(subcode) == 0
            || (image_start <= subcode && subcode < image_end)
        {
            kprint!(
                "Kernel page fault at address 0x{:x}, eip = 0x{:x}\n",
                subcode,
                regs.eip,
            );
            bad_trap(regs, type_, code);
        }
        map
    } else {
        let map = thread.map_or(ptr::null_mut::<VmMap>(), |thread| {
            // SAFETY: the caller promises a live thread, whose task and map
            // are live.
            unsafe { (*(*thread.as_ptr()).task).map }.cast::<VmMap>()
        });
        // SAFETY: `KERNEL_MAP` is the map the boot path set up and never
        // frees.
        if thread.is_none() || map == unsafe { KERNEL_MAP }.cast::<VmMap>() {
            kprint!("kernel page fault at {:08x}:\n", subcode);
            // SAFETY: `regs` is the live trap frame.
            unsafe { crate::arch::x86_64::debug_i386::dump_ss(regs) };
            kpanic!("kernel_trap", "kernel thread accessed user space!\n");
        }
        map
    };

    let protection = if code & T_PF_WRITE != 0 {
        VmProt::READ | VmProt::WRITE
    } else {
        VmProt::READ
    };

    // SAFETY: `map` is live, either the kernel map or the faulting thread's,
    // and `vm_fault()` handles the fault at the page `trunc_page()` names.
    let faulted = unsafe {
        vm_fault::fault(
            map,
            trunc_page(subcode),
            protection,
            false,
            false,
            None,
        )
    };

    if faulted.is_ok() {
        let _ = retry(
            regs,
            ptr::addr_of!(mig::__start_mach_retry),
            ptr::addr_of!(mig::__stop_mach_retry),
        );
        return;
    }

    general_protection(
        regs,
        thread.map_or(ptr::null_mut(), NonNull::as_ptr),
        type_,
        code,
    );
}

/// Dispatches a kernel-mode trap to its handler.
///
/// # Safety
///
/// `regs` must be the live frame the assembly trap entry built.
pub(crate) unsafe fn kernel_trap(regs: &mut I386SavedState) {
    let type_ = regs.trapno;
    let code = regs.err;
    let thread = per_cpu::thread();

    match type_ {
        T_NO_FPU => {
            // SAFETY: the FPU path runs on the trap stack with no lock held.
            unsafe { fpu::fpnoextflt() };
        }
        T_FPU_FAULT => unsafe { fpu::fpextovrflt() },
        T_FLOATING_POINT_ERROR => {
            unsafe { fpu::fpexterrflt() };
        }
        T_PAGE_FAULT => page_fault(regs, NonNull::new(thread), type_, code),
        T_GENERAL_PROTECTION => general_protection(regs, thread, type_, code),
        _ => bad_trap(regs, type_, code),
    }
}

/// Checks for an emulated system call (`int 0x80` or `lcall 7:0`) and bumps
/// the instruction pointer past it.
fn emulated_syscall(regs: &mut I386SavedState, thread: *mut Thread) -> bool {
    // SAFETY: the trap path runs on a live thread, whose task is live.
    if unsafe { (*(*thread).task).eml_dispatch }.is_null() {
        return false;
    }

    let opcode = fetch_byte(regs.eip, regs.cs, 0);
    let intno = fetch_byte(regs.eip, regs.cs, 1);
    if opcode == 0xcd && intno == 0x80 {
        regs.eip = regs.eip.wrapping_add(2);
        return true;
    }

    let mut address = [0u8; 4];
    for (i, byte) in address.iter_mut().enumerate() {
        *byte = fetch_byte(regs.eip, regs.cs, i as c_ulong + 1);
    }
    let mut segment = [0u8; 2];
    for (i, byte) in segment.iter_mut().enumerate() {
        *byte = fetch_byte(regs.eip, regs.cs, i as c_ulong + 5);
    }
    if opcode == 0x9a && segment[0] == 0x7 && segment[1] == 0 {
        regs.eip = regs.eip.wrapping_add(7);
        return true;
    }

    false
}

/// The continuation a user page fault resumes through once `vm_fault()`
/// finishes.
///
/// # Safety
///
/// `vm_fault()` calls this with the result its fault attempt finished
/// with.
unsafe fn user_page_fault_continue(result: Result<(), Error>) {
    let thread = per_cpu::thread();
    // SAFETY: the trap path runs on a live thread whose pcb is set up.
    let regs = unsafe { &mut (*(*thread).pcb).iss };

    match result {
        // SAFETY: the routine returns to user mode and never comes back.
        Ok(()) => unsafe {
            crate::arch::x86_64::locore::thread_exception_return();
        },
        // The exception message carries the fault's error as its code.
        Err(error) => unsafe {
            i386_exception(
                EXC_BAD_ACCESS,
                c_int::from(error),
                regs.cr2 as c_long,
            )
        },
    }
}

/// Dispatches a user-mode trap to its handler or exception.
///
/// # Safety
///
/// `regs` must be the live frame the assembly trap entry built.
pub(crate) unsafe fn user_trap(regs: &mut I386SavedState) -> c_int {
    let thread = per_cpu::thread();
    let type_ = regs.trapno;

    let (exc, code, subcode) = match type_ {
        T_DIVIDE_ERROR => (EXC_ARITHMETIC, EXC_I386_DIV, 0),
        T_DEBUG => {
            // SAFETY: the trap path runs on a live thread; its pcb may not be
            // built yet.
            unsafe {
                if !(*thread).pcb.is_null() {
                    (*(*thread).pcb).ims.ids.dr[6] =
                        (get_dr6() & 0x600f) as c_uint;
                }
            }
            set_dr6(0);
            (EXC_BREAKPOINT, EXC_I386_SGL, 0)
        }
        T_INT3 => (EXC_BREAKPOINT, EXC_I386_BPT, 0),
        T_OVERFLOW => (EXC_ARITHMETIC, EXC_I386_INTO, 0),
        T_OUT_OF_BOUNDS => (EXC_SOFTWARE, EXC_I386_BOUND, 0),
        T_INVALID_OPCODE => (EXC_BAD_INSTRUCTION, EXC_I386_INVOP, 0),
        T_NO_FPU | 32 => {
            // SAFETY: the FPU path runs on the trap stack with no lock held.
            unsafe { fpu::fpnoextflt() };
            return 0;
        }
        T_FPU_FAULT => unsafe { fpu::fpextovrflt() },
        10 => (
            EXC_BAD_INSTRUCTION,
            EXC_I386_INVTSSFLT,
            (regs.err & 0xffff) as c_long,
        ),
        T_SEGMENT_NOT_PRESENT => (
            EXC_BAD_INSTRUCTION,
            EXC_I386_SEGNPFLT,
            (regs.err & 0xffff) as c_long,
        ),
        T_STACK_FAULT => (
            EXC_BAD_INSTRUCTION,
            EXC_I386_STKFLT,
            (regs.err & 0xffff) as c_long,
        ),
        T_GENERAL_PROTECTION => {
            if emulated_syscall(regs, thread) {
                return 1;
            }
            (
                EXC_BAD_INSTRUCTION,
                EXC_I386_GPFLT,
                (regs.err & 0xffff) as c_long,
            )
        }
        T_PAGE_FAULT => {
            // As above: the fault address is the frame's register value.
            let subcode = regs.cr2 as VmOffset;
            if subcode >= LINEAR_MIN_KERNEL_ADDRESS {
                // SAFETY: `i386_exception()` does not return.
                unsafe {
                    i386_exception(
                        EXC_BAD_ACCESS,
                        EXC_I386_PGFLT,
                        subcode as c_long,
                    )
                };
            }

            let protection = if regs.err & T_PF_WRITE != 0 {
                VmProt::READ | VmProt::WRITE
            } else {
                VmProt::READ
            };
            // SAFETY: the trap path runs on a live thread whose task map is
            // live; the continuation resumes the faulting thread with the
            // result.
            let _ = unsafe {
                vm_fault::fault(
                    (*(*thread).task).map.cast::<VmMap>(),
                    trunc_page(subcode),
                    protection,
                    false,
                    false,
                    Some(user_page_fault_continue),
                )
            };
            (0, 0, subcode as c_long)
        }
        T_FLOATING_POINT_ERROR => {
            // SAFETY: the FPU path runs on the trap stack with no lock held.
            unsafe { fpu::fpexterrflt() };
            return 0;
        }
        _ => {
            // SAFETY: `splhigh()` is the real asm routine.
            let _ = unsafe { spl::splhigh() };
            kprint!("user trap, type {}, code = {:x}\n", type_, regs.err);
            // SAFETY: `regs` is the live trap frame.
            unsafe { crate::arch::x86_64::debug_i386::dump_ss(regs) };
            kpanic!("user_trap", "trap");
        }
    };

    // SAFETY: the trap path holds no lock, and `i386_exception()` does not
    // return.
    unsafe { i386_exception(exc, code, subcode) }
}

/// Reports a double fault and halts the kernel.
///
/// # Safety
///
/// `regs` must be the live frame the double-fault entry built.
pub(crate) unsafe fn handle_double_fault(regs: &I386SavedState) {
    // SAFETY: `regs` is the live double-fault frame.
    unsafe { crate::arch::x86_64::debug_i386::dump_ss(regs) };
    kpanic!("handle_double_fault", "DOUBLE FAULT! This is critical\n")
}

/// The C-ABI entry for the AST interrupt.
///
/// # Safety
///
/// Called from the interrupt path with this CPU's AST set by an IPI.
pub(crate) unsafe extern "C" fn i386_astintr() {
    unsafe { astintr() };
}

/// The C-ABI trap entry the assembly stubs call for kernel mode.
///
/// # Safety
///
/// `regs` must point at the live frame the assembly trap entry built.
pub(crate) unsafe extern "C" fn kernel_trap_entry(regs: *mut I386SavedState) {
    unsafe { kernel_trap(&mut *regs) };
}

/// The C-ABI trap entry the assembly stubs call for user mode.
///
/// # Safety
///
/// `regs` must point at the live frame the assembly trap entry built.
pub(crate) unsafe extern "C" fn user_trap_entry(
    regs: *mut I386SavedState,
) -> c_int {
    unsafe { user_trap(&mut *regs) }
}

/// The C-ABI entry the assembly double-fault stub calls.
///
/// # Safety
///
/// `regs` must point at the live frame the double-fault entry built.
pub(crate) unsafe extern "C" fn handle_double_fault_entry(
    regs: *mut I386SavedState,
) {
    unsafe { handle_double_fault(&*regs) };
}
