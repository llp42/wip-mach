// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/pcb.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// Derived from i386/i386/thread.h and i386/i386/seg.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// Derived from i386/include/mach/i386/thread_status.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The PCB, the user-state save and restore and the context switch.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::{KERNEL_STACK_SIZE, VM_MAX_USER_ADDRESS};
use crate::arch::x86_64::cswitch;
use crate::arch::x86_64::error::Error;
use crate::arch::x86_64::fpu::{self, I386FpSaveState};
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::pmap::{activate_user, deactivate_user};
use crate::arch::x86_64::{db_interface, user_ldt};
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::kern::task::{Task, current_task};
use crate::kern::thread::{Continuation, StackResume, Thread};
use crate::vm::vm_map::VmMap;
use core::ffi::{c_int, c_long, c_uint, c_ulong, c_ushort, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};

/// The alignment of a kernel stack.
const KERNEL_STACK_ALIGN: usize = 16;

/// The alignment of a user stack.
const USER_STACK_ALIGN: VmSize = 16;

/// The user code and data selectors.
const USER_CS: c_ulong = 0x1f;
const USER_DS: c_ulong = 0x17;

/// The kernel LDT, user LDT and user GDT selectors.
const KERNEL_LDT: c_ushort = 0x18;
const USER_LDT: c_ushort = 0x28;
const USER_GDT: c_ushort = 0x48;
/// The per-thread GDT entries.
const USER_GDT_SLOTS: usize = 2;

/// An offset outside the permission bitmap, which disables all permission.
const IOPB_INVAL: c_ushort = 0x2fff;
/// The interrupt-enable flag.
const EFL_IF: c_ulong = 0x0000_0200;
/// The flags a user state always has set, and always has clear.
const EFL_USER_SET: c_ulong = EFL_IF;
const EFL_USER_CLEAR: c_ulong = 0x3000 | 0x4000 | 0x0001_0000;

/// The selector privilege-level mask and the user level.
const SEL_PL: c_uint = 0x03;
const SEL_PL_U: c_uint = 0x03;

/// The FS, GS and kernel-GS base MSRs; the other registers below are the ones
/// [`ldt`](crate::arch::x86_64::ldt) and [`gdt`](crate::arch::x86_64::gdt)
/// write.
pub(crate) const MSR_REG_FSBASE: u32 = 0xc000_0100;
pub(crate) const MSR_REG_GSBASE: u32 = 0xc000_0101;
pub(crate) const MSR_REG_KGSBASE: u32 = 0xc000_0102;
/// The EFER, STAR, LSTAR and FMASK MSRs.
pub(crate) const MSR_REG_EFER: u32 = 0xc000_0080;
pub(crate) const MSR_REG_STAR: u32 = 0xc000_0081;
pub(crate) const MSR_REG_LSTAR: u32 = 0xc000_0082;
pub(crate) const MSR_REG_FMASK: u32 = 0xc000_0084;
/// The EFER bit that enables SYSCALL/SYSRET.
pub(crate) const MSR_EFER_SCE: u64 = 0x1;
/// The EFER bit that enables long mode.
pub(crate) const MSR_REG_EFER_LONG_MODE_EN: u64 = 1 << 8;

/// The thread-state flavors.
pub(crate) const I386_THREAD_STATE: c_int = 1;
pub(crate) const I386_ISA_PORT_MAP_STATE: c_int = 3;
pub(crate) const I386_REGS_SEGS_STATE: c_int = 5;
pub(crate) const I386_DEBUG_STATE: c_int = 6;
pub(crate) const I386_FSGS_BASE_STATE: c_int = 7;
/// The flavor that lists the flavors.
const THREAD_STATE_FLAVOR_LIST: c_int = 0;

/// The size of an [`I386ThreadState`], in integers.
const I386_THREAD_STATE_COUNT: c_uint =
    (size_of::<I386ThreadState>() / size_of::<c_uint>()) as c_uint;
/// The size of a float state, in integers.
const I386_FLOAT_STATE_COUNT: c_uint =
    (size_of::<fpu::I386FloatState>() / size_of::<c_uint>()) as c_uint;
/// The size of an [`I386IsaPortMapState`], in integers.
const I386_ISA_PORT_MAP_STATE_COUNT: c_uint =
    (size_of::<I386IsaPortMapState>() / size_of::<c_uint>()) as c_uint;
/// The size of an [`I386DebugState`], in integers.
const I386_DEBUG_STATE_COUNT: c_uint =
    (size_of::<I386DebugState>() / size_of::<c_uint>()) as c_uint;
/// The size of an [`I386FsgsBaseState`], in integers.
const I386_FSGS_BASE_STATE_COUNT: c_uint = 4;

/// The user registers as saved on kernel entry.  It lives in the pcb and is
/// pushed on the stack for kernel exceptions.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386SavedState {
    pub r15: c_ulong,
    pub r14: c_ulong,
    pub r13: c_ulong,
    pub r12: c_ulong,
    pub r11: c_ulong,
    pub r10: c_ulong,
    pub r9: c_ulong,
    pub r8: c_ulong,
    pub edi: c_ulong,
    pub esi: c_ulong,
    pub ebp: c_ulong,
    pub cr2: c_ulong,
    pub ebx: c_ulong,
    pub edx: c_ulong,
    pub ecx: c_ulong,
    pub eax: c_ulong,
    pub trapno: c_ulong,
    pub err: c_ulong,
    pub eip: c_ulong,
    pub cs: c_ulong,
    pub efl: c_ulong,
    pub uesp: c_ulong,
    pub ss: c_ulong,
}

const _: () = {
    assert!(size_of::<I386SavedState>() == 184);
    assert!(align_of::<I386SavedState>() == align_of::<c_ulong>());
    assert!(offset_of!(I386SavedState, r15) == 0);
    assert!(offset_of!(I386SavedState, r8) == 56);
    assert!(offset_of!(I386SavedState, edi) == 64);
    assert!(offset_of!(I386SavedState, cr2) == 88);
    assert!(offset_of!(I386SavedState, eax) == 120);
    assert!(offset_of!(I386SavedState, trapno) == 128);
    assert!(offset_of!(I386SavedState, eip) == 144);
    assert!(offset_of!(I386SavedState, efl) == 160);
    assert!(offset_of!(I386SavedState, uesp) == 168);
    assert!(offset_of!(I386SavedState, ss) == 176);
};

/// The registers an interrupt pushes before the kernel can switch to the
/// interrupt stack.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386InterruptState {
    pub r12: c_long,
    pub r11: c_long,
    pub r10: c_long,
    pub r9: c_long,
    pub r8: c_long,
    pub rdi: c_long,
    pub rsi: c_long,
    pub edx: c_long,
    pub ecx: c_long,
    pub eax: c_long,
    pub eip: c_long,
    pub cs: c_long,
    pub efl: c_long,
}

const _: () = {
    assert!(size_of::<I386InterruptState>() == 104);
    assert!(align_of::<I386InterruptState>() == align_of::<c_long>());
    assert!(offset_of!(I386InterruptState, r12) == 0);
    assert!(offset_of!(I386InterruptState, r8) == 32);
    assert!(offset_of!(I386InterruptState, edx) == 56);
    assert!(offset_of!(I386InterruptState, eip) == 80);
    assert!(offset_of!(I386InterruptState, efl) == 96);
};

/// The kernel registers as saved in a context switch, at the base of the
/// stack.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386KernelState {
    pub k_ebx: c_long,
    pub k_esp: c_long,
    pub k_ebp: c_long,
    pub k_eip: c_long,
    pub k_r12: c_long,
    pub k_r13: c_long,
    pub k_r14: c_long,
    pub k_r15: c_long,
}

const _: () = {
    assert!(size_of::<I386KernelState>() == 64);
    assert!(align_of::<I386KernelState>() == align_of::<c_long>());
    assert!(offset_of!(I386KernelState, k_eip) == 24);
    assert!(offset_of!(I386KernelState, k_r12) == 32);
};

/// The pointer to the current thread's user registers at the high end of the
/// kernel stack.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386ExceptionLink {
    pub saved_state: *mut I386SavedState,
}

const _: () = {
    assert!(size_of::<I386ExceptionLink>() == size_of::<*mut c_void>());
    assert!(align_of::<I386ExceptionLink>() == align_of::<*mut c_void>());
    assert!(offset_of!(I386ExceptionLink, saved_state) == 0);
};

/// `struct i386_debug_state`: the debug registers of a thread.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386DebugState {
    pub dr: [c_uint; 8],
}

const _: () = {
    assert!(size_of::<I386DebugState>() == 32);
    assert!(align_of::<I386DebugState>() == align_of::<c_uint>());
    assert!(offset_of!(I386DebugState, dr) == 0);
};

/// The FS and GS bases of a thread.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386SegmentBaseState {
    pub fsbase: c_ulong,
    pub gsbase: c_ulong,
}

const _: () = {
    assert!(size_of::<I386SegmentBaseState>() == 16);
    assert!(align_of::<I386SegmentBaseState>() == align_of::<c_ulong>());
    assert!(offset_of!(I386SegmentBaseState, fsbase) == 0);
    assert!(offset_of!(I386SegmentBaseState, gsbase) == 8);
};

/// A segment descriptor, whose bitfields are kept as two words.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct RealDescriptor {
    pub limit_low_base_low: u32,
    pub access_and_base_high: u32,
}

impl RealDescriptor {
    /// An all-zero descriptor, the image a C `static` began with.
    pub(crate) const ZERO: Self = Self {
        limit_low_base_low: 0,
        access_and_base_high: 0,
    };

    /// The `access` byte of the C's `desc->access`.
    pub(crate) const fn access(self) -> u8 {
        (self.access_and_base_high >> 8) as u8
    }

    /// The `granularity` nibble of the C's `desc->granularity`.
    pub(crate) const fn granularity(self) -> u8 {
        ((self.access_and_base_high >> 20) & 0xf) as u8
    }

    /// The `limit_low` half of the C's `desc->limit_low`.
    pub(crate) const fn limit_low(self) -> u16 {
        self.limit_low_base_low as u16
    }
}

const _: () = {
    assert!(size_of::<RealDescriptor>() == 8);
    assert!(align_of::<RealDescriptor>() == align_of::<u32>());
    assert!(offset_of!(RealDescriptor, limit_low_base_low) == 0);
    assert!(offset_of!(RealDescriptor, access_and_base_high) == 4);
};

/// A descriptor table in static storage, aligned so that no descriptor
/// straddles a cache line.
///
/// The CPU sets a descriptor's accessed and busy bits with a locked write,
/// and a host that detects split locks faults one that spans two lines;
/// during interrupt delivery that fault stops the machine.
#[repr(C, align(8))]
pub(crate) struct DescriptorTable<const N: usize>(
    pub(crate) [RealDescriptor; N],
);

/// The descriptor for the table itself followed by the table, which is larger
/// than one entry in practice.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct UserLdt {
    pub desc: RealDescriptor,
    pub ldt: [RealDescriptor; 1],
}

const _: () = {
    assert!(size_of::<UserLdt>() == 16);
    assert!(align_of::<UserLdt>() == align_of::<RealDescriptor>());
    assert!(offset_of!(UserLdt, desc) == 0);
    assert!(offset_of!(UserLdt, ldt) == 8);
};

/// The bytes of an I/O permission bitmap: one bit per I/O port.
const IOPB_BYTES: usize = 0x2000;

/// The x86 task state segment.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386Tss {
    pub reserved0: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    pub reserved1: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    pub reserved2: u64,
    pub reserved3: c_ushort,
    pub io_bit_map_offset: c_ushort,
}

const _: () = {
    assert!(size_of::<I386Tss>() == 104);
    assert!(align_of::<I386Tss>() == 1);
    assert!(offset_of!(I386Tss, rsp0) == 4);
    assert!(offset_of!(I386Tss, io_bit_map_offset) == 102);
};

/// The TSS plus the I/O permission bitmap and its terminating barrier byte.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct TaskTss {
    pub tss: I386Tss,
    pub iopb: [u8; IOPB_BYTES],
    pub barrier: u8,
}

const _: () = {
    assert!(size_of::<TaskTss>() == 8297);
    assert!(align_of::<TaskTss>() == 1);
    assert!(offset_of!(TaskTss, tss) == 0);
    assert!(offset_of!(TaskTss, barrier) == 8296);
};

/// The machine-dependent part of a pcb that is not saved by default.
#[repr(C)]
#[allow(missing_docs)]
pub struct I386MachineState {
    pub ldt: *mut UserLdt,
    pub ifps: *mut I386FpSaveState,
    pub user_gdt: [RealDescriptor; USER_GDT_SLOTS],
    pub ids: I386DebugState,
    pub sbs: I386SegmentBaseState,
}

const _: () = {
    assert!(size_of::<I386MachineState>() == 80);
    assert!(align_of::<I386MachineState>() == align_of::<*mut c_void>());
    assert!(offset_of!(I386MachineState, ldt) == 0);
    assert!(offset_of!(I386MachineState, ifps) == 8);
    assert!(offset_of!(I386MachineState, user_gdt) == 16);
    assert!(offset_of!(I386MachineState, ids) == 32);
    assert!(offset_of!(I386MachineState, sbs) == 64);
};

/// The process control block.
#[repr(C)]
#[allow(missing_docs)]
pub struct Pcb {
    pub iis: [I386InterruptState; 2],
    pub pad: c_ulong,
    pub iss: I386SavedState,
    pub ims: I386MachineState,
    pub lock: SimpleLock,
    pub init_control: c_ushort,
}

const _: () = {
    assert!(size_of::<Pcb>() == 488);
    assert!(align_of::<Pcb>() == align_of::<c_ulong>());
    assert!(offset_of!(Pcb, iis) == 0);
    assert!(offset_of!(Pcb, pad) == 208);
    assert!(offset_of!(Pcb, iss) == 216);
    assert!(offset_of!(Pcb, ims) == 400);
    assert!(offset_of!(Pcb, lock) == 480);
    assert!(offset_of!(Pcb, init_control) == 484);
};

/// `struct i386_thread_state`: the user registers of a thread.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386ThreadState {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: c_uint,
    pub rfl: u64,
    pub ursp: u64,
    pub ss: c_uint,
}

const _: () = {
    assert!(size_of::<I386ThreadState>() == 168);
    assert!(align_of::<I386ThreadState>() == align_of::<u64>());
    assert!(offset_of!(I386ThreadState, r8) == 0);
    assert!(offset_of!(I386ThreadState, rdi) == 64);
    assert!(offset_of!(I386ThreadState, rip) == 128);
    assert!(offset_of!(I386ThreadState, cs) == 136);
    assert!(offset_of!(I386ThreadState, rfl) == 144);
    assert!(offset_of!(I386ThreadState, ursp) == 152);
    assert!(offset_of!(I386ThreadState, ss) == 160);
};

/// `struct i386_isa_port_map_state`: a thread's I/O permission bitmap.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386IsaPortMapState {
    pub pm: [u8; 0x400 >> 3],
}

const _: () = {
    assert!(size_of::<I386IsaPortMapState>() == 128);
    assert!(align_of::<I386IsaPortMapState>() == 1);
    assert!(offset_of!(I386IsaPortMapState, pm) == 0);
};

/// `struct i386_fsgs_base_state`: a thread's FS and GS bases.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386FsgsBaseState {
    pub fs_base: c_ulong,
    pub gs_base: c_ulong,
}

const _: () = {
    assert!(size_of::<I386FsgsBaseState>() == 16);
    assert!(align_of::<I386FsgsBaseState>() == align_of::<c_ulong>());
    assert!(offset_of!(I386FsgsBaseState, fs_base) == 0);
    assert!(offset_of!(I386FsgsBaseState, gs_base) == 8);
};

/// The program's entry point and loaded ranges, of which [`set_user_regs`]
/// reads the entry point.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct ExecInfo {
    pub format: c_int,
    pub entry: VmOffset,
    pub init_dp: VmOffset,
    pub interp: VmOffset,
    pub stack_prot: c_int,
}

const _: () = {
    assert!(size_of::<ExecInfo>() == 40);
    assert!(align_of::<ExecInfo>() == align_of::<VmOffset>());
    assert!(offset_of!(ExecInfo, entry) == 8);
};

/// The slab cache of [`Pcb`] records.
static mut PCB_CACHE: KmemCache = KmemCache::zeroed();

/// The top of each CPU's active stack, which the low-level entries index by
/// CPU number.
pub static mut KERNEL_STACK: [VmOffset; crate::config::MAX_NCPUS] =
    [0; crate::config::MAX_NCPUS];

/// The descriptor index of `selector`.
fn sel_idx(selector: c_ushort) -> usize {
    usize::from(selector >> 3)
}

/// The kernel state at the top of `stack`.
const fn stack_iks(stack: VmOffset) -> *mut I386KernelState {
    ptr::with_exposed_provenance_mut(
        stack + KERNEL_STACK_SIZE - size_of::<I386KernelState>(),
    )
}

/// The exception link at the top of `stack`.
const fn stack_iel(stack: VmOffset) -> *mut I386ExceptionLink {
    ptr::with_exposed_provenance_mut(
        stack + KERNEL_STACK_SIZE
            - size_of::<I386KernelState>()
            - size_of::<I386ExceptionLink>(),
    )
}

/// Reads the LDT register.
fn get_ldt() -> c_ushort {
    let segment: c_ushort;
    // SAFETY: `sldt` reads the local descriptor table register at CPL0.
    unsafe {
        core::arch::asm!("sldt {segment:x}", segment = out(reg) segment, options(nostack));
    };
    segment
}

/// Loads the LDT register with `segment`.
fn set_ldt(segment: c_ushort) {
    // SAFETY: `lldt` loads the LDT register with a descriptor the kernel
    // built in its GDT.
    unsafe {
        core::arch::asm!("lldt {segment:x}", segment = in(reg) segment, options(nostack));
    };
}

/// Writes `value` to the MSR `register`.
pub(crate) fn write_msr(register: u32, value: u64) {
    // SAFETY: WRMSR writes a model-specific register at CPL0; the caller names
    // one the CPU has.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") register,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack),
        );
    };
}

/// Reads the MSR `register`.
pub(crate) fn read_msr(register: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: RDMSR reads a model-specific register at CPL0; the caller names
    // one the CPU has.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") register,
            out("eax") low,
            out("edx") high,
            options(nostack),
        );
    };
    (u64::from(high) << 32) | u64::from(low)
}

/// Saves the registers if they are live.
///
/// # Safety
///
/// `thread` must be live and not running on another CPU.
unsafe fn fpu_save_context(thread: *mut Thread) {
    let ifps = unsafe { (*(*thread).pcb).ims.ifps };
    // SAFETY: `ifps` is the thread's own live save area.
    if !ifps.is_null() && unsafe { (*ifps).fp_valid } == 0 {
        unsafe { fpu::fpu_save(ifps) };
        fpu::set_ts();
    }
}

/// Attaches the kernel `stack` to `thread`, so it resumes in `continuation`.
///
/// # Safety
///
/// `thread` must be a live thread whose stack is not attached, `stack` must
/// be a whole kernel stack, and `continuation` a stack continuation.
pub(crate) unsafe fn stack_attach(
    thread: *mut Thread,
    stack: VmOffset,
    continuation: StackResume,
) {
    unsafe { (*thread).kernel_stack = stack };

    let iks = stack_iks(stack);
    let iel = stack_iel(stack);
    // SAFETY: `stack` is a whole kernel stack, so the two records at its top
    // are inside it, and the thread's pcb is live.
    unsafe {
        let thread_continue =
            cswitch::thread_continue as *const () as usize as c_long;

        (*iks).k_eip = thread_continue;
        (*iks).k_ebx = continuation.map_or(0, |f| f as usize) as c_long;
        (*iks).k_esp = iel as usize as c_long;
        (*iks).k_ebp = 0;
        (*iel).saved_state = &raw mut (*(*thread).pcb).iss;
    }
}

/// Points this CPU's TSS and descriptors at the thread whose pcb is `pcb`.
///
/// # Safety
///
/// `pcb` must be the live pcb of a thread about to run on this CPU.
pub(crate) unsafe fn switch_ktss(pcb: *mut Pcb) {
    let mycpu = cpu_id();

    let pcb_stack_top =
        unsafe { ptr::addr_of!((*pcb).iss).add(1) as VmOffset };

    // SAFETY: `MP_KTSS` holds one live TSS per CPU, and `mycpu` names the CPU
    // this code runs on.
    let ktss_ref = unsafe {
        (*ptr::addr_of!(crate::arch::x86_64::mp_desc::MP_KTSS))
            [mycpu.as_usize()]
    };
    unsafe {
        ptr::addr_of_mut!((*ktss_ref).tss.rsp0).write(pcb_stack_top as u64);
    };

    unsafe {
        let tldt = (*pcb).ims.ldt;
        if tldt.is_null() {
            if get_ldt() != KERNEL_LDT {
                set_ldt(KERNEL_LDT);
            }
        } else {
            let gdt_entry =
                (*ptr::addr_of!(crate::arch::x86_64::mp_desc::MP_GDT))
                    [mycpu.as_usize()];
            *gdt_entry.add(sel_idx(USER_LDT)) = (*tldt).desc;
            set_ldt(USER_LDT);
        }

        let gdt_entry = (*ptr::addr_of!(crate::arch::x86_64::mp_desc::MP_GDT))
            [mycpu.as_usize()];
        *gdt_entry.add(sel_idx(USER_GDT)) = (*pcb).ims.user_gdt[0];
        *gdt_entry.add(sel_idx(USER_GDT) + 1) = (*pcb).ims.user_gdt[1];
    }

    unsafe {
        write_msr(MSR_REG_FSBASE, (*pcb).ims.sbs.fsbase);
        write_msr(MSR_REG_KGSBASE, (*pcb).ims.sbs.gsbase);
    }

    unsafe { db_interface::load_context(pcb) };
}

/// Loads `size` bytes of the I/O permission bitmap `new_iopb` into this CPU's
/// TSS, or none.
///
/// # Safety
///
/// The caller must hold `iopb_lock` of the task whose bitmap this is, and
/// `new_iopb` must be readable for `size` bytes.
pub(crate) unsafe fn update_ktss_iopb(
    new_iopb: Option<NonNull<u8>>,
    size: c_ushort,
) {
    // SAFETY: `MP_KTSS` holds one live TSS per CPU.
    let tss = unsafe {
        (*ptr::addr_of!(crate::arch::x86_64::mp_desc::MP_KTSS))
            [cpu_id().as_usize()]
    };
    if let Some(new_iopb) = new_iopb
        && size > 0
    {
        let offset = offset_of!(TaskTss, barrier) - usize::from(size);
        // SAFETY: the task's `iopb_size` is an `IOPB_MAX`-wide port count, so
        // the offset lands inside the task_tss the TSS points at; the caller
        // promises the source is readable.
        unsafe {
            ptr::addr_of_mut!((*tss).tss.io_bit_map_offset)
                .write(offset as c_ushort);
            ptr::copy_nonoverlapping(
                new_iopb.as_ptr(),
                tss.cast::<u8>().add(offset),
                usize::from(size),
            );
        }
    } else {
        unsafe {
            ptr::addr_of_mut!((*tss).tss.io_bit_map_offset).write(IOPB_INVAL);
        };
    }
}

/// Hands the kernel stack of `old` to `new`, switching the address space.
///
/// # Safety
///
/// `old` must be the running thread and `new` the thread about to run, both
/// live and not running on any other CPU.
pub(crate) unsafe fn stack_handoff(old: *mut Thread, new: *mut Thread) {
    // The C `pmap` routines take the CPU number as an `int`.
    let mycpu = cpu_id().bits() as c_int;
    unsafe { fpu_save_context(old) };

    unsafe {
        let old_task = (*old).task;
        let new_task = (*new).task;
        if old_task != new_task {
            deactivate_user((*(*old_task).map.cast::<VmMap>()).pmap, mycpu);
            activate_user((*(*new_task).map.cast::<VmMap>()).pmap, mycpu);

            (*new_task).machine.iopb_lock.lock();
            // The C passed the `int` through `io_port_t`; the size is at
            // most IOPB_MAX.
            update_ktss_iopb(
                NonNull::new((*new_task).machine.iopb),
                (*new_task).machine.iopb_size as c_ushort,
            );
            (*new_task).machine.iopb_lock.unlock();
        }
    }

    // SAFETY: the new thread's pcb is live.
    unsafe { switch_ktss((*new).pcb) };

    let stack = per_cpu::stack();
    unsafe {
        (*old).kernel_stack = 0;
        (*new).kernel_stack = stack;
        per_cpu::set_thread(new);
        (*stack_iel(stack)).saved_state = &raw mut (*(*new).pcb).iss;
    }
}

/// Switches from `old` to `new`, saving `old`'s kernel context with
/// `continuation`; returns the thread switched away from.
///
/// # Safety
///
/// `old` must be the running thread and `new` the thread about to run, both
/// live and not running on any other CPU; `continuation` is where `old`
/// resumes.
pub(crate) unsafe fn switch_context(
    old: *mut Thread,
    continuation: Continuation,
    new: *mut Thread,
) -> *mut Thread {
    unsafe { fpu_save_context(old) };

    // The C `pmap` routines take the CPU number as an `int`.
    let mycpu = cpu_id().bits() as c_int;
    unsafe {
        let old_task = (*old).task;
        let new_task = (*new).task;
        if old_task != new_task {
            deactivate_user((*(*old_task).map.cast::<VmMap>()).pmap, mycpu);
            activate_user((*(*new_task).map.cast::<VmMap>()).pmap, mycpu);

            (*new_task).machine.iopb_lock.lock();
            update_ktss_iopb(
                NonNull::new((*new_task).machine.iopb),
                (*new_task).machine.iopb_size as c_ushort,
            );
            (*new_task).machine.iopb_lock.unlock();
        }

        // SAFETY: the new thread's pcb is live, and the switch resumes its
        // saved kernel context.
        switch_ktss((*new).pcb);

        cswitch::switch_context(old, continuation, new)
    }
}

/// Creates the pcb cache and sets the FPU module up.
///
/// # Safety
///
/// Called once at startup, before any thread is created.
pub(crate) unsafe fn pcb_module_init() {
    unsafe {
        (*ptr::addr_of_mut!(PCB_CACHE)).init(
            b"pcb",
            size_of::<Pcb>(),
            KERNEL_STACK_ALIGN,
            None,
            CacheInitFlags::EMPTY,
        );
    }
    // SAFETY: the FPU cache is built once, in the same startup step.
    unsafe { fpu::fpu_module_init() };
}

/// The C's `panic("pcb_init")` when the slab layer reports no memory.
fn panic_no_pcb() -> ! {
    kpanic!("pcb_init", "pcb_init")
}

/// Gives `thread` a fresh pcb with the user segments and flags.
///
/// # Safety
///
/// `parent_task` must be the task `thread` is being created in, both live,
/// called before the thread can run.
///
/// # Panics
///
/// Halts the kernel if the slab layer reports no memory for the pcb, as the
/// C `panic("pcb_init")` did.
pub(crate) unsafe fn pcb_init(parent_task: *mut Task, thread: *mut Thread) {
    let pcb = unsafe { (*ptr::addr_of_mut!(PCB_CACHE)).alloc() }
        .map_or_else(|| panic_no_pcb(), |buf| buf.as_ptr().cast::<Pcb>());
    // SAFETY: the object just came from the cache, is uninitialized, and the
    // C zeroed it whole so no random value would leak to the user.
    unsafe {
        ptr::write_bytes(pcb.cast::<u8>(), 0, size_of::<Pcb>());
        (*pcb).lock.init();

        (*pcb).iss.cs = USER_CS;
        (*pcb).iss.ss = USER_DS;
        (*pcb).iss.efl = EFL_USER_SET;

        (*thread).pcb = pcb;

        if !per_cpu::thread().is_null()
            && parent_task == current_task().as_ptr()
        {
            fpu::fpinherit(per_cpu::thread(), thread);
        }
    }
}

/// Frees `thread`'s pcb, with its FPU state and LDT.
///
/// # Safety
///
/// `thread` must be a live thread that will not run again.
pub(crate) unsafe fn pcb_terminate(thread: *mut Thread) {
    let pcb = unsafe { (*thread).pcb };

    // SAFETY: the save area and LDT belong to this pcb alone, and the caller
    // gives the thread up.
    unsafe {
        if !(*pcb).ims.ifps.is_null() {
            fpu::free_fp_state((*pcb).ims.ifps);
        }
        if !(*pcb).ims.ldt.is_null() {
            user_ldt::free((*pcb).ims.ldt);
        }
        if let Some(buf) = NonNull::new(pcb.cast::<u8>()) {
            (*ptr::addr_of_mut!(PCB_CACHE)).free(buf);
        }
        (*thread).pcb = ptr::null_mut();
    }
}

/// Sets `thread`'s machine state of `flavor`.
///
/// # Safety
///
/// `thread` must point at a live thread, and `tstate` must be readable for
/// `count` words of the record `flavor` names.
pub(crate) unsafe fn thread_setstatus(
    thread: *mut Thread,
    flavor: c_int,
    tstate: *mut c_uint,
    count: c_uint,
) -> Result<(), Error> {
    match flavor {
        I386_THREAD_STATE | I386_REGS_SEGS_STATE => {
            if count < I386_THREAD_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            let state = tstate.cast::<I386ThreadState>();
            let saved_state = unsafe { &mut (*(*thread).pcb).iss };

            if flavor == I386_REGS_SEGS_STATE {
                unsafe {
                    (*state).cs &= 0xffff;
                    (*state).ss &= 0xffff;

                    if (*state).cs == 0
                        || ((*state).cs & SEL_PL) != SEL_PL_U
                        || (*state).ss == 0
                        || ((*state).ss & SEL_PL) != SEL_PL_U
                    {
                        return Err(Error::InvalidArgument);
                    }
                }
            }

            // SAFETY: the state record and the saved state are live.
            unsafe {
                saved_state.r8 = (*state).r8;
                saved_state.r9 = (*state).r9;
                saved_state.r10 = (*state).r10;
                saved_state.r11 = (*state).r11;
                saved_state.r12 = (*state).r12;
                saved_state.r13 = (*state).r13;
                saved_state.r14 = (*state).r14;
                saved_state.r15 = (*state).r15;
                saved_state.edi = (*state).rdi;
                saved_state.esi = (*state).rsi;
                saved_state.ebp = (*state).rbp;
                saved_state.uesp = (*state).ursp;
                saved_state.ebx = (*state).rbx;
                saved_state.edx = (*state).rdx;
                saved_state.ecx = (*state).rcx;
                saved_state.eax = (*state).rax;
                saved_state.eip = (*state).rip;
                saved_state.efl =
                    ((*state).rfl & !EFL_USER_CLEAR) | EFL_USER_SET;
            }

            Ok(())
        }

        fpu::I386_FLOAT_STATE => {
            if count < I386_FLOAT_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                fpu::fpu_set_state(thread, tstate.cast::<c_void>(), flavor)
            }
        }

        fpu::I386_XFLOAT_STATE => {
            let mut xfp_size: VmSize = 0;
            // SAFETY: `xfp_size` is a local.
            unsafe { fpu::i386_get_xstate_size(&raw mut xfp_size) };
            xfp_size /= size_of::<c_int>();
            // `c_uint` is 32 bits and `usize` is at least that wide here.
            if (count as usize) < xfp_size {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                fpu::fpu_set_state(thread, tstate.cast::<c_void>(), flavor)
            }
        }

        I386_ISA_PORT_MAP_STATE => {
            if count < I386_ISA_PORT_MAP_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            Ok(())
        }

        I386_DEBUG_STATE => {
            if count < I386_DEBUG_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                db_interface::set_debug_state(
                    (*thread).pcb,
                    tstate.cast::<I386DebugState>(),
                )
            }
        }

        I386_FSGS_BASE_STATE => {
            if count < I386_FSGS_BASE_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                let state = tstate.cast::<I386FsgsBaseState>();
                if (*state).gs_base & 0x8000_0000_0000_0000 != 0 {
                    kprint!("WARNING: negative gs base not allowed\n");
                }
                (*(*thread).pcb).ims.sbs.fsbase = (*state).fs_base;
                (*(*thread).pcb).ims.sbs.gsbase =
                    (*state).gs_base & 0x7fff_ffff_ffff_ffff;
                if thread == per_cpu::thread() {
                    write_msr(MSR_REG_FSBASE, (*state).fs_base);
                    write_msr(MSR_REG_KGSBASE, (*state).gs_base);
                }
            }
            Ok(())
        }

        _ => Err(Error::InvalidArgument),
    }
}

/// Reports `thread`'s machine state of `flavor`.
///
/// # Safety
///
/// `thread` must point at a live thread, `tstate` must be writable for
/// `count` words of the record `flavor` names, and `count` must be valid for
/// a read and a write.
pub(crate) unsafe fn thread_getstatus(
    thread: *mut Thread,
    flavor: c_int,
    tstate: *mut c_uint,
    count: *mut c_uint,
) -> Result<(), Error> {
    let requested = unsafe { *count };

    match flavor {
        THREAD_STATE_FLAVOR_LIST => {
            let ncount: c_uint = 3;
            if requested < ncount {
                return Err(Error::InvalidArgument);
            }
            // SAFETY: the check above leaves three writable words.
            unsafe {
                *tstate.add(0) = I386_THREAD_STATE as c_uint;
                *tstate.add(1) = fpu::I386_FLOAT_STATE as c_uint;
                *tstate.add(2) = I386_ISA_PORT_MAP_STATE as c_uint;
                *count = ncount;
            }
            Ok(())
        }

        I386_THREAD_STATE | I386_REGS_SEGS_STATE => unsafe {
            get_thread_state(thread, tstate, requested, count)
        },

        fpu::I386_FLOAT_STATE => {
            if requested < I386_FLOAT_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                *count = I386_FLOAT_STATE_COUNT;
                fpu::fpu_get_state(thread, tstate.cast::<c_void>(), flavor)
            }
        }

        fpu::I386_XFLOAT_STATE => {
            let mut xfp_size: VmSize = 0;
            // SAFETY: `xfp_size` is a local.
            unsafe { fpu::i386_get_xstate_size(&raw mut xfp_size) };
            xfp_size /= size_of::<c_int>();
            // `c_uint` is 32 bits and `usize` is at least that wide here.
            if (requested as usize) < xfp_size {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                *count = xfp_size as c_uint;
                fpu::fpu_get_state(thread, tstate.cast::<c_void>(), flavor)
            }
        }

        I386_ISA_PORT_MAP_STATE => {
            if requested < I386_ISA_PORT_MAP_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                let state = tstate.cast::<I386IsaPortMapState>();
                let task = (*thread).task;
                (*task).machine.iopb_lock.lock();
                if (*task).machine.iopb.is_null() {
                    ptr::write_bytes(
                        (*state).pm.as_mut_ptr(),
                        0xff,
                        0x400 >> 3,
                    );
                } else {
                    ptr::copy_nonoverlapping(
                        (*task).machine.iopb,
                        (*state).pm.as_mut_ptr(),
                        0x400 >> 3,
                    );
                }
                (*task).machine.iopb_lock.unlock();
                *count = I386_ISA_PORT_MAP_STATE_COUNT;
            }
            Ok(())
        }

        I386_DEBUG_STATE => {
            if requested < I386_DEBUG_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                db_interface::get_debug_state(
                    (*thread).pcb,
                    tstate.cast::<I386DebugState>(),
                );
                *count = I386_DEBUG_STATE_COUNT;
            }
            Ok(())
        }

        I386_FSGS_BASE_STATE => {
            if requested < I386_FSGS_BASE_STATE_COUNT {
                return Err(Error::InvalidArgument);
            }
            unsafe {
                let state = tstate.cast::<I386FsgsBaseState>();
                (*state).fs_base = (*(*thread).pcb).ims.sbs.fsbase;
                (*state).gs_base = (*(*thread).pcb).ims.sbs.gsbase;
                *count = I386_FSGS_BASE_STATE_COUNT;
            }
            Ok(())
        }

        _ => Err(Error::InvalidArgument),
    }
}

/// Copy the saved registers into the state record, the `I386_THREAD_STATE`
/// case of `thread_getstatus()`.
///
/// # Safety
///
/// `thread` must point at a live thread, `tstate` must be writable for a
/// thread-state record, and `count` must be valid for a write.
unsafe fn get_thread_state(
    thread: *mut Thread,
    tstate: *mut c_uint,
    requested: c_uint,
    count: *mut c_uint,
) -> Result<(), Error> {
    if requested < I386_THREAD_STATE_COUNT {
        return Err(Error::InvalidArgument);
    }
    let (state, saved_state) = unsafe {
        (tstate.cast::<I386ThreadState>(), &mut (*(*thread).pcb).iss)
    };

    // SAFETY: both records are live.
    unsafe {
        (*state).r8 = saved_state.r8;
        (*state).r9 = saved_state.r9;
        (*state).r10 = saved_state.r10;
        (*state).r11 = saved_state.r11;
        (*state).r12 = saved_state.r12;
        (*state).r13 = saved_state.r13;
        (*state).r14 = saved_state.r14;
        (*state).r15 = saved_state.r15;
        (*state).rdi = saved_state.edi;
        (*state).rsi = saved_state.esi;
        (*state).rbp = saved_state.ebp;
        (*state).rbx = saved_state.ebx;
        (*state).rdx = saved_state.edx;
        (*state).rcx = saved_state.ecx;
        (*state).rax = saved_state.eax;
        (*state).rip = saved_state.eip;
        (*state).ursp = saved_state.uesp;
        (*state).rfl = saved_state.efl;
        (*state).rsp = 0;
    }

    unsafe {
        (*state).cs = saved_state.cs as c_uint;
        (*state).ss = saved_state.ss as c_uint;
    }

    unsafe {
        *count = I386_THREAD_STATE_COUNT;
    }
    Ok(())
}

/// Sets `retval` as the value `thread`'s system call returns.
///
/// # Safety
///
/// `thread` must point at a live thread.
pub(crate) unsafe fn thread_set_syscall_return(
    thread: *mut Thread,
    retval: c_int,
) {
    unsafe { (*(*thread).pcb).iss.eax = retval as c_ulong };
}

/// The lowest address of a user stack of `stack_size` bytes.
pub(crate) const fn user_stack_low(stack_size: VmSize) -> VmOffset {
    VM_MAX_USER_ADDRESS.wrapping_sub(stack_size)
}

/// Points the current thread's user registers at the entry of `exec_info`,
/// with its stack below `arg_size` bytes of arguments, and returns the
/// arguments' address.
///
/// # Safety
///
/// Runs on the current thread, whose pcb is live, and `exec_info` points at
/// a live record.
pub(crate) unsafe fn set_user_regs(
    stack_base: VmOffset,
    stack_size: VmOffset,
    exec_info: *const ExecInfo,
    arg_size: VmSize,
) -> VmOffset {
    let arg_size =
        arg_size.wrapping_add(USER_STACK_ALIGN - 1) & !(USER_STACK_ALIGN - 1);
    let arg_addr = stack_base + stack_size - arg_size;

    unsafe {
        let saved_state = &mut (*(*per_cpu::thread()).pcb).iss;
        saved_state.uesp = arg_addr as c_ulong;
        saved_state.eip = (*exec_info).entry as c_ulong;
    }

    arg_addr
}

/// Detaches and returns `thread`'s kernel stack.
///
/// # Safety
///
/// `thread` must point at a live thread, and the caller must own its
/// `kernel_stack` field for the duration: `stack_free()` calls this at
/// splsched with the thread locked.
pub(crate) unsafe fn stack_detach(thread: *mut Thread) -> VmOffset {
    unsafe { core::mem::replace(&mut (*thread).kernel_stack, 0) }
}

/// Runs `new` as this CPU's first thread.
///
/// # Safety
///
/// `new` must point at a live thread whose kernel stack and saved context
/// are ready to resume, and no other CPU may be running it.
pub(crate) unsafe fn load_context(new: *mut Thread) -> ! {
    let pcb = unsafe { (*new).pcb };
    unsafe { switch_ktss(pcb) };

    unsafe { cswitch::load_context(new) }
}
