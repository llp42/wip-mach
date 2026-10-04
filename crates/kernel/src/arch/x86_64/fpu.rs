// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 1992-1989 Carnegie Mellon University
// SPDX-FileCopyrightText: 1994 Linus Torvalds
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from Mach4 (commit e8a91124a56b72f46c5337679517cb5e4349d766)
//   <https://github.com/openmach/mach4>
// original files: i386/kernel/i386/fpu.c and i386/kernel/i386/fpu.h
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: i386/i386/fpu.c, i386/i386/fpu.h,
//   i386/include/mach/i386/fp_reg.h and
//   i386/include/mach/i386/thread_status.h

//! The FPU save-area records, the instruction wrappers that move state to
//! and from them, and the traps and interrupts that load, save and report
//! thread FPU state.

use crate::arch::types::VmSize;
use crate::arch::x86_64::ast::I386_FP;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::arch::x86_64::trap;
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::machine;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::kern::thread::Thread;
use crate::kern::types::KernError;
use core::ffi::{c_int, c_long, c_uint, c_ushort, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, Ordering};

/// `CR0.NE`: the x87 numeric-error reporting enable.
pub(crate) const CR0_NE: usize = 0x20;
/// `CR0.PG`: paging enable.
pub(crate) const CR0_PG: usize = 0x8000_0000;
/// `CR0.CD`: cache disable.
pub(crate) const CR0_CD: usize = 0x4000_0000;
/// `CR0.NW`: not-write-through.
pub(crate) const CR0_NW: usize = 0x2000_0000;
/// `CR0.AM`: alignment-mask check enable.
pub(crate) const CR0_AM: usize = 0x0004_0000;
/// `CR0.WP`: supervisor write-protect enable.
pub(crate) const CR0_WP: usize = 0x0001_0000;
/// `CR0.TS`: the task-switched x87 save bit.
pub(crate) const CR0_TS: usize = 0x08;
/// `CR0.EM`: x87 emulation mode.
pub(crate) const CR0_EM: usize = 0x04;
/// `CR0.MP`: monitor coprocessor, the `FWAIT` trap control.
pub(crate) const CR0_MP: usize = 0x02;
/// `CR0.PE`: protection enable.
pub(crate) const CR0_PE: usize = 0x01;

/// `CR4.PAE`: physical-address extension.
pub(crate) const CR4_PAE: usize = 0x0020;
/// `CR4.PGE`: global-page enable.
pub(crate) const CR4_PGE: usize = 0x0080;
/// `CR4.OSFXSR`: OS support for the SSE save/restore instructions.
const CR4_OSFXSR: usize = 0x0200;
/// `CR4.OSXSAVE`: OS support for the XSAVE instruction set.
const CR4_OSXSAVE: usize = 0x40000;

/// The first CPU type with a real FPU trap.
const CPU_TYPE_I486: c_int = 17;

/// The XSAVE bit in the second word of the processor-feature table.
const CPU_FEATURE_XSAVE: u32 = 32 + 26;
/// The FXSR bit in the first word of the processor-feature table.
const CPU_FEATURE_FXSR: u32 = 24;

/// The XSAVEOPT bit CPUID leaf 0xd, subleaf 1 reports.
const CPU_FEATURE_XSAVEOPT: u32 = 1 << 0;
/// The XSAVEC bit CPUID leaf 0xd, subleaf 1 reports.
const CPU_FEATURE_XSAVEC: u32 = 1 << 1;
/// The XSAVES bit CPUID leaf 0xd, subleaf 1 reports.
const CPU_FEATURE_XSAVES: u32 = 1 << 3;

/// The x87 state bit of the XCR0 extended-control register.
const CPU_XCR0_X87: u64 = 1 << 0;
/// The compacted-format bit of the XSAVE header's `xcomp_bv`.
const XSAVE_XCOMP_BV_COMPACT: u64 = 1 << 63;

/// The thread-state flavor naming the FNSAVE-format FPU record.
pub(crate) const I386_FLOAT_STATE: c_int = 2;
/// The thread-state flavor naming the XSAVE-format FPU record.
pub(crate) const I386_XFLOAT_STATE: c_int = 8;

/// The size of the FNSAVE image, the control block plus its registers.
const FP_STATE_BYTES: usize =
    size_of::<I386FpSave>() + size_of::<I386FpRegs>();

/// The x87 environment half of an FNSAVE image, without the data registers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386FpSave {
    pub fp_control: c_ushort,
    pub fp_unused_1: c_ushort,
    pub fp_status: c_ushort,
    pub fp_unused_2: c_ushort,
    pub fp_tag: c_ushort,
    pub fp_unused_3: c_ushort,
    pub fp_eip: c_uint,
    pub fp_cs: c_ushort,
    pub fp_opcode: c_ushort,
    pub fp_dp: c_uint,
    pub fp_ds: c_ushort,
    pub fp_unused_4: c_ushort,
}

const _: () = {
    assert!(size_of::<I386FpSave>() == 28);
    assert!(align_of::<I386FpSave>() == align_of::<c_uint>());
    assert!(offset_of!(I386FpSave, fp_control) == 0);
    assert!(offset_of!(I386FpSave, fp_status) == 4);
    assert!(offset_of!(I386FpSave, fp_tag) == 8);
    assert!(offset_of!(I386FpSave, fp_eip) == 12);
    assert!(offset_of!(I386FpSave, fp_cs) == 16);
    assert!(offset_of!(I386FpSave, fp_opcode) == 18);
    assert!(offset_of!(I386FpSave, fp_dp) == 20);
    assert!(offset_of!(I386FpSave, fp_ds) == 24);
};

/// The eight 80-bit x87 data registers of an FNSAVE image.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386FpRegs {
    pub fp_reg_word: [[c_ushort; 5]; 8],
}

const _: () = {
    assert!(size_of::<I386FpRegs>() == 80);
    assert!(align_of::<I386FpRegs>() == align_of::<c_ushort>());
    assert!(offset_of!(I386FpRegs, fp_reg_word) == 0);
};

/// The XSAVE header that closes the architectural save area, packed.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386XfpXstateHeader {
    pub xfp_features: u64,
    pub xcomp_bv: u64,
    pub reserved: [u64; 6],
}

const _: () = {
    assert!(size_of::<I386XfpXstateHeader>() == 64);
    assert!(align_of::<I386XfpXstateHeader>() == 1);
    assert!(offset_of!(I386XfpXstateHeader, xfp_features) == 0);
    assert!(offset_of!(I386XfpXstateHeader, xcomp_bv) == 8);
    assert!(offset_of!(I386XfpXstateHeader, reserved) == 16);
};

/// The XSAVE image: x87, SSE and extended state in architectural order.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386XfpSave {
    pub fp_control: c_ushort,
    pub fp_status: c_ushort,
    pub fp_tag: c_ushort,
    pub fp_opcode: c_ushort,
    pub fp_eip: c_uint,
    pub fp_cs: c_ushort,
    pub fp_eip3: c_ushort,
    pub fp_dp: c_uint,
    pub fp_ds: c_ushort,
    pub fp_dp3: c_ushort,
    pub fp_mxcsr: c_uint,
    pub fp_mxcsr_mask: c_uint,
    pub fp_reg_word: [[u8; 16]; 8],
    pub fp_xreg_word: [[u8; 16]; 16],
    pub padding: [c_uint; 24],
    pub header: I386XfpXstateHeader,
    pub extended: [u8; 0],
}

const _: () = {
    assert!(size_of::<I386XfpSave>() == 576);
    assert!(align_of::<I386XfpSave>() == 64);
    assert!(offset_of!(I386XfpSave, fp_control) == 0);
    assert!(offset_of!(I386XfpSave, fp_status) == 2);
    assert!(offset_of!(I386XfpSave, fp_tag) == 4);
    assert!(offset_of!(I386XfpSave, fp_opcode) == 6);
    assert!(offset_of!(I386XfpSave, fp_eip) == 8);
    assert!(offset_of!(I386XfpSave, fp_cs) == 12);
    assert!(offset_of!(I386XfpSave, fp_eip3) == 14);
    assert!(offset_of!(I386XfpSave, fp_dp) == 16);
    assert!(offset_of!(I386XfpSave, fp_ds) == 20);
    assert!(offset_of!(I386XfpSave, fp_dp3) == 22);
    assert!(offset_of!(I386XfpSave, fp_mxcsr) == 24);
    assert!(offset_of!(I386XfpSave, fp_mxcsr_mask) == 28);
    assert!(offset_of!(I386XfpSave, fp_reg_word) == 32);
    assert!(offset_of!(I386XfpSave, fp_xreg_word) == 160);
    assert!(offset_of!(I386XfpSave, padding) == 416);
    assert!(offset_of!(I386XfpSave, header) == 512);
    assert!(offset_of!(I386XfpSave, extended) == 576);
};

/// The FNSAVE arm of the save-area union: environment plus register file.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct I386FpSaveNative {
    pub fp_save_state: I386FpSave,
    pub fp_regs: I386FpRegs,
}

const _: () = {
    assert!(size_of::<I386FpSaveNative>() == FP_STATE_BYTES);
    assert!(align_of::<I386FpSaveNative>() == align_of::<c_uint>());
    assert!(offset_of!(I386FpSaveNative, fp_save_state) == 0);
    assert!(offset_of!(I386FpSaveNative, fp_regs) == 28);
};

/// The two image formats a save area may hold.
#[repr(C)]
#[allow(missing_docs)]
pub union I386FpSaveStateUnion {
    pub native: I386FpSaveNative,
    pub xfp_save_state: I386XfpSave,
}

const _: () = {
    assert!(size_of::<I386FpSaveStateUnion>() == 576);
    assert!(align_of::<I386FpSaveStateUnion>() == 64);
};

/// One thread's saved FPU state, either the FNSAVE image or the XSAVE one.
#[repr(C)]
#[allow(missing_docs)]
pub struct I386FpSaveState {
    pub fp_valid: c_int,
    pub save: I386FpSaveStateUnion,
}

const _: () = {
    assert!(size_of::<I386FpSaveState>() == 640);
    assert!(align_of::<I386FpSaveState>() == 64);
    assert!(offset_of!(I386FpSaveState, fp_valid) == 0);
    assert!(offset_of!(I386FpSaveState, save) == 64);
};

impl I386FpSaveState {
    /// The FNSAVE arm, valid while the save kind is [`FpSaveKind::FnSave`].
    ///
    /// # Safety
    ///
    /// The caller must know the state was saved with FNSAVE.
    const unsafe fn native(&mut self) -> &mut I386FpSaveNative {
        unsafe { &mut self.save.native }
    }

    /// The XSAVE arm: the 576 bytes of the union the XSAVE instructions
    /// write.
    ///
    /// # Safety
    ///
    /// The caller must know the XSAVE arm is live, or deliberately wants
    /// to write the inactive arm, as [`fill_state()`] does for an XFLOAT
    /// record while the save kind is FNSAVE.
    const unsafe fn xfp(&mut self) -> &mut I386XfpSave {
        unsafe { &mut self.save.xfp_save_state }
    }
}

/// The thread-status record that carries an FNSAVE-format image.
#[repr(C)]
#[allow(missing_docs)]
pub struct I386FloatState {
    pub fpkind: c_int,
    pub initialized: c_int,
    pub hw_state: [u8; FP_STATE_BYTES],
    pub exc_status: c_int,
}

const _: () = {
    assert!(size_of::<I386FloatState>() == 120);
    assert!(align_of::<I386FloatState>() == align_of::<c_int>());
    assert!(offset_of!(I386FloatState, fpkind) == 0);
    assert!(offset_of!(I386FloatState, initialized) == 4);
    assert!(offset_of!(I386FloatState, hw_state) == 8);
    assert!(offset_of!(I386FloatState, exc_status) == 116);
};

/// The thread-status record that carries an XSAVE-format image.
#[repr(C)]
#[allow(missing_docs)]
pub struct I386XfloatState {
    pub fpkind: c_int,
    pub initialized: c_int,
    pub exc_status: c_int,
    pub fp_save_kind: c_int,
    pub hw_state: [u8; 0],
}

const _: () = {
    assert!(size_of::<I386XfloatState>() == 16);
    assert!(align_of::<I386XfloatState>() == align_of::<c_int>());
    assert!(offset_of!(I386XfloatState, fpkind) == 0);
    assert!(offset_of!(I386XfloatState, initialized) == 4);
    assert!(offset_of!(I386XfloatState, exc_status) == 8);
    assert!(offset_of!(I386XfloatState, fp_save_kind) == 12);
    assert!(offset_of!(I386XfloatState, hw_state) == 16);
};

/// The kind of instruction that saves a thread's FPU state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpSaveKind {
    /// The 387 `fnsave` state.
    FnSave = 0,
    /// The SSE `fxsave` state.
    FxSave = 1,
    /// The `xsave` state.
    XSave = 2,
    /// The `xsaveopt` state.
    XSaveOpt = 3,
    /// The compacted `xsavec` state.
    XSaveC = 4,
    /// The supervisor `xsaves` state.
    XSaveS = 5,
}

impl FpSaveKind {
    /// The kind `value` names, or [`None`] when it is out of range.
    pub(crate) const fn from_int(value: c_int) -> Option<Self> {
        match value {
            0 => Some(Self::FnSave),
            1 => Some(Self::FxSave),
            2 => Some(Self::XSave),
            3 => Some(Self::XSaveOpt),
            4 => Some(Self::XSaveC),
            5 => Some(Self::XSaveS),
            _ => None,
        }
    }
}

/// The FPU class the boot probe detected.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FpKind {
    No = 0,
    Soft = 1,
    Fp287 = 2,
    Fp387 = 3,
    Fp387Fx = 4,
    Fp387X = 5,
}

/// The save instruction in use, as an `FpSaveKind` byte.  `Relaxed` reads:
/// [`init_fpu()`] writes it before the processor it runs on can schedule a
/// thread, and no other CPU writes it.
static FP_SAVE_KIND: AtomicU8 = AtomicU8::new(FpSaveKind::FnSave as u8);

/// The detected FPU class, written under the same rule as [`FP_SAVE_KIND`].
static FP_KIND: AtomicU8 = AtomicU8::new(FpKind::Fp387 as u8);

/// The size XSAVE writes, at least that of [`I386XfpSave`].
static FP_XSAVE_SIZE: AtomicU32 =
    AtomicU32::new(size_of::<I386XfpSave>() as u32);

/// The low half of the XCR0 mask the XSAVE instructions take in `%eax`.
static FP_XSAVE_SUPPORT_LO: AtomicU32 = AtomicU32::new(0);

/// The high half of the XCR0 mask, passed in `%edx`.
static FP_XSAVE_SUPPORT_HI: AtomicU32 = AtomicU32::new(0);

/// The mask every user-supplied MXCSR is `ANDed` with before it is loaded.
static MXCSR_FEATURE_MASK: AtomicU32 = AtomicU32::new(0xffff_ffff);

/// The default FPU state a new thread starts from, built once at boot.
static FP_DEFAULT_STATE: AtomicPtr<I386FpSaveState> =
    AtomicPtr::new(ptr::null_mut());

/// The slab cache the FPU save areas come from.
static mut IFPS_CACHE: KmemCache = KmemCache::zeroed();

/// Returns a save area to the slab cache.
///
/// # Safety
///
/// `ifps` must be a live object from the save-area cache and must not be
/// used again.
pub(crate) unsafe fn free_fp_state(ifps: *mut I386FpSaveState) {
    let Some(buf) = NonNull::new(ifps.cast::<u8>()) else {
        return;
    };
    // SAFETY: `fpu_module_init()` built the cache before any thread could
    // reach this free, and the caller gives up the object.
    unsafe { (*ptr::addr_of_mut!(IFPS_CACHE)).free(buf) };
}

/// Allocates a save area from the slab cache.
///
/// # Panics
///
/// Halts the kernel if the slab layer cannot extend the cache.
fn alloc_fp_state() -> *mut I386FpSaveState {
    // SAFETY: the cache is built by `fpu_module_init()` before any caller.
    unsafe { (*ptr::addr_of_mut!(IFPS_CACHE)).alloc() }.map_or_else(
        || kpanic!("kmem_cache_alloc", "fpu: out of FP save areas"),
        |buf| buf.as_ptr().cast(),
    )
}

/// Resets the x87 state to its power-on value.
fn fninit() {
    // SAFETY: `fninit` resets the x87 state and is valid at CPL0.
    unsafe { core::arch::asm!("fninit", options(nostack)) };
}

/// Returns the x87 status word.
fn fnstsw() -> c_ushort {
    let mut status: c_ushort = 0;
    // SAFETY: `fnstsw` writes the two-byte x87 status word to the local and
    // is valid at CPL0.
    unsafe {
        core::arch::asm!(
            "fnstsw [{status}]",
            status = in(reg) &raw mut status,
            options(nostack),
        );
    };
    status
}

/// Returns the x87 control word.
fn fnstcw() -> c_ushort {
    let mut control: c_ushort = 0;
    // SAFETY: `fnstcw` writes the two-byte x87 control word to the local and
    // is valid at CPL0.
    unsafe {
        core::arch::asm!(
            "fnstcw [{control}]",
            control = in(reg) &raw mut control,
            options(nostack),
        );
    };
    control
}

/// Loads the x87 control word.
fn fldcw(control: c_ushort) {
    // SAFETY: `fldcw` loads the x87 control word from the local and is valid
    // at CPL0.
    unsafe {
        core::arch::asm!(
            "fldcw [{control}]",
            control = in(reg) &raw const control,
            options(nostack),
        );
    };
}

/// Writes the 108-byte FNSAVE image to `state`.
fn fnsave(state: *mut I386FpSave) {
    // SAFETY: the caller passes a live FNSAVE image; `fnsave` writes its 108
    // bytes there.
    unsafe {
        core::arch::asm!("fnsave [{state}]", state = in(reg) state, options(nostack));
    };
}

/// Restores the x87 state from a 108-byte FNSAVE image.
fn frstor(state: *const I386FpSave) {
    // SAFETY: the caller passes a live FNSAVE image; `frstor` reads 108 bytes.
    unsafe {
        core::arch::asm!("frstor [{state}]", state = in(reg) state, options(nostack));
    };
}

/// Writes the 512-byte FXSAVE image to `state`.
fn fxsave(state: *mut I386XfpSave) {
    // SAFETY: the caller passes a live save area, 64-byte aligned as FXSAVE
    // requires; FXSAVE writes its 512 bytes there.
    unsafe {
        core::arch::asm!("fxsave [{state}]", state = in(reg) state, options(nostack));
    };
}

/// Restores the x87/SSE state from a 512-byte FXSAVE image.
fn fxrstor(state: *const I386XfpSave) {
    // SAFETY: the caller passes a live, aligned XSAVE/FXSAVE image; FXRSTOR
    // reads its 512 bytes.
    unsafe {
        core::arch::asm!("fxrstor [{state}]", state = in(reg) state, options(nostack));
    };
}

/// The two halves of the XCR0 mask the XSAVE instructions take.
fn xsave_support() -> (u32, u32) {
    (
        FP_XSAVE_SUPPORT_LO.load(Ordering::Relaxed),
        FP_XSAVE_SUPPORT_HI.load(Ordering::Relaxed),
    )
}

/// Writes the full XSAVE image to `state`.
fn xsave(state: *mut I386XfpSave) {
    let (lo, hi) = xsave_support();
    // SAFETY: the caller passes a live, 64-byte aligned save area and the
    // mask `set_xcr0()` enabled.
    unsafe {
        core::arch::asm!(
            "xsave [{state}]",
            state = in(reg) state,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    };
}

/// Writes the XSAVE image, skipping state already valid in memory.
fn xsaveopt(state: *mut I386XfpSave) {
    let (lo, hi) = xsave_support();
    // SAFETY: the caller passes a live, 64-byte aligned save area and the mask
    // `set_xcr0()` enabled; the processor reported XSAVEOPT.
    unsafe {
        core::arch::asm!(
            "xsaveopt [{state}]",
            state = in(reg) state,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    };
}

/// Writes the compacted XSAVE image to `state`.
fn xsavec(state: *mut I386XfpSave) {
    let (lo, hi) = xsave_support();
    // SAFETY: the caller passes a live, 64-byte aligned save area and the mask
    // `set_xcr0()` enabled; the processor reported XSAVEC.
    unsafe {
        core::arch::asm!(
            "xsavec [{state}]",
            state = in(reg) state,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    };
}

/// Writes the supervisor XSAVE image to `state`.
fn xsaves(state: *mut I386XfpSave) {
    let (lo, hi) = xsave_support();
    // SAFETY: the caller passes a live, 64-byte aligned save area and the mask
    // `set_xcr0()` enabled; the processor reported XSAVES.
    unsafe {
        core::arch::asm!(
            "xsaves [{state}]",
            state = in(reg) state,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    };
}

/// Restores state from an XSAVE image.
fn xrstor(state: *const I386XfpSave) {
    let (lo, hi) = xsave_support();
    // SAFETY: the caller passes a live, aligned image of a kind the
    // processor can restore with the mask `set_xcr0()` enabled.
    unsafe {
        core::arch::asm!(
            "xrstor [{state}]",
            state = in(reg) state,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    };
}

/// Restores state from a supervisor XSAVE image.
fn xrstors(state: *const I386XfpSave) {
    let (lo, hi) = xsave_support();
    // SAFETY: the caller passes a live, aligned image of a kind the
    // processor can restore with the mask `set_xcr0()` enabled; the
    // processor reported XSAVES.
    unsafe {
        core::arch::asm!(
            "xrstors [{state}]",
            state = in(reg) state,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    };
}

/// Writes an extended-control register.
fn xsetbv(index: u32, value: u64) {
    // SAFETY: the caller ran CPUID for XSAVE and set CR4.OSXSAVE; `xsetbv`
    // writes an extended-control register the processor reported.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") index,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack),
        );
    };
}

/// Sets XCR0, the mask of enabled XSAVE state components.
fn set_xcr0(value: u64) {
    xsetbv(0, value);
}

/// Returns the current CR0.
pub(crate) fn read_cr0() -> usize {
    let value: usize;
    // SAFETY: reading CR0 is legal at CPL0.
    unsafe {
        core::arch::asm!("mov {value}, cr0", value = out(reg) value, options(nostack, preserves_flags, readonly));
    };
    value
}

/// Loads CR0.
pub(crate) fn write_cr0(value: usize) {
    // SAFETY: writing CR0 is legal at CPL0.
    unsafe {
        core::arch::asm!("mov cr0, {value}", value = in(reg) value, options(nostack, preserves_flags));
    };
}

/// Returns the current CR4.
pub(crate) fn read_cr4() -> usize {
    let value: usize;
    // SAFETY: reading CR4 is legal at CPL0.
    unsafe {
        core::arch::asm!("mov {value}, cr4", value = out(reg) value, options(nostack, preserves_flags, readonly));
    };
    value
}

/// Loads CR4.
pub(crate) fn write_cr4(value: usize) {
    // SAFETY: writing CR4 is legal at CPL0.
    unsafe {
        core::arch::asm!("mov cr4, {value}", value = in(reg) value, options(nostack, preserves_flags));
    };
}

/// Sets `CR0.TS` so the next x87 use traps.
pub(crate) fn set_ts() {
    write_cr0(read_cr0() | CR0_TS);
}

/// Clears `CR0.TS`.
pub(crate) fn clear_ts() {
    // SAFETY: `clts` is the processor's own instruction and is valid at
    // CPL0.
    unsafe { core::arch::asm!("clts", options(nostack, preserves_flags)) };
}

/// Runs `cpuid` for a leaf and subleaf, returning its four outputs.
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: `cpuid` is a plain CPU instruction; the surrounding moves save
    // and restore `%rbx`, which LLVM reserves.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
        );
    };
    (eax, ebx, ecx, edx)
}

/// Tests a bit of the boot probe's CPU-feature table.
fn has_cpu_feature(feature: u32) -> bool {
    // SAFETY: `locore::CPU_FEATURES` is written once by the early CPU
    // probe, and `feature` is one of the `CPU_FEATURE_*` constants below
    // 64, so the index is 0 or 1.
    let table = core::ptr::addr_of!(locore::CPU_FEATURES);
    let word =
        // SAFETY: the table is probe-initialized and `feature` is
        // below 64.
        unsafe { table.cast::<u32>().add((feature / 32) as usize).read() };
    word & (1 << (feature % 32)) != 0
}

/// Reports whether infinity compares equal to its negation: true on an
/// 80287, whose infinity has no sign, and false on a 387.
fn infinity_has_no_sign() -> bool {
    let equal: u8;
    // SAFETY: the sequence leaves the x87 stack as it found it: `fdivp` in
    // its no-operand form divides `st(1)` by `st(0)` and pops, `fcomip` pops
    // the negated copy, and `fstp` the remaining infinity.
    unsafe {
        core::arch::asm!(
            "fld1",
            "fldz",
            "fdivp",
            "fld st(0)",
            "fchs",
            "fcomip st, st(1)",
            "fstp st(0)",
            "sete {equal}",
            equal = out(reg_byte) equal,
            options(nostack),
        );
    };
    equal != 0
}

/// Puts an 80287 into protected mode; later FPUs treat it as a no-op.
fn fnsetpm() {
    // SAFETY: the 80287's `fnsetpm` is a no-op on later FPUs.
    unsafe { core::arch::asm!(".byte 0xdb", ".byte 0xe4", options(nostack)) };
}

/// Saves `ifps` with the instruction the current save kind selects.
///
/// # Safety
///
/// `ifps` must be a live save area, and the caller must have turned off the
/// FPU's task-switched trap for the running thread.
pub(crate) unsafe fn fpu_save(ifps: *mut I386FpSaveState) {
    let ifps = unsafe { &mut *ifps };
    match save_kind() {
        FpSaveKind::FnSave => {
            // SAFETY: the arm matches the kind, so the FNSAVE image is live.
            let native = unsafe { ifps.native() };
            fnsave(&raw mut native.fp_save_state);
        }
        FpSaveKind::FxSave => {
            // SAFETY: the arm matches the kind, so the XSAVE image is live.
            let xfp = unsafe { ifps.xfp() };
            fxsave(xfp);
        }
        FpSaveKind::XSave => {
            // SAFETY: the arm matches the kind, so the XSAVE image is live.
            let xfp = unsafe { ifps.xfp() };
            xsave(xfp);
        }
        FpSaveKind::XSaveOpt => {
            let xfp = unsafe { ifps.xfp() };
            xsaveopt(xfp);
        }
        FpSaveKind::XSaveC => {
            let xfp = unsafe { ifps.xfp() };
            xsavec(xfp);
        }
        FpSaveKind::XSaveS => {
            let xfp = unsafe { ifps.xfp() };
            xsaves(xfp);
        }
    }
    ifps.fp_valid = 1;
}

/// Restores `ifps` with the instruction the current save kind selects.
///
/// # Safety
///
/// `ifps` must hold an image of the kind the current save kind uses.
pub(crate) unsafe fn fpu_rstor(ifps: *mut I386FpSaveState) {
    let ifps = unsafe { &*ifps };
    match save_kind() {
        FpSaveKind::FnSave => {
            // SAFETY: the arm matches the kind, so the FNSAVE image is live.
            let native = unsafe { &ifps.save.native };
            frstor(&raw const native.fp_save_state);
        }
        FpSaveKind::FxSave => {
            // SAFETY: the arm matches the kind, so the XSAVE image is live.
            let xfp = unsafe { &ifps.save.xfp_save_state };
            fxrstor(xfp);
        }
        FpSaveKind::XSave | FpSaveKind::XSaveOpt | FpSaveKind::XSaveC => {
            let xfp = unsafe { &ifps.save.xfp_save_state };
            xrstor(xfp);
        }
        FpSaveKind::XSaveS => {
            let xfp = unsafe { &ifps.save.xfp_save_state };
            xrstors(xfp);
        }
    }
}

/// The save instruction the global holds, as an [`FpSaveKind`].
fn save_kind() -> FpSaveKind {
    match FP_SAVE_KIND.load(Ordering::Relaxed) {
        0 => FpSaveKind::FnSave,
        1 => FpSaveKind::FxSave,
        2 => FpSaveKind::XSave,
        3 => FpSaveKind::XSaveOpt,
        4 => FpSaveKind::XSaveC,
        _ => FpSaveKind::XSaveS,
    }
}

fn set_save_kind(kind: FpSaveKind) {
    FP_SAVE_KIND.store(kind as u8, Ordering::Relaxed);
}

fn fp_kind() -> FpKind {
    match FP_KIND.load(Ordering::Relaxed) {
        0 => FpKind::No,
        1 => FpKind::Soft,
        2 => FpKind::Fp287,
        3 => FpKind::Fp387,
        4 => FpKind::Fp387Fx,
        _ => FpKind::Fp387X,
    }
}

fn set_fp_kind(kind: FpKind) {
    FP_KIND.store(kind as u8, Ordering::Relaxed);
}

fn xfp_save_size() -> u32 {
    FP_XSAVE_SIZE.load(Ordering::Relaxed)
}

/// Converts an x87 tag word to the FXSAVE tag encoding.
fn twd_i387_to_fxsr(twd: c_ushort) -> c_ushort {
    let mut tmp = !c_uint::from(twd);
    tmp = (tmp | (tmp >> 1)) & 0x5555;
    tmp = (tmp | (tmp >> 1)) & 0x3333;
    tmp = (tmp | (tmp >> 2)) & 0x0f0f;
    tmp = (tmp | (tmp >> 4)) & 0x00ff;
    tmp as c_ushort
}

/// One 80-bit register inside an FXSAVE image's register file.
#[repr(C)]
#[allow(missing_docs)]
struct FxReg {
    significand: [c_ushort; 4],
    exponent: c_ushort,
    padding: [c_ushort; 3],
}

const _: () = {
    assert!(size_of::<FxReg>() == 16);
    assert!(offset_of!(FxReg, exponent) == 8);
};

/// Converts an FXSAVE tag word to its x87 encoding, classifying each
/// register from the register file.
fn twd_fxsr_to_i387(fxsave: &I386XfpSave) -> c_uint {
    let tos = (c_uint::from(fxsave.fp_status) >> 11) & 7;
    let mut twd = c_uint::from(fxsave.fp_tag);
    let mut ret: c_uint = 0xffff_0000;
    for i in 0..8u32 {
        let tag = if twd & 1 != 0 {
            let index = i.wrapping_sub(tos) & 7;
            // SAFETY: the index is masked into the eight-register array, so
            // the cast points inside it, and the array is 16-byte aligned.
            let st = unsafe {
                &*fxsave.fp_reg_word[index as usize].as_ptr().cast::<FxReg>()
            };
            match st.exponent & 0x7fff {
                0x7fff => 2,
                0x0000 => {
                    if st.significand[0] == 0
                        && st.significand[1] == 0
                        && st.significand[2] == 0
                        && st.significand[3] == 0
                    {
                        1
                    } else {
                        2
                    }
                }
                _ => {
                    if st.significand[3] & 0x8000 != 0 {
                        0
                    } else {
                        2
                    }
                }
            }
        } else {
            3
        };
        ret |= tag << (2 * i);
        twd >>= 1;
    }
    ret
}

/// Loads a thread's first FPU state: the default image plus its stored
/// control word.
///
/// # Safety
///
/// `thread` must be the current thread, whose pcb `pcb_init()` built.
unsafe fn fpinit(thread: *mut Thread) {
    clear_ts();
    // SAFETY: `fpu_module_init()` set `FP_DEFAULT_STATE` before any
    // thread could reach this init, and the default image matches the
    // save kind.
    unsafe { fpu_rstor(FP_DEFAULT_STATE.load(Ordering::Relaxed)) };
    let control = unsafe { (*(*thread).pcb).init_control };
    if control != 0 {
        fldcw(control);
    }
}

/// Probes and initializes the FPU on the calling CPU.
///
/// # Safety
///
/// Runs at boot on each CPU before that CPU schedules any thread.
///
/// # Panics
///
/// Halts the kernel when no FPU answers the probe or the processor reports
/// an XSAVE area smaller than [`I386XfpSave`].
pub(crate) unsafe fn init_fpu() {
    // SAFETY: the slot `machine::slot()` returns is the boot probe's
    // record, one per CPU, and `cpu_id()` names this one.
    let native =
        if unsafe { (*machine::slot(cpu_id())).cpu_type } >= CPU_TYPE_I486 {
            CR0_NE
        } else {
            0
        };

    write_cr0((read_cr0() & !(CR0_EM | CR0_TS)) | native);
    fninit();
    let status = fnstsw();
    let control = fnstcw();

    if status & 0xff != 0 || control & 0x103f != 0x3f {
        kpanic!("init_fpu", "No FPU!")
    }

    if infinity_has_no_sign() {
        set_fp_kind(FpKind::Fp287);
        set_save_kind(FpSaveKind::FnSave);
        fnsetpm();
    } else {
        set_fp_kind(FpKind::Fp387);
        set_save_kind(FpSaveKind::FnSave);

        if has_cpu_feature(CPU_FEATURE_XSAVE) {
            let (eax, _, _, edx) = cpuid(0xd, 0x0);
            FP_XSAVE_SUPPORT_LO.store(eax, Ordering::Relaxed);
            FP_XSAVE_SUPPORT_HI.store(edx, Ordering::Relaxed);

            write_cr4(read_cr4() | CR4_OSFXSR | CR4_OSXSAVE);
            set_xcr0(u64::from(eax) | (u64::from(edx) << 32));

            let (xsave_cpu_features, ebx, _, _) = cpuid(0xd, 0x1);

            if xsave_cpu_features & CPU_FEATURE_XSAVES != 0 {
                FP_XSAVE_SIZE.store(ebx, Ordering::Relaxed);
                if ebx < size_of::<I386XfpSave>() as u32 {
                    panic_xsave_size(ebx);
                }
                set_save_kind(FpSaveKind::XSaveS);
            } else {
                let (_, ebx, _, _) = cpuid(0xd, 0x0);
                FP_XSAVE_SIZE.store(ebx, Ordering::Relaxed);
                if ebx < size_of::<I386XfpSave>() as u32 {
                    panic_xsave_size(ebx);
                }

                if xsave_cpu_features & CPU_FEATURE_XSAVEOPT != 0 {
                    set_save_kind(FpSaveKind::XSaveOpt);
                } else if xsave_cpu_features & CPU_FEATURE_XSAVEC != 0 {
                    set_save_kind(FpSaveKind::XSaveC);
                } else {
                    set_save_kind(FpSaveKind::XSave);
                }
            }

            set_fp_kind(FpKind::Fp387X);
        } else if has_cpu_feature(CPU_FEATURE_FXSR) {
            write_cr4(read_cr4() | CR4_OSFXSR);
            set_fp_kind(FpKind::Fp387Fx);
            set_save_kind(FpSaveKind::FxSave);
        }

        if save_kind() != FpSaveKind::FnSave {
            // SAFETY: the area is a local aligned the way FXSAVE requires,
            // and the assignment below runs before it is used.
            let save = unsafe {
                let mut save = core::mem::MaybeUninit::<I386XfpSave>::zeroed();
                fxsave(save.as_mut_ptr());
                save.assume_init()
            };
            let mask = if save.fp_mxcsr_mask == 0 {
                0x0000_ffbf
            } else {
                save.fp_mxcsr_mask
            };
            MXCSR_FEATURE_MASK.fetch_and(mask, Ordering::Relaxed);
        }
    }

    write_cr0(read_cr0() | CR0_TS | CR0_MP);
}

/// Halts the kernel when the processor's XSAVE area is too small.
fn panic_xsave_size(size: u32) -> ! {
    kpanic!(
        "init_fpu",
        "CPU-provided xstate size {} is smaller than our minimum {}!\n",
        size as c_int,
        size_of::<I386XfpSave>() as c_int,
    )
}

/// Writes the current size of an XFLOAT record to `size`.
///
/// # Safety
///
/// `size` must be valid for a write.
pub(crate) unsafe fn i386_get_xstate_size(size: *mut VmSize) {
    unsafe {
        *size = size_of::<I386XfloatState>() + xfp_save_size() as usize;
    }
}

/// Builds the save-area cache and the default state; runs once at startup.
///
/// # Safety
///
/// Called once at startup, before any thread can save FPU state.
///
/// # Panics
///
/// Halts the kernel if the slab layer reports no memory for the default
/// state.
pub(crate) unsafe fn fpu_module_init() {
    unsafe {
        (*ptr::addr_of_mut!(IFPS_CACHE)).init(
            b"i386_fpsave_state",
            offset_of!(I386FpSaveState, save) + xfp_save_size() as usize,
            align_of::<I386FpSaveState>(),
            None,
            CacheInitFlags::EMPTY,
        );
    }

    let state = alloc_fp_state();
    // SAFETY: the object just came from the cache at the cache's own size.
    unsafe {
        ptr::write_bytes(
            state.cast::<u8>(),
            0,
            offset_of!(I386FpSaveState, save) + xfp_save_size() as usize,
        );
    };
    FP_DEFAULT_STATE.store(state, Ordering::Relaxed);

    clear_ts();
    fninit();
    // SAFETY: the default image was just built and matches the save kind.
    unsafe { fpu_save(state) };
    set_ts();
}

/// Installs a user thread-state record as the thread's FPU state.
///
/// # Safety
///
/// `thread` must point at a live thread; `state` must hold the record
/// `flavor` names, readable for that flavor's current size.
///
/// # Panics
///
/// Halts the kernel if the slab layer reports no memory for a save area.
pub(crate) unsafe fn fpu_set_state(
    thread: *mut Thread,
    state: *mut c_void,
    flavor: c_int,
) -> Result<(), KernError> {
    if fp_kind() == FpKind::No {
        return Err(KernError::Failure);
    }

    let xfstate = state.cast::<I386XfloatState>();
    if flavor == I386_XFLOAT_STATE
        && unsafe { (*xfstate).initialized != 0 }
        && unsafe { FpSaveKind::from_int((*xfstate).fp_save_kind) }
            != Some(save_kind())
    {
        return Err(KernError::InvalidArgument);
    }

    let fstate = state.cast::<I386FloatState>();
    let invalid = if flavor == I386_FLOAT_STATE {
        unsafe { (*fstate).initialized == 0 }
    } else {
        unsafe { flavor == I386_XFLOAT_STATE && (*xfstate).initialized == 0 }
    };

    let pcb = unsafe { (*thread).pcb };

    if invalid {
        // SAFETY: `pcb` is live and the lock protects `ims.ifps`.
        let ifps = unsafe {
            (*pcb).lock.lock();
            let ifps = (*pcb).ims.ifps;
            (*pcb).ims.ifps = ptr::null_mut();
            (*pcb).lock.unlock();
            ifps
        };
        // SAFETY: the pointer was the thread's own save area, now detached.
        unsafe { free_fp_state(ifps) };
        return Ok(());
    }

    let mut new_ifps: *mut I386FpSaveState = ptr::null_mut();
    loop {
        // SAFETY: `pcb` is live and the lock protects `ims.ifps`.
        let ifps = unsafe {
            (*pcb).lock.lock();
            let ifps = (*pcb).ims.ifps;
            if ifps.is_null() {
                if new_ifps.is_null() {
                    (*pcb).lock.unlock();
                    new_ifps = alloc_fp_state();
                    continue;
                }
                let ifps = new_ifps;
                new_ifps = ptr::null_mut();
                (*pcb).ims.ifps = ifps;
                ifps
            } else {
                ifps
            }
        };

        // SAFETY: the object is the thread's own live save area; the
        // reserved part below the XSAVE size is zeroed before the record
        // is filled.
        unsafe {
            let ifps_ref = &mut *ifps;
            ptr::write_bytes(
                ptr::from_mut::<I386FpSaveState>(ifps_ref).cast::<u8>(),
                0,
                offset_of!(I386FpSaveState, save) + xfp_save_size() as usize,
            );
            ifps_ref.fp_valid = 1;
            fill_state(ifps_ref, state, flavor);
        }

        // SAFETY: the lock `pcb_init()` initialized is held here.
        unsafe { (*pcb).lock.unlock() };
        break;
    }

    // SAFETY: the retry path allocates at most one spare, which this frees.
    unsafe { free_fp_state(new_ifps) };
    Ok(())
}

/// Copies the FLOAT record into the live save area, the
/// [`I386_FLOAT_STATE`] arm of [`fill_state()`].
///
/// # Safety
///
/// `ifps` must be live and zeroed, and `state` must hold the FLOAT record.
unsafe fn fill_float_state(ifps: &mut I386FpSaveState, state: *mut c_void) {
    let fstate = state.cast::<I386FloatState>();
    let (user_fp_state, user_fp_regs) = unsafe {
        (
            (*fstate).hw_state.as_ptr().cast::<I386FpSave>(),
            (*fstate)
                .hw_state
                .as_ptr()
                .add(size_of::<I386FpSave>())
                .cast::<I386FpRegs>(),
        )
    };

    if save_kind() == FpSaveKind::FnSave {
        // SAFETY: the kind selected the FNSAVE arm.
        let native = unsafe { ifps.native() };
        unsafe {
            native.fp_save_state.fp_control = (*user_fp_state).fp_control;
            native.fp_save_state.fp_status = (*user_fp_state).fp_status;
            native.fp_save_state.fp_tag = (*user_fp_state).fp_tag;
            native.fp_save_state.fp_eip = (*user_fp_state).fp_eip;
            native.fp_save_state.fp_cs = (*user_fp_state).fp_cs;
            native.fp_save_state.fp_opcode = (*user_fp_state).fp_opcode;
            native.fp_save_state.fp_dp = (*user_fp_state).fp_dp;
            native.fp_save_state.fp_ds = (*user_fp_state).fp_ds;
            native.fp_regs = *user_fp_regs;
        }
    } else {
        // SAFETY: the kind selected the XSAVE arm.
        let xfp = unsafe { ifps.xfp() };
        // SAFETY: both pointers name records inside the caller's state.
        unsafe {
            xfp.fp_control = (*user_fp_state).fp_control;
            xfp.fp_status = (*user_fp_state).fp_status;
            xfp.fp_tag = twd_i387_to_fxsr((*user_fp_state).fp_tag);
            xfp.fp_eip = (*user_fp_state).fp_eip;
            xfp.fp_cs = (*user_fp_state).fp_cs;
            xfp.fp_opcode = (*user_fp_state).fp_opcode;
            xfp.fp_dp = (*user_fp_state).fp_dp;
            xfp.fp_ds = (*user_fp_state).fp_ds;
        }
        xfp.fp_mxcsr = 0x1f80;
        xfp.fp_mxcsr_mask = MXCSR_FEATURE_MASK.load(Ordering::Relaxed);
        for (slot, word) in xfp
            .fp_reg_word
            .iter_mut()
            .zip(unsafe { (*user_fp_regs).fp_reg_word.iter() })
        {
            // SAFETY: the source and destination are separate live arrays,
            // and the ten bytes copied fit the sixteen-byte slot.
            unsafe {
                ptr::copy_nonoverlapping(
                    word.as_ptr().cast::<u8>(),
                    slot.as_mut_ptr(),
                    size_of::<[c_ushort; 5]>(),
                );
            };
        }
        xfp.header.xfp_features = CPU_XCR0_X87;
        if save_kind() == FpSaveKind::XSaveS {
            xfp.header.xcomp_bv = XSAVE_XCOMP_BV_COMPACT;
        }
    }
}

/// Copies the user record into a fresh save area, the valid-state arm of
/// [`fpu_set_state()`].
///
/// # Safety
///
/// `ifps` must be live and zeroed, and `state` must hold the record `flavor`
/// names.
unsafe fn fill_state(
    ifps: &mut I386FpSaveState,
    state: *mut c_void,
    flavor: c_int,
) {
    if flavor == I386_FLOAT_STATE {
        unsafe { fill_float_state(ifps, state) };
    } else if flavor == I386_XFLOAT_STATE {
        let xfstate = state.cast::<I386XfloatState>();
        let image = unsafe { (*xfstate).hw_state.as_ptr() };
        // The caller's record is only four-byte aligned, below the 64 bytes
        // [`I386XfpSave`] demands, so the image is read into an aligned
        // copy rather than referenced in place.
        let user = unsafe { ptr::read_unaligned(image.cast::<I386XfpSave>()) };
        // SAFETY: the caller supplied the XFLOAT record, and the union
        // spans the full 576-byte XSAVE image regardless of the save kind
        // in use.
        let xfp = unsafe { ifps.xfp() };
        xfp.fp_control = user.fp_control;
        xfp.fp_status = user.fp_status;
        xfp.fp_tag = user.fp_tag;
        xfp.fp_eip = user.fp_eip;
        xfp.fp_cs = user.fp_cs;
        xfp.fp_opcode = user.fp_opcode;
        xfp.fp_dp = user.fp_dp;
        xfp.fp_ds = user.fp_ds;
        xfp.fp_dp3 = user.fp_dp3;
        xfp.fp_mxcsr =
            user.fp_mxcsr & MXCSR_FEATURE_MASK.load(Ordering::Relaxed);
        xfp.fp_mxcsr_mask =
            user.fp_mxcsr_mask & MXCSR_FEATURE_MASK.load(Ordering::Relaxed);
        xfp.fp_reg_word = user.fp_reg_word;
        xfp.fp_xreg_word = user.fp_xreg_word;
        xfp.header = user.header;
        let xsave_size = xfp_save_size() as usize;
        if xsave_size > size_of::<I386XfpSave>() {
            unsafe {
                ptr::copy_nonoverlapping(
                    image.add(offset_of!(I386XfpSave, extended)),
                    xfp.extended.as_mut_ptr(),
                    xsave_size - size_of::<I386XfpSave>(),
                );
            };
        }
    }
}

/// Copies the live save area into the FLOAT record, the
/// [`I386_FLOAT_STATE`] arm of [`fpu_get_state()`].
///
/// # Safety
///
/// `ifps` must be live, and `state` must be writable as a FLOAT record.
unsafe fn get_float_state(ifps: *mut I386FpSaveState, state: *mut c_void) {
    let fstate = state.cast::<I386FloatState>();
    let (user_fp_state, user_fp_regs) = unsafe {
        (*fstate).fpkind = fp_kind() as c_int;
        (*fstate).exc_status = 0;
        (
            (*fstate).hw_state.as_mut_ptr().cast::<I386FpSave>(),
            (*fstate)
                .hw_state
                .as_mut_ptr()
                .add(size_of::<I386FpSave>())
                .cast::<I386FpRegs>(),
        )
    };
    unsafe {
        ptr::write_bytes(
            user_fp_state.cast::<u8>(),
            0,
            size_of::<I386FpSave>(),
        );
    };

    if save_kind() == FpSaveKind::FnSave {
        // SAFETY: the kind selected the FNSAVE arm.
        let native = unsafe { &(*ifps).save.native };
        // SAFETY: both pointers name live records.
        unsafe {
            (*fstate).initialized = (*ifps).fp_valid;
            (*user_fp_state).fp_control = native.fp_save_state.fp_control;
            (*user_fp_state).fp_status = native.fp_save_state.fp_status;
            (*user_fp_state).fp_tag = native.fp_save_state.fp_tag;
            (*user_fp_state).fp_eip = native.fp_save_state.fp_eip;
            (*user_fp_state).fp_cs = native.fp_save_state.fp_cs;
            (*user_fp_state).fp_opcode = native.fp_save_state.fp_opcode;
            (*user_fp_state).fp_dp = native.fp_save_state.fp_dp;
            (*user_fp_state).fp_ds = native.fp_save_state.fp_ds;
            *user_fp_regs = native.fp_regs;
        }
    } else {
        // SAFETY: the kind selected the XSAVE arm.
        let xfp = unsafe { &(*ifps).save.xfp_save_state };
        // SAFETY: both pointers name live records.
        unsafe {
            (*fstate).initialized = (*ifps).fp_valid;
            (*user_fp_state).fp_control = xfp.fp_control;
            (*user_fp_state).fp_status = xfp.fp_status;
            // The converter returns a full word; the tag word is its low
            // 16 bits.
            (*user_fp_state).fp_tag = twd_fxsr_to_i387(xfp) as c_ushort;
            (*user_fp_state).fp_eip = xfp.fp_eip;
            (*user_fp_state).fp_cs = xfp.fp_cs;
            (*user_fp_state).fp_opcode = xfp.fp_opcode;
            (*user_fp_state).fp_dp = xfp.fp_dp;
            (*user_fp_state).fp_ds = xfp.fp_ds;
        }
        for (slot, word) in xfp
            .fp_reg_word
            .iter()
            .zip(unsafe { (*user_fp_regs).fp_reg_word.iter_mut() })
        {
            // SAFETY: the source and destination are separate live arrays,
            // and ten bytes fit the destination.
            unsafe {
                ptr::copy_nonoverlapping(
                    slot.as_ptr(),
                    word.as_mut_ptr().cast::<u8>(),
                    size_of::<[c_ushort; 5]>(),
                );
            };
        }
    }
}

/// Copies the live save area into the XFLOAT record, the
/// [`I386_XFLOAT_STATE`] arm of [`fpu_get_state()`].
///
/// # Safety
///
/// `ifps` must be live, and `state` must be writable as an XFLOAT record of
/// its current size.
unsafe fn get_xfloat_state(ifps: *mut I386FpSaveState, state: *mut c_void) {
    let xfstate = state.cast::<I386XfloatState>();
    let image = unsafe {
        (*xfstate).fpkind = fp_kind() as c_int;
        (*xfstate).exc_status = 0;
        (*xfstate).initialized = (*ifps).fp_valid;
        (*xfstate).fp_save_kind = save_kind() as c_int;
        (*xfstate).hw_state.as_mut_ptr()
    };
    // SAFETY: the flavor is not FLOAT and the kind is not FnSave, so the
    // object holds the XSAVE arm.
    let xfp = unsafe { &(*ifps).save.xfp_save_state };

    // The caller's record is only four-byte aligned, below the 64 bytes
    // [`I386XfpSave`] demands, so the image is built in an aligned, zeroed
    // copy and then stored unaligned.
    // SAFETY: every field of the image is an integer or an array of them,
    // for which all-zero bits are valid.
    let mut user: I386XfpSave = unsafe { core::mem::zeroed() };
    user.fp_control = xfp.fp_control;
    user.fp_status = xfp.fp_status;
    user.fp_tag = xfp.fp_tag;
    user.fp_eip = xfp.fp_eip;
    user.fp_cs = xfp.fp_cs;
    user.fp_opcode = xfp.fp_opcode;
    user.fp_dp = xfp.fp_dp;
    user.fp_ds = xfp.fp_ds;
    user.fp_dp3 = xfp.fp_dp3;
    user.fp_mxcsr = xfp.fp_mxcsr;
    user.fp_mxcsr_mask = xfp.fp_mxcsr_mask;
    user.fp_reg_word = xfp.fp_reg_word;
    user.fp_xreg_word = xfp.fp_xreg_word;
    user.header = xfp.header;
    unsafe { ptr::write_unaligned(image.cast::<I386XfpSave>(), user) };

    let xsave_size = xfp_save_size() as usize;
    if xsave_size > size_of::<I386XfpSave>() {
        unsafe {
            ptr::copy_nonoverlapping(
                xfp.extended.as_ptr(),
                image.add(offset_of!(I386XfpSave, extended)),
                xsave_size - size_of::<I386XfpSave>(),
            );
        };
    }
}

/// Writes the thread's FPU state into the user record `flavor` names.
///
/// # Safety
///
/// `thread` must point at a live thread; `state` must be writable for the
/// record `flavor` names, at that flavor's current size.
pub(crate) unsafe fn fpu_get_state(
    thread: *mut Thread,
    state: *mut c_void,
    flavor: c_int,
) -> Result<(), KernError> {
    if fp_kind() == FpKind::No {
        return Err(KernError::Failure);
    }
    if flavor != I386_FLOAT_STATE && save_kind() == FpSaveKind::FnSave {
        return Err(KernError::Failure);
    }

    let pcb = unsafe { (*thread).pcb };

    // SAFETY: `pcb` is live and the lock protects `ims.ifps`.  It is held
    // across the whole copy, so a concurrent `fpu_set_state()` cannot free
    // the area under us.
    unsafe { (*pcb).lock.lock() };
    // SAFETY: the lock is held.
    let ifps = unsafe { (*pcb).ims.ifps };
    if ifps.is_null() {
        // SAFETY: the lock taken above.
        unsafe { (*pcb).lock.unlock() };

        if flavor == I386_FLOAT_STATE {
            unsafe {
                ptr::write_bytes(
                    state.cast::<u8>(),
                    0,
                    size_of::<I386FloatState>(),
                );
            };
        } else if flavor == I386_XFLOAT_STATE {
            unsafe {
                ptr::write_bytes(
                    state.cast::<u8>(),
                    0,
                    size_of::<I386XfloatState>() + xfp_save_size() as usize,
                );
            };
        }
        return Ok(());
    }

    if thread == per_cpu::thread() {
        clear_ts();
        unsafe { fpu_save(ifps) };
        set_ts();
    }

    if flavor == I386_FLOAT_STATE {
        // SAFETY: `ifps` is live under the pcb lock, and the caller
        // promises the FLOAT record writable.
        unsafe { get_float_state(ifps, state) };
    } else if flavor == I386_XFLOAT_STATE {
        // SAFETY: `ifps` is live under the pcb lock, and the caller promises
        // the XFLOAT record writable.
        unsafe { get_xfloat_state(ifps, state) };
    }

    // SAFETY: the lock taken for the lock-scoped copy above.
    unsafe { (*pcb).lock.unlock() };
    Ok(())
}

/// Saves a thread's FPU state unless the save area is already valid.
///
/// # Safety
///
/// `thread` must point at a live thread, and the caller must not hold its
/// pcb lock the wrong way: the FPU traps run on the thread, while
/// [`fpu_get_state()`] holds the lock.
pub(crate) unsafe fn fp_save(thread: *mut Thread) {
    let pcb = unsafe { (*thread).pcb };
    // SAFETY: the pcb is live and the thread is not running elsewhere when
    // the caller saves from a trap or holds the pcb lock.
    unsafe {
        let ifps = (*pcb).ims.ifps;
        if !ifps.is_null() && (*ifps).fp_valid == 0 {
            fpu_save(ifps);
        }
    }
}

/// Gives a child thread the parent's initial x87 control word.
///
/// # Safety
///
/// Both threads must be live, and the caller must hold no FPU state lock.
pub(crate) unsafe fn fpinherit(
    parent_thread: *mut Thread,
    thread: *mut Thread,
) {
    let pcb = unsafe { (*parent_thread).pcb };
    // SAFETY: the parent's pcb is live.
    let ifps = unsafe { (*pcb).ims.ifps };
    if !ifps.is_null() {
        // SAFETY: the parent's save area is live; `pcb_init()` built the
        // child's pcb.
        unsafe {
            if (*ifps).fp_valid == 1 {
                let native = &(*ifps).save.native;
                (*(*thread).pcb).init_control =
                    native.fp_save_state.fp_control;
            } else {
                let control = &raw mut (*(*thread).pcb).init_control;
                fnstcw_to(control);
            }
        }
    }
}

/// Writes the x87 control word to the caller's `control`.
fn fnstcw_to(control: *mut c_ushort) {
    // SAFETY: `fnstcw` writes two bytes to the caller's live control word.
    unsafe {
        core::arch::asm!("fnstcw [{control}]", control = in(reg) control, options(nostack));
    };
}

/// Handles a coprocessor overrun: drops the thread's FPU state and raises a
/// bad-access exception.
///
/// # Safety
///
/// Runs from the trap handler on the current thread, at spl0.
pub(crate) unsafe fn fpextovrflt() -> ! {
    let thread = per_cpu::thread();
    // SAFETY: the trap runs on the current thread, whose pcb `pcb_init()`
    // built.
    let pcb = unsafe { (*thread).pcb };
    // SAFETY: the lock protects `ims.ifps`.
    let ifps = unsafe {
        (*pcb).lock.lock();
        let ifps = (*pcb).ims.ifps;
        (*pcb).ims.ifps = ptr::null_mut();
        (*pcb).lock.unlock();
        ifps
    };

    clear_ts();
    fninit();
    set_ts();

    // SAFETY: the pointer was the thread's own save area, now detached.
    unsafe { free_fp_state(ifps) };

    // SAFETY: `i386_exception()` does not return.
    unsafe {
        trap::i386_exception(EXC_BAD_ACCESS, VM_PROT_READ | VM_PROT_EXECUTE, 0)
    }
}

/// The exception code for an inaccessible memory reference.
const EXC_BAD_ACCESS: c_int = 1;
/// The exception code for an arithmetic fault.
const EXC_ARITHMETIC: c_int = 3;
/// The x86 arithmetic subcode for an external x87 error.
const EXC_I386_EXTERR: c_int = 5;
/// The read permission bit of a VM protection mask.
const VM_PROT_READ: c_int = 1;
/// The execute permission bit of a VM protection mask.
const VM_PROT_EXECUTE: c_int = 4;

/// Returns the thread's x87 status word for the arithmetic exception.
///
/// # Safety
///
/// `thread` must be the current thread, whose save area is live.
unsafe fn fp_status_word(thread: *mut Thread) -> c_int {
    unsafe {
        let ifps = (*(*thread).pcb).ims.ifps;
        if save_kind() == FpSaveKind::FnSave {
            c_int::from((*ifps).save.native.fp_save_state.fp_status)
        } else {
            c_int::from((*ifps).save.xfp_save_state.fp_status)
        }
    }
}

/// Raises the pending arithmetic exception on the current thread.
///
/// # Safety
///
/// Runs from the exception handler on the current thread, at spl0.
pub(crate) unsafe fn fpexterrflt() {
    let thread = per_cpu::thread();
    // SAFETY: the trap runs on the current thread, whose save area belongs
    // to it.
    unsafe { fp_save(thread) };
    // SAFETY: `i386_exception()` does not return.
    unsafe {
        trap::i386_exception(
            EXC_ARITHMETIC,
            EXC_I386_EXTERR,
            c_long::from(fp_status_word(thread)),
        )
    }
}

/// Loads a thread's FPU state, allocating a save area on first use.
///
/// # Safety
///
/// `thread` must be the current thread, whose pcb is live, and the caller
/// must hold no pcb lock.
pub(crate) unsafe fn fp_load(thread: *mut Thread) {
    let pcb = unsafe { (*thread).pcb };
    // SAFETY: the pcb is live; `ims.ifps` is read without the lock here
    // because no other CPU runs this thread.
    unsafe {
        let mut ifps = (*pcb).ims.ifps;
        if ifps.is_null() {
            ifps = alloc_fp_state();
            ptr::copy_nonoverlapping(
                FP_DEFAULT_STATE.load(Ordering::Relaxed).cast::<u8>(),
                ifps.cast::<u8>(),
                offset_of!(I386FpSaveState, save) + xfp_save_size() as usize,
            );
            (*pcb).ims.ifps = ifps;
            fpinit(thread);
        } else if (*ifps).fp_valid == 2 {
            (*ifps).fp_valid = 1;
            set_ts();
            trap::i386_exception(
                EXC_ARITHMETIC,
                EXC_I386_EXTERR,
                c_long::from(fp_status_word(thread)),
            );
        } else if (*ifps).fp_valid == 0 {
            kprint!("fp_load: invalid FPU state!\n");
            fninit();
        } else {
            fpu_rstor(ifps);
        }
        (*ifps).fp_valid = 0;
    }
}

/// Handles the x87 error interrupt: clears the latch, saves the thread's
/// state and schedules the FPU AST.
///
/// # Safety
///
/// Runs from the IRQ handler on the interrupt stack, at spl1.
pub(crate) unsafe fn fpintr(_unit: c_int) {
    // SAFETY: writing port 0xf0 clears the AT's coprocessor error latch.
    crate::arch::x86_64::pio::Port::new(0xf0).write_u8(0);
    let thread = per_cpu::thread();
    clear_ts();
    // SAFETY: the current thread's pcb is live and its save area belongs to
    // it.
    unsafe { fp_save(thread) };
    fninit();
    set_ts();
    // SAFETY: `splsched()` is the real asm routine.
    let s = unsafe { spl::splsched() };
    crate::kern::ast::on(cpu_id(), I386_FP);
    // SAFETY: `s` came from `splsched()`.
    unsafe { spl::splx(s) };
}

/// The C-ABI entry the interrupt vector table calls for the x87 error
/// interrupt.
///
/// # Safety
///
/// Runs from the IRQ handler on the interrupt stack, at spl1.
pub(crate) unsafe extern "C" fn fpintr_entry(unit: c_int) {
    unsafe { fpintr(unit) };
}

/// Handles the coprocessor-not-present trap by loading the thread's state.
///
/// # Safety
///
/// Runs from the trap handler on the current thread, at spl0.
pub(crate) unsafe fn fpnoextflt() {
    clear_ts();
    // SAFETY: the trap runs on the current thread, which is the thread
    // `fp_load()` wants; `fpu_module_init()` built the cache before any
    // thread can reach this trap.
    unsafe { fp_load(per_cpu::thread()) };
}

const _: () = assert!(
    FP_STATE_BYTES == 108,
    "i386_fp_save plus i386_fp_regs is the 108-byte FNSAVE image"
);
