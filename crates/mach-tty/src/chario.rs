// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The tty line discipline, the tty record and its status record.

use crate::cirbuf::{self, Cirbuf};
use core::ffi::{c_char, c_int, c_long, c_short, c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::slice;
use lock::RawIrqSpinLock;
use lock::lock_api::RawMutex as _;
use mach_device::ds_routines;
use mach_device::io_req::{DeviceMode, IoOp};
use mach_device::io_req::{IoDone, IoReq, IoReqQueue};
use mach_device::platform::Platform;
use mach_device::r#return::{DeviceError, DeviceSuccess, IoResult};
use mach_device::types::Message;
use mach_ipc::IpcPort;
use mach_sched::sched::CLOCK_HZ;
use mach_thread::sched::Callout;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::types::VmProt;
use mach_vm::vm_map::VmMapCopy;
use mach_vm::vm_map::{round_page, trunc_page};
use mach_vm::vm_user;

/// How many baud-rate slots the speed tables have.
pub const NSPEEDS: usize = 18;

/// The speed indices, the rows of the pseudo-DMA tables.
const B300: usize = 7;
const B600: usize = 8;
const B1200: usize = 9;
const B1800: usize = 10;
const B2400: usize = 11;
const B4800: usize = 12;
const B9600: usize = 13;
const EXTA: usize = 14;
const EXTB: usize = 15;
const B57600: usize = 16;
const B115200: usize = 17;

bitflags::bitflags! {
    /// The line state bits.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TtyState: c_int {
        /// The tty record is initialized.
        const INIT = 0x0000_0001;
        /// A delay timeout is in progress.
        const TIMEOUT = 0x0000_0002;
        /// An open waits to complete.
        const WOPEN = 0x0000_0004;
        /// The device is open.
        const ISOPEN = 0x0000_0008;
        /// The output queue was flushed during DMA.
        const FLUSH = 0x0000_0010;
        /// The software copy of carrier-present.
        const CARR_ON = 0x0000_0020;
        /// Output is in progress.
        const BUSY = 0x0000_0040;
        /// Output is stopped by a stop character.
        const TTSTOP = 0x0000_0100;
        /// Hang up upon the last close.
        const HUPCLS = 0x0000_0200;
        /// The device is open without carrier.
        const ONDELAY = 0x0000_2000;
        /// Input is buffered when possible.
        const MIN = 0x0000_4000;
        /// The timeout of the input buffering is active.
        const MIN_TO = 0x0000_8000;
        /// The modem asked to stop.
        const RTS_DOWN = 0x0002_0000;
        /// A character arrived during the receive timeout.
        const MIN_TO_RCV = 0x0040_0000;
    }
}

bitflags::bitflags! {
    /// The line flag bits.  They come from userspace with the status, and
    /// the bits the kernel does not name are kept.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TtyFlags: c_int {
        /// Send the stop character when input fills up.
        const TANDEM = 0x0000_0001;
        /// Get and send odd parity.
        const ODDP = 0x0000_0002;
        /// Get and send even parity.
        const EVENP = 0x0000_0004;
        /// Output all eight bits.
        const LITOUT = 0x0000_0008;
        /// Start and stop output on carrier.
        const MDMBUF = 0x0000_0010;
        /// Send no hangup signal on carrier drop.
        const NOHANG = 0x0000_0020;
        /// Hang up the outgoing line on the last close.
        const HUPCLS = 0x0000_0040;
        /// The device wants the user to echo input.
        const ECHO = 0x0000_0080;
        /// The device wants `\r\n`, not `\n`.
        const CRMOD = 0x0000_0100;
        /// The device does not understand tabs.
        const XTABS = 0x0000_0200;
        // The flags userspace sets that the kernel does not name.
        const _ = !0;
    }
}

/// The modem-control operation that sets the signals.
pub const DMSET: c_int = 0;
/// The modem-control operation that sets the given signal bits.
pub const DMBIS: c_int = 1;
/// The modem-control operation that clears the given signal bits.
pub const DMBIC: c_int = 2;
/// The modem-control operation that reads the signals.
pub const DMGET: c_int = 3;

bitflags::bitflags! {
    /// The modem signals.  A line keeps the bits userspace sets, named or
    /// not.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ModemBits: c_int {
        /// Data terminal ready.
        const DTR = 0x0002;
        /// Request to send.
        const RTS = 0x0004;
        /// Clear to send.
        const CTS = 0x0020;
        /// Carrier detect.
        const CAR = 0x0040;
        /// Ring.
        const RNG = 0x0080;
        /// Data set ready.
        const DSR = 0x0100;
        /// Set a line break.
        const BRK = 0x0200;
        // The signals userspace sets that the kernel does not name.
        const _ = !0;
    }
}

impl ModemBits {
    /// No signal: the hang-up the C spelled `TM_HUP`.
    pub const HUP: Self = Self::empty();
}

/// One row of the PDMA tick table: a speed's `B*` index and the baud rate its
/// timeout divides `hz` by.
const PDMA_TIMEOUT_ROWS: [(usize, c_int); 11] = [
    (B300, 30),
    (B600, 60),
    (B1200, 120),
    (B1800, 180),
    (B2400, 240),
    (B4800, 480),
    (B9600, 960),
    (EXTA, 1440),
    (EXTB, 1920),
    (B57600, 5760),
    (B115200, 11520),
];

/// The slow speeds' water marks, as integers.
const PDMA_SLOW_MARK_ROWS: [(usize, c_int); 6] = [
    (B300, 24),
    (B600, 24),
    (B1200, 24),
    (B1800, 36),
    (B2400, 48),
    (B4800, 96),
];

/// The speeds that buffer half the input queue instead.
const PDMA_FAST_SPEEDS: [usize; 5] = [B9600, EXTA, EXTB, B57600, B115200];

const _: () = assert!(B115200 < NSPEEDS);

/// A driver's `t_getstat` routine: invoked with the owning tty's device
/// number, a status flavor and a writable buffer for it, with the tty lock
/// held.
type TtyGetstat =
    unsafe fn(u16, c_uint, *mut c_int, *mut u32) -> Result<(), DeviceError>;
/// A driver's `t_setstat` routine: invoked with the owning tty's device
/// number, a status flavor and a readable buffer of that many words, with
/// the tty lock held.
type TtySetstat =
    unsafe fn(u16, c_uint, *mut c_int, u32) -> Result<(), DeviceError>;

/// A tty line.
#[repr(C)]
#[allow(missing_docs)]
// The fields keep their `t_` prefix.
#[allow(clippy::struct_field_names)]
pub struct Tty<P: Platform> {
    pub t_lock: RawIrqSpinLock<P::Lock>,
    pub t_inq: Cirbuf,
    pub t_outq: Cirbuf,
    pub t_addr: Option<NonNull<c_char>>,
    pub t_dev: c_int,
    /// The driver's start routine: invoked with the owning tty, whose lock
    /// the caller must hold.
    pub t_start: Option<unsafe fn(*mut Self)>,
    /// The driver's stop routine: invoked with the owning tty and the
    /// sides being stopped, whose lock the caller must hold.
    pub t_stop: Option<unsafe fn(*mut Self, DeviceMode)>,
    /// The driver's modem-control routine: invoked with the owning tty and
    /// a `TM_*`/`DM*` command pair, whose lock the caller must hold.
    pub t_mctl: Option<unsafe fn(*mut Self, ModemBits, c_int) -> ModemBits>,
    pub t_ispeed: u8,
    pub t_ospeed: u8,
    pub t_breakc: c_char,
    pub t_flags: TtyFlags,
    pub t_state: TtyState,
    pub t_line: c_int,
    pub t_delayed_read: IoReqQueue<P>,
    pub t_delayed_write: IoReqQueue<P>,
    pub t_delayed_open: IoReqQueue<P>,
    t_timeout: Callout<P>,
    pub t_getstat: Option<TtyGetstat>,
    pub t_setstat: Option<TtySetstat>,
    t_tops: Option<NonNull<c_void>>,
}

// The record has no fixed size or field offsets: `t_timeout` is a `Callout`,
// and nothing MIG-visible reads it.

impl<P: Platform> Tty<P> {
    /// The zero image a C `static` began with, ready for [`chars`].
    pub const fn new() -> Self {
        Self {
            t_lock: RawIrqSpinLock::named("tty"),
            t_inq: Cirbuf::new(),
            t_outq: Cirbuf::new(),
            t_addr: None,
            t_dev: 0,
            t_start: None,
            t_stop: None,
            t_mctl: None,
            t_ispeed: 0,
            t_ospeed: 0,
            t_breakc: 0,
            t_flags: TtyFlags::empty(),
            t_state: TtyState::empty(),
            t_line: 0,
            t_delayed_read: IoReqQueue::<P>::new(),
            t_delayed_write: IoReqQueue::<P>::new(),
            t_delayed_open: IoReqQueue::<P>::new(),
            t_timeout: Callout::<P>::new(P::WHEEL, ttypush_action::<P>, ()),
            t_getstat: None,
            t_setstat: None,
            t_tops: None,
        }
    }
}

impl<P: Platform> Default for Tty<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// `struct tty_status`: a line's settings, as the status calls exchange them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
// The field names are the C `struct tty_status`'s `tt_*` members.
#[allow(clippy::struct_field_names)]
pub struct TtyStatus {
    pub tt_ispeed: c_int,
    pub tt_ospeed: c_int,
    pub tt_breakc: c_int,
    pub tt_flags: c_int,
}

const _: () = {
    assert!(size_of::<TtyStatus>() == 16);
    assert!(align_of::<TtyStatus>() == align_of::<c_int>());
    assert!(offset_of!(TtyStatus, tt_ispeed) == 0);
    assert!(offset_of!(TtyStatus, tt_ospeed) == 4);
    assert!(offset_of!(TtyStatus, tt_breakc) == 8);
    assert!(offset_of!(TtyStatus, tt_flags) == 12);
};

/// `TTY_STATUS`: `('t'<<16) + 1`, the status flavor of a line's settings.
const TTY_STATUS: c_uint = 0x0074_0001;
/// `TTY_STATUS_COUNT`: the four integers of `struct tty_status`.
const TTY_STATUS_COUNT: u32 = 4;
/// `TTY_FLUSH`: `('t'<<16) + 3`, the status flavor that flushes the line.
const TTY_FLUSH: c_uint = 0x0074_0003;
/// `TTY_FLUSH_COUNT`: one flags integer.
const TTY_FLUSH_COUNT: u32 = 1;
/// `TTY_STOP`: `('t'<<16) + 4`, the status flavor that stops the output.
const TTY_STOP: c_uint = 0x0074_0004;
/// `TTY_START`: `('t'<<16) + 5`, the status flavor that restarts the output.
const TTY_START: c_uint = 0x0074_0005;

/// The high water mark of each speed.
static TTHIWAT: [c_short; NSPEEDS] = [
    100, 100, 100, 100, 100, 100, 100, 200, 200, 400, 400, 400, 650, 650,
    1300, 2000, 2000, 2000,
];

/// The low water mark of each speed, which the serial driver reads too.
pub static TTLOWAT: [c_short; NSPEEDS] = [
    30, 30, 30, 30, 30, 30, 30, 50, 50, 120, 120, 120, 125, 125, 125, 125,
    125, 125,
];

/// The input buffer's allocation.
const TTY_INQ_SIZE: c_uint = 4096;

/// The output buffer's allocation.
static TTY_OUTQ_SIZE: c_uint = 2048;

/// Pseudo-DMA on for every line.
static PDMA_DEFAULT: c_int = 1;

/// The ticks of each speed's receive timeout; a speed no row names, below
/// 300 baud among them, has none.
static PDMA_TIMEOUTS: [c_int; NSPEEDS] = {
    let mut table = [0; NSPEEDS];
    let mut i = 0;
    while i < PDMA_TIMEOUT_ROWS.len() {
        let (speed, baud) = PDMA_TIMEOUT_ROWS[i];
        table[speed] = CLOCK_HZ / baud + 2;
        i += 1;
    }
    table
};

/// Input-queue water marks: the slow rows' own, half the input buffer for
/// the fast lines, and none below 300 baud.
static PDMA_WATER_MARK: [c_int; NSPEEDS] = {
    let mut table = [0; NSPEEDS];
    let mut i = 0;
    while i < PDMA_SLOW_MARK_ROWS.len() {
        let (speed, mark) = PDMA_SLOW_MARK_ROWS[i];
        table[speed] = mark;
        i += 1;
    }
    let mut i = 0;
    while i < PDMA_FAST_SPEEDS.len() {
        // The C value is 4096, so half is far inside `c_int`; the C narrowed
        // the same unsigned half implicitly when it stored it in the table.
        table[PDMA_FAST_SPEEDS[i]] = (TTY_INQ_SIZE / 2) as c_int;
        i += 1;
    }
    table
};

/// The table row `speed` names, or `None` when it is outside the tables.
fn speed_row(speed: c_int) -> Option<u8> {
    let row = u8::try_from(speed).ok()?;
    if usize::from(row) < NSPEEDS {
        Some(row)
    } else {
        None
    }
}

/// The high water mark of `tp`'s speed.
fn high_water<P: Platform>(tp: &Tty<P>) -> c_short {
    TTHIWAT.get(usize::from(tp.t_ospeed)).copied().unwrap_or(0)
}

/// The low water mark of `tp`'s speed.
pub fn low_water<P: Platform>(tp: &Tty<P>) -> c_short {
    TTLOWAT.get(usize::from(tp.t_ospeed)).copied().unwrap_or(0)
}

/// The receive timeout of `speed`, in ticks.
fn pdma_timeout(speed: u8) -> c_int {
    PDMA_TIMEOUTS.get(usize::from(speed)).copied().unwrap_or(0)
}

/// The input-queue water mark of `speed`.
fn pdma_water(speed: u8) -> c_int {
    PDMA_WATER_MARK
        .get(usize::from(speed))
        .copied()
        .unwrap_or(0)
}

/// Pins the queue at `head` for one operation.
///
/// Each operation pins afresh, so a completion callback that queues onto
/// the same head does not meet a pin still held by its caller.
///
/// # Safety
///
/// `head` must be a live queue head that never moves, and nothing else may
/// reach the queue while the result lives.
unsafe fn pinned<'a, P: Platform>(
    head: *mut IoReqQueue<P>,
) -> Pin<&'a mut IoReqQueue<P>> {
    // SAFETY: the caller promises the head is live, stays in place and is
    // unshared.
    unsafe { Pin::new_unchecked(&mut *head) }
}

/// Queues `ior` on `head`, to be completed later through `done`.
///
/// # Safety
///
/// `head` must be a live queue head that stays at its address, `ior`
/// must stay at its address until the queue completes it, and the caller must
/// hold the tty lock.
pub(crate) unsafe fn queue_delayed_reply<P: Platform>(
    head: *mut IoReqQueue<P>,
    ior: &mut IoReq<P>,
    done: IoDone<P>,
) {
    ior.set_done(done);
    // SAFETY: the caller promises the head and the request stay in place,
    // and holds the tty lock.
    unsafe { pinned(head).push_back_ptr(NonNull::from(ior)) };
}

/// Empty every `io_req` on `head` through `iodone()`.
///
/// # Safety
///
/// `head` must be a live queue head that stays at its address, every
/// entry must be a live `io_req`, and nothing else may access the queue
/// during the call except a completion callback.
unsafe fn complete<P: Platform>(head: *mut IoReqQueue<P>) {
    // SAFETY: every entry of these queues is a live `io_req`.
    while let Some(entry) = unsafe { pinned(head) }.pop_front() {
        unsafe { ds_routines::iodone(ptr::from_mut(entry)) };
    }
}

/// Completes every request on `queue`, when it is not null.
///
/// # Safety
///
/// `queue` must be a live queue head that stays at its address while
/// entries are linked, every entry must be an `io_req`, and nothing else may
/// access the queue during the call.
pub unsafe fn complete_queue<P: Platform>(queue: *mut IoReqQueue<P>) {
    if queue.is_null() {
        return;
    }
    unsafe { complete(queue) };
}

/// Drain one of `close()`'s delayed queues, recording `done` on each
/// request before completing it.
///
/// # Safety
///
/// Same contract as [`complete()`], and the caller must hold the tty lock.
unsafe fn drain<P: Platform>(head: *mut IoReqQueue<P>, done: IoDone<P>) {
    if head.is_null() {
        return;
    }
    // SAFETY: every entry is a live `io_req`, and `iodone()` completes it
    // once.
    while let Some(ior) = unsafe { pinned(head) }.pop_front() {
        ior.done = Some(done);
        unsafe { ds_routines::iodone(ptr::from_mut(ior)) };
    }
}

/// The done routine of an open pending when the line closes: fails it with the
/// device down.
///
/// # Safety
///
/// `ior` must be the live request `close()`'s delayed-open queue held,
/// as [`ds_routines::ds_open_done`] requires.
unsafe fn tty_close_open_reply<P: Platform>(ior: *mut IoReq<P>) -> bool {
    // SAFETY: `iodone()` passes back the live request it was queued with.
    unsafe {
        (*ior).error = Err(DeviceError::DeviceDown);
        ds_routines::ds_open_done(ior);
    }
    true
}

/// The done routine of a write pending when the line closes: fails it with the
/// device down.
///
/// # Safety
///
/// `ior` must be the live request `close()`'s delayed-write queue held,
/// as [`ds_routines::ds_write_done`] requires.
unsafe fn tty_close_write_reply<P: Platform>(ior: *mut IoReq<P>) -> bool {
    // SAFETY: `iodone()` passes back the live request it was queued with.
    unsafe {
        (*ior).residual = (*ior).count;
        (*ior).error = Err(DeviceError::DeviceDown);
        ds_routines::ds_write_done(ior);
    }
    true
}

/// The done routine of a read pending when the line closes: fails it with the
/// device down.
///
/// # Safety
///
/// `ior` must be the live request `close()`'s delayed-read queue held,
/// as [`ds_routines::ds_read_done`] requires.
unsafe fn tty_close_read_reply<P: Platform>(ior: *mut IoReq<P>) -> bool {
    // SAFETY: `iodone()` passes back the live request it was queued with.
    unsafe {
        (*ior).residual = (*ior).count;
        (*ior).error = Err(DeviceError::DeviceDown);
        ds_routines::ds_read_done(ior);
    }
    true
}

/// Open the tty, queueing the request when the carrier is not up yet.
pub fn open<P: Platform>(
    tp: &mut Tty<P>,
    dev: c_int,
    mode: DeviceMode,
    ior: &mut IoReq<P>,
) -> DeviceSuccess {
    tp.t_lock.lock();
    tp.t_dev = dev;

    if let Some(mctl) = tp.t_mctl {
        // SAFETY: the driver's modem-control routine takes its own tty; the
        // tty lock is held, as its contract requires.
        unsafe { mctl(ptr::from_mut(tp), ModemBits::DTR, DMSET) };
    }

    if PDMA_DEFAULT != 0 {
        tp.t_state |= TtyState::MIN;
    }

    if !tp.t_state.intersects(TtyState::CARR_ON) {
        if mode.contains(DeviceMode::NODELAY) {
            tp.t_state |= TtyState::ONDELAY;
        } else {
            tp.t_state |= TtyState::WOPEN;
            ior.dev_ptr = ptr::from_mut(tp).cast::<c_char>();
            // SAFETY: the open queue is the tty's and stays at its address;
            // the request stays live until `char_open_done()` completes it.
            unsafe {
                queue_delayed_reply(
                    ptr::from_mut(&mut tp.t_delayed_open),
                    ior,
                    char_open_done,
                );
            };
            // SAFETY: the tty lock was taken above.
            unsafe { tp.t_lock.unlock() };
            return DeviceSuccess::IoQueued;
        }
    }

    tp.t_state |= TtyState::ISOPEN;
    if let Some(mctl) = tp.t_mctl {
        // SAFETY: the driver's modem-control routine takes its own tty;
        // the tty lock is held, as its contract requires.
        unsafe { mctl(ptr::from_mut(tp), ModemBits::RTS, DMBIS) };
    }

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    DeviceSuccess::Success
}

/// The done routine of a delayed open: completes it once the carrier is up.
///
/// # Safety
///
/// `ior` is the live open request `open()` queued on a tty.
pub(crate) unsafe fn char_open_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    let ior = unsafe { &mut *ior };
    // SAFETY: `open()` set `dev_ptr` to the tty that stays live.
    let tp = unsafe { &mut *ior.dev_ptr.cast::<Tty<P>>() };
    tp.t_lock.lock();

    if !tp.t_state.intersects(TtyState::ISOPEN) {
        // SAFETY: the open queue is the tty's and stays at its address.
        unsafe {
            queue_delayed_reply(
                ptr::from_mut(&mut tp.t_delayed_open),
                ior,
                char_open_done,
            );
        };
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return false;
    }

    tp.t_state |= TtyState::ISOPEN;
    tp.t_state &= !TtyState::WOPEN;
    if let Some(mctl) = tp.t_mctl {
        // SAFETY: the driver's modem-control routine takes its own tty; the
        // tty lock is held.
        unsafe { mctl(ptr::from_mut(tp), ModemBits::RTS, DMBIS) };
    }

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };

    ior.error = Ok(());
    unsafe { ds_routines::ds_open_done(ptr::from_mut(ior)) };
    true
}

/// Write the request's data to the tty's output queue.
///
/// # Errors
///
/// [`DeviceError::IoError`] when the line has no carrier and was not opened
/// without one, [`DeviceError::WouldBlock`] when it has no carrier and the
/// request may not wait, and [`DeviceError::Vm`] when the data cannot be
/// mapped in.
pub fn write<P: Platform>(tp: &mut Tty<P>, ior: &mut IoReq<P>) -> IoResult {
    let count = ior.count;
    if count == 0 {
        return Ok(DeviceSuccess::Success);
    }

    let inband = ior.op.contains(IoOp::INBAND);
    let mut addr: VmOffset = 0;
    let mut data = ior.data;
    if !inband {
        // SAFETY: the request's data is a live map copy, the device I/O map is
        // the boot map `ds_routines` owns, and `addr` is writable.
        let copied = NonNull::new(data.cast::<VmMapCopy<P>>()).map_or(
            Ok(0),
            |copy| unsafe {
                (*ds_routines::device_io_map::<P>()).copyout(copy)
            },
        );
        match copied {
            Ok(mapped) => addr = mapped,
            Err(error) => return Err(DeviceError::Vm(error)),
        }
        // The tty lock spins with interrupts off, and a fault on the fresh
        // mapping would sleep for the map's lock: wire the bytes first.  The
        // deallocation below unwires them.
        if addr != 0 {
            // SAFETY: the device I/O map is the boot map `ds_routines` owns.
            let map = unsafe { &mut *ds_routines::device_io_map::<P>() };
            let end = addr + count as usize;
            if let Err(error) = map.pageable(
                trunc_page(addr),
                round_page(end),
                VmProt::READ,
                true,
                true,
            ) {
                let _ = vm_user::deallocate(map, addr, count as VmSize);
                return Err(DeviceError::Vm(error));
            }
        }
        // SAFETY: `vm_map_copyout()` mapped the copy's bytes at `addr` on
        // success.
        data = with_exposed_provenance_mut(addr);
    }

    tp.t_lock.lock();

    let result = if !tp.t_state.intersects(TtyState::CARR_ON)
        && !tp.t_state.intersects(TtyState::ONDELAY)
    {
        Err(DeviceError::IoError)
    } else if !tp.t_state.intersects(TtyState::CARR_ON)
        && ior.mode.contains(DeviceMode::NOWAIT)
    {
        Err(DeviceError::WouldBlock)
    } else {
        Ok(write_output(tp, ior, data, count))
    };

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };

    if !inband {
        // SAFETY: the copyout above mapped `count` bytes at `addr` in
        // the device I/O map, and the request still owns them.
        let _ = vm_user::deallocate(
            unsafe { &mut *ds_routines::device_io_map::<P>() },
            addr,
            count as VmSize,
        );
    }

    result
}

/// The output path of `write()`, the tty lock held and the carrier checked.
fn write_output<P: Platform>(
    tp: &mut Tty<P>,
    ior: &mut IoReq<P>,
    data: *mut c_char,
    count: c_long,
) -> DeviceSuccess {
    // A negative `count` is outside the device layer's contract and counts
    // as empty.
    let len = usize::try_from(count).unwrap_or(0);
    // SAFETY: the caller guarantees `len` readable bytes at `data`: the
    // inband buffer or the copyout mapping.
    let input = unsafe { slice::from_raw_parts(data.cast::<u8>(), len) };
    let entered = tp.t_outq.write(input);
    // A negative count is clamped to zero, and the residual comes from the
    // clamped value.
    ior.residual = len as c_long - entered as c_long;

    tp.t_state &= !TtyState::TTSTOP;
    start(tp);

    if tp.t_outq.count() > high_water(tp)
        || !tp.t_state.intersects(TtyState::CARR_ON)
    {
        ior.dev_ptr = ptr::from_mut(tp).cast::<c_char>();
        // SAFETY: the write queue is the tty's and stays at its address; the
        // request stays live until `char_write_done()` completes it.
        unsafe {
            queue_delayed_reply(
                ptr::from_mut(&mut tp.t_delayed_write),
                ior,
                char_write_done,
            );
        };
        return DeviceSuccess::IoQueued;
    }
    DeviceSuccess::Success
}

/// The done routine of a queued write: copies more data to the line, or
/// completes the write.
///
/// # Safety
///
/// `ior` is the live write request `write()` queued on a tty.
pub(crate) unsafe fn char_write_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    let ior = unsafe { &mut *ior };
    // SAFETY: `write_output()` set `dev_ptr` to the tty that stays live.
    let tp = unsafe { &mut *ior.dev_ptr.cast::<Tty<P>>() };
    tp.t_lock.lock();

    if tp.t_outq.count() > high_water(tp)
        || !tp.t_state.intersects(TtyState::CARR_ON)
    {
        // SAFETY: the write queue is the tty's and stays at its address.
        unsafe {
            queue_delayed_reply(
                ptr::from_mut(&mut tp.t_delayed_write),
                ior,
                char_write_done,
            );
        };
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return false;
    }

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };

    if let Some(port) = IpcPort::valid(ior.reply_port) {
        // SAFETY: the reply consumes the live reply port.
        let _ = unsafe {
            P::send(Message::WriteReply {
                reply_port: port.as_ptr(),
                reply_port_type: ior.reply_port_type,
                inband: ior.op.contains(IoOp::INBAND),
                result: ior.error,
                // The C narrowed the long difference to the reply's `int`
                // count.
                bytes_written: (ior.total - ior.residual) as c_int,
            })
        };
    }
    unsafe {
        mach_device::dev_lookup::deallocate::<P>(ior.device.cast());
    };
    true
}

/// Read the tty's input queue into the request's data buffer.
///
/// # Errors
///
/// [`DeviceError::IoError`] when the line has no carrier and was not opened
/// without one, [`DeviceError::WouldBlock`] when it has no carrier and the
/// request may not wait, and the buffer's allocation error when the data
/// buffer cannot be set up.
pub fn read<P: Platform>(tp: &mut Tty<P>, ior: &mut IoReq<P>) -> IoResult {
    // The C narrowed `io_count` to `vm_size_t`; the device layer sizes the
    // count, so the conversion cannot lose anything that matters.
    let size = ior.count as VmSize;
    // SAFETY: `device_read_alloc()`'s contract; the request is live.
    unsafe { ds_routines::device_read_alloc(ptr::from_mut(ior), size) }?;

    tp.t_lock.lock();

    if !tp.t_state.intersects(TtyState::CARR_ON)
        && !tp.t_state.intersects(TtyState::ONDELAY)
    {
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return Err(DeviceError::IoError);
    }
    if !tp.t_state.intersects(TtyState::CARR_ON)
        && ior.mode.contains(DeviceMode::NOWAIT)
    {
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return Err(DeviceError::WouldBlock);
    }

    if tp.t_inq.count() <= 0 || !tp.t_state.intersects(TtyState::CARR_ON) {
        ior.dev_ptr = ptr::from_mut(tp).cast::<c_char>();
        // SAFETY: the read queue is the tty's and stays at its address; the
        // request stays live until `char_read_done()` completes it.
        unsafe {
            queue_delayed_reply(
                ptr::from_mut(&mut tp.t_delayed_read),
                ior,
                char_read_done,
            );
        };
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return Ok(DeviceSuccess::IoQueued);
    }

    let out = if ior.count <= 0 {
        None
    } else {
        // SAFETY: `device_read_alloc()` allocated `count` writable bytes at
        // `data` above.
        Some(unsafe {
            slice::from_raw_parts_mut(
                ior.data.cast::<u8>(),
                ior.count as usize,
            )
        })
    };
    let copied = match out {
        Some(out) => tp.t_inq.read(out),
        None => 0,
    };
    ior.residual = ior.count - copied as c_long;

    if tp.t_state.intersects(TtyState::RTS_DOWN) {
        if let Some(mctl) = tp.t_mctl {
            // SAFETY: the driver's modem-control routine takes its own tty;
            // the tty lock is held.
            unsafe { mctl(ptr::from_mut(tp), ModemBits::RTS, DMBIS) };
        }
        tp.t_state &= !TtyState::RTS_DOWN;
    }

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    Ok(DeviceSuccess::Success)
}

/// The done routine of a queued read: copies the input that arrived, or keeps
/// waiting.
///
/// # Safety
///
/// `ior` is the live read request `read()` queued on a tty.
pub(crate) unsafe fn char_read_done<P: Platform>(ior: *mut IoReq<P>) -> bool {
    let ior = unsafe { &mut *ior };
    // SAFETY: `read()` set `dev_ptr` to the tty that stays live.
    let tp = unsafe { &mut *ior.dev_ptr.cast::<Tty<P>>() };
    tp.t_lock.lock();

    if tp.t_inq.count() <= 0 || !tp.t_state.intersects(TtyState::CARR_ON) {
        // SAFETY: the read queue is the tty's and stays at its address.
        unsafe {
            queue_delayed_reply(
                ptr::from_mut(&mut tp.t_delayed_read),
                ior,
                char_read_done,
            );
        };
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return false;
    }

    let out = if ior.count <= 0 {
        None
    } else {
        // SAFETY: `device_read_alloc()` allocated `count` writable bytes at
        // `data` when the request was queued.
        Some(unsafe {
            slice::from_raw_parts_mut(
                ior.data.cast::<u8>(),
                ior.count as usize,
            )
        })
    };
    let copied = match out {
        Some(out) => tp.t_inq.read(out),
        None => 0,
    };
    ior.residual = ior.count - copied as c_long;

    if tp.t_state.intersects(TtyState::RTS_DOWN) {
        if let Some(mctl) = tp.t_mctl {
            // SAFETY: the driver's modem-control routine takes its own tty;
            // the tty lock is held.
            unsafe { mctl(ptr::from_mut(tp), ModemBits::RTS, DMBIS) };
        }
        tp.t_state &= !TtyState::RTS_DOWN;
    }

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };

    unsafe { ds_routines::ds_read_done(ior) };
    true
}

/// Completes the delayed replies and hangs up.
///
/// # Safety
///
/// The caller must hold the tty lock, as the C contract requires.
pub fn close<P: Platform>(tp: &mut Tty<P>) {
    // SAFETY: the delayed queues are the tty's, initialized before any
    // request is queued, and the caller holds the tty lock.
    unsafe {
        drain(ptr::from_mut(&mut tp.t_delayed_read), tty_close_read_reply);
        drain(
            ptr::from_mut(&mut tp.t_delayed_write),
            tty_close_write_reply,
        );
        drain(ptr::from_mut(&mut tp.t_delayed_open), tty_close_open_reply);
    }

    if let Some(mctl) = tp.t_mctl {
        // SAFETY: the driver's modem-control routine takes its own tty; the
        // tty lock is held.
        unsafe {
            mctl(ptr::from_mut(tp), ModemBits::BRK | ModemBits::RTS, DMBIC)
        };
        if tp.t_state.intersects(TtyState::HUPCLS | TtyState::WOPEN)
            || !tp.t_state.intersects(TtyState::ISOPEN)
        {
            // SAFETY: the driver's modem-control routine takes its own tty;
            // the tty lock is held.
            unsafe { mctl(ptr::from_mut(tp), ModemBits::HUP, DMSET) };
        }
    }

    tp.t_state &= TtyState::MIN | TtyState::CARR_ON;
}

/// The `TTY_STATUS` read of `tty_get_status()`.
pub(crate) fn status<P: Platform>(tp: &Tty<P>) -> TtyStatus {
    tp.t_lock.lock();
    let mut status = TtyStatus {
        tt_ispeed: c_int::from(tp.t_ispeed),
        tt_ospeed: c_int::from(tp.t_ospeed),
        tt_breakc: c_int::from(tp.t_breakc),
        tt_flags: tp.t_flags.bits(),
    };
    if tp.t_state.intersects(TtyState::HUPCLS) {
        status.tt_flags |= TtyFlags::HUPCLS.bits();
    }
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    status
}

/// Reports the line's status flavor `flavor` into `data`.
///
/// # Errors
///
/// [`DeviceError::InvalidOperation`] for a flavor the line does not report,
/// or a buffer too small for it.
///
/// # Safety
///
/// `tp` must point at a live tty; `data` must be writable for `*count`
/// integers, and `count` writable.
pub unsafe fn tty_get_status<P: Platform>(
    tp: *mut Tty<P>,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut u32,
) -> Result<(), DeviceError> {
    match flavor {
        TTY_STATUS => {
            if unsafe { *count } < TTY_STATUS_COUNT {
                return Err(DeviceError::InvalidOperation);
            }
            let status = status(unsafe { &*tp });
            unsafe { data.cast::<TtyStatus>().write(status) };
            unsafe { *count = TTY_STATUS_COUNT };
            Ok(())
        }
        _ => Err(DeviceError::InvalidOperation),
    }
}

/// The `TTY_STATUS` write of `tty_set_status()`.
pub(crate) fn apply_status<P: Platform>(
    tp: &mut Tty<P>,
    status: &TtyStatus,
) -> Result<(), DeviceError> {
    let Some(ispeed) = speed_row(status.tt_ispeed) else {
        return Err(DeviceError::InvalidOperation);
    };
    let Some(ospeed) = speed_row(status.tt_ospeed) else {
        return Err(DeviceError::InvalidOperation);
    };

    tp.t_lock.lock();
    tp.t_ispeed = ispeed;
    tp.t_ospeed = ospeed;
    // The C stored the int in a char, truncating; this keeps that.
    tp.t_breakc = status.tt_breakc as c_char;
    tp.t_flags =
        TtyFlags::from_bits_retain(status.tt_flags) & !TtyFlags::HUPCLS;
    if status.tt_flags & TtyFlags::HUPCLS.bits() != 0 {
        tp.t_state |= TtyState::HUPCLS;
    }
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    Ok(())
}

/// The `TTY_FLUSH` case of `tty_set_status()`.
pub(crate) fn set_flush<P: Platform>(tp: &mut Tty<P>, flags: DeviceMode) {
    tp.t_lock.lock();
    flush(tp, flags);
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// The `TTY_STOP` case of `tty_set_status()`.
pub(crate) fn stop_output<P: Platform>(tp: &mut Tty<P>) {
    tp.t_lock.lock();
    if !tp.t_state.intersects(TtyState::TTSTOP) {
        tp.t_state |= TtyState::TTSTOP;
        if let Some(stop) = tp.t_stop {
            // SAFETY: the driver's stop routine takes its own tty; the tty
            // lock is held.
            unsafe { stop(ptr::from_mut(tp), DeviceMode::empty()) };
        }
    }
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// The `TTY_START` case of `tty_set_status()`.
pub(crate) fn start_output<P: Platform>(tp: &mut Tty<P>) {
    tp.t_lock.lock();
    if tp.t_state.intersects(TtyState::TTSTOP) {
        tp.t_state &= !TtyState::TTSTOP;
        start(tp);
    }
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// Applies the status flavor `flavor` from `data` to the line.
///
/// # Errors
///
/// [`DeviceError::InvalidOperation`] for a flavor the line does not take,
/// a buffer too short for it, or a speed the line does not have.
///
/// # Safety
///
/// `tp` must point at a live tty, and `data` must be readable for `count`
/// integers.
pub unsafe fn tty_set_status<P: Platform>(
    tp: *mut Tty<P>,
    flavor: c_uint,
    data: *mut c_int,
    count: u32,
) -> Result<(), DeviceError> {
    match flavor {
        TTY_FLUSH => {
            if count < TTY_FLUSH_COUNT {
                return Err(DeviceError::InvalidOperation);
            }
            let flags =
                DeviceMode::from_bits_retain(unsafe { *data } as c_uint);
            let flags = if flags.is_empty() {
                DeviceMode::READ | DeviceMode::WRITE
            } else {
                flags
            };
            set_flush(unsafe { &mut *tp }, flags);
            Ok(())
        }
        TTY_STOP => {
            stop_output(unsafe { &mut *tp });
            Ok(())
        }
        TTY_START => {
            start_output(unsafe { &mut *tp });
            Ok(())
        }
        TTY_STATUS => {
            if count < TTY_STATUS_COUNT {
                return Err(DeviceError::InvalidOperation);
            }
            let status = unsafe { data.cast::<TtyStatus>().read() };
            apply_status(unsafe { &mut *tp }, &status)
        }
        _ => Err(DeviceError::InvalidOperation),
    }
}

/// Initializes the line's request queues and buffers on its first use.
pub fn chars<P: Platform>(tp: &mut Tty<P>) {
    // The C tested `t_flags` against `TS_INIT`, which shares its value 1
    // with `TF_TANDEM`; the test is kept exactly.
    if !tp.t_flags.contains(TtyFlags::TANDEM) {
        tp.t_delayed_open = IoReqQueue::<P>::new();
        tp.t_delayed_read = IoReqQueue::<P>::new();
        tp.t_delayed_write = IoReqQueue::<P>::new();

        // SAFETY: `cb_alloc()`'s contract; `kalloc_init()` has run by the
        // time a tty is first opened, and the buffers are the tty's own.
        // The sizes are the C `unsigned int` constants, which fit `usize`.
        unsafe {
            cirbuf::cb_alloc::<P>(
                ptr::from_mut(&mut tp.t_inq),
                TTY_INQ_SIZE as usize,
            );
        }

        if tp.t_mctl.is_some() && tp.t_inq.hog() > 30 {
            tp.t_inq.lower_hog(30);
        }

        // SAFETY: `cb_alloc()`'s contract; `kalloc_init()` has run by the
        // time a tty is first opened, and the buffers are the tty's own.
        // The sizes are the C `unsigned int` constants, which fit `usize`.
        unsafe {
            cirbuf::cb_alloc::<P>(
                ptr::from_mut(&mut tp.t_outq),
                TTY_OUTQ_SIZE as usize,
            );
        }

        tp.t_state |= TtyState::INIT;
    }

    tp.t_breakc = 0;
}

/// Discards the input, the output or both, as `rw` says, and completes the
/// waiting reads or writes.
///
/// # Safety
///
/// The caller must hold the tty lock, as the C contract requires.
pub(crate) fn flush<P: Platform>(tp: &mut Tty<P>, rw: DeviceMode) {
    if rw.contains(DeviceMode::READ) {
        tp.t_inq.clear();
        // SAFETY: the read queue is the tty's and stays at its address.
        unsafe { complete_queue(ptr::from_mut(&mut tp.t_delayed_read)) };
    }
    if rw.contains(DeviceMode::WRITE) {
        tp.t_state &= !TtyState::TTSTOP;
        if let Some(stop) = tp.t_stop {
            // SAFETY: the driver's stop routine takes its own tty; the tty
            // lock is held.
            unsafe { stop(ptr::from_mut(tp), rw) };
        }
        tp.t_outq.clear();
        // SAFETY: the write queue is the tty's and stays at its address.
        unsafe { complete_queue(ptr::from_mut(&mut tp.t_delayed_write)) };
    }
}

/// Starts the line's output when it is not already running.
///
/// # Safety
///
/// The caller must hold the tty lock, as the C contract requires.
pub(crate) fn start<P: Platform>(tp: &mut Tty<P>) {
    if tp
        .t_state
        .intersects(TtyState::TIMEOUT | TtyState::TTSTOP | TtyState::BUSY)
    {
        return;
    }
    if let Some(driver_start) = tp.t_start {
        // SAFETY: the driver's start routine takes its own tty; the tty lock
        // is held.
        unsafe { driver_start(ptr::from_mut(tp)) };
    }
    if tp.t_outq.count() <= low_water(tp) {
        // SAFETY: the write queue is the tty's and stays at its address.
        unsafe { complete_queue(ptr::from_mut(&mut tp.t_delayed_write)) };
    }
}

/// The expiry of [`Tty::t_timeout`]: the PDMA receive timeout.
fn ttypush_action<P: Platform>(callout: Pin<&Callout<P>>) {
    // SAFETY: `t_timeout` is the callout field of a live `Tty`.
    let tp = unsafe { tty_from_timeout::<P>(callout.get_ref()) };
    // SAFETY: `tp` is a live tty the callout is embedded in.
    unsafe { ttypush(tp) };
}

/// Recover the tty that owns `t_timeout`.
///
/// # Safety
///
/// `callout` must be `&tty.t_timeout` for a live tty.
unsafe fn tty_from_timeout<P: Platform>(
    callout: *const Callout<P>,
) -> *mut Tty<P> {
    let base = callout
        .expose_provenance()
        .wrapping_sub(offset_of!(Tty<P>, t_timeout));
    with_exposed_provenance_mut(base)
}

/// The pseudo-DMA receive timeout callback: hands the buffered input to the
/// reader.
///
/// # Safety
///
/// `tp` must be the live `Tty` whose `t_timeout` fired.
unsafe fn ttypush<P: Platform>(tp: *mut Tty<P>) {
    // SAFETY: the callout recovers the tty it is embedded in, which stays live.
    let tp = unsafe { &mut *tp };
    tp.t_lock.lock();
    let state = tp.t_state;

    if state.intersects(TtyState::MIN_TO) {
        if state.intersects(TtyState::MIN_TO_RCV) {
            tp.t_state = state & !TtyState::MIN_TO_RCV;
            let ticks =
                clock::Ticks::new(pdma_timeout(tp.t_ispeed).max(1) as u64);
            // SAFETY: the tty is live and does not move while armed.
            unsafe {
                Pin::new_unchecked(&tp.t_timeout).start(ticks);
            }
        } else {
            tp.t_state = state & !TtyState::MIN_TO;
            if tp.t_inq.count() != 0 {
                // SAFETY: the read queue is the tty's and stays at its
                // address.
                unsafe {
                    complete_queue(ptr::from_mut(&mut tp.t_delayed_read));
                };
            }
        }
    } else {
        tp.t_state = state & !TtyState::MIN_TO_RCV;
    }

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// Put one input character on the tty's input queue.
///
/// # Safety
///
/// The caller must hold the tty lock, as the C contract requires.
pub fn input<P: Platform>(tp: &mut Tty<P>, c: c_uint) {
    if tp.t_inq.count() >= tp.t_inq.hog() {
        if let Some(mctl) = tp.t_mctl {
            // SAFETY: the driver's modem-control routine takes its own tty;
            // the tty lock is held.
            unsafe { mctl(ptr::from_mut(tp), ModemBits::RTS, DMBIC) };
            tp.t_state |= TtyState::RTS_DOWN;
        }
        // SAFETY: the read queue is the tty's and stays at its address.
        unsafe { complete_queue(ptr::from_mut(&mut tp.t_delayed_read)) };
        return;
    }

    let _ = tp.t_inq.put((c & 0xff) as u8);

    if !tp.t_state.intersects(TtyState::MIN)
        || c_int::from(tp.t_inq.count()) > pdma_water(tp.t_ispeed)
    {
        if tp.t_state.intersects(TtyState::MIN_TO) {
            tp.t_state &= !(TtyState::MIN_TO | TtyState::MIN_TO_RCV);
            let _ = tp.t_timeout.stop();
        }
        // SAFETY: the read queue is the tty's and stays at its address.
        unsafe { complete_queue(ptr::from_mut(&mut tp.t_delayed_read)) };
    } else {
        let ptime = pdma_timeout(tp.t_ispeed);
        if ptime > 0 {
            if tp.t_state.intersects(TtyState::MIN_TO) {
                tp.t_state |= TtyState::MIN_TO_RCV;
            } else {
                tp.t_state |= TtyState::MIN_TO;
                let ticks = clock::Ticks::new(ptime.max(1) as u64);
                // SAFETY: the tty is live and does not move while armed.
                unsafe {
                    Pin::new_unchecked(&tp.t_timeout).start(ticks);
                }
            }
        }
    }
}

/// Handles a carrier transition; returns `false` when a carrier loss hung the
/// line up.
///
/// # Safety
///
/// The caller must hold the tty lock, as the C contract requires.
pub fn modem<P: Platform>(tp: &mut Tty<P>, carrier_up: bool) -> bool {
    if !tp.t_state.intersects(TtyState::WOPEN)
        && tp.t_flags.intersects(TtyFlags::MDMBUF)
    {
        if carrier_up {
            tp.t_state &= !TtyState::TTSTOP;
            start(tp);
        } else if !tp.t_state.intersects(TtyState::TTSTOP) {
            tp.t_state |= TtyState::TTSTOP;
            if let Some(stop) = tp.t_stop {
                // SAFETY: the driver's stop routine takes its own tty; the
                // tty lock is held.
                unsafe { stop(ptr::from_mut(tp), DeviceMode::empty()) };
            }
        }
    } else if carrier_up {
        tp.t_state |= TtyState::CARR_ON;
        // SAFETY: the open queue is the tty's and stays at its address.
        unsafe { complete_queue(ptr::from_mut(&mut tp.t_delayed_open)) };
    } else {
        tp.t_state &= !TtyState::CARR_ON;
        if tp.t_state.intersects(TtyState::ISOPEN)
            && !tp.t_flags.intersects(TtyFlags::NOHANG)
        {
            flush(tp, DeviceMode::READ | DeviceMode::WRITE);
            return false;
        }
    }
    true
}

/// Handles a clear-to-send transition: stops or restarts the output.
///
/// # Safety
///
/// The caller must hold the tty lock and be on the master CPU, as the C
/// contract requires.
pub fn cts<P: Platform>(tp: &mut Tty<P>, cts_up: bool) {
    if tp.t_state.intersects(TtyState::ISOPEN) {
        if cts_up {
            tp.t_state &= !(TtyState::TTSTOP | TtyState::BUSY);
            start(tp);
        } else {
            tp.t_state |= TtyState::TTSTOP | TtyState::BUSY;
            if let Some(stop) = tp.t_stop {
                // SAFETY: the driver's stop routine takes its own tty; the
                // tty lock is held.
                unsafe {
                    stop(ptr::from_mut(tp), DeviceMode::WRITE);
                };
            }
        }
    }
}
