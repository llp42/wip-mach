// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The mouse driver.

use crate::arch::x86_64::com::{
    self, InterruptEnable, LineControl, LineStatus, ModemControl,
};
use crate::arch::x86_64::ioapic;
use crate::arch::x86_64::irq;
use crate::arch::x86_64::kd::{KEYBOARD, KbdStatus, keyboard};
use crate::arch::x86_64::kd_event::drain;
use crate::arch::x86_64::pio::Port;
use crate::arch::x86_64::platform::MachPlatform;
use crate::device::{IoReq, IoReqQueue};
use crate::kern::console::kprint;
use core::ffi::{c_int, c_long, c_uint};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use lock::IrqSpinLock;
use lock::irq_spin_lock;
use mach_device::ds_routines::{device_read_alloc, ds_read_done, iodone};
use mach_device::io_req::{
    DEV_GET_SIZE, DEV_GET_SIZE_COUNT, DEV_GET_SIZE_DEVICE_SIZE,
    DEV_GET_SIZE_RECORD_SIZE, DevT, DeviceMode,
};
use mach_device::r#return::{DeviceError, DeviceSuccess, IoResult};
use mach_device::subrs;
use mach_kd::{Event, EventQueue, Mouse, Protocol};
use mach_thread::sched_prim::{assert_wait, thread_block};

/// The signature of an interrupt handler.
type InterruptHandler = unsafe extern "C" fn(c_int);

/// The bytes of a PS/2 command reply.
const REPLY_LEN: usize = 3;

/// The interrupt line of the PS/2 mouse.
const IBM_MOUSE_IRQ: c_int = 12;

const RDAT: u16 = 0;
const RIE: u16 = 1;
const RID: u16 = 2;
const RLC: u16 = 3;
const RMC: u16 = 4;
const RLS: u16 = 5;
const RDLSB: u16 = 0;
const RDMSB: u16 = 1;
const IDRD: u8 = 0x04;
const IDLS: u8 = 0x06;
const BCNT1200: c_int = 0x60;

const K_RDWR: u16 = 0x60;
const K_CMD: u16 = 0x64;

/// Whether `/dev/mouse` is open.
static MOUSE_IN_USE: AtomicI32 = AtomicI32::new(0);

/// Whether the mouse has taken over the console (X is running).
pub(crate) fn mouse_in_use() -> c_int {
    MOUSE_IN_USE.load(Ordering::Acquire)
}

/// The driver's mutable state: the event queue, the packet decoder, and the
/// PS/2 command reply being collected.
struct State {
    queue: EventQueue,
    read_queue: IoReqQueue,
    decoder: Mouse,
    mouse_baud: c_int,
    /// Bytes go to the reply buffer, not the decoder.
    mouse_char_cmd: bool,
    mouse_char_wanted: bool,
    /// The reply bytes received.
    mousebufindex: usize,
    /// The reply bytes [`read_char`] has taken.
    mouse_char_index: usize,
    mousebuf: [u8; REPLY_LEN],
    oldvect: Option<InterruptHandler>,
    oldunit: c_int,
    track_man: [c_int; 10],
}

impl State {
    const fn new() -> Self {
        Self {
            queue: EventQueue::new(),
            read_queue: IoReqQueue::new(),
            decoder: Mouse::new(),
            mouse_baud: BCNT1200,
            mouse_char_cmd: false,
            mouse_char_wanted: false,
            mousebufindex: 0,
            mouse_char_index: 0,
            mousebuf: [0; REPLY_LEN],
            oldvect: None,
            oldunit: 0,
            track_man: [0; 10],
        }
    }
}

// SAFETY: the read queue links requests the device layer owns, which any CPU
// may complete, and the saved handler is a plain function pointer.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the queued requests are shared between CPUs, which their type \
              does not say"
)]
unsafe impl Send for State {}

/// The mouse state, under an irq spin lock, since the mouse interrupts feed
/// it.  The keyboard interrupt hands it PS/2 bytes with [`KEYBOARD`] held,
/// so nothing takes [`KEYBOARD`] while holding this lock.
static STATE: IrqSpinLock<State, MachPlatform> =
    irq_spin_lock!("kd mouse", State::new());

/// The read queue head.
///
/// # Safety
///
/// `s` must be the state in `STATE`, which never moves.
const unsafe fn read_queue(s: &mut State) -> Pin<&mut IoReqQueue> {
    // SAFETY: the caller passes the state in a static, so the head never
    // moves.
    unsafe { Pin::new_unchecked(&mut s.read_queue) }
}

/// Prints the first time a full queue drops an event, then never again.
fn printf_once() {
    static PRINTED: AtomicBool = AtomicBool::new(false);
    if !PRINTED.swap(true, Ordering::Relaxed) {
        kprint!("mouse: queue full\n");
    }
}

/// Enqueue `ev` and complete any reads waiting for data.
fn enqueue(s: &mut State, ev: &Event) {
    if s.queue.is_full() {
        printf_once();
    } else {
        s.queue.push_back(*ev);
    }
    // SAFETY: `s` is the state in `STATE`.
    while let Some(entry) = unsafe { read_queue(s) }.pop_front() {
        // SAFETY: the state's lock is held; each entry is an `io_req`, still
        // owned by the device layer and valid for `iodone()`.
        unsafe { iodone(ptr::from_mut(entry)) };
    }
}

/// Programs the serial port.
fn init_mouse_hw(s: &State, unit: c_int, mode: LineControl) {
    let base_addr = com::base_addr(unit) as u16;
    Port::new(base_addr + RIE).write_u8(0);
    Port::new(base_addr + RLC).write_u8(LineControl::DLAB.bits());
    Port::new(base_addr + RDLSB).write_u8((s.mouse_baud & 0xff) as u8);
    Port::new(base_addr + RDMSB).write_u8(((s.mouse_baud >> 8) & 0xff) as u8);
    Port::new(base_addr + RLC).write_u8(mode.bits());
    Port::new(base_addr + RMC).write_u8(
        (ModemControl::DTR | ModemControl::RTS | ModemControl::OUT2).bits(),
    );
    Port::new(base_addr + RIE)
        .write_u8((InterruptEnable::RX | InterruptEnable::ERROR).bits());
}

/// Takes over the unit's interrupt vector; the line is masked while its
/// handler and unit change.
fn serial_open(s: &mut State, dev: DevT) {
    let unit = c_int::from(dev & 7);
    let mouse_pic = com::irq(unit);
    let Ok(line) = c_uint::try_from(mouse_pic) else {
        return;
    };
    irq::__disable_irq(line);
    s.oldvect = irq::handler(mouse_pic);
    irq::set_handler(mouse_pic, Some(mouseintr));
    s.oldunit = irq::unit(mouse_pic);
    irq::set_unit(mouse_pic, unit);
    irq::__enable_irq(line);
}

/// Routes the IRQ to the keyboard driver: the line is still masked while its
/// handler changes, and unmasked after.
fn kd_open(s: &mut State, mouse_pic: c_int) {
    s.oldvect = irq::handler(mouse_pic);
    irq::set_handler(mouse_pic, Some(keyboard::kdintr));
    ioapic::unmask(mouse_pic);
}

/// Gives back the unit's interrupt vector; the line is masked while its
/// handler and unit change.
fn serial_close(s: &State, dev: DevT) {
    let unit = c_int::from(dev & 7);
    let mouse_pic = com::irq(unit);
    let base_addr = com::base_addr(unit) as u16;
    Port::new(base_addr + RIE).write_u8(0);
    Port::new(base_addr + RMC).write_u8(0);
    let Ok(line) = c_uint::try_from(mouse_pic) else {
        return;
    };
    irq::__disable_irq(line);
    irq::set_handler(mouse_pic, s.oldvect);
    irq::set_unit(mouse_pic, s.oldunit);
    irq::__enable_irq(line);
}

/// Routes the IRQ back away from the keyboard driver, masking it first.
fn kd_close(s: &State, mouse_pic: c_int) {
    ioapic::mask(mouse_pic);
    irq::set_handler(mouse_pic, s.oldvect);
}

/// Sends a byte to the PS/2 mouse, through the keyboard controller.  The
/// caller holds [`KEYBOARD`].
fn write_char(ch: u8) {
    while KbdStatus::read().contains(KbdStatus::IBUF_FUL) {
        core::hint::spin_loop();
    }
    Port::new(K_CMD).write_u8(0xd4);
    while KbdStatus::read().contains(KbdStatus::IBUF_FUL) {
        core::hint::spin_loop();
    }
    Port::new(K_RDWR).write_u8(ch);
}

/// Waits for a byte the interrupt path delivers, or `-1` past the buffer.
fn read_char() -> c_int {
    loop {
        let mut s = STATE.lock();
        if s.mouse_char_index >= REPLY_LEN {
            return -1;
        }
        if s.mousebufindex > s.mouse_char_index {
            let ch = s.mousebuf.get(s.mouse_char_index).copied().unwrap_or(0);
            s.mouse_char_index += 1;
            return c_int::from(ch);
        }
        s.mouse_char_wanted = true;
        // SAFETY: the wait channel is the buffer in the static state, which
        // the handler wakes; the wait is asserted under the lock, so a byte
        // that arrives after the check still wakes this thread, and the
        // block holds no lock.
        unsafe {
            assert_wait::<MachPlatform>(
                NonNull::new(ptr::addr_of_mut!(s.mousebuf).cast()),
                0,
            );
            drop(s);
            thread_block::<MachPlatform>(None);
        }
    }
}

/// Resets the byte the interrupt path delivers.
const fn read_reset(s: &mut State) {
    s.mousebufindex = 0;
    s.mouse_char_index = 0;
}

/// Resets the reply buffer and sends `ch` to the PS/2 mouse.  The keyboard
/// lock is held across both, so no byte the interrupt path delivers can land
/// between them.
fn send_command(ch: u8) {
    let _keyboard = KEYBOARD.lock();
    read_reset(&mut STATE.lock());
    write_char(ch);
}

/// Enables the PS/2 mouse; the caller has set the command mode.
fn ps2_open() {
    {
        let _keyboard = KEYBOARD.lock();
        keyboard::sendcmd(0xa8);
        keyboard::cmdreg_write(0x47);
    }
    send_command(0xff);
    if read_char() != 0xfa {
        return;
    }
    let _ = read_char();
    let _ = read_char();
    send_command(0xea);
    if read_char() != 0xfa {
        return;
    }
    send_command(0xf4);
    if read_char() != 0xfa {
        return;
    }
    let mut s = STATE.lock();
    read_reset(&mut s);
    s.mouse_char_cmd = false;
}

/// Disables the PS/2 mouse.
fn ps2_close() {
    STATE.lock().mouse_char_cmd = true;
    send_command(0xff);
    if read_char() == 0xfa {
        let _ = read_char();
        let _ = read_char();
    }
    let _keyboard = KEYBOARD.lock();
    keyboard::sendcmd(0xa7);
    keyboard::cmdreg_write(0x65);
}

/// Collects a PS/2 command reply byte, or decodes a packet byte and queues
/// the events it completes.
fn handle_byte(s: &mut State, ch: u8) {
    if s.mouse_char_cmd {
        if let Some(slot) = s.mousebuf.get_mut(s.mousebufindex) {
            *slot = ch;
            s.mousebufindex += 1;
        }
        if s.mouse_char_wanted {
            s.mouse_char_wanted = false;
            // The channel is the buffer `read_char()` waits on.
            subrs::wakeup::<MachPlatform>(ptr::addr_of!(s.mousebuf) as usize);
        }
        return;
    }
    for event in s.decoder.byte(ch).as_slice() {
        enqueue(s, event);
    }
}

/// Opens the mouse device for the protocol its minor number names.
///
/// # Safety
///
/// The device layer calls this with a valid, open request.
pub(crate) unsafe fn mouseopen(
    dev: DevT,
    _flags: c_int,
    _ior: *mut IoReq,
) -> IoResult {
    if MOUSE_IN_USE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(DeviceError::AlreadyOpen);
    }
    let mut s = STATE.lock();
    s.queue.clear();
    let protocol = Protocol::from_minor(dev);
    s.decoder.open(protocol);
    let unit = c_int::from(dev & 7);
    match protocol {
        Some(Protocol::Microsoft7) => {
            serial_open(&mut s, dev);
            init_mouse_hw(&s, unit, LineControl::WORD_7);
        }
        Some(Protocol::Microsoft | Protocol::MouseSystems) => {
            serial_open(&mut s, dev);
            init_mouse_hw(&s, unit, LineControl::WORD_8);
        }
        Some(Protocol::LogitechTrackman) => {
            serial_open(&mut s, dev);
            init_mouse_hw(&s, unit, LineControl::WORD_7);
            s.track_man[0] = com::getc(unit);
            s.track_man[1] = com::getc(unit);
            if s.track_man[0] != 0x4d && s.track_man[1] != 0x33 {
                kprint!("LOGITECH_TRACKMAN: NOT M3");
            }
        }
        Some(Protocol::Ps2) => {
            s.mouse_char_cmd = true;
            kd_open(&mut s, IBM_MOUSE_IRQ);
            // The PS/2 handshake sleeps for the mouse's replies, so it runs
            // with the state's lock released.
            drop(s);
            ps2_open();
            s = STATE.lock();
        }
        None => {}
    }
    s.mousebufindex = 0;
    drop(s);
    Ok(DeviceSuccess::Success)
}

/// Closes the mouse device.
///
/// # Safety
///
/// The device layer calls this for an open mouse.
pub(crate) unsafe fn mouseclose(dev: DevT, _flags: c_int) {
    let protocol = STATE.lock().decoder.protocol();
    match protocol {
        Some(
            Protocol::Microsoft
            | Protocol::Microsoft7
            | Protocol::MouseSystems
            | Protocol::LogitechTrackman,
        ) => serial_close(&STATE.lock(), dev),
        Some(Protocol::Ps2) => {
            ps2_close();
            kd_close(&STATE.lock(), IBM_MOUSE_IRQ);
            let mut i: c_int = 20000;
            while i != 0 {
                i -= 1;
                core::hint::black_box(i);
            }
            let _keyboard = KEYBOARD.lock();
            keyboard::mouse_drain();
        }
        None => {}
    }
    STATE.lock().queue.clear();
    MOUSE_IN_USE.store(0, Ordering::Release);
}

/// Reads queued mouse events, or queues the request until one arrives.
///
/// # Safety
///
/// The device layer calls this with a valid, read-only request whose buffer
/// `device_read_alloc()` may allocate.
pub(crate) unsafe fn mouseread(_dev: DevT, ior: *mut IoReq) -> IoResult {
    let wanted = unsafe { (*ior).count() };
    if wanted % size_of::<Event>() as c_long != 0 {
        return Err(DeviceError::InvalidSize);
    }
    unsafe { device_read_alloc(ior, wanted as usize) }?;
    let mut s = STATE.lock();
    if s.queue.is_empty() {
        if unsafe { (*ior).mode() }.contains(DeviceMode::NOWAIT) {
            return Err(DeviceError::WouldBlock);
        }
        unsafe { (*ior).set_done(mouse_read_done) };
        // SAFETY: the read queue is the locked state's, and the request
        // stays at its address until `iodone()`.
        unsafe {
            read_queue(&mut s).push_back_ptr(NonNull::new_unchecked(ior));
        };
        return Ok(DeviceSuccess::IoQueued);
    }
    let count = drain(&mut s.queue, unsafe { &mut *ior });
    drop(s);
    unsafe { (*ior).set_residual((*ior).count() - count) };
    Ok(DeviceSuccess::Success)
}

/// Completes a queued read once events arrive.
///
/// # Safety
///
/// `ior` must be the live request `mouseread()` queued, and the call must
/// come through `ior`'s `done` slot, as `iodone()` invokes it.
unsafe fn mouse_read_done(ior: *mut IoReq) -> bool {
    let mut s = STATE.lock();
    if s.queue.is_empty() {
        unsafe { (*ior).set_done(mouse_read_done) };
        unsafe {
            read_queue(&mut s).push_back_ptr(NonNull::new_unchecked(ior));
        };
        return false;
    }
    let count = drain(&mut s.queue, unsafe { &mut *ior });
    drop(s);
    unsafe { (*ior).set_residual((*ior).count() - count) };
    // SAFETY: the request is complete; its data buffer is populated.
    unsafe { ds_read_done(ior) };
    true
}

/// Reports a status flavor of the mouse device.
///
/// # Safety
///
/// The device layer calls this with `data` able to hold the two
/// `DEV_GET_SIZE_*` values and a valid `count`.
pub(crate) unsafe fn mousegetstat(
    _dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut u32,
) -> Result<(), DeviceError> {
    if flavor == DEV_GET_SIZE {
        unsafe {
            *data.add(DEV_GET_SIZE_DEVICE_SIZE) = 0;
            *data.add(DEV_GET_SIZE_RECORD_SIZE) = size_of::<Event>() as c_int;
            *count = DEV_GET_SIZE_COUNT;
        }
        Ok(())
    } else {
        Err(DeviceError::InvalidOperation)
    }
}

/// The serial mouse's interrupt handler.
unsafe extern "C" fn mouseintr(unit: c_int) {
    let base_addr = com::base_addr(unit) as u16;
    let id = Port::new(base_addr + RID).read_u8();
    let ls =
        LineStatus::from_bits_retain(Port::new(base_addr + RLS).read_u8());
    if id == IDLS {
        if ls.contains(LineStatus::DR) {
            let _ = Port::new(base_addr + RDAT).read_u8();
        }
        return;
    }
    if id & IDRD != 0 {
        let ch = Port::new(base_addr + RDAT).read_u8();
        handle_byte(&mut STATE.lock(), ch);
    }
}

/// Feeds a PS/2 byte to the packet decoder; the kd interrupt path calls
/// this.
pub(crate) fn mouse_handle_byte(ch: u8) {
    handle_byte(&mut STATE.lock(), ch);
}

/// Queues an event the keyboard's mouse keys stand for.  The caller may hold
/// [`KEYBOARD`].
pub(crate) fn mouse_event(event: &Event) {
    enqueue(&mut STATE.lock(), event);
}
