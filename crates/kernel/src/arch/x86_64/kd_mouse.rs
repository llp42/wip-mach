// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd_mouse.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The mouse driver.

use super::io_req::{
    D_NOWAIT, DEV_GET_SIZE, DEV_GET_SIZE_COUNT, DEV_GET_SIZE_DEVICE_SIZE,
    DEV_GET_SIZE_RECORD_SIZE, DevT, IoReq, IoReqQueue, drain,
};
use crate::arch::x86_64::com;
use crate::arch::x86_64::ioapic;
use crate::arch::x86_64::irq;
use crate::arch::x86_64::kd::{KEYBOARD, keyboard};
use crate::arch::x86_64::pio::Port;
use crate::arch::x86_64::platform::MachPlatform;
use crate::device::ds_routines::{device_read_alloc, ds_read_done, iodone};
use crate::device::r#return::{DeviceError, DeviceSuccess, IoResult};
use crate::device::subrs;
use crate::kern::console::kprint;
use crate::kern::sched_prim::{assert_wait, thread_block};
use crate::utils::kd_queue::{KdEvent, KdEventQueue, KevType, MouseMotion};
use core::ffi::{c_int, c_long, c_uint};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use lock::IrqSpinLock;

/// The signature of an interrupt handler.
type InterruptHandler = unsafe extern "C" fn(c_int);

/// The bytes of the largest mouse packet.
const MOUSEBUFSIZE: usize = 5;

/// Button directions: `MOUSE_DOWN` is the C's 0, and the direction a
/// `mouse_button()` caller passes.
const MOUSE_UP: u8 = 1;
const MOUSE_DOWN: u8 = 0;
const MOUSE_ALL_UP: u8 = 0x7;

/// The interrupt line of the PS/2 mouse.
const IBM_MOUSE_IRQ: c_int = 12;

/// Mouse protocols, from the high bits of the minor number.
const MOUSE_SYSTEM_MOUSE: c_int = 0;
const MICROSOFT_MOUSE: c_int = 1;
const IBM_MOUSE: c_int = 2;
const LOGITECH_TRACKMAN: c_int = 4;
const MICROSOFT_MOUSE7: c_int = 5;

/// The mouse event types.
const MOUSE_LEFT: KevType = 1;
const MOUSE_MIDDLE: KevType = 2;
const MOUSE_RIGHT: KevType = 3;

const RDAT: u16 = 0;
const RIE: u16 = 1;
const RID: u16 = 2;
const RLC: u16 = 3;
const RMC: u16 = 4;
const RLS: u16 = 5;
const RDLSB: u16 = 0;
const RDMSB: u16 = 1;
const IERD: u8 = 0x01;
const IELS: u8 = 0x04;
const IDRD: u8 = 0x04;
const IDLS: u8 = 0x06;
const LC7: u8 = 0x02;
const LC8: u8 = 0x03;
const LCDLAB: u8 = 0x80;
const LSDR: u8 = 0x01;
const MCDTR: u8 = 0x01;
const MCRTS: u8 = 0x02;
const MCOUT2: u8 = 0x08;
const BCNT1200: c_int = 0x60;

const K_RDWR: u16 = 0x60;
const K_STATUS: u16 = 0x64;
const K_CMD: u16 = 0x64;
const K_IBUF_FUL: u8 = 0x02;

/// Whether `/dev/mouse` is open.
static MOUSE_IN_USE: AtomicI32 = AtomicI32::new(0);

/// Whether the mouse has taken over the console (X is running).
pub(crate) fn mouse_in_use() -> c_int {
    MOUSE_IN_USE.load(Ordering::Acquire)
}

/// The driver's mutable state: the C file's file-scope globals.
struct State {
    queue: KdEventQueue,
    read_queue: IoReqQueue,
    lastbuttons: u8,
    mouse_baud: c_int,
    mouse_type: c_int,
    mousebufsize: c_int,
    mousebufindex: c_int,
    mouse_char_cmd: bool,
    mouse_char_wanted: bool,
    mouse_char_index: c_int,
    lastgitech: c_int,
    fourthgitech: c_int,
    middlegitech: c_int,
    mousebuf: [u8; MOUSEBUFSIZE],
    oldvect: Option<InterruptHandler>,
    oldunit: c_int,
    track_man: [c_int; 10],
    mouse_packets: c_int,
    show_mouse_byte: c_int,
}

impl State {
    const fn new() -> Self {
        Self {
            queue: KdEventQueue::new(),
            read_queue: IoReqQueue::new(),
            lastbuttons: 0,
            mouse_baud: BCNT1200,
            mouse_type: 0,
            mousebufsize: 0,
            mousebufindex: 0,
            mouse_char_cmd: false,
            mouse_char_wanted: false,
            mouse_char_index: 0,
            lastgitech: 0x40,
            fourthgitech: 0,
            middlegitech: 0,
            mousebuf: [0; MOUSEBUFSIZE],
            oldvect: None,
            oldunit: 0,
            track_man: [0; 10],
            mouse_packets: 0,
            show_mouse_byte: 0,
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
    IrqSpinLock::new(State::new());

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
fn enqueue(s: &mut State, ev: &KdEvent) {
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

/// Queues a motion event.
fn motion_event(s: &mut State, moved: MouseMotion) {
    enqueue(s, &KdEvent::motion(moved));
}

/// Queues a button event.
fn button_event(s: &mut State, which: KevType, direction: u8) {
    enqueue(s, &KdEvent::button(which, direction == MOUSE_UP));
}

/// Programs the serial port.
fn init_mouse_hw(s: &State, unit: c_int, mode: u8) {
    let base_addr = com::base_addr(unit) as u16;
    Port::new(base_addr + RIE).write_u8(0);
    Port::new(base_addr + RLC).write_u8(LCDLAB);
    Port::new(base_addr + RDLSB).write_u8((s.mouse_baud & 0xff) as u8);
    Port::new(base_addr + RDMSB).write_u8(((s.mouse_baud >> 8) & 0xff) as u8);
    Port::new(base_addr + RLC).write_u8(mode);
    Port::new(base_addr + RMC).write_u8(MCDTR | MCRTS | MCOUT2);
    Port::new(base_addr + RIE).write_u8(IERD | IELS);
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
    while Port::new(K_STATUS).read_u8() & K_IBUF_FUL != 0 {
        core::hint::spin_loop();
    }
    Port::new(K_CMD).write_u8(0xd4);
    while Port::new(K_STATUS).read_u8() & K_IBUF_FUL != 0 {
        core::hint::spin_loop();
    }
    Port::new(K_RDWR).write_u8(ch);
}

/// Waits for a byte the interrupt path delivers, or `-1` past the buffer.
fn read_char() -> c_int {
    loop {
        let mut s = STATE.lock();
        if s.mouse_char_index >= s.mousebufsize {
            return -1;
        }
        if s.mousebufindex > s.mouse_char_index {
            let ch = s.mousebuf[s.mouse_char_index as usize];
            s.mouse_char_index += 1;
            return c_int::from(ch);
        }
        s.mouse_char_wanted = true;
        // SAFETY: the wait channel is the buffer in the static state, which
        // the handler wakes; the wait is asserted under the lock, so a byte
        // that arrives after the check still wakes this thread, and the
        // block holds no lock.
        unsafe {
            assert_wait(NonNull::new(ptr::addr_of_mut!(s.mousebuf).cast()), 0);
            drop(s);
            thread_block(None);
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

/// Decodes a Mouse Systems packet.
fn packet_mouse_system(s: &mut State, buf: [u8; MOUSEBUFSIZE]) {
    let buttons = buf[0] & 0x7;
    let buttonchanges = buttons ^ s.lastbuttons;
    let moved = MouseMotion {
        mm_delta_x: i16::from(buf[1] as i8)
            .wrapping_add(i16::from(buf[3] as i8)),
        mm_delta_y: i16::from(buf[2] as i8)
            .wrapping_add(i16::from(buf[4] as i8)),
    };
    if moved.mm_delta_x != 0 || moved.mm_delta_y != 0 {
        motion_event(s, moved);
    }
    if buttonchanges != 0 {
        s.lastbuttons = buttons;
        if buttonchanges & 1 != 0 {
            button_event(s, MOUSE_RIGHT, buttons & 1);
        }
        if buttonchanges & 2 != 0 {
            button_event(s, MOUSE_MIDDLE, (buttons & 2) >> 1);
        }
        if buttonchanges & 4 != 0 {
            button_event(s, MOUSE_LEFT, (buttons & 4) >> 2);
        }
    }
}

/// Decodes a Microsoft packet.
fn packet_microsoft(s: &mut State, buf: [u8; MOUSEBUFSIZE]) {
    let mut buttons = (buf[0] & 0x30) >> 4;
    buttons |= s.middlegitech as u8;
    buttons = !buttons & 0x07;
    let buttonchanges = buttons ^ s.lastbuttons;
    let mut dx = i16::from(buf[0] & 0x03) << 6 | i16::from(buf[1] & 0x3f);
    let mut dy = i16::from(buf[0] & 0x0c) << 4 | i16::from(buf[2] & 0x3f);
    if dx & 0x80 != 0 {
        dx -= 0x100;
    }
    if dy & 0x80 != 0 {
        dy -= 0x100;
    }
    let moved = MouseMotion {
        mm_delta_x: dx,
        mm_delta_y: -dy,
    };
    if moved.mm_delta_x != 0 || moved.mm_delta_y != 0 {
        motion_event(s, moved);
    }
    if buttonchanges != 0 {
        s.lastbuttons = buttons;
        if buttonchanges & 1 != 0 {
            let dir = if buttons & 1 != 0 {
                MOUSE_UP
            } else {
                MOUSE_DOWN
            };
            button_event(s, MOUSE_RIGHT, dir);
        }
        if buttonchanges & 2 != 0 {
            let dir = if buttons & 2 != 0 {
                MOUSE_UP
            } else {
                MOUSE_DOWN
            };
            button_event(s, MOUSE_LEFT, dir);
        }
        if buttonchanges & 4 != 0 {
            let dir = if buttons & 4 != 0 {
                MOUSE_UP
            } else {
                MOUSE_DOWN
            };
            button_event(s, MOUSE_MIDDLE, dir);
        }
    }
}

/// Decodes a PS/2 packet.
fn packet_ibm_ps2(s: &mut State, buf: [u8; MOUSEBUFSIZE]) {
    let buttons = buf[0] & 0x7;
    let buttonchanges = buttons ^ s.lastbuttons;
    let moved = MouseMotion {
        mm_delta_x: if buf[0] & 0x10 != 0 {
            (0xffff_ff00u32 | u32::from(buf[1])) as i16
        } else {
            i16::from(buf[1])
        },
        mm_delta_y: if buf[0] & 0x20 != 0 {
            (0xffff_ff00u32 | u32::from(buf[2])) as i16
        } else {
            i16::from(buf[2])
        },
    };
    if s.mouse_packets != 0 {
        kprint!(
            "({:x}:{:x}:{:x})",
            c_int::from(buf[0]),
            c_int::from(buf[1]),
            c_int::from(buf[2]),
        );
        return;
    }
    if moved.mm_delta_x != 0 || moved.mm_delta_y != 0 {
        motion_event(s, moved);
    }
    if buttonchanges != 0 {
        s.lastbuttons = buttons;
        if buttonchanges & 1 != 0 {
            button_event(s, MOUSE_LEFT, u8::from(buttons & 1 == 0));
        }
        if buttonchanges & 2 != 0 {
            button_event(s, MOUSE_RIGHT, u8::from(buttons & 2 == 0));
        }
        if buttonchanges & 4 != 0 {
            button_event(s, MOUSE_MIDDLE, u8::from(buttons & 4 == 0));
        }
    }
}

/// Accumulates bytes until a packet is complete, then decodes it.
fn handle_byte(s: &mut State, ch: u8) {
    if s.show_mouse_byte != 0 {
        kprint!("{:x}({}) ", c_int::from(ch), char::from(ch));
    }
    if s.mouse_char_cmd {
        if s.mousebufindex < s.mousebufsize {
            s.mousebuf[s.mousebufindex as usize] = ch;
            s.mousebufindex += 1;
        }
        if s.mouse_char_wanted {
            s.mouse_char_wanted = false;
            // SAFETY: the channel is the buffer `read_char()` waits on.
            unsafe { subrs::wakeup(ptr::addr_of!(s.mousebuf) as usize) };
        }
        return;
    }
    if s.mousebufindex == 0 {
        match s.mouse_type {
            MICROSOFT_MOUSE7 => {
                if ch & 0x40 != 0x40 {
                    return;
                }
            }
            MICROSOFT_MOUSE => {
                if ch & 0xc0 != 0xc0 {
                    return;
                }
            }
            MOUSE_SYSTEM_MOUSE => {
                if ch & 0xf8 != 0x80 {
                    return;
                }
            }
            LOGITECH_TRACKMAN => {
                if s.fourthgitech == 1 {
                    s.fourthgitech = 0;
                    s.middlegitech = if ch & 0xf0 != 0 { 0x4 } else { 0x0 };
                    let buf = s.mousebuf;
                    packet_microsoft(s, buf);
                    return;
                } else if ch & 0xc0 != 0x40 {
                    return;
                }
            }
            _ => {}
        }
    }
    s.mousebuf[s.mousebufindex as usize] = ch;
    s.mousebufindex += 1;
    if s.mousebufindex < s.mousebufsize {
        return;
    }
    s.mousebufindex = 0;
    let buf = s.mousebuf;
    match s.mouse_type {
        MICROSOFT_MOUSE7 | MICROSOFT_MOUSE => packet_microsoft(s, buf),
        MOUSE_SYSTEM_MOUSE => packet_mouse_system(s, buf),
        LOGITECH_TRACKMAN => {
            if buf[1] != 0 || buf[2] != 0 || buf[0] != s.lastgitech as u8 {
                packet_microsoft(s, buf);
                s.lastgitech = c_int::from(buf[0] & 0xf0);
            } else {
                s.fourthgitech = 1;
            }
        }
        IBM_MOUSE => packet_ibm_ps2(s, buf),
        _ => {}
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
    s.lastbuttons = MOUSE_ALL_UP;
    s.mouse_type = c_int::from(((dev & 0xff) & 0xf8) >> 3);
    match s.mouse_type {
        MICROSOFT_MOUSE7 => {
            s.mousebufsize = 3;
            serial_open(&mut s, dev);
            init_mouse_hw(&s, c_int::from(dev & 7), LC7);
        }
        MICROSOFT_MOUSE => {
            s.mousebufsize = 3;
            serial_open(&mut s, dev);
            init_mouse_hw(&s, c_int::from(dev & 7), LC8);
        }
        MOUSE_SYSTEM_MOUSE => {
            s.mousebufsize = 5;
            serial_open(&mut s, dev);
            init_mouse_hw(&s, c_int::from(dev & 7), LC8);
        }
        LOGITECH_TRACKMAN => {
            s.mousebufsize = 3;
            serial_open(&mut s, dev);
            init_mouse_hw(&s, c_int::from(dev & 7), LC7);
            s.track_man[0] = com::getc(c_int::from(dev & 7));
            s.track_man[1] = com::getc(c_int::from(dev & 7));
            if s.track_man[0] != 0x4d && s.track_man[1] != 0x33 {
                kprint!("LOGITECH_TRACKMAN: NOT M3");
            }
        }
        IBM_MOUSE => {
            s.mousebufsize = 3;
            s.lastbuttons = 0;
            s.mouse_char_cmd = true;
            kd_open(&mut s, IBM_MOUSE_IRQ);
            // The PS/2 handshake sleeps for the mouse's replies, so it runs
            // with the state's lock released.
            drop(s);
            ps2_open();
            s = STATE.lock();
        }
        _ => {}
    }
    s.mousebufindex = 0;
    Ok(DeviceSuccess::Success)
}

/// Closes the mouse device.
///
/// # Safety
///
/// The device layer calls this for an open mouse.
pub(crate) unsafe fn mouseclose(dev: DevT, _flags: c_int) {
    let mouse_type = STATE.lock().mouse_type;
    match mouse_type {
        MICROSOFT_MOUSE | MICROSOFT_MOUSE7 | MOUSE_SYSTEM_MOUSE
        | LOGITECH_TRACKMAN => serial_close(&STATE.lock(), dev),
        IBM_MOUSE => {
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
        _ => {}
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
    if wanted % size_of::<KdEvent>() as c_long != 0 {
        return Err(DeviceError::InvalidSize);
    }
    unsafe { device_read_alloc(ior, wanted as usize) }?;
    let mut s = STATE.lock();
    if s.queue.is_empty() {
        if unsafe { (*ior).mode() } & D_NOWAIT != 0 {
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
            *data.add(DEV_GET_SIZE_RECORD_SIZE) =
                size_of::<KdEvent>() as c_int;
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
    let ls = Port::new(base_addr + RLS).read_u8();
    if id == IDLS {
        if ls & LSDR != 0 {
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

/// Queues a motion event.
pub(crate) fn mouse_moved(where_: MouseMotion) {
    motion_event(&mut STATE.lock(), where_);
}

/// Queues a button event.
pub(crate) fn mouse_button(which: KevType, direction: u8) {
    button_event(&mut STATE.lock(), which, direction);
}
