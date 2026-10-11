// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The 8250 serial driver, its register bits, and the bus records the
//! autoconfiguration walks.
//!
//! Every entry point runs at or above `spltty`, or at boot before interrupts
//! are enabled, so [`COM`] needs no lock of its own.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::autoconf;
use crate::arch::x86_64::busses::configure_device;
use crate::arch::x86_64::clock_platform::{MachCallout, wheel};
use crate::arch::x86_64::kd::ConsDev;
use crate::arch::x86_64::pio::Port;
use crate::config::NCOM;
use crate::device::IoReq;
use crate::device::Tty;
use crate::kern::console::{CStrArg, kprint, write_cstr};
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use lock::lock_api::RawMutex as _;
use mach_device::io_req::DevT;
use mach_device::io_req::DeviceMode;
use mach_device::r#return::{DeviceError, IoResult};
use mach_tty::chario::{
    self, DMBIC, DMBIS, DMGET, DMSET, ModemBits, TtyFlags, TtyState,
};
use volatile::VolatilePtr;

/// A bus driver: its probe, attach and naming hooks.
#[repr(C)]
#[allow(missing_docs)]
pub struct BusDriver {
    /// # Safety
    ///
    /// Autoconfiguration calls this before interrupts are enabled, with a
    /// live [`BusCtlr`] entry and the virtual address it maps to probe;
    /// the callee may assume single-threaded execution.
    pub probe: Option<unsafe fn(VmOffset, *mut BusCtlr) -> bool>,
    /// # Safety
    ///
    /// Autoconfiguration calls this before interrupts are enabled, with a
    /// live [`BusDevice`] entry and the virtual address of the master
    /// controller it is a slave of.
    pub slave: Option<unsafe fn(*mut BusDevice, VmOffset) -> bool>,
    /// # Safety
    ///
    /// Autoconfiguration calls this before interrupts are enabled, once
    /// for each live [`BusDevice`] entry it has just marked alive.
    pub attach: Option<unsafe fn(*mut BusDevice)>,
    /// # Safety
    ///
    /// The device-start ("go") routine `bus_device_go()` would call this
    /// with a live, attached [`BusDevice`] entry.
    pub dgo: Option<unsafe fn(*mut BusDevice) -> c_int>,
    pub addr: *mut VmOffset,
    pub dname: *mut c_char,
    pub dinfo: *mut *mut BusDevice,
    pub mname: *mut c_char,
    pub minfo: *mut *mut BusCtlr,
    pub flags: c_int,
}

const _: () = {
    assert!(size_of::<BusDriver>() == 80);
    assert!(align_of::<BusDriver>() == align_of::<VmOffset>());
    assert!(offset_of!(BusDriver, probe) == 0);
    assert!(offset_of!(BusDriver, slave) == 8);
    assert!(offset_of!(BusDriver, attach) == 16);
    assert!(offset_of!(BusDriver, dgo) == 24);
    assert!(offset_of!(BusDriver, addr) == 32);
    assert!(offset_of!(BusDriver, dname) == 40);
    assert!(offset_of!(BusDriver, dinfo) == 48);
    assert!(offset_of!(BusDriver, mname) == 56);
    assert!(offset_of!(BusDriver, minfo) == 64);
    assert!(offset_of!(BusDriver, flags) == 72);
};

/// A bus controller table entry.
#[repr(C)]
#[allow(missing_docs)]
pub struct BusCtlr {
    pub driver: *mut BusDriver,
    pub name: *mut c_char,
    pub unit: c_int,
    /// # Safety
    ///
    /// The interrupt dispatch table calls this at interrupt level, with
    /// the PIC/IOAPIC line masked, and its argument is the unit number
    /// registered with `irq::set_handler()`.
    pub intr: Option<unsafe extern "C" fn(c_int)>,
    pub address: VmOffset,
    pub am: c_int,
    pub phys_address: VmOffset,
    pub adaptor: c_char,
    pub alive: c_char,
    pub flags: c_char,
    pub sysdep: VmOffset,
    pub sysdep1: c_uint,
}

const _: () = {
    assert!(size_of::<BusCtlr>() == 80);
    assert!(align_of::<BusCtlr>() == align_of::<VmOffset>());
    assert!(offset_of!(BusCtlr, driver) == 0);
    assert!(offset_of!(BusCtlr, name) == 8);
    assert!(offset_of!(BusCtlr, unit) == 16);
    assert!(offset_of!(BusCtlr, intr) == 24);
    assert!(offset_of!(BusCtlr, address) == 32);
    assert!(offset_of!(BusCtlr, am) == 40);
    assert!(offset_of!(BusCtlr, phys_address) == 48);
    assert!(offset_of!(BusCtlr, adaptor) == 56);
    assert!(offset_of!(BusCtlr, alive) == 57);
    assert!(offset_of!(BusCtlr, flags) == 58);
    assert!(offset_of!(BusCtlr, sysdep) == 64);
    assert!(offset_of!(BusCtlr, sysdep1) == 72);
};

/// A bus device table entry.
#[repr(C)]
#[allow(missing_docs)]
pub struct BusDevice {
    pub driver: *mut BusDriver,
    pub name: *mut c_char,
    pub unit: c_int,
    /// # Safety
    ///
    /// The interrupt dispatch table calls this at interrupt level, with
    /// the PIC/IOAPIC line masked, and its argument is the unit number
    /// registered with `irq::set_handler()`.
    pub intr: Option<unsafe extern "C" fn(c_int)>,
    pub address: VmOffset,
    pub am: c_int,
    pub phys_address: VmOffset,
    pub adaptor: c_char,
    pub alive: c_char,
    pub ctlr: c_char,
    pub slave: c_char,
    pub flags: c_int,
    pub mi: *mut BusCtlr,
    pub next: *mut Self,
    pub sysdep: VmOffset,
    pub sysdep1: c_uint,
}

const _: () = {
    assert!(size_of::<BusDevice>() == 96);
    assert!(align_of::<BusDevice>() == align_of::<VmOffset>());
    assert!(offset_of!(BusDevice, driver) == 0);
    assert!(offset_of!(BusDevice, name) == 8);
    assert!(offset_of!(BusDevice, unit) == 16);
    assert!(offset_of!(BusDevice, intr) == 24);
    assert!(offset_of!(BusDevice, address) == 32);
    assert!(offset_of!(BusDevice, am) == 40);
    assert!(offset_of!(BusDevice, phys_address) == 48);
    assert!(offset_of!(BusDevice, adaptor) == 56);
    assert!(offset_of!(BusDevice, alive) == 57);
    assert!(offset_of!(BusDevice, ctlr) == 58);
    assert!(offset_of!(BusDevice, slave) == 59);
    assert!(offset_of!(BusDevice, flags) == 60);
    assert!(offset_of!(BusDevice, mi) == 64);
    assert!(offset_of!(BusDevice, next) == 72);
    assert!(offset_of!(BusDevice, sysdep) == 80);
    assert!(offset_of!(BusDevice, sysdep1) == 88);
};

/// The device attached to each unit, which `configure_device()` writes
/// through `COMDRIVER.dinfo`.
static mut COMINFO: [*mut BusDevice; NCOM] = [ptr::null_mut(); NCOM];

/// The CSR addresses `COMDRIVER.addr` names.
static mut COM_STD: [VmOffset; NCOM] = [0; NCOM];

/// The bus driver the AT bus table names.
pub(crate) static mut COMDRIVER: BusDriver = BusDriver {
    probe: Some(comprobe),
    slave: None,
    attach: Some(comattach),
    dgo: None,
    addr: ptr::addr_of_mut!(COM_STD).cast::<VmOffset>(),
    dname: c"com".as_ptr().cast_mut(),
    dinfo: ptr::addr_of_mut!(COMINFO).cast::<*mut BusDevice>(),
    mname: ptr::null_mut(),
    minfo: ptr::null_mut(),
    flags: 0,
};

/// The driver's mutable state: the ttys, modem and carrier bits, FIFO flags,
/// the stuck-output timer, the console unit and line, the overrun flag and
/// counters.
struct Com {
    tty: [Tty; NCOM],
    modem: [ModemBits; NCOM],
    carrier: [c_int; NCOM],
    fifo: [c_int; NCOM],
    timer_active: c_int,
    timer_state: [c_int; NCOM],
    rcline: c_int,
    cndev: *mut BusDevice,
    overrun: bool,
    st_1: c_int,
    st_2: c_int,
    st_3: c_int,
    st_4: c_int,
    timer_interval: c_int,
}

impl Com {
    const fn new() -> Self {
        Self {
            tty: [const { Tty::new() }; NCOM],
            modem: [ModemBits::empty(); NCOM],
            carrier: [0; NCOM],
            fifo: [0; NCOM],
            timer_active: 0,
            timer_state: [0; NCOM],
            rcline: -1,
            cndev: ptr::null_mut(),
            overrun: false,
            st_1: 0,
            st_2: 0,
            st_3: 0,
            st_4: 0,
            timer_interval: 5,
        }
    }
}

static COM: SyncCell<Com> = SyncCell(UnsafeCell::new(Com::new()));

fn com() -> &'static mut Com {
    // SAFETY: the driver's entry points run at or above spltty, or at boot
    // before interrupts are enabled, and no other module touches `COM`.
    unsafe { &mut *COM.0.get() }
}

bitflags::bitflags! {
    /// The 8250 line-control register.  The word length is a two-bit field
    /// at the bottom.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct LineControl: u8 {
        /// Seven-bit words.
        const WORD_7 = 0x02;
        /// Eight-bit words.
        const WORD_8 = 0x03;
        /// Two stop bits.
        const STB = 0x04;
        /// Parity enable.
        const PEN = 0x08;
        /// Even parity.
        const EPS = 0x10;
        /// Send a break.
        const SET_BREAK = 0x40;
        /// Divisor-latch access.
        const DLAB = 0x80;
        // The bits the driver does not set.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The 8250 line-status register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct LineStatus: u8 {
        /// Data ready.
        const DR = 0x01;
        /// Overrun.
        const OR = 0x02;
        /// Parity error.
        const PE = 0x04;
        /// Framing error.
        const FE = 0x08;
        /// Break received.
        const BREAK = 0x10;
        /// Transmitter holding register empty.
        const THRE = 0x20;
        // The bits the driver does not read.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The 8250 interrupt-enable register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct InterruptEnable: u8 {
        /// Received data.
        const RX = 0x01;
        /// Transmitter empty.
        const TX = 0x02;
        /// Line status.
        const ERROR = 0x04;
        /// Modem status.
        const MODEM = 0x08;
    }
}

bitflags::bitflags! {
    /// The 8250 modem-control register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ModemControl: u8 {
        /// Data terminal ready.
        const DTR = 0x01;
        /// Request to send.
        const RTS = 0x02;
        /// The interrupt line enable.
        const OUT2 = 0x08;
    }
}

bitflags::bitflags! {
    /// The 8250 modem-status register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ModemStatus: u8 {
        /// Clear to send.
        const CTS = 0x10;
        /// Data set ready.
        const DSR = 0x20;
        /// Ring indicator.
        const RI = 0x40;
        /// Carrier detect.
        const RLSD = 0x80;
        // The change bits the driver does not read.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The 16550 FIFO-control register.  The trigger level is a two-bit
    /// field at the top.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FifoControl: u8 {
        /// FIFO enable.
        const ENABLE = 0x01;
        /// Interrupt at 14 characters.
        const TRIGGER_14 = 0xc0;
        // The bits the driver does not read.
        const _ = !0;
    }
}

/// The interrupt identifications: modem status, transmitter empty, received
/// data, line status, character timeout, and their mask.
const MODI: u8 = 0;
const TRAI: u8 = 2;
const RECI: u8 = 4;
const LINI: u8 = 6;
const CTII: u8 = 0xc;
const MASKI: u8 = 0xf;

/// The tty status flavors.
pub(crate) const TTY_STATUS: c_uint = 0x0074_0001;
pub(crate) const TTY_MODEM: c_uint = 0x0074_0002;
pub(crate) const TTY_SET_BREAK: c_uint = 0x0074_0006;
pub(crate) const TTY_CLEAR_BREAK: c_uint = 0x0074_0007;

/// The tty speed indices the driver names.
const B0: u8 = 0;
const B110: u8 = 3;
const B300: u8 = 7;
const B115200: u8 = 17;

/// The initial line speed.
const ISPEED: u8 = B115200;

/// The console line speed.
const RCBAUD: usize = B115200 as usize;

/// The initial tty flags.
const IFLAGS: TtyFlags = TtyFlags::EVENP
    .union(TtyFlags::ODDP)
    .union(TtyFlags::ECHO)
    .union(TtyFlags::CRMOD)
    .union(TtyFlags::XTABS)
    .union(TtyFlags::LITOUT);

/// The 8250 divisor of each tty speed index.
const DIVISORREG: [u16; chario::NSPEEDS] = [
    0, 2304, 1536, 1047, 857, 768, 576, 384, 192, 96, 64, 48, 24, 12, 6, 3, 2,
    1,
];

/// The command-line parameter that names the console line.
const CONSOLE_PARAMETER: &CStr = c" console=com";

/// The console priorities of a dead line and a remote one.
const CN_DEAD: core::ffi::c_short = 0;
const CN_REMOTE: core::ffi::c_short = 3;

/// The transmit/receive register of the port at `addr`.
const fn txrx(addr: u16) -> Port {
    Port::new(addr)
}

/// The low divisor byte of the port at `addr`.
const fn baud_lsb(addr: u16) -> Port {
    Port::new(addr)
}

/// The high divisor byte of the port at `addr`.
const fn baud_msb(addr: u16) -> Port {
    Port::new(addr + 1)
}

/// The interrupt-enable register of the port at `addr`.
const fn intr_enab(addr: u16) -> Port {
    Port::new(addr + 1)
}

/// The interrupt-identification register of the port at `addr`.
const fn intr_id(addr: u16) -> Port {
    Port::new(addr + 2)
}

/// The FIFO-control register of the port at `addr`.
const fn fifo_ctl(addr: u16) -> Port {
    Port::new(addr + 2)
}

/// The line-control register of the port at `addr`.
const fn line_ctl(addr: u16) -> Port {
    Port::new(addr + 3)
}

/// The modem-control register of the port at `addr`.
const fn modem_ctl_reg(addr: u16) -> Port {
    Port::new(addr + 4)
}

/// The line-status register of the port at `addr`.
const fn line_stat(addr: u16) -> Port {
    Port::new(addr + 5)
}

/// The modem-status register of the port at `addr`.
const fn modem_stat(addr: u16) -> Port {
    Port::new(addr + 6)
}

/// The scratch register of the port at `addr`.
const fn scr(addr: u16) -> Port {
    Port::new(addr + 7)
}

/// `addr` as the 16-bit I/O port the C truncated it to at every access.
const fn port_addr(addr: VmOffset) -> u16 {
    // The x86 I/O port space is 16 bits wide.
    addr as u16
}

/// The port number the C kept in `tty.t_addr`.
fn tty_addr(tp: &Tty) -> u16 {
    port_addr(tp.t_addr.map_or(0, |p| p.as_ptr().addr()))
}

/// The minor number of `dev`.
const fn minor(dev: c_int) -> c_int {
    dev & 0xff
}

/// The device number of `minor`, with major number zero.
const fn makedev(minor: c_int) -> u16 {
    (minor & 0xff) as u16
}

/// The configured index `unit` names, or [`None`] when it is outside `NCOM`.
fn index(unit: c_int) -> Option<usize> {
    let index = usize::try_from(unit).ok()?;
    (index < NCOM).then_some(index)
}

/// The attached device `configure_device()` left at `index`.
fn info(index: usize) -> *mut BusDevice {
    // SAFETY: `index` is below the declaration's `NCOM` length, and the array
    // lives for the kernel's lifetime.
    unsafe {
        ptr::addr_of!(COMINFO)
            .cast::<*mut BusDevice>()
            .add(index)
            .read()
    }
}

/// Record the device attached at `index`.
fn set_info(index: usize, dev: *mut BusDevice) {
    // SAFETY: `index` is below the declaration's `NCOM` length, and the array
    // lives for the kernel's lifetime.
    unsafe {
        ptr::addr_of_mut!(COMINFO)
            .cast::<*mut BusDevice>()
            .add(index)
            .write(dev);
    }
}

/// The tty of `unit`, or [`None`] when the unit is outside `NCOM`.
pub(crate) fn tty_mut(unit: c_int) -> Option<&'static mut Tty> {
    let index = index(unit)?;
    com().tty.get_mut(index)
}

/// The `com_base_addr()` accessor the mouse driver calls: the attached
/// device's `address`, or zero when nothing is attached.
pub(crate) fn base_addr(unit: c_int) -> VmOffset {
    let Some(index) = index(unit) else {
        return 0;
    };
    let dev = info(index);
    if dev.is_null() {
        return 0;
    }
    // SAFETY: `configure_device()` wrote this live entry.
    unsafe { (*dev).address }
}

/// The `com_irq()` accessor the mouse driver calls: the attached device's
/// `sysdep1`, or zero when nothing is attached.
pub(crate) fn irq(unit: c_int) -> c_int {
    let Some(index) = index(unit) else {
        return 0;
    };
    let dev = info(index);
    if dev.is_null() {
        return 0;
    }
    // SAFETY: `configure_device()` wrote this live entry.
    unsafe { (*dev).sysdep1 as c_int }
}

/// Whether an 8250 answers at `address` for `unit`, printing what it found
/// when `noisy`.
pub(crate) fn probe_general(
    address: VmOffset,
    unit: c_int,
    noisy: bool,
) -> bool {
    let addr = port_addr(address);

    let Some(index) = index(unit) else {
        kprint!("com {} out of range\n", unit);
        return false;
    };

    let oldctl = line_ctl(addr).read_u8();
    let oldmsb = baud_msb(addr).read_u8();
    line_ctl(addr).write_u8(0);
    baud_msb(addr).write_u8(0);
    if baud_msb(addr).read_u8() != 0 {
        line_ctl(addr).write_u8(oldctl);
        baud_msb(addr).write_u8(oldmsb);
        return false;
    }
    line_ctl(addr).write_u8(LineControl::DLAB.bits());
    baud_msb(addr).write_u8(255);
    if baud_msb(addr).read_u8() != 255 {
        line_ctl(addr).write_u8(oldctl);
        baud_msb(addr).write_u8(oldmsb);
        return false;
    }
    line_ctl(addr).write_u8(0);
    if baud_msb(addr).read_u8() != 0 {
        line_ctl(addr).write_u8(oldctl);
        baud_msb(addr).write_u8(oldmsb);
        return false;
    }

    let mut i = 0u32;
    while i < 256 {
        scr(addr).write_u8(i as u8);
        if scr(addr).read_u8() != i as u8 {
            break;
        }
        i += 1;
    }

    let mut chip = c"8250";
    if i == 256 {
        scr(addr).write_u8(0);
        chip = c"82450 or 16450";
        fifo_ctl(addr)
            .write_u8((FifoControl::ENABLE | FifoControl::TRIGGER_14).bits());
        if FifoControl::from_bits_retain(fifo_ctl(addr).read_u8())
            .intersects(FifoControl::TRIGGER_14)
        {
            if FifoControl::from_bits_retain(fifo_ctl(addr).read_u8())
                .contains(FifoControl::TRIGGER_14)
            {
                chip = c"82550 or 16550";
                com().fifo[index] = 1;
            } else {
                chip = c"82550 or 16550 with non-working FIFO";
            }
            intr_id(addr).write_u8(0);
        }
    }
    if noisy {
        kprint!("com{}: {} chip.\n", unit, CStrArg::from(chip));
    }
    true
}

/// The bus probe hook: whether the unit `dev` names answers.
///
/// # Safety
///
/// `dev` must point at a live `BusCtlr` table entry; the bus configuration
/// calls it that way.
pub(crate) unsafe fn comprobe(_port: VmOffset, dev: *mut BusCtlr) -> bool {
    let (unit, address) = unsafe {
        (
            ptr::addr_of!((*dev).unit).read(),
            ptr::addr_of!((*dev).address).read(),
        )
    };
    probe_general(address, unit, false)
}

/// Picks the console line from the command line, or the first unit that
/// answers.
pub(crate) fn cnprobe(cp: &mut ConsDev) {
    let parameter = CONSOLE_PARAMETER.to_bytes();
    let cmdline = crate::arch::x86_64::model_dep::kernel_cmdline();
    let line = cmdline.to_bytes();

    // The parameter opens the line without its leading space, or follows
    // a space anywhere in it; a parameter with no unit number selects no
    // line.
    let value = if line.starts_with(&parameter[1..]) {
        Some(parameter.len() - 1)
    } else {
        line.windows(parameter.len())
            .position(|window| window == parameter)
            .map(|at| at + parameter.len())
    };
    if let Some(rest) = value.and_then(|start| line.get(start..)) {
        let digits =
            rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        com().rcline = rest
            .get(..digits)
            .and_then(|digits| str::from_utf8(digits).ok())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(-1);
    }

    let mut unit = -1;
    let mut pri = CN_DEAD;
    for device in autoconf::bus_devices() {
        // SAFETY: every entry up to the sentinel is an initialized
        // `BusDevice`, and the sentinel ends the walk.
        let (name, dev_unit, address) =
            unsafe { ((*device).name, (*device).unit, (*device).address) };
        // SAFETY: `name` is the entry's NUL-terminated name.
        let named = unsafe { CStr::from_ptr(name) } == c"com";
        if named
            && dev_unit == com().rcline
            && probe_general(address, dev_unit, false)
        {
            com().cndev = device;
            unit = dev_unit;
            pri = CN_REMOTE;
            break;
        }
    }

    cp.cn_dev = makedev(unit);
    cp.cn_pri = pri;
}

/// The console table's probe entry of [`cnprobe`].
///
/// # Safety
///
/// `cp` must point at the console table's entry, writable.
pub(crate) unsafe fn comcnprobe(cp: *mut ConsDev) {
    cnprobe(unsafe { &mut *cp });
}

/// Attaches the unit `dev` names: records it and resets its line.
pub(crate) fn attach(dev: &BusDevice) {
    // The unit is kept in a byte, truncating.
    let unit = dev.unit as u8;
    let addr = port_addr(dev.address);

    if usize::from(unit) >= NCOM {
        kprint!(", disabled by NCOM configuration\n");
        return;
    }

    autoconf::take_dev_irq(dev);
    kprint!(
        ", port = {:x}, spl = {}, pic = {}. (DOS COM{})",
        dev.address,
        dev.sysdep,
        dev.sysdep1,
        c_int::from(unit) + 1,
    );
    let Some(index) = index(c_int::from(unit)) else {
        return;
    };

    com().modem[index] = ModemBits::empty();

    intr_enab(addr).write_u8(0);
    modem_ctl_reg(addr).write_u8(0);
    while intr_id(addr).read_u8() & 1 == 0 {
        let _ = line_stat(addr).read_u8();
        let _ = txrx(addr).read_u8();
        let _ = modem_stat(addr).read_u8();
    }
}

/// The bus attach hook of [`attach`].
///
/// # Safety
///
/// `dev` must point at a live `BusDevice` table entry.
pub(crate) unsafe fn comattach(dev: *mut BusDevice) {
    attach(unsafe { &*dev });
}

/// Sets the console line up at its speed.
pub(crate) fn cninit(cp: &ConsDev) {
    let Some(cndev) = NonNull::new(com().cndev) else {
        return;
    };
    let dev = cndev.as_ptr();
    // SAFETY: `cndev` was set by `cnprobe()` to a live table entry.
    let (unit, address) = unsafe { ((*dev).unit, (*dev).address) };
    // The unit is kept in a byte, truncating.
    let unit = unit as u8;
    let addr = port_addr(address);

    // SAFETY: `cndev` is the live table entry `cnprobe()` selected.
    autoconf::take_dev_irq(unsafe { &*dev });

    // SAFETY: the entry the probe selected, and nothing else runs yet.
    unsafe {
        (*dev).alive = 1;
        (*dev).adaptor = 0;
    }

    let console_unit = usize::from(cp.cn_dev & 0xff);
    if console_unit < NCOM {
        set_info(console_unit, dev);
    }

    line_ctl(addr).write_u8(LineControl::DLAB.bits());
    baud_lsb(addr).write_u8((DIVISORREG[RCBAUD] & 0xff) as u8);
    baud_msb(addr).write_u8((DIVISORREG[RCBAUD] >> 8) as u8);
    line_ctl(addr).write_u8(LineControl::WORD_8.bits());
    intr_enab(addr).write_u8(0);
    modem_ctl_reg(addr).write_u8(
        (ModemControl::DTR | ModemControl::RTS | ModemControl::OUT2).bits(),
    );

    let mut msg = [0; 128];
    write_cstr(
        &mut msg,
        format_args!(
            "    **** using COM port {} for console ****",
            c_int::from(unit) + 1,
        ),
    );
    let vga = ptr::with_exposed_provenance_mut::<u8>(
        crate::arch::vm_param::VM_MIN_KERNEL_ADDRESS + 0xb8000,
    );
    for (i, ch) in msg.iter().enumerate() {
        if *ch == 0 {
            break;
        }
        // SAFETY: the VGA text window is mapped at the direct-map address,
        // and each cell is two bytes.
        unsafe {
            VolatilePtr::new(NonNull::new_unchecked(vga.add(2 * i)))
                .write(*ch as u8);
            VolatilePtr::new(NonNull::new_unchecked(vga.add(2 * i + 1)))
                .write(0x0c);
        }
    }
}

/// The console table's init entry of [`cninit`].
///
/// # Safety
///
/// `cp` must point at the console table's entry, initialized by
/// `comcnprobe()`.
pub(crate) unsafe fn comcninit(cp: *mut ConsDev) {
    cninit(unsafe { &*cp });
}

/// Probes and attaches the unit `unit` again, for a line found after boot.
fn reprobe(unit: c_int) -> bool {
    for device in autoconf::bus_devices() {
        // SAFETY: every entry up to the sentinel is an initialized
        // `BusDevice`.
        let (driver, dev_unit, alive, ctlr, name, address, phys) = unsafe {
            (
                (*device).driver,
                (*device).unit,
                (*device).alive,
                (*device).ctlr,
                (*device).name,
                (*device).address,
                (*device).phys_address,
            )
        };
        if driver != ptr::addr_of_mut!(COMDRIVER)
            || dev_unit != unit
            || alive != 0
            || ctlr != -1
        {
            continue;
        }
        // SAFETY: an initialized entry's `name` is NUL-terminated.
        let name = unsafe { CStr::from_ptr(name) };
        if configure_device(name, address, phys, 0, c"atbus") {
            return true;
        }
    }
    false
}

/// Opens the line `dev`, setting it up on the first open.
pub(crate) fn open(dev: c_int, flag: c_int, ior: &mut IoReq) -> IoResult {
    let unit = minor(dev);
    let Some(index) = index(unit) else {
        return Err(DeviceError::NoSuchDevice);
    };

    let mut isai = info(index);
    // SAFETY: `isai` is the attached entry or null, checked before the field
    // read.
    if isai.is_null() || unsafe { (*isai).alive } == 0 {
        if !reprobe(unit) {
            return Err(DeviceError::NoSuchDevice);
        }
        isai = info(index);
        // SAFETY: `isai` is the attached entry or null, checked before the
        // field read.
        if isai.is_null() || unsafe { (*isai).alive } == 0 {
            return Err(DeviceError::NoSuchDevice);
        }
    }

    let tp = &mut com().tty[index];
    if !tp.t_state.intersects(TtyState::ISOPEN | TtyState::WOPEN) {
        chario::chars(tp);
        tp.t_addr = NonNull::new(ptr::with_exposed_provenance_mut(
            // SAFETY: `isai` is a live attached entry.
            unsafe { (*isai).address },
        ));
        tp.t_dev = dev;
        tp.t_start = Some(comstart);
        tp.t_stop = Some(comstop);
        tp.t_mctl = Some(commctl);
        tp.t_getstat = Some(comgetstat);
        tp.t_setstat = Some(comsetstat);
        if tp.t_ispeed == 0 {
            tp.t_ispeed = ISPEED;
            tp.t_ospeed = ISPEED;
            tp.t_flags = IFLAGS;
            tp.t_state &= !TtyState::BUSY;
        }
    }
    if !tp.t_state.intersects(TtyState::ISOPEN) {
        params(tp, index);
    }
    let addr = tty_addr(tp);

    tp.t_lock.lock();
    if com().carrier[index] == 0 {
        tp.t_state |= TtyState::CARR_ON;
    } else {
        let status = ModemStatus::from_bits_retain(modem_stat(addr).read_u8());
        if status.contains(ModemStatus::RLSD) {
            tp.t_state |= TtyState::CARR_ON;
        } else {
            tp.t_state &= !TtyState::CARR_ON;
        }
        fix_modem_state(unit, c_int::from(status.bits()));
    }
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };

    // The C passed the `int` mode to the `dev_mode_t` parameter unchanged.
    let result = chario::open(
        tp,
        dev,
        DeviceMode::from_bits_retain(flag as c_uint),
        ior,
    );

    if com().timer_active == 0 {
        com().timer_active = 1;
        timer();
    }

    tp.t_lock.lock();
    while intr_id(addr).read_u8() & 1 == 0 {
        let _ = line_stat(addr).read_u8();
        let _ = txrx(addr).read_u8();
        let _ = modem_stat(addr).read_u8();
    }
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    Ok(result)
}

/// The device-switch entry of [`open`].
///
/// # Safety
///
/// `ior` must point at a live open request.
pub(crate) unsafe fn comopen(
    dev: DevT,
    flag: c_int,
    ior: *mut IoReq,
) -> IoResult {
    open(c_int::from(dev), flag, unsafe { &mut *ior })
}

/// Closes the line `dev`, dropping the modem lines on a hang-up close.
pub(crate) fn close(dev: c_int) {
    let unit = minor(dev);
    let Some(index) = index(unit) else {
        return;
    };
    let tp = &mut com().tty[index];
    let addr = tty_addr(tp);

    // The tty is closed under its lock, as `chario::close` requires.
    tp.t_lock.lock();
    chario::close(tp);
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };

    if tp.t_state.intersects(TtyState::HUPCLS)
        || !tp.t_state.intersects(TtyState::ISOPEN)
    {
        intr_enab(addr).write_u8(0);
        modem_ctl_reg(addr).write_u8(0);
        tp.t_state &= !TtyState::BUSY;
        com().modem[index] = ModemBits::empty();
        if com().fifo[index] != 0 {
            intr_id(addr).write_u8(0);
        }
    }
}

/// The device-switch entry of [`close`].
///
/// # Safety
///
/// The device layer calls this for an open unit.
pub(crate) unsafe fn comclose(dev: DevT, _flag: c_int) {
    close(c_int::from(dev));
}

/// Reads from the line `dev` through its line discipline.
pub(crate) fn read(dev: c_int, ior: &mut IoReq) -> IoResult {
    let Some(tp) = tty_mut(minor(dev)) else {
        return Err(DeviceError::NoSuchDevice);
    };
    chario::read(tp, ior)
}

/// The device-switch entry of [`read()`].
///
/// # Safety
///
/// `ior` must point at a live read request.
pub(crate) unsafe fn comread(dev: DevT, ior: *mut IoReq) -> IoResult {
    read(c_int::from(dev), unsafe { &mut *ior })
}

/// Writes to the line `dev` through its line discipline.
pub(crate) fn write(dev: c_int, ior: &mut IoReq) -> IoResult {
    let Some(tp) = tty_mut(minor(dev)) else {
        return Err(DeviceError::NoSuchDevice);
    };
    chario::write(tp, ior)
}

/// The device-switch entry of [`write()`].
///
/// # Safety
///
/// `ior` must point at a live write request.
pub(crate) unsafe fn comwrite(dev: DevT, ior: *mut IoReq) -> IoResult {
    write(c_int::from(dev), unsafe { &mut *ior })
}

/// Reports a status flavor of the line: its modem bits, or the tty's flavors.
///
/// # Safety
///
/// `data` must be writable for `*count` integers and `count` writable.
pub(crate) unsafe fn comgetstat(
    dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: *mut u32,
) -> Result<(), DeviceError> {
    let unit = c_int::from(dev) & 0xff;
    if flavor == TTY_MODEM {
        let status = modem_status(unit);
        unsafe {
            *data = status;
            *count = 1;
        }
        return Ok(());
    }
    let Some(tp) = tty_mut(unit) else {
        return Err(DeviceError::NoSuchDevice);
    };
    unsafe { chario::tty_get_status(ptr::from_mut(tp), flavor, data, count) }
}

/// Applies a status flavor to the line: its modem bits, a break, or the tty's
/// flavors, then reapplies the line parameters.
///
/// # Safety
///
/// `data` must be readable for `count` integers.
pub(crate) unsafe fn comsetstat(
    dev: DevT,
    flavor: c_uint,
    data: *mut c_int,
    count: u32,
) -> Result<(), DeviceError> {
    let unit = c_int::from(dev) & 0xff;
    let Some(tp) = tty_mut(unit) else {
        return Err(DeviceError::NoSuchDevice);
    };
    let (bits, how) = match flavor {
        TTY_SET_BREAK => (ModemBits::BRK, DMBIS),
        TTY_CLEAR_BREAK => (ModemBits::BRK, DMBIC),
        TTY_MODEM => (ModemBits::from_bits_retain(unsafe { *data }), DMSET),
        _ => {
            let result = unsafe {
                chario::tty_set_status(ptr::from_mut(tp), flavor, data, count)
            };
            if result.is_ok() && flavor == TTY_STATUS {
                apply_params(tp, unit);
            }
            return result;
        }
    };
    tp.t_lock.lock();
    modem_ctl(tp, bits, how);
    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
    Ok(())
}

/// The `TTY_MODEM` value `comgetstat()` reads back.
pub(crate) fn modem_status(unit: c_int) -> c_int {
    let Some(index) = index(unit) else {
        return 0;
    };
    let dev = info(index);
    if dev.is_null() {
        return com().modem[index].bits();
    }
    // SAFETY: `configure_device()` wrote this live entry.
    let status = modem_stat(port_addr(unsafe { (*dev).address })).read_u8();
    fix_modem_state(unit, c_int::from(status));
    com().modem[index].bits()
}

/// Services the line `unit`'s pending interrupts: received data, transmitter
/// empty, line and modem status.
pub(crate) fn intr(unit: c_int) {
    let Some(index) = index(unit) else {
        return;
    };
    let dev = info(index);
    if dev.is_null() {
        return;
    }
    // SAFETY: `configure_device()` wrote this live entry.
    let addr = port_addr(unsafe { (*dev).address });

    // The line's tty lock covers its state and its registers, against the
    // thread side and the other CPUs.
    com().tty[index].t_lock.lock();
    loop {
        let id = intr_id(addr).read_u8() & MASKI;
        if id & 1 != 0 {
            break;
        }
        match id {
            MODI => {
                modem_intr(unit, c_int::from(modem_stat(addr).read_u8()));
            }
            TRAI => {
                com().timer_state[index] = 0;
                let tp = &mut com().tty[index];
                tp.t_state &= !(TtyState::BUSY | TtyState::FLUSH);
                // SAFETY: the write queue is the tty's and stays at its
                // address.
                unsafe {
                    chario::complete_queue(ptr::from_mut(
                        &mut tp.t_delayed_write,
                    ));
                };
                start(tp);
            }
            RECI | CTII => {
                let tp = &mut com().tty[index];
                if tp.t_state.intersects(TtyState::ISOPEN) {
                    let mut escape = false;
                    while LineStatus::from_bits_retain(
                        line_stat(addr).read_u8(),
                    )
                    .contains(LineStatus::DR)
                    {
                        let c = txrx(addr).read_u8();
                        if c == 0x1b {
                            escape = true;
                            continue;
                        }
                        if escape {
                            // The C sent the held escape before the byte that
                            // followed it.
                            chario::input(tp, 0x1b);
                        }
                        chario::input(tp, c_uint::from(c));
                        escape = false;
                    }
                    if escape {
                        chario::input(tp, 0x1b);
                    }
                } else {
                    // SAFETY: the open queue is the tty's and stays at its
                    // address.
                    unsafe {
                        chario::complete_queue(ptr::from_mut(
                            &mut tp.t_delayed_open,
                        ));
                    };
                }
            }
            LINI => {
                let status =
                    LineStatus::from_bits_retain(line_stat(addr).read_u8());
                let tp = &mut com().tty[index];
                let parity = tp.t_flags & (TtyFlags::EVENP | TtyFlags::ODDP);
                if status.contains(LineStatus::PE)
                    && (parity == TtyFlags::EVENP || parity == TtyFlags::ODDP)
                {
                    continue;
                }
                if status.contains(LineStatus::OR) && !com().overrun {
                    kprint!("com{}: overrun\n", unit);
                    com().overrun = true;
                } else if status.intersects(LineStatus::FE | LineStatus::BREAK)
                {
                    // The C promoted the signed `char` to `unsigned int`,
                    // sign-extending it.
                    let breakc = tp.t_breakc as u32;
                    chario::input(tp, breakc);
                }
            }
            _ => (),
        }
    }
    // SAFETY: the tty lock was taken above.
    unsafe { com().tty[index].t_lock.unlock() };
}

/// The interrupt handler of [`intr`].
///
/// # Safety
///
/// The interrupt vector calls this with the unit the device was attached at.
pub(crate) unsafe extern "C" fn comintr(unit: c_int) {
    intr(unit);
}

/// Applies the tty's speed and flags to the line `unit`; [`comsetstat`] reruns
/// it after a status write.
pub(crate) fn apply_params(tp: &mut Tty, unit: c_int) {
    if let Some(index) = index(unit) {
        params(tp, index);
    }
}

/// Programs the line's divisor, character format and interrupts from the tty.
fn params(tp: &mut Tty, index: usize) {
    let addr = tty_addr(tp);

    tp.t_lock.lock();

    if tp.t_ispeed == B0 {
        tp.t_state |= TtyState::HUPCLS;
        modem_ctl_reg(addr).write_u8(ModemControl::OUT2.bits());
        com().modem[index] = ModemBits::empty();
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
        return;
    }

    if tp.t_ispeed >= B300 {
        tp.t_state |= TtyState::MIN;
    }

    line_ctl(addr).write_u8(LineControl::DLAB.bits());
    let divisor = DIVISORREG
        .get(usize::from(tp.t_ispeed))
        .copied()
        .unwrap_or(0);
    baud_lsb(addr).write_u8((divisor & 0xff) as u8);
    baud_msb(addr).write_u8((divisor >> 8) as u8);

    let mut mode = if tp.t_flags.intersects(TtyFlags::LITOUT) {
        LineControl::WORD_8
    } else {
        LineControl::WORD_7 | LineControl::PEN
    };
    if tp.t_flags.intersects(TtyFlags::EVENP) {
        mode |= LineControl::EPS;
    }
    if tp.t_ispeed == B110 {
        mode |= LineControl::STB;
    }
    line_ctl(addr).write_u8(mode.bits());

    intr_enab(addr).write_u8(
        (InterruptEnable::TX
            | InterruptEnable::RX
            | InterruptEnable::MODEM
            | InterruptEnable::ERROR)
            .bits(),
    );
    if com().fifo[index] != 0 {
        fifo_ctl(addr)
            .write_u8((FifoControl::ENABLE | FifoControl::TRIGGER_14).bits());
    }
    modem_ctl_reg(addr).write_u8(
        (ModemControl::DTR | ModemControl::RTS | ModemControl::OUT2).bits(),
    );
    com().modem[index] |= ModemBits::DTR | ModemBits::RTS;

    // SAFETY: the tty lock was taken above.
    unsafe { tp.t_lock.unlock() };
}

/// Sends the next queued character when the transmitter is free.
pub(crate) fn start(tp: &mut Tty) {
    // One machine-wide com timer; arming re-arms it.
    static COM_TIMER: MachCallout =
        MachCallout::new(wheel(), com_timer_action, ());
    if tp
        .t_state
        .intersects(TtyState::TIMEOUT | TtyState::TTSTOP | TtyState::BUSY)
    {
        com().st_1 += 1;
        return;
    }
    if !tp.t_delayed_write.is_empty()
        && c_int::from(tp.t_outq.count()) <= c_int::from(chario::low_water(tp))
    {
        com().st_2 += 1;
        // SAFETY: the write queue is the tty's and stays at its address.
        unsafe {
            chario::complete_queue(ptr::from_mut(&mut tp.t_delayed_write));
        };
    }
    if tp.t_outq.count() == 0 {
        com().st_3 += 1;
        return;
    }

    let Some(nch) = tp.t_outq.get() else {
        return;
    };
    if nch & 0x80 != 0 && !tp.t_flags.intersects(TtyFlags::LITOUT) {
        let delay = c_int::from(nch & 0x7f) + 6;
        Pin::static_ref(&COM_TIMER)
            .start(clock::Ticks::new(delay.max(1) as u64));
        tp.t_state |= TtyState::TIMEOUT;
        com().st_4 += 1;
        return;
    }
    txrx(tty_addr(tp)).write_u8(nch);
    tp.t_state |= TtyState::BUSY;
}

/// The tty's start hook of [`start`].
///
/// # Safety
///
/// `tp` must point at a live tty whose lock the caller holds, as the tty
/// layer's start contract requires.
pub(crate) unsafe fn comstart(tp: *mut Tty) {
    start(unsafe { &mut *tp });
}

/// The expiry of the machine-wide com timer.
fn com_timer_action(callout: Pin<&MachCallout>) {
    timer();
    callout.start(clock::Ticks::new(
        (com().timer_interval * mach_sched::sched::CLOCK_HZ).max(1) as u64,
    ));
}

/// Kicks every line whose output stayed stuck across two ticks.
pub(crate) fn timer() {
    for index in 0..NCOM {
        let tp = &mut com().tty[index];
        tp.t_lock.lock();
        if tp.t_state.intersects(TtyState::ISOPEN) && tp.t_outq.count() != 0 {
            com().timer_state[index] += 1;
            if com().timer_state[index] >= 2 {
                let stuck = ptr::from_mut(tp);
                kprint!("Tty {:x} was stuck\n", stuck.expose_provenance());
                let nch = tp.t_outq.get().unwrap_or(0xff);
                txrx(tty_addr(tp)).write_u8(nch);
            }
        }
        // SAFETY: the tty lock was taken above.
        unsafe { tp.t_lock.unlock() };
    }
}

/// Records the modem status `modem_stat` as the line `unit`'s modem bits.
pub(crate) fn fix_modem_state(unit: c_int, modem_stat: c_int) {
    let Some(index) = index(unit) else {
        return;
    };
    let mut stat = ModemBits::empty();
    if modem_stat & c_int::from(ModemStatus::CTS.bits()) != 0 {
        stat |= ModemBits::CTS;
    }
    if modem_stat & c_int::from(ModemStatus::DSR.bits()) != 0 {
        stat |= ModemBits::DSR;
    }
    if modem_stat & c_int::from(ModemStatus::RI.bits()) != 0 {
        stat |= ModemBits::RNG;
    }
    if modem_stat & c_int::from(ModemStatus::RLSD.bits()) != 0 {
        stat |= ModemBits::CAR;
    }
    com().modem[index] = (com().modem[index]
        & !(ModemBits::CTS
            | ModemBits::DSR
            | ModemBits::RNG
            | ModemBits::CAR))
        | stat;
}

/// Handles a modem-status change on the line `unit`, resuming or stopping
/// output on a CTS change.
pub(crate) fn modem_intr(unit: c_int, stat: c_int) {
    let Some(index) = index(unit) else {
        return;
    };
    let changed = com().modem[index];
    fix_modem_state(unit, stat);
    let stat = com().modem[index];
    let changed = changed ^ stat;

    if changed.intersects(ModemBits::CTS) {
        let Some(tp) = com().tty.get_mut(index) else {
            return;
        };
        chario::cts(tp, stat.intersects(ModemBits::CTS));
    }
}

/// Sets, clears or reports the line's modem bits, per `how`.  The caller
/// holds `tp`'s lock.
pub(crate) fn modem_ctl(tp: &Tty, bits: ModemBits, how: c_int) -> ModemBits {
    let unit = minor(tp.t_dev);
    let Some(index) = index(unit) else {
        return ModemBits::empty();
    };

    let mut bits = bits;
    let how = if bits == ModemBits::HUP {
        bits = ModemBits::DTR | ModemBits::RTS;
        DMBIC
    } else {
        how
    };

    if how == DMGET {
        return com().modem[index];
    }

    let dev = info(index);
    if dev.is_null() {
        return com().modem[index];
    }
    // SAFETY: `configure_device()` wrote this live entry.
    let dev_addr = port_addr(unsafe { (*dev).address });

    let mut b = ModemBits::empty();
    match how {
        DMSET => b = bits,
        DMBIS => b = com().modem[index] | bits,
        DMBIC => b = com().modem[index] & !bits,
        _ => (),
    }
    com().modem[index] = b;

    if bits.intersects(ModemBits::BRK) {
        if b.intersects(ModemBits::BRK) {
            line_ctl(dev_addr).write_u8(
                (LineControl::from_bits_retain(line_ctl(dev_addr).read_u8())
                    | LineControl::SET_BREAK)
                    .bits(),
            );
        } else {
            line_ctl(dev_addr).write_u8(
                (LineControl::from_bits_retain(line_ctl(dev_addr).read_u8())
                    & !LineControl::SET_BREAK)
                    .bits(),
            );
        }
    }

    if bits.intersects(ModemBits::DTR | ModemBits::RTS) {
        let mut out = ModemControl::OUT2;
        if b.intersects(ModemBits::DTR) {
            out |= ModemControl::DTR;
        }
        if b.intersects(ModemBits::RTS) {
            out |= ModemControl::RTS;
        }
        modem_ctl_reg(dev_addr).write_u8(out.bits());
    }

    com().modem[index]
}

/// The tty's modem-control hook of [`modem_ctl`].
///
/// # Safety
///
/// `tp` must point at a live tty whose lock the caller holds.
pub(crate) unsafe fn commctl(
    tp: *mut Tty,
    bits: ModemBits,
    how: c_int,
) -> ModemBits {
    modem_ctl(unsafe { &mut *tp }, bits, how)
}

/// Asks a busy, unstopped line to flush its output.
pub(crate) const fn stop(tp: &mut Tty) {
    if tp.t_state.intersects(TtyState::BUSY)
        && !tp.t_state.intersects(TtyState::TTSTOP)
    {
        tp.t_state = tp.t_state.union(TtyState::FLUSH);
    }
}

/// The tty's stop hook of [`stop`].
///
/// # Safety
///
/// `tp` must point at a live tty whose lock the caller holds, as the tty
/// layer's stop contract requires.
pub(crate) unsafe fn comstop(tp: *mut Tty, _flags: DeviceMode) {
    stop(unsafe { &mut *tp });
}

/// Reads a character from the line `unit`, spinning for one.
pub(crate) fn getc(unit: c_int) -> c_int {
    let Some(index) = index(unit) else {
        return 0;
    };
    let dev = info(index);
    if dev.is_null() {
        return 0;
    }
    // SAFETY: `configure_device()` wrote this live entry.
    let addr = port_addr(unsafe { (*dev).address });

    // The line's lock keeps its interrupt handler from taking the character.
    let lock = &com().tty[index].t_lock;
    lock.lock();
    while !LineStatus::from_bits_retain(line_stat(addr).read_u8())
        .contains(LineStatus::DR)
    {
        core::hint::spin_loop();
    }
    let c = txrx(addr).read_u8();
    // SAFETY: the tty lock was taken above.
    unsafe { lock.unlock() };
    c_int::from(c)
}

/// Writes `c` to the console line, waiting for the transmitter; a newline goes
/// out as CR LF.
pub(crate) fn console_putc(dev: c_int, c: c_int) {
    let Some(index) = index(minor(dev)) else {
        return;
    };
    let dev_ptr = info(index);
    if dev_ptr.is_null() {
        return;
    }
    // SAFETY: `configure_device()` wrote this live entry.
    let addr = port_addr(unsafe { (*dev_ptr).address });

    while !LineStatus::from_bits_retain(line_stat(addr).read_u8())
        .contains(LineStatus::THRE)
    {
        core::hint::spin_loop();
    }

    if c == c_int::from(b'\n') {
        console_putc(dev, c_int::from(b'\r'));
    }
    // The C passed the `int` to `outb()`, which writes the low byte.
    txrx(addr).write_u8(c as u8);
}

/// The console table's putc entry of [`console_putc`].
///
/// # Safety
///
/// The console layer calls this for its own console unit.
pub(crate) unsafe fn comcnputc(dev: DevT, c: c_int) {
    console_putc(c_int::from(dev), c);
}

/// Reads a 7-bit character from the console line, or 0 when `wait` is clear
/// and none is there.
pub(crate) fn console_getc(dev: c_int, wait: bool) -> c_int {
    let Some(index) = index(minor(dev)) else {
        return 0;
    };
    let dev_ptr = info(index);
    if dev_ptr.is_null() {
        return 0;
    }
    // SAFETY: `configure_device()` wrote this live entry.
    let addr = port_addr(unsafe { (*dev_ptr).address });

    while !LineStatus::from_bits_retain(line_stat(addr).read_u8())
        .contains(LineStatus::DR)
    {
        if !wait {
            return 0;
        }
    }

    c_int::from(txrx(addr).read_u8() & 0x7f)
}

/// The console table's getc entry of [`console_getc`].
///
/// # Safety
///
/// The console layer calls this for its own console unit.
pub(crate) unsafe fn comcngetc(dev: DevT, wait: c_int) -> c_int {
    console_getc(c_int::from(dev), wait != 0)
}
