// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The EGA/VGA text display the kd terminal draws on: the text memory, the
//! CRTC cursor and the bell.

use super::slam::{copy_backward, copy_forward, fill_words};
use super::{
    C_BITMAP_START, C_HIGH, C_LOW, C_START, C_STOP, EGA_IDX_REG, EGA_IO_REG,
    EGA_START, ring_bell,
};
use crate::arch::x86_64::pio::Port;
use mach_kd::Screen;

/// The CRT cursor shape scanlines the firmware default is replaced with when
/// it left them zero.
const CURSOR_START_SCANLINE: u8 = 14;
const CURSOR_STOP_SCANLINE: u8 = 15;
/// Bytes of the bitmap the C cleared at initialization.
const BITMAP_CLEAR_BYTES: usize = 200;
/// The cells of text memory from `EGA_START` to the end of the video window.
const TEXT_CELLS: usize = 0x4000;

/// The text display: its memory, and the CRTC ports that place the cursor.
pub(crate) struct Vga {
    /// The mapped text memory, [`TEXT_CELLS`] cells of character and
    /// attribute; null until [`Self::init`].
    cells: *mut u16,
    index_reg: u16,
    io_reg: u16,
}

impl Vga {
    pub(crate) const fn new() -> Self {
        Self {
            cells: core::ptr::null_mut(),
            index_reg: EGA_IDX_REG,
            io_reg: EGA_IO_REG,
        }
    }

    /// Maps the text memory, clears the bitmap, gives the cursor a shape if
    /// the firmware left it none, and returns the cell the firmware left the
    /// cursor in.
    pub(crate) fn init(&mut self) -> usize {
        self.cells = phystokv(EGA_START) as *mut u16;
        self.index_reg = EGA_IDX_REG;
        self.io_reg = EGA_IO_REG;
        let bitmap = phystokv(C_BITMAP_START) as *mut u8;
        // SAFETY: the bitmap base is mapped by the boot.
        unsafe { core::ptr::write_bytes(bitmap, 0, BITMAP_CLEAR_BYTES) };

        Port::new(self.index_reg).write_u8(C_START);
        let mut start = Port::new(self.io_reg).read_u8();
        start &= !0x20;
        Port::new(self.io_reg).write_u8(start);
        Port::new(self.index_reg).write_u8(C_STOP);
        let stop = Port::new(self.io_reg).read_u8();

        if start == 0 && stop == 0 {
            Port::new(self.index_reg).write_u8(C_START);
            Port::new(self.io_reg).write_u8(CURSOR_START_SCANLINE);
            Port::new(self.index_reg).write_u8(C_STOP);
            Port::new(self.io_reg).write_u8(CURSOR_STOP_SCANLINE);
        }

        Port::new(self.index_reg).write_u8(C_HIGH);
        let high = Port::new(self.io_reg).read_u8();
        Port::new(self.index_reg).write_u8(C_LOW);
        let low = Port::new(self.io_reg).read_u8();
        usize::from(u16::from(low) | (u16::from(high) << 8))
    }

    /// The text memory from cell `pos` on, if `count` cells from it are
    /// inside it.
    fn cells_at(&self, pos: usize, count: usize) -> Option<*mut u16> {
        if self.cells.is_null() || pos.checked_add(count)? > TEXT_CELLS {
            return None;
        }
        // SAFETY: `pos` is inside the mapped text memory.
        Some(unsafe { self.cells.add(pos) })
    }
}

impl Screen for Vga {
    fn put(&mut self, pos: usize, ch: u8, attr: u8) {
        if let Some(cell) = self.cells_at(pos, 1) {
            // SAFETY: the cell is inside the mapped text memory.
            unsafe { cell.write(u16::from(ch) | (u16::from(attr) << 8)) };
        }
    }

    fn clear(&mut self, pos: usize, count: usize, attr: u8) {
        if let Some(cells) = self.cells_at(pos, count) {
            let blank = u16::from(b' ') | (u16::from(attr) << 8);
            // SAFETY: the `count` cells are inside the mapped text memory.
            unsafe { fill_words(cells, count, blank) };
        }
    }

    fn copy(&mut self, from: usize, to: usize, count: usize) {
        if count == 0 {
            return;
        }
        let (Some(src), Some(dst)) =
            (self.cells_at(from, count), self.cells_at(to, count))
        else {
            return;
        };
        // SAFETY: both ranges are inside the mapped text memory; a copy to
        // a higher cell runs from the last cell down, so the overlap is read
        // before it is written.
        unsafe {
            if to <= from {
                copy_forward(src, dst, count);
            } else {
                copy_backward(src.add(count - 1), dst.add(count - 1), count);
            }
        }
    }

    fn set_cursor(&mut self, pos: usize) {
        let pos = pos as u16;
        Port::new(self.index_reg).write_u8(C_HIGH);
        Port::new(self.io_reg).write_u8((pos >> 8) as u8);
        Port::new(self.index_reg).write_u8(C_LOW);
        Port::new(self.io_reg).write_u8((pos & 0xff) as u8);
    }

    fn bell(&mut self) {
        ring_bell();
    }
}

/// Prepare the display for reboot: the text display needs no reset.
pub(crate) const fn reset() {}

/// The kernel virtual address of the physical address `addr`.
const fn phystokv(addr: usize) -> usize {
    const BASE: usize = 0xffff_ffff_8000_0000;
    addr.wrapping_add(BASE)
}
