// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The text screen a terminal draws on.

/// The screen's columns.
pub const COLUMNS: usize = 80;
/// The screen's rows.
const ROWS: usize = 25;
/// The screen's cells.
pub const CELLS: usize = COLUMNS * ROWS;

/// The text screen and the bell a [`Terminal`](crate::Terminal) draws on.
///
/// A cell is named by its index, row by row from the top left.  An
/// attribute is the PC text-mode attribute byte: the foreground in bits 0
/// to 3, the background in bits 4 to 6, and blink in bit 7.
///
/// The terminal touches only cells below `CELLS + COLUMNS`: a
/// cursor-position sequence can rest the cursor on the cell just past the
/// last row, and line edits there reach the row past the screen.
pub trait Screen {
    /// Draws `ch` in cell `pos` with the attribute `attr`.
    fn put(&mut self, pos: usize, ch: u8, attr: u8);
    /// Blanks `count` cells from `pos` with the attribute `attr`.
    fn clear(&mut self, pos: usize, count: usize, attr: u8);
    /// Copies `count` cells from `from` to `to`; the ranges may overlap.
    fn copy(&mut self, from: usize, to: usize, count: usize);
    /// Shows the cursor in cell `pos`.
    fn set_cursor(&mut self, pos: usize);
    /// Sounds the bell.
    fn bell(&mut self);
}
