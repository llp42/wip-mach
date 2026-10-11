// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`FakeScreen`]: a text screen in memory, for `mach-kd`'s terminal.

use mach_kd::{CELLS, COLUMNS, Screen};

/// A cell no one has drawn: a space, light grey on black.
const BLANK: (u8, u8) = (b' ', 0x07);

/// A text screen in memory: its cells and the row just past the last,
/// which a terminal may touch, the cell it last showed the cursor in, and
/// the bells it rang.
///
/// A terminal draws through `&mut FakeScreen`, so a test reads the screen
/// once the terminal is gone.  A cell outside the screen panics, as the
/// terminal broke its side of [`Screen`].
#[derive(Debug)]
pub struct FakeScreen {
    cells: Vec<(u8, u8)>,
    cursor: Option<usize>,
    bells: usize,
}

impl Default for FakeScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeScreen {
    /// A blank screen with no cursor shown and no bell rung.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cells: vec![BLANK; CELLS + COLUMNS],
            cursor: None,
            bells: 0,
        }
    }

    /// The character and attribute in cell `pos`.
    #[must_use]
    pub fn cell(&self, pos: usize) -> (u8, u8) {
        self.cells[pos]
    }

    /// The characters of row `row`, without the blanks that end it.
    #[must_use]
    pub fn row(&self, row: usize) -> String {
        let cells = &self.cells[row * COLUMNS..(row + 1) * COLUMNS];
        let text: String =
            cells.iter().map(|&(ch, _)| char::from(ch)).collect();
        text.trim_end().to_owned()
    }

    /// The cell the cursor was last shown in, if any.
    #[must_use]
    pub const fn cursor(&self) -> Option<usize> {
        self.cursor
    }

    /// The bells rung.
    #[must_use]
    pub const fn bells(&self) -> usize {
        self.bells
    }
}

impl Screen for &mut FakeScreen {
    fn put(&mut self, pos: usize, ch: u8, attr: u8) {
        self.cells[pos] = (ch, attr);
    }

    fn clear(&mut self, pos: usize, count: usize, attr: u8) {
        self.cells[pos..pos + count].fill((b' ', attr));
    }

    fn copy(&mut self, from: usize, to: usize, count: usize) {
        self.cells.copy_within(from..from + count, to);
    }

    fn set_cursor(&mut self, pos: usize) {
        self.cursor = Some(pos);
    }

    fn bell(&mut self) {
        self.bells += 1;
    }
}
