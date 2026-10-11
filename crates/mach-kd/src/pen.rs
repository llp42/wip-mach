// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The terminal's pen: the screen, the cursor on it and the rendition, which
//! act on the text, the controls and the sequences the parser recognizes.

use crate::screen::{CELLS, COLUMNS, Screen};
use crate::types::Rendition;
use oem_cp::code_table::ENCODING_TABLE_CP437;
use vte::{Params, Perform};

/// The first cell of the last row.
const BOTTOM_LINE: usize = CELLS - COLUMNS;

const LF: u8 = 0x0a;
const CR: u8 = 0x0d;
const BS: u8 = 0x08;
const HT: u8 = 0x09;
const BEL: u8 = 0x07;
const SPACE: u8 = 0x20;

/// The glyph a character the screen's code page lacks draws as.
const MISSING_GLYPH: u8 = b'?';

/// The attribute of light grey on black.
const NORMAL: u8 = 0x07;
/// The foreground underlined text takes, which the screen cannot underline.
const UNDERLINE_COLOR: u8 = 0x0f;
/// The foreground dim text takes.
const DIM_COLOR: u8 = 0x08;
/// The PC color of each ANSI color.
const ANSI_COLORS: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];

/// The screen, the cursor on it and the rendition text is drawn with.
pub struct Pen<S> {
    screen: S,
    /// At most [`CELLS`].
    cursor: usize,
    /// The attribute text is drawn with, from `color` and `flags`.
    attr: u8,
    /// The colors the rendition selects, before its flags apply.
    color: u8,
    flags: Rendition,
}

impl<S: Screen> Pen<S> {
    /// A pen on `screen` with the normal rendition, its cursor in cell
    /// `cursor`.  A cursor past the screen starts the last row instead.
    pub(crate) const fn new(screen: S, cursor: usize) -> Self {
        Self {
            screen,
            cursor: if cursor > CELLS { BOTTOM_LINE } else { cursor },
            attr: NORMAL,
            color: NORMAL,
            flags: Rendition::empty(),
        }
    }

    /// Acts on `byte` as a control character, or draws it.  A NUL draws
    /// nothing.
    pub(crate) fn put(&mut self, byte: u8) {
        match byte {
            0 => {}
            LF => self.move_down(),
            CR => self.carriage_return(),
            BS => self.move_left(),
            HT => {
                let spaces = 8 - (self.cursor % COLUMNS) % 8;
                for _ in 0..spaces {
                    self.draw(SPACE);
                }
            }
            BEL => self.screen.bell(),
            _ => self.draw(byte),
        }
    }

    /// Draws the glyph `byte` at the cursor and moves past it.
    fn draw(&mut self, byte: u8) {
        self.screen.put(self.cursor, byte, self.attr);
        self.move_right();
    }

    /// Applies the parameters of one select-graphic-rendition sequence, in
    /// order, and derives the attribute text is drawn with.
    fn set_rendition(&mut self, values: impl Iterator<Item = usize>) {
        let (mut flags, mut color) = (self.flags, self.color);
        for value in values {
            match value {
                0 => {
                    flags = Rendition::empty();
                    color = NORMAL;
                }
                1 => {
                    flags |= Rendition::BOLD;
                    flags &= !Rendition::DIM;
                }
                2 => {
                    flags |= Rendition::DIM;
                    flags &= !Rendition::BOLD;
                }
                4 => flags |= Rendition::UNDERLINE,
                5 => flags |= Rendition::BLINK,
                7 => flags |= Rendition::REVERSE,
                8 => flags |= Rendition::INVISIBLE,
                21 | 22 => flags &= !(Rendition::BOLD | Rendition::DIM),
                24 => flags &= !Rendition::UNDERLINE,
                25 => flags &= !Rendition::BLINK,
                27 => flags &= !Rendition::REVERSE,
                38 => {
                    flags |= Rendition::UNDERLINE;
                    color = (color & 0xf0) | (NORMAL & 0x0f);
                }
                39 => {
                    flags &= !Rendition::UNDERLINE;
                    color = (color & 0xf0) | (NORMAL & 0x0f);
                }
                v @ 30..=37 => {
                    let c = ANSI_COLORS.get(v - 30).copied().unwrap_or(0);
                    color = (color & 0xf0) | c;
                }
                v @ 40..=47 => {
                    let c = ANSI_COLORS.get(v - 40).copied().unwrap_or(0);
                    color = (color & 0x0f) | (c << 4);
                }
                _ => {}
            }
        }
        self.flags = flags;
        self.color = color;

        let mut attr = color;
        if flags.contains(Rendition::UNDERLINE) {
            attr = (attr & 0xf0) | UNDERLINE_COLOR;
        } else if flags.contains(Rendition::DIM) {
            attr = (attr & 0xf0) | DIM_COLOR;
        }
        if flags.contains(Rendition::REVERSE) {
            // Swap the foreground and background, keeping blink and bright.
            attr = (attr & 0x88) | (attr.rotate_left(4) & 0x77);
        }
        if flags.contains(Rendition::BLINK) {
            attr ^= 0x80;
        }
        if flags.contains(Rendition::BOLD) {
            attr ^= 0x08;
        }
        self.attr = attr;
    }

    /// Moves the cursor to cell `pos`; past the screen, scrolls up once and
    /// moves to the last row's start instead.
    fn move_to(&mut self, pos: usize) {
        let pos = if pos > CELLS {
            self.scroll_up();
            BOTTOM_LINE
        } else {
            pos
        };
        self.screen.set_cursor(pos);
        self.cursor = pos;
    }

    /// Moves one row up, scrolling the screen down at the top.
    fn move_up(&mut self) {
        if self.cursor < COLUMNS {
            self.scroll_down();
        } else {
            self.move_to(self.cursor - COLUMNS);
        }
    }

    /// Moves one row down, scrolling the screen up at the bottom.
    fn move_down(&mut self) {
        if self.cursor >= CELLS - COLUMNS {
            self.scroll_up();
        } else {
            self.move_to(self.cursor + COLUMNS);
        }
    }

    /// Moves one cell right; at the screen's end, scrolls up and moves to the
    /// row's start.
    fn move_right(&mut self) {
        if self.cursor < CELLS - 1 {
            self.move_to(self.cursor + 1);
        } else {
            self.scroll_up();
            self.move_to(line_start(self.cursor));
        }
    }

    /// Moves one cell left, stopping at the screen's start.
    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.move_to(self.cursor - 1);
        }
    }

    fn carriage_return(&mut self) {
        self.move_to(line_start(self.cursor));
    }

    fn scroll_up(&mut self) {
        self.screen.copy(COLUMNS, 0, CELLS - COLUMNS);
        self.screen.clear(BOTTOM_LINE, COLUMNS, self.attr);
    }

    fn scroll_down(&mut self) {
        self.screen.copy(0, COLUMNS, CELLS - COLUMNS);
        self.screen.clear(0, COLUMNS, self.attr);
    }

    fn clear_screen(&mut self) {
        self.screen.clear(0, CELLS, self.attr);
    }

    /// Blanks the cells `from..to` one at a time.
    fn blank(&mut self, from: usize, to: usize) {
        for pos in from..to {
            self.screen.put(pos, SPACE, self.attr);
        }
    }

    /// Opens `count` blank cells at the cursor, pushing the rest of the row
    /// right and off its end.
    fn insert_chars(&mut self, count: usize) {
        let pos = self.cursor;
        let line_end = line_start(pos) + COLUMNS;
        let inserted = count.min(line_end - pos);
        let kept = line_end - pos - inserted;
        if kept > 0 {
            self.screen.copy(pos, pos + inserted, kept);
        }
        self.screen.clear(pos, inserted, self.attr);
    }

    /// Deletes `count` cells at the cursor, pulling the rest of the row left
    /// and blanking its end.
    fn delete_chars(&mut self, count: usize) {
        let pos = self.cursor;
        let line_end = line_start(pos) + COLUMNS;
        let deleted = count.min(line_end - pos);
        if pos + deleted < line_end {
            self.screen
                .copy(pos + deleted, pos, line_end - pos - deleted);
        }
        self.screen.clear(line_end - deleted, deleted, self.attr);
    }

    /// Opens `count` blank rows at the cursor's row, pushing the rows below
    /// down and off the screen.
    fn insert_lines(&mut self, count: usize) {
        let top = line_start(self.cursor);
        let below = CELLS.saturating_sub(top);
        let inserted = count.saturating_mul(COLUMNS).min(below);
        let kept = below - inserted;
        if kept > 0 {
            self.screen.copy(top, top + inserted, kept);
        }
        self.screen.clear(top, inserted, self.attr);
    }

    /// Deletes `count` rows at the cursor's row, pulling the rows below up
    /// and blanking the screen's bottom.
    fn delete_lines(&mut self, count: usize) {
        let top = line_start(self.cursor);
        let below = CELLS.saturating_sub(top);
        let deleted = count.saturating_mul(COLUMNS).min(below);
        if deleted < below {
            self.screen.copy(top + deleted, top, below - deleted);
        }
        self.screen.clear(CELLS - deleted, deleted, self.attr);
    }
}

impl<S: Screen> Perform for Pen<S> {
    /// Draws `c` as its glyph in the screen's code page, 437, or as
    /// [`MISSING_GLYPH`] where the page has none.
    fn print(&mut self, c: char) {
        let glyph = u8::try_from(c)
            .ok()
            .filter(u8::is_ascii)
            .or_else(|| ENCODING_TABLE_CP437.get(&c).copied())
            .unwrap_or(MISSING_GLYPH);
        self.draw(glyph);
    }

    fn execute(&mut self, byte: u8) {
        self.put(byte);
    }

    /// Runs a control sequence's command.  A sequence with a private marker
    /// or an intermediate byte, or one the parser gave up on, is dropped.
    ///
    /// A parameter left out reads as 0, so a count of 0 moves or edits by
    /// one, as one left out does.
    fn csi_dispatch(
        &mut self,
        params: &Params,
        intermediates: &[u8],
        ignore: bool,
        action: char,
    ) {
        if ignore || !intermediates.is_empty() {
            return;
        }
        let value =
            |param: &[u16]| param.first().map_or(0, |&v| usize::from(v));
        let mut values = params.iter().map(value);
        let first = values.next().unwrap_or(0);
        let second = values.next().unwrap_or(0);
        let count = first.max(1);
        let pos = self.cursor;
        match action {
            'm' => self.set_rendition(params.iter().map(value)),
            '@' => self.insert_chars(count),
            'A' => (0..count).for_each(|_| self.move_up()),
            'B' => (0..count).for_each(|_| self.move_down()),
            'C' => (0..count).for_each(|_| self.move_right()),
            'D' => (0..count).for_each(|_| self.move_left()),
            'E' => {
                self.carriage_return();
                (0..count).for_each(|_| self.move_down());
            }
            'F' => {
                self.carriage_return();
                (0..count).for_each(|_| self.move_up());
            }
            'G' => {
                self.move_to(
                    line_start(pos).saturating_add(zero_based(first)),
                );
            }
            'f' | 'H' => {
                let to = zero_based(first)
                    .saturating_mul(COLUMNS)
                    .saturating_add(zero_based(second));
                self.move_to(if to > CELLS { CELLS - 1 } else { to });
            }
            'J' => match first {
                0 => {
                    self.screen.clear(
                        pos,
                        CELLS.saturating_sub(pos),
                        self.attr,
                    );
                }
                1 => self.screen.clear(0, pos + 1, self.attr),
                2 => self.clear_screen(),
                _ => {}
            },
            'K' => match first {
                0 => self.blank(pos, line_start(pos) + COLUMNS),
                1 => self.blank(line_start(pos), pos + 1),
                2 => {
                    let start = line_start(pos);
                    self.blank(start, start + COLUMNS);
                }
                _ => {}
            },
            'L' => self.insert_lines(count),
            'M' => self.delete_lines(count),
            'P' => self.delete_chars(count),
            'S' => (0..count).for_each(|_| self.scroll_up()),
            'T' => (0..count).for_each(|_| self.scroll_down()),
            'X' => {
                let line_end = line_start(pos) + COLUMNS;
                self.blank(pos, pos.saturating_add(count).min(line_end));
            }
            _ => {}
        }
    }

    /// Runs an escape sequence's command: `ESC c` clears the screen and
    /// homes the cursor; any other is dropped.
    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        if intermediates.is_empty() && byte == b'c' {
            self.clear_screen();
            self.move_to(0);
        }
    }
}

/// The first cell of the row holding cell `pos`.
const fn line_start(pos: usize) -> usize {
    pos - pos % COLUMNS
}

/// A one-based position parameter as a zero-based one; 0 reads as 1.
const fn zero_based(n: usize) -> usize {
    n.saturating_sub(1)
}
