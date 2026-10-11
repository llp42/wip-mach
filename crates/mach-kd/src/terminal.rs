// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The console terminal, on an 80 by 25 text screen.
//!
//! It draws text, and acts on the control characters, the escape sequences
//! and the ANSI control sequences that move the cursor, edit the screen and
//! set the rendition.  `vte` recognizes them in the bytes written, and a
//! [`Pen`] acts on them on the [`Screen`] the driver gives it.

use crate::pen::Pen;
use crate::screen::Screen;
use vte::Parser;

/// The parser bytes are written to, and the pen it drives.
pub struct Terminal<S> {
    /// Built at the first byte written: the parser has no `const`
    /// constructor, and the driver's terminal is a `static`.  It keeps no
    /// operating-system command, which the terminal has no use for.
    parser: Option<Parser<0>>,
    pen: Pen<S>,
}

impl<S: Screen> Terminal<S> {
    /// A terminal on `screen` with the normal rendition, its cursor in cell
    /// `cursor`, where the screen already shows it.  A cursor past the screen
    /// starts the last row instead.
    #[must_use]
    pub const fn new(screen: S, cursor: usize) -> Self {
        Self {
            parser: None,
            pen: Pen::new(screen, cursor),
        }
    }

    /// Writes `byte`: the parser draws it, acts on it as a control
    /// character, or adds it to the sequence it is reading and acts on that
    /// sequence once it is complete.
    pub fn write(&mut self, byte: u8) {
        self.parser
            .get_or_insert_with(Parser::new_with_size)
            .advance(&mut self.pen, &[byte]);
    }

    /// Draws `byte` at the cursor, or acts on it as a control character,
    /// whether or not a sequence is being read.  A NUL draws nothing.
    pub fn put(&mut self, byte: u8) {
        self.pen.put(byte);
    }
}
