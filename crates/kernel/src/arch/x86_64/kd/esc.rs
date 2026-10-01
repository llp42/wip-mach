// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd.c and i386/i386at/kd.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
//   Copyright 1988, 1989 by Intel Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kd output engine of <i386at/kd.c>: `kd_putc()` draws one character,
//! `kd_putc_esc()` collects escape sequences, and `kd_parserest()` interprets
//! the ANSI commands the console writes.

use super::display::{
    dclear, dmvdown, dmvup, dput, scrolldn, scrollup, setpos,
};
use super::{
    COLOR_TABLE, K_BEL, K_BS, K_CR, K_ESC, K_HT, K_LF, K_MAXESC, K_SPACE,
    KA_NORMAL, KAX_BLINK, KAX_BOLD, KAX_COL_DIM, KAX_COL_UNDERLINE, KAX_DIM,
    KAX_INVISIBLE, KAX_REVERSE, KAX_UNDERLINE, ONE_LINE, ONE_PAGE, ONE_SPACE,
    beg_of_line, current_column, kd_belloff, kd_bellon, state,
};
use crate::arch::x86_64::clock_platform::{MachCallout, wheel};
use crate::kern::machine;
use core::ffi::{c_int, c_short};
use core::pin::Pin;

/// The most `\e[...]` parameters the C parser kept.
const MAX_PARAMS: usize = 16;

/// Whether an escape sequence is complete or still collecting bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    /// A command byte was seen and acted on; the sequence is done.
    Done,
    /// Nothing to act on yet; the collected bytes stay put.
    Incomplete,
}

/// `kd_putc()` in C.
pub(crate) fn putc(ch: u8) {
    if ch == 0 && state().sit_for_0 {
        return;
    }
    match ch {
        K_LF => move_down(),
        K_CR => carriage_return(),
        K_BS => move_left(),
        K_HT => tab(),
        K_BEL => ring_bell(),
        _ => {
            let (pos, attr) = cursor();
            dput(pos, ch, attr);
            move_right();
        }
    }
}

/// Sound the bell until the callout switches it off.
fn ring_bell() {
    if state().kd_bellstate {
        return;
    }
    kd_bellon();
    // A leaked static callout; the action is `kd_belloff`.
    static BELL: MachCallout = MachCallout::new(wheel(), bell_off_action, ());
    Pin::static_ref(&BELL)
        .start(clock::Ticks::new((machine::CLOCK_HZ / 8) as u64));
    state().kd_bellstate = true;
}

fn bell_off_action(_callout: Pin<&MachCallout>) {
    // SAFETY: `kd_belloff` only touches the console state.
    unsafe { kd_belloff(core::ptr::null_mut()) };
}

/// `kd_putc_esc()` in C.
pub(crate) fn putc_esc(c: u8) {
    let spt = state().esc_spt;

    if c == K_ESC {
        if spt == 0 {
            let s = state();
            s.esc_seq[0] = K_ESC;
            s.esc_spt = 1;
            s.esc_seq[1] = 0;
        } else {
            putc(K_ESC);
            state().esc_spt = 0;
        }
    } else if spt != 0 {
        if spt > K_MAXESC - 1 {
            state().esc_spt = 0;
            return;
        }
        {
            let s = state();
            s.esc_seq[spt] = c;
            s.esc_spt = spt + 1;
            s.esc_seq[spt + 1] = 0;
        }
        if parse_escape() == Progress::Done {
            state().esc_spt = 0;
        }
    } else {
        putc(c);
    }
}

/// `kd_parseesc()` in C.
fn parse_escape() -> Progress {
    let seq = state().esc_seq;
    match seq[1] {
        b'c' => {
            clear_screen();
            home();
            Progress::Done
        }
        b'[' => parse_parameters(&seq, 2),
        0 => Progress::Incomplete,
        c => {
            putc(c);
            Progress::Done
        }
    }
}

/// `kd_parserest()` in C.
fn parse_parameters(seq: &[u8], start: usize) -> Progress {
    let mut cp = start;
    let mut number: [Option<c_int>; MAX_PARAMS] = [None; MAX_PARAMS];
    let mut last = 0;

    let private = seq[cp] == b'?' || seq[cp] == b'<';
    if private {
        cp += 1;
    }

    loop {
        let (used, value) = take_number(seq, cp);
        cp += used;
        number[last] = value;
        if last == MAX_PARAMS - 1 || seq[cp] != b';' {
            break;
        }
        last += 1;
        cp += 1;
    }

    if private {
        return match seq[cp] {
            0 => Progress::Incomplete,
            c => {
                if !is_final_byte(c) {
                    putc(c);
                }
                Progress::Done
            }
        };
    }

    let count = number[0].unwrap_or(1);

    match seq[cp] {
        b'm' => set_attributes(&number[..=last]),
        b'@' => insert_chars(count),
        b'A' => repeat(count, move_up),
        b'B' => repeat(count, move_down),
        b'C' => repeat(count, move_right),
        b'D' => repeat(count, move_left),
        b'E' => {
            carriage_return();
            repeat(count, move_down);
        }
        b'F' => {
            carriage_return();
            repeat(count, move_up);
        }
        b'G' => {
            let pos = state().kd_curpos;
            setpos(
                beg_of_line(pos)
                    + zero_based(number[0]) as c_short * ONE_SPACE,
            );
        }
        b'f' | b'H' => {
            if number[0].is_none() && number[1].is_none() {
                home();
            } else {
                let mut newpos = zero_based(number[0]) as c_short * ONE_LINE;
                newpos += zero_based(number[1]) as c_short * ONE_SPACE;
                if newpos < 0 {
                    newpos = 0; // upper left
                }
                if newpos > ONE_PAGE {
                    newpos = ONE_PAGE - ONE_SPACE; // lower right
                }
                setpos(newpos);
            }
        }
        b'J' => match number[0] {
            None | Some(0) => clear_to_bottom(),
            Some(1) => clear_from_top(),
            Some(2) => clear_screen(),
            _ => {}
        },
        b'K' => match number[0] {
            None | Some(0) => clear_to_line_end(),
            Some(1) => clear_from_line_start(),
            Some(2) => erase_line(),
            _ => {}
        },
        b'L' => insert_lines(count),
        b'M' => delete_lines(count),
        b'P' => delete_chars(count),
        b'S' => repeat(count, scrollup),
        b'T' => repeat(count, scrolldn),
        b'X' => erase_chars(count),
        0 => return Progress::Incomplete,
        c => {
            if !is_final_byte(c) {
                putc(c);
            }
        }
    }
    Progress::Done
}

/// Apply one `\e[...m` attribute list and refresh `kd_attr`.
fn set_attributes(values: &[Option<c_int>]) {
    let (mut flags, mut color) = {
        let s = state();
        (s.kd_attrflags, s.kd_color)
    };
    for value in values {
        match *value {
            None | Some(0) => {
                flags = 0;
                color = KA_NORMAL;
            }
            Some(1) => {
                flags |= KAX_BOLD;
                flags &= !KAX_DIM;
            }
            Some(2) => {
                flags |= KAX_DIM;
                flags &= !KAX_BOLD;
            }
            Some(4) => flags |= KAX_UNDERLINE,
            Some(5) => flags |= KAX_BLINK,
            Some(7) => flags |= KAX_REVERSE,
            Some(8) => flags |= KAX_INVISIBLE,
            Some(21 | 22) => flags &= !(KAX_BOLD | KAX_DIM),
            Some(24) => flags &= !KAX_UNDERLINE,
            Some(25) => flags &= !KAX_BLINK,
            Some(27) => flags &= !KAX_REVERSE,
            Some(38) => {
                flags |= KAX_UNDERLINE;
                color = (color & 0xf0) | (KA_NORMAL & 0x0f);
            }
            Some(39) => {
                flags &= !KAX_UNDERLINE;
                color = (color & 0xf0) | (KA_NORMAL & 0x0f);
            }
            Some(v) if (30..=37).contains(&v) => {
                let c = COLOR_TABLE[(v - 30) as usize];
                color = (color & 0xf0) | c;
            }
            Some(v) if (40..=47).contains(&v) => {
                let c = COLOR_TABLE[(v - 40) as usize];
                color = (color & 0x0f) | (c << 4);
            }
            _ => {}
        }
    }
    {
        let s = state();
        s.kd_attrflags = flags;
        s.kd_color = color;
    }
    update_attr();
}

/// `kd_update_kd_attr()` in C: blend `kd_attrflags` and `kd_color` into
/// `kd_attr`.
fn update_attr() {
    let s = state();
    let mut attr = s.kd_color;
    if s.kd_attrflags & KAX_UNDERLINE != 0 {
        attr = (attr & 0xf0) | KAX_COL_UNDERLINE;
    } else if s.kd_attrflags & KAX_DIM != 0 {
        attr = (attr & 0xf0) | KAX_COL_DIM;
    }
    if s.kd_attrflags & KAX_REVERSE != 0 {
        attr = reverse_video(attr);
    }
    if s.kd_attrflags & KAX_BLINK != 0 {
        attr ^= 0x80;
    }
    if s.kd_attrflags & KAX_BOLD != 0 {
        attr ^= 0x08;
    }
    s.kd_attr = attr;
}

/// The `reverse_video_char()` macro of <i386at/kd.c>.
const fn reverse_video(attr: u8) -> u8 {
    (attr & 0x88) | (attr.rotate_left(4) & 0x77)
}

/// `kd_up()` in C: one line up, scrolling the screen down at the top.
fn move_up() {
    let pos = state().kd_curpos;
    if pos < ONE_LINE {
        scrolldn();
    } else {
        setpos(pos - ONE_LINE);
    }
}

/// `kd_down()` in C: one line down, scrolling the screen up at the bottom.
fn move_down() {
    let pos = state().kd_curpos;
    if pos >= ONE_PAGE - ONE_LINE {
        scrollup();
    } else {
        setpos(pos + ONE_LINE);
    }
}

/// `kd_right()` in C: one cell right, scrolling at the line end.
fn move_right() {
    let pos = state().kd_curpos;
    if pos < ONE_PAGE - ONE_SPACE {
        setpos(pos + ONE_SPACE);
    } else {
        scrollup();
        setpos(beg_of_line(pos));
    }
}

/// `kd_left()` in C: one cell left, stopping at the screen start.
fn move_left() {
    let pos = state().kd_curpos;
    if pos > 0 {
        setpos(pos - ONE_SPACE);
    }
}

/// `kd_cr()` in C.
fn carriage_return() {
    setpos(beg_of_line(state().kd_curpos));
}

/// `kd_home()` in C.
fn home() {
    setpos(0);
}

/// `kd_tab()` in C: spaces up to the next multiple of eight.
fn tab() {
    let pos = state().kd_curpos;
    let spaces = 8 - current_column(pos) % 8;
    let mut i = 0;
    while i < spaces {
        putc(b' ');
        i += 1;
    }
}

/// `kd_cls()` in C: blank the whole screen.
fn clear_screen() {
    let (_, attr) = cursor();
    dclear(0, c_int::from(ONE_PAGE / ONE_SPACE), attr);
}

/// `kd_cltobcur()` in C: blank from the cursor to the screen bottom.
fn clear_to_bottom() {
    let (pos, attr) = cursor();
    let count = (ONE_PAGE - pos) / ONE_SPACE;
    dclear(pos, c_int::from(count), attr);
}

/// `kd_cltopcur()` in C: blank from the screen top to the cursor.
fn clear_from_top() {
    let (pos, attr) = cursor();
    let count = (pos + ONE_SPACE) / ONE_SPACE;
    dclear(0, c_int::from(count), attr);
}

/// `kd_cltoecur()` in C: blank from the cursor to the line end.
fn clear_to_line_end() {
    let (pos, attr) = cursor();
    blank(pos, beg_of_line(pos) + ONE_LINE, attr);
}

/// `kd_clfrbcur()` in C: blank from the line start through the cursor.
fn clear_from_line_start() {
    let (pos, attr) = cursor();
    blank(beg_of_line(pos), pos + ONE_SPACE, attr);
}

/// `kd_eraseln()` in C: blank the whole line.
fn erase_line() {
    let (pos, attr) = cursor();
    blank(beg_of_line(pos), beg_of_line(pos) + ONE_LINE, attr);
}

/// `kd_erase()` in C: blank `number` cells from the cursor, stopping at the
/// line end.
fn erase_chars(number: c_int) {
    let (pos, attr) = cursor();
    let mut stop = pos + ONE_SPACE * number as c_short;
    let line_end = beg_of_line(pos) + ONE_LINE;
    if stop > line_end {
        stop = line_end;
    }
    blank(pos, stop, attr);
}

/// `kd_insch()` in C: open `number` cells for characters at the cursor.
fn insert_chars(number: c_int) {
    if number <= 0 {
        return;
    }
    let (pos, attr) = cursor();
    let nextline = beg_of_line(pos) + ONE_LINE;
    let mut insbytes = number * c_int::from(ONE_SPACE);
    if c_int::from(pos) + insbytes > c_int::from(nextline) {
        insbytes = c_int::from(nextline) - c_int::from(pos);
    }
    let to = nextline - ONE_SPACE;
    let from = to - insbytes as c_short;
    if from >= pos {
        let count = c_int::from((from - pos + ONE_SPACE) / ONE_SPACE);
        dmvdown(from, to, count);
    }
    let count = insbytes / c_int::from(ONE_SPACE);
    dclear(pos, count, attr);
}

/// `kd_delln()` in C: delete `number` lines at the cursor.
fn delete_lines(number: c_int) {
    if number <= 0 {
        return;
    }
    let (pos, attr) = cursor();
    let mut delbytes = number * c_int::from(ONE_LINE);
    let to = beg_of_line(pos);
    if c_int::from(to) + delbytes >= c_int::from(ONE_PAGE) {
        delbytes = c_int::from(ONE_PAGE) - c_int::from(to);
    }
    if (c_int::from(to) + delbytes) < c_int::from(ONE_PAGE) {
        let from = to + delbytes as c_short;
        let count = c_int::from((ONE_PAGE - from) / ONE_SPACE);
        dmvup(from, to, count);
    }
    let to = ONE_PAGE - delbytes as c_short;
    let count = delbytes / c_int::from(ONE_SPACE);
    dclear(to, count, attr);
}

/// `kd_insln()` in C: open `number` lines at the cursor.
fn insert_lines(number: c_int) {
    if number <= 0 {
        return;
    }
    let (pos, attr) = cursor();
    let top = beg_of_line(pos);
    let mut insbytes = number * c_int::from(ONE_LINE);
    if c_int::from(top) + insbytes > c_int::from(ONE_PAGE) {
        insbytes = c_int::from(ONE_PAGE) - c_int::from(top);
    }
    let to = ONE_PAGE - ONE_SPACE;
    let from = to - insbytes as c_short;
    if from > top {
        let count = c_int::from((from - top + ONE_SPACE) / ONE_SPACE);
        dmvdown(from, to, count);
    }
    let count = insbytes / c_int::from(ONE_SPACE);
    dclear(top, count, attr);
}

/// `kd_delch()` in C: delete `number` cells at the cursor.
fn delete_chars(number: c_int) {
    if number <= 0 {
        return;
    }
    let (pos, attr) = cursor();
    let nextline = beg_of_line(pos) + ONE_LINE;
    let mut delbytes = number * c_int::from(ONE_SPACE);
    if c_int::from(pos) + delbytes > c_int::from(nextline) {
        delbytes = c_int::from(nextline) - c_int::from(pos);
    }
    if (c_int::from(pos) + delbytes) < c_int::from(nextline) {
        let from = pos + delbytes as c_short;
        let to = pos;
        let count = c_int::from((nextline - from) / ONE_SPACE);
        dmvup(from, to, count);
    }
    let to = nextline - delbytes as c_short;
    let count = delbytes / c_int::from(ONE_SPACE);
    dclear(to, count, attr);
}

/// Blank `from..to`, one cell at a time.
fn blank(from: c_short, to: c_short, attr: u8) {
    let mut pos = from;
    while pos < to {
        dput(pos, K_SPACE, attr);
        pos += ONE_SPACE;
    }
}

/// Run `f` `n` times; zero or less runs nothing, as the C loops did.
fn repeat(n: c_int, f: fn()) {
    for _ in 0..n {
        f();
    }
}

/// An ANSI final byte: the command that ends a `\e[...` sequence.
fn is_final_byte(byte: u8) -> bool {
    (b'@'..=b'~').contains(&byte)
}

/// The cursor position and the attribute to draw with.
fn cursor() -> (c_short, u8) {
    let s = state();
    (s.kd_curpos, s.kd_attr)
}

/// `take_number()` cannot produce a negative one.
const fn zero_based(n: Option<c_int>) -> c_int {
    match n {
        None => 0,
        Some(value) if value > 0 => value - 1,
        Some(value) => value,
    }
}

/// The leading decimal digits of `seq` at `cp`: the number of bytes they
/// occupy and their value.
fn take_number(seq: &[u8], cp: usize) -> (usize, Option<c_int>) {
    let rest = seq.get(cp..).unwrap_or_default();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let number = core::str::from_utf8(rest.get(..digits).unwrap_or_default())
        .ok()
        .and_then(|s| s.parse::<c_int>().ok());
    (digits, number)
}
