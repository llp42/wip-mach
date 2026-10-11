// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The terminal, drawing on a screen in memory.

use mach_fake::FakeScreen;
use mach_kd::{CELLS, COLUMNS, Terminal};

/// The first cell of the last row.
const BOTTOM_LINE: usize = CELLS - COLUMNS;
/// The attribute of light grey on black.
const NORMAL: u8 = 0x07;

/// The screen after a terminal with its cursor in cell `cursor` wrote
/// `bytes`.
fn after(cursor: usize, bytes: &[u8]) -> FakeScreen {
    let mut screen = FakeScreen::new();
    {
        let mut terminal = Terminal::new(&mut screen, cursor);
        for &byte in bytes {
            terminal.write(byte);
        }
    }
    screen
}

/// The attribute `x` is drawn with after the rendition sequence `sgr`.
fn attr_after(sgr: &[u8]) -> u8 {
    let screen = after(0, &[sgr, b"x"].concat());
    assert_eq!(screen.cell(0).0, b'x');
    screen.cell(0).1
}

#[test]
fn text_draws_at_the_cursor_and_moves_it() {
    let screen = after(0, b"hi");
    assert_eq!(screen.row(0), "hi");
    assert_eq!(screen.cell(0), (b'h', NORMAL));
    assert_eq!(screen.cursor(), Some(2));
}

#[test]
fn a_cursor_past_the_screen_starts_the_last_row() {
    let screen = after(CELLS + 1, b"x");
    assert_eq!(screen.row(24), "x");
    assert_eq!(screen.cursor(), Some(BOTTOM_LINE + 1));
}

#[test]
fn the_last_cell_scrolls_and_returns_to_the_row_start() {
    let screen = after(CELLS - 1, b"ab");
    assert_eq!(screen.cell(BOTTOM_LINE - 1), (b'a', NORMAL));
    assert_eq!(screen.row(24), "b");
    assert_eq!(screen.cursor(), Some(BOTTOM_LINE + 1));
}

#[test]
fn a_line_feed_moves_down_and_a_carriage_return_to_the_row_start() {
    assert_eq!(after(0, b"ab\ncd").row(1), "  cd");
    assert_eq!(after(0, b"ab\rc").row(0), "cb");
}

#[test]
fn a_line_feed_on_the_last_row_scrolls() {
    let screen = after(BOTTOM_LINE, b"x\n");
    assert_eq!(screen.row(23), "x");
    assert_eq!(screen.row(24), "");
    assert_eq!(screen.cursor(), Some(BOTTOM_LINE + 1));
}

#[test]
fn a_backspace_moves_left_but_not_past_the_start() {
    assert_eq!(after(0, b"ab\x08c").row(0), "ac");
    assert_eq!(after(0, b"\x08x").row(0), "x");
}

#[test]
fn a_tab_moves_to_the_next_stop() {
    let screen = after(0, b"a\tb");
    assert_eq!(screen.row(0), "a       b");
    assert_eq!(screen.cursor(), Some(9));
}

#[test]
fn a_bell_rings_and_a_nul_draws_nothing() {
    let screen = after(0, b"\x07\0");
    assert_eq!(screen.bells(), 1);
    assert_eq!(screen.cursor(), None);
}

#[test]
fn escape_c_clears_the_screen_and_homes_the_cursor() {
    let screen = after(0, b"abc\x1bc");
    assert_eq!(screen.row(0), "");
    assert_eq!(screen.cursor(), Some(0));
}

#[test]
fn a_second_escape_starts_the_sequence_again() {
    assert_eq!(after(0, b"\x1b\x1bx").row(0), "");
    assert_eq!(after(0, b"\x1b\x1b[2Cx").cell(2).0, b'x');
}

#[test]
fn an_unknown_escape_is_dropped() {
    assert_eq!(after(0, b"\x1bxy").row(0), "y");
}

#[test]
fn a_control_inside_a_sequence_acts_without_ending_it() {
    assert_eq!(after(0, b"\x1b[2\nCx").cell(COLUMNS + 2).0, b'x');
    assert_eq!(after(0, b"\x1b\0[Cx").row(0), " x");
}

#[test]
fn an_overlong_sequence_is_dropped() {
    let params = b"1;".repeat(40);
    let screen = after(0, &[b"\x1b[".as_slice(), &params, b"Cok"].concat());
    assert_eq!(screen.row(0), "ok");
}

#[test]
fn put_draws_while_a_sequence_is_open() {
    let mut screen = FakeScreen::new();
    {
        let mut terminal = Terminal::new(&mut screen, 0);
        terminal.write(0x1b);
        terminal.put(b'a');
        terminal.write(b'b');
    }
    assert_eq!(screen.row(0), "a");
}

#[test]
fn cursor_sequences_move_by_their_count() {
    assert_eq!(after(0, b"\x1b[5Cx").cell(5).0, b'x');
    assert_eq!(after(0, b"abcdef\x1b[3Dx").row(0), "abcxef");
    assert_eq!(after(0, b"\n\n\x1b[2Ax").row(0), "x");
    assert_eq!(after(0, b"\x1b[2Bx").cell(2 * COLUMNS).0, b'x');
    assert_eq!(after(0, b"ab\x1b[2Ex").row(2), "x");
    assert_eq!(after(0, b"\n\nab\x1b[2Fx").row(0), "x");
    assert_eq!(after(0, b"abc\x1b[Cx").row(0), "abc x");
}

#[test]
fn moving_up_from_the_top_row_scrolls_down() {
    let screen = after(0, b"a\x1b[Ab");
    assert_eq!(screen.row(0), " b");
    assert_eq!(screen.row(1), "a");
}

#[test]
fn a_column_sequence_moves_within_the_row() {
    assert_eq!(after(0, b"abc\x1b[10Gx").cell(9).0, b'x');
    assert_eq!(after(0, b"abc\x1b[Gx").row(0), "xbc");
    assert_eq!(after(0, b"abc\x1b[0Gx").row(0), "xbc");
}

#[test]
fn a_column_past_the_screen_scrolls_to_the_last_row() {
    let screen = after(BOTTOM_LINE, b"a\x1b[200Gx");
    assert_eq!(screen.row(23), "a");
    assert_eq!(screen.row(24), "x");
}

#[test]
fn a_position_sequence_moves_to_its_row_and_column() {
    assert_eq!(after(0, b"\x1b[3;5Hx").cell(2 * COLUMNS + 4).0, b'x');
    assert_eq!(after(0, b"\x1b[3fx").cell(2 * COLUMNS).0, b'x');
    assert_eq!(after(0, b"\x1b[;5Hx").cell(4).0, b'x');
    assert_eq!(after(0, b"abc\x1b[Hx").row(0), "xbc");
}

#[test]
fn a_position_past_the_screen_stops_at_its_end() {
    assert_eq!(after(0, b"\x1b[30;1H").cursor(), Some(CELLS - 1));
    let screen = after(0, b"\x1b[26;1Hx");
    assert_eq!(screen.cell(CELLS), (b'x', NORMAL));
}

#[test]
fn erase_in_display_clears_the_part_it_names() {
    assert_eq!(after(0, b"abc\n\rd\x1b[A\x1b[J").row(0), "a");
    assert_eq!(after(0, b"abc\n\rd\x1b[A\x1b[J").row(1), "");
    assert_eq!(after(0, b"abc\x1b[2D\x1b[0J").row(0), "a");
    assert_eq!(after(0, b"abc\n\rd\x1b[1J").row(0), "");
    assert_eq!(after(0, b"abc\n\rdef\x1b[2D\x1b[1J").row(1), "  f");
    let cleared = after(0, b"abc\x1b[2J");
    assert_eq!(cleared.row(0), "");
    assert_eq!(cleared.cursor(), Some(3));
    assert_eq!(after(0, b"abc\x1b[3J").row(0), "abc");
}

#[test]
fn erase_in_line_clears_the_part_it_names() {
    assert_eq!(after(0, b"abcd\x1b[2D\x1b[K").row(0), "ab");
    assert_eq!(after(0, b"abcd\x1b[2D\x1b[0K").row(0), "ab");
    assert_eq!(after(0, b"abcd\x1b[2D\x1b[1K").row(0), "   d");
    assert_eq!(after(0, b"abcd\x1b[2D\x1b[2K").row(0), "");
    assert_eq!(after(0, b"abcd\x1b[2D\x1b[5K").row(0), "abcd");
}

#[test]
fn erase_characters_blanks_up_to_the_row_end() {
    assert_eq!(after(0, b"abcdef\x1b[4D\x1b[2X").row(0), "ab  ef");
    assert_eq!(after(0, b"abcdef\x1b[4D\x1b[200X").row(0), "ab");
    assert_eq!(after(0, b"abcdef\x1b[4D\x1b[2X").row(1), "");
}

#[test]
fn inserting_characters_pushes_the_row_right() {
    assert_eq!(after(0, b"abcd\x1b[3D\x1b[2@").row(0), "a  bcd");
    assert_eq!(after(0, b"abcd\x1b[3D\x1b[100@").row(0), "a");
    assert_eq!(after(0, b"abcd\x1b[3D\x1b[0@").row(0), "a bcd");
}

#[test]
fn deleting_characters_pulls_the_row_left() {
    assert_eq!(after(0, b"abcdef\x1b[5D\x1b[2P").row(0), "adef");
    assert_eq!(after(0, b"abcdef\x1b[5D\x1b[100P").row(0), "a");
    assert_eq!(after(0, b"abcdef\x1b[5D\x1b[0P").row(0), "acdef");
}

#[test]
fn inserting_lines_pushes_the_rows_down() {
    let screen = after(0, b"a\n\rb\x1b[H\x1b[L");
    assert_eq!(
        [screen.row(0), screen.row(1), screen.row(2)],
        ["", "a", "b"]
    );
    let screen = after(0, b"a\n\rb\x1b[H\x1b[30L");
    assert_eq!([screen.row(0), screen.row(1)], ["", ""]);
    assert_eq!(after(0, b"a\x1b[H\x1b[0L").row(1), "a");
}

#[test]
fn deleting_lines_pulls_the_rows_up() {
    let screen = after(0, b"a\n\rb\n\rc\x1b[H\x1b[M");
    assert_eq!(
        [screen.row(0), screen.row(1), screen.row(2)],
        ["b", "c", ""]
    );
    let screen = after(0, b"a\n\rb\x1b[H\x1b[30M");
    assert_eq!([screen.row(0), screen.row(1)], ["", ""]);
    assert_eq!(after(0, b"a\x1b[H\x1b[0M").row(0), "");
}

#[test]
fn scroll_sequences_move_the_whole_screen() {
    let up = after(0, b"a\n\rb\x1b[S");
    assert_eq!([up.row(0), up.row(1)], ["b", ""]);
    let down = after(0, b"a\x1b[2T");
    assert_eq!([down.row(0), down.row(1), down.row(2)], ["", "", "a"]);
}

#[test]
fn bold_and_dim_exclude_each_other() {
    assert_eq!(attr_after(b"\x1b[1m"), 0x0f);
    assert_eq!(attr_after(b"\x1b[2m"), 0x08);
    assert_eq!(attr_after(b"\x1b[1;2m"), 0x08);
    assert_eq!(attr_after(b"\x1b[2;1m"), 0x0f);
    assert_eq!(attr_after(b"\x1b[1;22m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[2;21m"), NORMAL);
}

#[test]
fn underline_blink_reverse_and_invisible_set_their_flags() {
    assert_eq!(attr_after(b"\x1b[4m"), 0x0f);
    assert_eq!(attr_after(b"\x1b[5m"), 0x87);
    assert_eq!(attr_after(b"\x1b[7m"), 0x70);
    assert_eq!(attr_after(b"\x1b[8m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[1;5;7m"), 0xf8);
    assert_eq!(attr_after(b"\x1b[4;24m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[5;25m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[7;27m"), NORMAL);
}

#[test]
fn colors_set_the_foreground_and_background() {
    assert_eq!(attr_after(b"\x1b[31m"), 0x04);
    assert_eq!(attr_after(b"\x1b[44m"), 0x17);
    assert_eq!(attr_after(b"\x1b[31;44m"), 0x14);
    assert_eq!(attr_after(b"\x1b[31;38m"), 0x0f);
    assert_eq!(attr_after(b"\x1b[38;39m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[31;1m"), 0x0c);
}

#[test]
fn a_reset_or_an_empty_rendition_restores_the_normal_attribute() {
    assert_eq!(attr_after(b"\x1b[1;31;0m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[1;31m\x1b[m"), NORMAL);
    assert_eq!(attr_after(b"\x1b[99m"), NORMAL);
}

#[test]
fn a_rendition_lasts_across_sequences_and_colors_erasing() {
    assert_eq!(attr_after(b"\x1b[1m\x1b[31m"), 0x0c);
    assert_eq!(after(0, b"\x1b[44m\x1b[2J").cell(5), (b' ', 0x17));
}

#[test]
fn a_private_sequence_is_ignored() {
    assert_eq!(after(0, b"\x1b[?25hx").row(0), "x");
    assert_eq!(after(0, b"\x1b[<1hx").row(0), "x");
    assert_eq!(after(0, b"\x1b[?1:x").row(0), "");
}

#[test]
fn an_unknown_command_is_dropped() {
    assert_eq!(after(0, b"\x1b[1zx").row(0), "x");
    assert_eq!(after(0, b"\x1b[1:2zx").row(0), "x");
}

#[test]
fn a_zero_count_moves_by_one_as_a_missing_one_does() {
    assert_eq!(after(0, b"abc\x1b[0Cx").row(0), "abc x");
    assert_eq!(after(0, b"\n\x1b[0Ax").row(0), "x");
}

#[test]
fn utf8_text_draws_its_code_page_437_glyphs() {
    let screen = after(0, "é─".as_bytes());
    assert_eq!(screen.cell(0).0, 0x82);
    assert_eq!(screen.cell(1).0, 0xc4);
    assert_eq!(screen.cursor(), Some(2));
}

#[test]
fn a_character_without_a_glyph_draws_a_question_mark() {
    assert_eq!(after(0, "€".as_bytes()).row(0), "?");
    assert_eq!(after(0, b"\xffx").row(0), "?x");
}
