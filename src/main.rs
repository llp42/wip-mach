// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//! wip-mach: a minimal freestanding hello-world kernel for x86_64.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

// Multiboot hands off in 32-bit protected mode even for a 64-bit kernel, so
// this builds a minimal identity-mapped page table for the first 1GiB,
// enables long mode, and far-jumps into 64-bit code before calling into Rust.
global_asm!(
    r#"
.section .multiboot_header, "a"
.align 4
.long 0x1BADB002
.long 0
.long -0x1BADB002

.section .bss
.align 4096
p4_table: .skip 4096
p3_table: .skip 4096
p2_table: .skip 4096
.align 16
stack_bottom: .skip 16384
stack_top:

.section .rodata
.align 8
gdt64:
    .quad 0
gdt64_code:
    .quad (1<<43) | (1<<44) | (1<<47) | (1<<53)
gdt64_end:
gdt64_pointer:
    .word gdt64_end - gdt64 - 1
    .quad gdt64

.section .text
.code32
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp

    # identity-map the first 1GiB with 2MiB pages
    mov $p3_table, %eax
    or $0b11, %eax
    mov %eax, (p4_table)

    mov $p2_table, %eax
    or $0b11, %eax
    mov %eax, (p3_table)

    xor %ecx, %ecx
.map_p2_loop:
    mov $0x200000, %eax
    mul %ecx
    or $0b10000011, %eax
    mov %eax, p2_table(,%ecx,8)
    inc %ecx
    cmp $512, %ecx
    jne .map_p2_loop

    # enable PAE, long mode, and paging
    mov $p4_table, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4
    mov $0xC0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr
    mov %cr0, %eax
    or $(1 << 31), %eax
    mov %eax, %cr0

    lgdt (gdt64_pointer)
    ljmp $(gdt64_code - gdt64), $long_mode_start

.code64
long_mode_start:
    xor %ax, %ax
    mov %ax, %ss
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    call kernel_main
.hang:
    hlt
    jmp .hang
"#,
    options(att_syntax)
);

const VGA_BUFFER: *mut u8 = 0xb8000 as *mut u8;
const VGA_LIGHT_GREY_ON_BLACK: u8 = 0x0f;

const COM1: u16 = 0x3f8;

unsafe fn outb(port: u16, val: u8) {
    unsafe {
        asm!("out %al, %dx", in("al") val, in("dx") port, options(nomem, nostack, preserves_flags, att_syntax));
    }
}

fn serial_init() {
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // enable DLAB to set the baud rate divisor
        outb(COM1 + 0, 0x03); // divisor low byte: 38400 baud
        outb(COM1 + 1, 0x00); // divisor high byte
        outb(COM1 + 3, 0x03); // 8 bits, no parity, one stop bit; DLAB off
        outb(COM1 + 2, 0xc7); // enable + clear FIFOs
        outb(COM1 + 4, 0x0b); // RTS/DSR set
    }
}

fn serial_write(s: &[u8]) {
    for &byte in s {
        unsafe { outb(COM1, byte) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    serial_init();
    print_str(b"Hello, world! (wip-mach)");
    halt_forever();
}

fn print_str(s: &[u8]) {
    for (i, &byte) in s.iter().enumerate() {
        unsafe {
            VGA_BUFFER.add(i * 2).write_volatile(byte);
            VGA_BUFFER.add(i * 2 + 1).write_volatile(VGA_LIGHT_GREY_ON_BLACK);
        }
    }
    serial_write(s);
    serial_write(b"\r\n");
}

fn halt_forever() -> ! {
    loop {
        unsafe { asm!("hlt") };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt_forever()
}
