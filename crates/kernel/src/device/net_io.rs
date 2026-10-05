// SPDX-License-Identifier: CMU-Mach AND BSD-4-Clause-Shortened
// Derived from device/net_io.c:
//   Copyright (c) 1993-1989 Carnegie Mellon University.
//   The Berkeley Packet Filter section comes from the Stanford/CMU enet
//   packet filter distributed in 4.3BSD:
//   Copyright (c) 1990-1991 The Regents of the University of California.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The network input path: the packet-filter machinery, the kmsg pool the
//! receive thread fills, the filter lists an interface heads, and the layouts
//! their bodies read.
//!
//! The locks are [`SimpleLock`] values, and [`net_thread`] is the receive
//! thread's entry.

use crate::arch::x86_64::per_cpu::cpu_id;
use crate::arch::x86_64::spl;
use crate::ipc::ipc_kmsg::{self, Kmsg, ikm_plus_overhead};
use crate::ipc::ipc_mqueue;
use crate::ipc::ipc_port;
use crate::ipc::{IpcPort, MachMsgHeader, MachMsgType};
use crate::kern::ast::{self, AstReason};
use crate::kern::lock::SimpleLock;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_wakeup_prim,
};
use crate::kern::slab::{self, CacheInitFlags, KmemCache};
use crate::kern::thread::{IpcKmsgQueue, Thread};
use crate::utils::cell::SyncCell;
use collections::list::{self, List};
use collections::tail_queue::{self, TailQueue};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_short, c_uint, c_void};
use core::mem::{offset_of, size_of};
use core::pin::{Pin, pin};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

/// The most filter words a receive port holds.
pub(crate) const NET_MAX_FILTER: usize = 128;
/// The packet bytes a network message carries.
pub(crate) const NET_RCV_MAX: u32 = 4095;
/// The buckets a filter hash has.
pub(crate) const NET_HASH_SIZE: u32 = 256;
/// The keys one match instruction carries.
pub(crate) const N_NET_HASH_KEYS: usize = 4;
/// The interpreter's scratch words.
const BPF_MEMWORDS: usize = 16;

/// `struct bpf_insn`: one BPF instruction.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: c_int,
}

const _: () = assert!(size_of::<BpfInsn>() == 8);
const _: () = assert!(align_of::<BpfInsn>() == 4);
const _: () = assert!(offset_of!(BpfInsn, code) == 0);
const _: () = assert!(offset_of!(BpfInsn, jt) == 2);
const _: () = assert!(offset_of!(BpfInsn, jf) == 3);
const _: () = assert!(offset_of!(BpfInsn, k) == 4);

/// The link pair [`IfQueue`] keeps, which only drivers use.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct QueueChain {
    pub next: *mut Self,
    pub prev: *mut Self,
}

const _: () = assert!(size_of::<QueueChain>() == 2 * size_of::<*mut ()>());
const _: () = assert!(align_of::<QueueChain>() == align_of::<*mut ()>());
const _: () = assert!(offset_of!(QueueChain, next) == 0);
const _: () = assert!(offset_of!(QueueChain, prev) == size_of::<*mut ()>());

/// A receive port registered on an interface, with its filter.
///
/// A port's `input` link is reused as the dead-port chain's link once the
/// port is off both interface lists.
#[repr(C)]
#[allow(missing_docs)]
pub struct NetRcvPort {
    pub input: tail_queue::Link,
    pub output: tail_queue::Link,
    pub rcv_port: *mut c_void,
    pub rcv_qlimit: c_int,
    pub rcv_count: c_int,
    pub priority: c_int,
    pub filter_end: *mut u16,
    pub filter: [u16; NET_MAX_FILTER],
}

// The record keeps its established size, alignment and field offsets.
const _: () = {
    assert!(size_of::<NetRcvPort>() == 320);
    assert!(align_of::<NetRcvPort>() == 8);
    assert!(offset_of!(NetRcvPort, input) == 0);
    assert!(offset_of!(NetRcvPort, output) == 16);
    assert!(offset_of!(NetRcvPort, rcv_port) == 32);
    assert!(offset_of!(NetRcvPort, rcv_qlimit) == 40);
    assert!(offset_of!(NetRcvPort, rcv_count) == 44);
    assert!(offset_of!(NetRcvPort, priority) == 48);
    assert!(offset_of!(NetRcvPort, filter_end) == 56);
    assert!(offset_of!(NetRcvPort, filter) == 64);
};

/// One entry of a filter hash table; `chain` links it.
#[repr(C)]
#[allow(missing_docs)]
pub struct NetHashEntry {
    pub chain: list::Link,
    pub rcv_port: *mut c_void,
    pub rcv_qlimit: c_int,
    pub keys: [c_uint; N_NET_HASH_KEYS],
}

const _: () = {
    assert!(size_of::<NetHashEntry>() == 48);
    assert!(align_of::<NetHashEntry>() == 8);
    assert!(offset_of!(NetHashEntry, chain) == 0);
    assert!(offset_of!(NetHashEntry, rcv_port) == 16);
    assert!(offset_of!(NetHashEntry, rcv_qlimit) == 24);
    assert!(offset_of!(NetHashEntry, keys) == 28);
};

/// A [`NetRcvPort`] with a 256-bucket hash table bolted on, so both can live
/// on the same port lists.
///
/// The C table's buckets had no head cell, so the Rust table holds an
/// intrusive list per bucket instead, each starting as `NetHashBucket::new()`;
/// only the `table` offset still matches the C layout.
#[repr(C)]
#[allow(missing_docs)]
pub struct NetHashHeader {
    pub rcv: NetRcvPort,
    pub n_keys: c_int,
    pub ref_count: c_int,
    pub table: [NetHashBucket; NET_HASH_SIZE as usize],
}

const _: () = {
    assert!(size_of::<NetHashHeader>() == 2376);
    assert!(align_of::<NetHashHeader>() == 8);
    assert!(offset_of!(NetHashHeader, rcv) == 0);
    assert!(offset_of!(NetHashHeader, n_keys) == 320);
    assert!(offset_of!(NetHashHeader, ref_count) == 324);
    assert!(offset_of!(NetHashHeader, table) == 328);
};

tail_queue::adapter!(
    /// The adapter for a receive port's `input` link, the `if_rcv_port_list`
    /// chain and the dead-port chain.
    pub NetRcvPortInputAdapter = NetRcvPort { input }
);

tail_queue::adapter!(
    /// The adapter for a receive port's `output` link, the `if_snd_port_list`
    /// chain.
    pub NetRcvPortOutputAdapter = NetRcvPort { output }
);

list::adapter!(
    /// The adapter for a hash entry's `chain` in a filter hash bucket.
    pub NetHashEntryAdapter = NetHashEntry { chain }
);

/// An interface's receive ports, or the ports a filter pass unlinked. A port
/// leaves from the middle and is promoted over its predecessor, so the list
/// is walked both ways.
pub type NetInputList = TailQueue<'static, NetRcvPortInputAdapter>;

/// An interface's send ports, ordered like [`NetInputList`].
pub type NetOutputList = TailQueue<'static, NetRcvPortOutputAdapter>;

/// A filter hash bucket, or the entries a filter pass unlinked. Keys are
/// compared in full, so the order within a bucket is unobservable.
pub type NetHashBucket = List<'static, NetHashEntryAdapter>;

// The port links and the list heads are two words each, so the offsets above
// stay; the bucket head is one word.
const _: () = assert!(size_of::<tail_queue::Link>() == 16);
const _: () = assert!(size_of::<list::Link>() == 16);
const _: () = assert!(size_of::<NetInputList>() == 16);
const _: () = assert!(size_of::<NetOutputList>() == 16);
const _: () = assert!(size_of::<NetHashBucket>() == size_of::<usize>());

/// The receive-port list of `ifp`, pinned for one operation.
///
/// # Safety
///
/// `ifp` must be live and stay in place while a port is on either of its
/// lists, and the caller must hold `if_rcv_port_list_lock` for as long as it
/// uses the result.
unsafe fn rcv_list<'a>(ifp: *mut IfNet) -> Pin<&'a mut NetInputList> {
    // SAFETY: the interface stays in place, and the lock the caller holds
    // keeps anything else from reaching the list.
    unsafe {
        Pin::new_unchecked(&mut *ptr::addr_of_mut!((*ifp).if_rcv_port_list))
    }
}

/// The send-port list of `ifp`, pinned for one operation.
///
/// # Safety
///
/// Same contract as [`rcv_list()`], with `if_snd_port_list_lock`.
unsafe fn snd_list<'a>(ifp: *mut IfNet) -> Pin<&'a mut NetOutputList> {
    // SAFETY: as for the receive list.
    unsafe {
        Pin::new_unchecked(&mut *ptr::addr_of_mut!((*ifp).if_snd_port_list))
    }
}

/// `BPF_ST`: store the accumulator into a scratch word.
const BPF_ST: u16 = 0x02;
/// `BPF_LD|BPF_W|BPF_ABS`: load the packet word at a fixed offset.
const BPF_LD_W_ABS: u16 = 0x20;
/// `BPF_LD|BPF_H|BPF_ABS`: load the packet half-word at a fixed offset.
const BPF_LD_H_ABS: u16 = 0x28;
/// `BPF_LD|BPF_B|BPF_ABS`: load the packet byte at a fixed offset.
const BPF_LD_B_ABS: u16 = 0x30;
/// `BPF_LD|BPF_W|BPF_LEN`: load the packet length.
const BPF_LD_W_LEN: u16 = 0x80;
/// `BPF_LDX|BPF_W|BPF_LEN`: load the packet length into the index register.
const BPF_LDX_W_LEN: u16 = 0x81;
/// `BPF_LD|BPF_W|BPF_IND`: load the packet word at the index register plus an
/// offset.
const BPF_LD_W_IND: u16 = 0x40;
/// `BPF_LD|BPF_H|BPF_IND`: load the packet half-word at the index register
/// plus an offset.
const BPF_LD_H_IND: u16 = 0x48;
/// `BPF_LD|BPF_B|BPF_IND`: load the packet byte at the index register plus an
/// offset.
const BPF_LD_B_IND: u16 = 0x50;
/// `BPF_LDX|BPF_MSH|BPF_B`: load four times the low nibble of a packet byte
/// into the index register.
const BPF_LDX_MSH_B: u16 = 0xb1;
/// `BPF_LD|BPF_IMM`: load a constant.
const BPF_LD_IMM: u16 = 0x00;
/// `BPF_LDX|BPF_IMM`: load a constant into the index register.
const BPF_LDX_IMM: u16 = 0x01;
/// `BPF_LD|BPF_MEM`: load a scratch word.
const BPF_LD_MEM: u16 = 0x60;
/// `BPF_LDX|BPF_MEM`: load a scratch word into the index register.
const BPF_LDX_MEM: u16 = 0x61;
/// `BPF_STX`: store the index register into a scratch word.
const BPF_STX: u16 = 0x03;
/// `BPF_JMP|BPF_JA`: jump unconditionally.
const BPF_JMP_JA: u16 = 0x05;
/// `BPF_JMP|BPF_JGT|BPF_K`: jump when the accumulator is above a constant.
const BPF_JMP_JGT_K: u16 = 0x25;
/// `BPF_JMP|BPF_JGE|BPF_K`: jump when the accumulator is at least a constant.
const BPF_JMP_JGE_K: u16 = 0x35;
/// `BPF_JMP|BPF_JEQ|BPF_K`: jump when the accumulator equals a constant.
const BPF_JMP_JEQ_K: u16 = 0x15;
/// `BPF_JMP|BPF_JSET|BPF_K`: jump when the accumulator shares a bit with a
/// constant.
const BPF_JMP_JSET_K: u16 = 0x45;
/// `BPF_JMP|BPF_JGT|BPF_X`: jump when the accumulator is above the index
/// register.
const BPF_JMP_JGT_X: u16 = 0x2d;
/// `BPF_JMP|BPF_JGE|BPF_X`: jump when the accumulator is at least the index
/// register.
const BPF_JMP_JGE_X: u16 = 0x3d;
/// `BPF_JMP|BPF_JEQ|BPF_X`: jump when the accumulator equals the index
/// register.
const BPF_JMP_JEQ_X: u16 = 0x1d;
/// `BPF_JMP|BPF_JSET|BPF_X`: jump when the accumulator shares a bit with the
/// index register.
const BPF_JMP_JSET_X: u16 = 0x4d;
/// `BPF_ALU|BPF_ADD|BPF_X`: add the index register to the accumulator.
const BPF_ALU_ADD_X: u16 = 0x0c;
/// `BPF_ALU|BPF_SUB|BPF_X`: subtract the index register from the accumulator.
const BPF_ALU_SUB_X: u16 = 0x1c;
/// `BPF_ALU|BPF_MUL|BPF_X`: multiply the accumulator by the index register.
const BPF_ALU_MUL_X: u16 = 0x2c;
/// `BPF_ALU|BPF_DIV|BPF_X`: divide the accumulator by the index register.
const BPF_ALU_DIV_X: u16 = 0x3c;
/// `BPF_ALU|BPF_MOD|BPF_X`: the accumulator modulo the index register.
const BPF_ALU_MOD_X: u16 = 0x9c;
/// `BPF_ALU|BPF_AND|BPF_X`: AND the index register into the accumulator.
const BPF_ALU_AND_X: u16 = 0x5c;
/// `BPF_ALU|BPF_OR|BPF_X`: OR the index register into the accumulator.
const BPF_ALU_OR_X: u16 = 0x4c;
/// `BPF_ALU|BPF_XOR|BPF_X`: XOR the index register into the accumulator.
const BPF_ALU_XOR_X: u16 = 0xac;
/// `BPF_ALU|BPF_LSH|BPF_X`: shift the accumulator left by the index register.
const BPF_ALU_LSH_X: u16 = 0x6c;
/// `BPF_ALU|BPF_RSH|BPF_X`: shift the accumulator right by the index register.
const BPF_ALU_RSH_X: u16 = 0x7c;
/// `BPF_ALU|BPF_ADD|BPF_K`: add a constant to the accumulator.
const BPF_ALU_ADD_K: u16 = 0x04;
/// `BPF_ALU|BPF_SUB|BPF_K`: subtract a constant from the accumulator.
const BPF_ALU_SUB_K: u16 = 0x14;
/// `BPF_ALU|BPF_MUL|BPF_K`: multiply the accumulator by a constant.
const BPF_ALU_MUL_K: u16 = 0x24;
/// `BPF_ALU|BPF_DIV|BPF_K`: divide the accumulator by a constant.
const BPF_ALU_DIV_K: u16 = 0x34;
/// `BPF_ALU|BPF_MOD|BPF_K`: the accumulator modulo a constant.
const BPF_ALU_MOD_K: u16 = 0x94;
/// `BPF_ALU|BPF_AND|BPF_K`: AND a constant into the accumulator.
const BPF_ALU_AND_K: u16 = 0x54;
/// `BPF_ALU|BPF_OR|BPF_K`: OR a constant into the accumulator.
const BPF_ALU_OR_K: u16 = 0x44;
/// `BPF_ALU|BPF_XOR|BPF_K`: XOR a constant into the accumulator.
const BPF_ALU_XOR_K: u16 = 0xa4;
/// `BPF_ALU|BPF_LSH|BPF_K`: shift the accumulator left by a constant.
const BPF_ALU_LSH_K: u16 = 0x64;
/// `BPF_ALU|BPF_RSH|BPF_K`: shift the accumulator right by a constant.
const BPF_ALU_RSH_K: u16 = 0x74;
/// `BPF_ALU|BPF_NEG`: negate the accumulator.
const BPF_ALU_NEG: u16 = 0x84;
/// `BPF_MISC|BPF_TAX`: copy the accumulator to the index register.
const BPF_MISC_TAX: u16 = 0x07;
/// `BPF_MISC|BPF_TXA`: copy the index register to the accumulator.
const BPF_MISC_TXA: u16 = 0x87;
/// `BPF_RET|BPF_K`: return a constant.
const BPF_RET_K: u16 = 0x06;
/// `BPF_RET|BPF_A`: return the accumulator.
const BPF_RET_A: u16 = 0x16;
/// `BPF_RET|BPF_MATCH_IMM`: return through the hash match of the immediate
/// keys.
const BPF_RET_MATCH_IMM: u16 = 0x1e;
/// Sum `keys` with the C's wrapping addition, reduced modulo the bucket count.
pub(crate) fn hash(keys: &[c_uint]) -> u32 {
    let mut hval = 0u32;
    for key in keys {
        hval = hval.wrapping_add(*key);
    }
    hval % NET_HASH_SIZE
}

/// What [`find_match`] found once the key counts agreed.
pub(crate) struct Match {
    /// The bucket the C wrote to `*hash_headpp`.
    pub(crate) bucket: *mut NetHashBucket,
    /// The entry whose keys matched, null when the bucket or the search was
    /// empty.
    pub(crate) entry: *mut NetHashEntry,
}

/// The bucket slot of `header` the keys name, and the entry in it whose keys
/// equal `keys`.
///
/// # Safety
///
/// `header` must point at a live [`NetHashHeader`] whose `table` is well
/// formed, and `keys` must be at most [`N_NET_HASH_KEYS`] long.
pub(crate) unsafe fn find_match(
    header: *mut NetHashHeader,
    keys: &[c_uint],
) -> Option<Match> {
    let n_keys = unsafe { (*header).n_keys };
    if n_keys != keys.len() as c_int {
        return None;
    }
    if keys.len() > N_NET_HASH_KEYS {
        return None;
    }
    let bucket =
        unsafe { (*header).table.as_mut_ptr().add(hash(keys) as usize) };
    // SAFETY: the caller guarantees the header is live and its buckets are
    // well formed, so every entry in the walked bucket is live.
    let mut cursor = unsafe { (*bucket).cursor_front() };
    while let Some(entry) = cursor.current() {
        if keys == &entry.keys[..keys.len()] {
            return Some(Match {
                bucket,
                entry: cursor
                    .current_ptr()
                    .map_or(ptr::null_mut(), NonNull::as_ptr),
            });
        }
        cursor.move_next();
    }
    Some(Match {
        bucket,
        entry: ptr::null_mut(),
    })
}

/// The C's `(pc->k <= wirelen) ? pc->k : wirelen`, on the unsigned bit
/// pattern of the signed `k`.
fn accept(k: c_int, wirelen: u32) -> c_int {
    // A negative `k` becomes a huge unsigned one and loses the comparison,
    // as it did in the C.  The C returned an `int`; a wire length is a
    // packet byte count.
    (k as u32).min(wirelen) as c_int
}

/// The BPF interpreter's state.
struct Interp {
    /// `filter[0]`, the first instruction the C could jump back to.
    start: *const BpfInsn,
    /// The instruction being run.
    pc: *const BpfInsn,
    /// The end of the program, which can name a byte inside an instruction.
    end: *const BpfInsn,
    packet: *const u8,
    header: *const u8,
    hlen: u32,
    wirelen: u32,
    a: u32,
    x: u32,
    mem: [u32; BPF_MEMWORDS],
    /// Whether `infp->rcv_port` is `MACH_PORT_NULL`, the dummy hash filter.
    rcv_port_null: bool,
    /// The receive port seen as the [`NetHashHeader`] a match instruction
    /// wants.
    hash: *mut NetHashHeader,
    /// Where a match stores the hash bucket it found.
    hash_headpp: *mut *mut NetHashBucket,
    /// Where a match stores the entry it found.
    entpp: *mut *mut NetHashEntry,
}

impl Interp {
    /// The `data + k` window: an offset below `hlen` is the header's, one
    /// above it is the packet's.  `size` is the width added to `k`: four for
    /// a word, two for a half, and one for the byte and MSH loads, whose
    /// comparisons are the strict `k < hlen` and `k < NET_RCV_MAX`.  A
    /// negative `k` fails both comparisons.
    fn locate(&self, k: c_int, size: u32) -> Option<(*const u8, isize)> {
        let ku = u64::from(k as u32);
        if ku + u64::from(size) <= u64::from(self.hlen) {
            Some((self.header, k as isize))
        } else if ku + u64::from(size) <= u64::from(NET_RCV_MAX) {
            Some((self.packet, k as isize - self.hlen as isize))
        } else {
            None
        }
    }

    /// The C's `load_word:` tail.
    fn load_word(&mut self, k: c_int) -> bool {
        match self.locate(k, 4) {
            // SAFETY: `locate` keeps the read in the header window or in the
            // packet window plus its three readable leading bytes, and the
            // read is as unaligned as the C's.
            Some((data, off)) => {
                self.a = u32::from_be(
                    // SAFETY: `locate` kept the read in the header window
                    // or the packet window, and the read is unaligned.
                    unsafe { data.offset(off).cast::<u32>().read_unaligned() },
                );
                true
            }
            None => false,
        }
    }

    /// The C's `load_half:` tail.
    fn load_half(&mut self, k: c_int) -> bool {
        match self.locate(k, 2) {
            // SAFETY: `locate` keeps the read in the header window or in
            // the packet window, and the two-byte read is as unaligned as
            // the C's.
            Some((data, off)) => {
                self.a = u32::from(u16::from_be(
                    // SAFETY: `locate` keeps the read in the header window
                    // or in the packet window, and the two-byte read is as
                    // unaligned as the C's.
                    unsafe { data.offset(off).cast::<u16>().read_unaligned() },
                ));
                true
            }
            None => false,
        }
    }

    /// The C's `load_byte:` tail.  The C loaded through `char`, so a byte
    /// with the top bit set sign-extended into `A`.
    fn load_byte(&mut self, k: c_int) -> bool {
        match self.locate(k, 1) {
            // SAFETY: `locate` keeps the read in the header window or in
            // the packet window; the byte is inside the window.
            Some((data, off)) => {
                self.a =
                    // SAFETY: `locate` keeps the read in the header window
                    // or in the packet window; the byte is inside the
                    // window.
                    i32::from(unsafe { data.offset(off).read() } as i8) as u32;
                true
            }
            None => false,
        }
    }

    /// The C's `pc += delta` followed by the loop's `++pc`, with the
    /// validated program's bounds kept even for a bad jump.
    fn jump(&mut self, delta: isize) -> bool {
        let target = self.pc.wrapping_offset(delta);
        let address = target as usize;
        if (self.start as usize) <= address && address <= (self.end as usize) {
            self.pc = target;
            true
        } else {
            false
        }
    }

    /// The instruction loop.
    ///
    /// # Safety
    ///
    /// The caller must have validated the program and must keep `packet`,
    /// `header` and the match outputs valid.
    unsafe fn execute(&mut self) -> c_int {
        while self.pc < self.end {
            // SAFETY: `pc` is inside the program, so the instruction is
            // readable; a two-byte alignment is read the way the C did.
            let insn = unsafe { self.pc.read_unaligned() };
            let pc = self.pc;
            // SAFETY: `pc < end`, so the result is at most `end`.
            self.pc = unsafe { pc.add(1) };
            match insn.code {
                BPF_RET_K | BPF_RET_A | BPF_RET_MATCH_IMM => {
                    return self.ret(insn);
                }
                BPF_LD_W_ABS | BPF_LD_H_ABS | BPF_LD_B_ABS | BPF_LD_W_LEN
                | BPF_LDX_W_LEN | BPF_LD_W_IND | BPF_LD_H_IND
                | BPF_LD_B_IND | BPF_LDX_MSH_B | BPF_LD_IMM | BPF_LDX_IMM => {
                    if let Some(value) = self.load(insn) {
                        return value;
                    }
                }
                // The C's validator bounds `BPF_ST` and `BPF_LD|BPF_MEM`
                // only; `STX` and `LDX|BPF_MEM` with a negative `k` would
                // index outside `mem`, so the port rejects the index
                // instead.
                BPF_LD_MEM | BPF_LDX_MEM | BPF_ST | BPF_STX => {
                    if let Some(value) = self.mem_op(insn) {
                        return value;
                    }
                }
                BPF_JMP_JA | BPF_JMP_JGT_K | BPF_JMP_JGE_K | BPF_JMP_JEQ_K
                | BPF_JMP_JSET_K | BPF_JMP_JGT_X | BPF_JMP_JGE_X
                | BPF_JMP_JEQ_X | BPF_JMP_JSET_X => {
                    if !self.cond_jump(insn) {
                        return 0;
                    }
                }
                BPF_ALU_ADD_X | BPF_ALU_SUB_X | BPF_ALU_MUL_X
                | BPF_ALU_DIV_X | BPF_ALU_MOD_X | BPF_ALU_AND_X
                | BPF_ALU_OR_X | BPF_ALU_XOR_X | BPF_ALU_LSH_X
                | BPF_ALU_RSH_X | BPF_ALU_ADD_K | BPF_ALU_SUB_K
                | BPF_ALU_MUL_K | BPF_ALU_DIV_K | BPF_ALU_MOD_K
                | BPF_ALU_AND_K | BPF_ALU_OR_K | BPF_ALU_XOR_K
                | BPF_ALU_LSH_K | BPF_ALU_RSH_K | BPF_ALU_NEG
                | BPF_MISC_TAX | BPF_MISC_TXA => {
                    if let Some(value) = self.alu(insn) {
                        return value;
                    }
                }
                _ => return 0,
            }
        }
        0
    }

    /// The C's three `BPF_RET` cases.
    fn ret(&mut self, insn: BpfInsn) -> c_int {
        match insn.code {
            BPF_RET_K => {
                if self.rcv_port_null && self.entp_is_null() {
                    0
                } else {
                    accept(insn.k, self.wirelen)
                }
            }
            BPF_RET_A => {
                if self.rcv_port_null && self.entp_is_null() {
                    0
                } else {
                    accept(self.a as c_int, self.wirelen)
                }
            }
            _ => {
                let n_keys = usize::from(insn.jt);
                if n_keys == 0 || n_keys > BPF_MEMWORDS {
                    return 0;
                }
                // SAFETY: the caller promises a live hash header behind
                // this port and a validated instruction.
                if let Some(m) =
                    // SAFETY: the caller promises the live hash
                    // header and a validated program.
                    unsafe {
                        find_match(self.hash, &self.mem[..n_keys])
                    }
                {
                    // SAFETY: the caller promises both out-params are
                    // writable.
                    unsafe {
                        *self.hash_headpp = m.bucket;
                    }
                    if m.entry.is_null() {
                        return 0;
                    }
                    // SAFETY: the caller promises both out-params are
                    // writable.
                    unsafe {
                        *self.entpp = m.entry;
                    }
                    return accept(insn.k, self.wirelen);
                }
                0
            }
        }
    }

    /// The C's `BPF_LD` and `BPF_LDX` cases; `Some(0)` is the C's failure
    /// return.
    fn load(&mut self, insn: BpfInsn) -> Option<c_int> {
        match insn.code {
            BPF_LD_W_ABS => {
                if self.load_word(insn.k) {
                    None
                } else {
                    Some(0)
                }
            }
            BPF_LD_H_ABS => {
                if self.load_half(insn.k) {
                    None
                } else {
                    Some(0)
                }
            }
            BPF_LD_B_ABS => {
                if self.load_byte(insn.k) {
                    None
                } else {
                    Some(0)
                }
            }
            BPF_LD_W_LEN => {
                self.a = self.wirelen;
                None
            }
            BPF_LDX_W_LEN => {
                self.x = self.wirelen;
                None
            }
            BPF_LD_W_IND => {
                let k = self.x.wrapping_add(insn.k as u32) as c_int;
                if self.load_word(k) { None } else { Some(0) }
            }
            BPF_LD_H_IND => {
                let k = self.x.wrapping_add(insn.k as u32) as c_int;
                if self.load_half(k) { None } else { Some(0) }
            }
            BPF_LD_B_IND => {
                let k = self.x.wrapping_add(insn.k as u32) as c_int;
                if self.load_byte(k) { None } else { Some(0) }
            }
            BPF_LDX_MSH_B => match self.locate(insn.k, 1) {
                // SAFETY: `locate` keeps the read in the header window or
                // in the packet window; the masked byte stays in bounds.
                Some((data, off)) => {
                    self.x = u32::from(
                        // SAFETY: `locate` keeps the read in the header
                        // window or in the packet window; the byte is
                        // inside the window.
                        unsafe { data.offset(off).read() } & 0xf,
                    ) << 2;
                    None
                }
                None => Some(0),
            },
            BPF_LD_IMM => {
                self.a = insn.k as u32;
                None
            }
            BPF_LDX_IMM => {
                self.x = insn.k as u32;
                None
            }
            _ => Some(0),
        }
    }

    /// The C's `BPF_ST` and `BPF_LD|BPF_MEM` cases.
    fn mem_op(&mut self, insn: BpfInsn) -> Option<c_int> {
        match insn.code {
            BPF_LD_MEM => match self.mem.get(insn.k as usize) {
                Some(value) => {
                    self.a = *value;
                    None
                }
                None => Some(0),
            },
            BPF_LDX_MEM => match self.mem.get(insn.k as usize) {
                Some(value) => {
                    self.x = *value;
                    None
                }
                None => Some(0),
            },
            BPF_ST => match self.mem.get_mut(insn.k as usize) {
                Some(slot) => {
                    *slot = self.a;
                    None
                }
                None => Some(0),
            },
            BPF_STX => match self.mem.get_mut(insn.k as usize) {
                Some(slot) => {
                    *slot = self.x;
                    None
                }
                None => Some(0),
            },
            _ => Some(0),
        }
    }

    /// The C's `BPF_JMP` cases; `false` is the C's failure return.
    fn cond_jump(&mut self, insn: BpfInsn) -> bool {
        let taken = match insn.code {
            BPF_JMP_JA => return self.jump(insn.k as isize),
            BPF_JMP_JGT_K => self.a > insn.k as u32,
            BPF_JMP_JGE_K => self.a >= insn.k as u32,
            BPF_JMP_JEQ_K => self.a == insn.k as u32,
            BPF_JMP_JSET_K => self.a & insn.k as u32 != 0,
            BPF_JMP_JGT_X => self.a > self.x,
            BPF_JMP_JGE_X => self.a >= self.x,
            BPF_JMP_JEQ_X => self.a == self.x,
            BPF_JMP_JSET_X => self.a & self.x != 0,
            _ => return false,
        };
        let delta = jump_delta(taken, insn);
        self.jump(delta)
    }

    /// The C's `BPF_ALU` and `BPF_MISC` cases; `Some(0)` is the C's
    /// division-by-zero exit.
    const fn alu(&mut self, insn: BpfInsn) -> Option<c_int> {
        match insn.code {
            BPF_ALU_ADD_X => self.a = self.a.wrapping_add(self.x),
            BPF_ALU_SUB_X => self.a = self.a.wrapping_sub(self.x),
            BPF_ALU_MUL_X => self.a = self.a.wrapping_mul(self.x),
            BPF_ALU_DIV_X => {
                if self.x == 0 {
                    return Some(0);
                }
                self.a /= self.x;
            }
            BPF_ALU_MOD_X => {
                if self.x == 0 {
                    return Some(0);
                }
                self.a %= self.x;
            }
            BPF_ALU_AND_X => self.a &= self.x,
            BPF_ALU_OR_X => self.a |= self.x,
            BPF_ALU_XOR_X => self.a ^= self.x,
            BPF_ALU_LSH_X => {
                self.a = if self.x < 32 {
                    self.a.wrapping_shl(self.x)
                } else {
                    0
                };
            }
            BPF_ALU_RSH_X => {
                self.a = if self.x < 32 {
                    self.a.wrapping_shr(self.x)
                } else {
                    0
                };
            }
            BPF_ALU_ADD_K => self.a = self.a.wrapping_add(insn.k as u32),
            BPF_ALU_SUB_K => self.a = self.a.wrapping_sub(insn.k as u32),
            BPF_ALU_MUL_K => self.a = self.a.wrapping_mul(insn.k as u32),
            BPF_ALU_DIV_K => {
                if insn.k == 0 {
                    return Some(0);
                }
                self.a /= insn.k as u32;
            }
            BPF_ALU_MOD_K => {
                if insn.k == 0 {
                    return Some(0);
                }
                self.a %= insn.k as u32;
            }
            BPF_ALU_AND_K => self.a &= insn.k as u32,
            BPF_ALU_OR_K => self.a |= insn.k as u32,
            BPF_ALU_XOR_K => self.a ^= insn.k as u32,
            BPF_ALU_LSH_K => {
                // The C shifted for every `k` below 32, negative counts
                // included; i386 masks the count, which `wrapping_shl`
                // reproduces.
                self.a = if insn.k < 32 {
                    self.a.wrapping_shl(insn.k as u32)
                } else {
                    0
                };
            }
            BPF_ALU_RSH_K => {
                self.a = if insn.k < 32 {
                    self.a.wrapping_shr(insn.k as u32)
                } else {
                    0
                };
            }
            BPF_ALU_NEG => self.a = 0u32.wrapping_sub(self.a),
            BPF_MISC_TAX => self.x = self.a,
            BPF_MISC_TXA => self.a = self.x,
            _ => return Some(0),
        }
        None
    }

    /// The C's `*entpp == 0` test.
    fn entp_is_null(&self) -> bool {
        // SAFETY: the caller promises the out-param is readable.
        unsafe { (*self.entpp).is_null() }
    }
}

/// The C's `pc->jt`/`pc->jf` selection.
fn jump_delta(taken: bool, insn: BpfInsn) -> isize {
    if taken {
        isize::from(insn.jt)
    } else {
        isize::from(insn.jf)
    }
}

/// Runs the BPF program of `port` over the packet and its header, returning
/// how much of the packet to accept: 0 rejects it.
///
/// # Safety
///
/// `port` must point at a live [`NetRcvPort`] or [`NetHashHeader`] whose
/// `filter` and `filter_end` delimit a validated program; `packet` must be
/// readable for [`NET_RCV_MAX`] bytes with the three bytes before it readable
/// too; `header` must be readable for `hlen` bytes; `hash_headpp` and `entpp`
/// must be writable, and `entpp` must be left null before the call.
pub(crate) unsafe fn do_filter(
    port: *mut NetRcvPort,
    packet: *const u8,
    wirelen: u32,
    header: *const u8,
    hlen: u32,
    hash_headpp: *mut *mut NetHashBucket,
    entpp: *mut *mut NetHashEntry,
) -> c_int {
    let filter = unsafe { (*port).filter.as_ptr() };
    let filter_end = unsafe { (*port).filter_end };
    let bytes = (filter_end as usize).saturating_sub(filter as usize);
    // The filter's end comes from its byte length, which need not be a
    // multiple of one instruction; the walk stops at the address, so a program
    // of one instruction or less never runs.
    if bytes <= size_of::<BpfInsn>() {
        return 0;
    }
    let rcv_port_null = unsafe { (*port).rcv_port.is_null() };
    let start = filter.cast::<BpfInsn>();
    let mut interp = Interp {
        // SAFETY: `bytes` is more than one instruction, so the second
        // instruction is inside the filter array.
        pc: unsafe { start.add(1) },
        start,
        end: filter_end.cast::<BpfInsn>(),
        packet,
        header,
        hlen,
        wirelen,
        a: 0,
        x: 0,
        mem: [0; BPF_MEMWORDS],
        rcv_port_null,
        hash: port.cast::<NetHashHeader>(),
        hash_headpp,
        entpp,
    };
    unsafe { interp.execute() }
}

/* ======== the kmsg pool, the filter lists and the receive thread ======== */

/// The most bytes of a hardware header.
const NET_HDW_HDR_MAX: usize = 64;
/// The `unsigned short` words a header filter may address.
const NET_HDR_WORDS: usize = NET_HDW_HDR_MAX / 2;
/// The depth of the old filter's stack.
const NET_FILTER_STACK_DEPTH: usize = 32;
/// The priority that stops delivery.
const NET_HI_PRI: c_int = 100;
/// The send option asking for a timeout.
const MACH_SEND_TIMEOUT: c_uint = 0x10;
/// The send-right disposition.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;
/// The type of a byte in a message body.
const MACH_MSG_TYPE_BYTE: u32 = 9;
/// The message id of a network receive message.
const NET_RCV_MSG_ID: c_int = 2999;

/// The filter-type bits of a filter's first word.
const NETF_TYPE_MASK: u16 = 0xfc00;
/// The filter type of a BPF program.
const NETF_BPF: u16 = 0x400;
/// The filter applies to incoming packets.
const NETF_IN: u16 = 0x1;
/// The filter applies to outgoing packets.
const NETF_OUT: u16 = 0x2;
/// The old filter's push argument that pushes nothing.
const NETF_NOPUSH: u16 = 0;
/// The old filter's push argument that pushes the literal after it.
const NETF_PUSHLIT: u16 = 1;
/// The old filter's push argument that pushes zero.
const NETF_PUSHZERO: u16 = 2;
/// The old filter's push argument that pushes the packet word the stack top
/// indexes.
const NETF_PUSHIND: u16 = 14;
/// The old filter's push argument that pushes the header word the stack top
/// indexes.
const NETF_PUSHHDRIND: u16 = 15;
/// The base of the old filter's push arguments that push a packet word.
const NETF_PUSHWORD: u16 = 16;
/// The base of the old filter's push arguments that push a header word.
const NETF_PUSHHDR: u16 = 960;
/// The base of the old filter's push arguments that push a stack word.
const NETF_PUSHSTK: u16 = 992;

/// The descriptor word of a `mach_msg_type_t` initializer.
const fn descriptor_word(name: u32, size: u32) -> u32 {
    name | (size << 8) | (1 << 29)
}

/// The 64-byte hardware header.
const HEADER_TYPE: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_BYTE, 8), 64);
/// The variable-length packet body.
const PACKET_TYPE: MachMsgType =
    MachMsgType::new(descriptor_word(MACH_MSG_TYPE_BYTE, 8), 0);

/// `struct packet_header`: the length and type words the BPF filter window
/// skips.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct PacketHeader {
    pub length: u16,
    pub type_: u16,
}

const _: () = assert!(size_of::<PacketHeader>() == 4);
const _: () = assert!(align_of::<PacketHeader>() == 2);
const _: () = assert!(offset_of!(PacketHeader, length) == 0);
const _: () = assert!(offset_of!(PacketHeader, type_) == 2);

/// An interface's output queue.
#[repr(C)]
#[allow(missing_docs)]
pub struct IfQueue {
    pub ifq_head: QueueChain,
    pub ifq_len: c_int,
    pub ifq_maxlen: c_int,
    pub ifq_drops: c_int,
    pub ifq_lock: SimpleLock,
}

const _: () = {
    assert!(size_of::<IfQueue>() == 32);
    assert!(align_of::<IfQueue>() == 8);
    assert!(offset_of!(IfQueue, ifq_head) == 0);
    assert!(offset_of!(IfQueue, ifq_len) == 16);
    assert!(offset_of!(IfQueue, ifq_maxlen) == 20);
    assert!(offset_of!(IfQueue, ifq_drops) == 24);
    assert!(offset_of!(IfQueue, ifq_lock) == 28);
};

/// A network interface's header.
///
/// Both port-list heads must start as empty lists when the interface is
/// created, and the interface stays in place while a port is on either.
#[repr(C)]
#[allow(missing_docs)]
pub struct IfNet {
    pub if_unit: c_short,
    pub if_flags: c_short,
    pub if_timer: c_short,
    pub if_mtu: c_short,
    pub if_header_size: c_short,
    pub if_header_format: c_short,
    pub if_address_size: c_short,
    pub if_alloc_size: c_short,
    pub if_address: *mut c_char,
    pub if_snd: IfQueue,
    pub if_rcv_port_list: NetInputList,
    pub if_snd_port_list: NetOutputList,
    pub if_rcv_port_list_lock: SimpleLock,
    pub if_snd_port_list_lock: SimpleLock,
    pub if_ipackets: c_int,
    pub if_ierrors: c_int,
    pub if_opackets: c_int,
    pub if_oerrors: c_int,
    pub if_collisions: c_int,
    pub if_rcvdrops: c_int,
}

// The record keeps its established sizes, alignments and field offsets.
const _: () = {
    assert!(size_of::<IfNet>() == 120);
    assert!(align_of::<IfNet>() == 8);
    assert!(offset_of!(IfNet, if_unit) == 0);
    assert!(offset_of!(IfNet, if_flags) == 2);
    assert!(offset_of!(IfNet, if_timer) == 4);
    assert!(offset_of!(IfNet, if_mtu) == 6);
    assert!(offset_of!(IfNet, if_header_size) == 8);
    assert!(offset_of!(IfNet, if_header_format) == 10);
    assert!(offset_of!(IfNet, if_address_size) == 12);
    assert!(offset_of!(IfNet, if_alloc_size) == 14);
    assert!(offset_of!(IfNet, if_address) == 16);
    assert!(offset_of!(IfNet, if_snd) == 24);
    assert!(offset_of!(IfNet, if_rcv_port_list) == 56);
    assert!(offset_of!(IfNet, if_snd_port_list) == 72);
    assert!(offset_of!(IfNet, if_rcv_port_list_lock) == 88);
    assert!(offset_of!(IfNet, if_snd_port_list_lock) == 92);
    assert!(offset_of!(IfNet, if_ipackets) == 96);
    assert!(offset_of!(IfNet, if_ierrors) == 100);
    assert!(offset_of!(IfNet, if_opackets) == 104);
    assert!(offset_of!(IfNet, if_oerrors) == 108);
    assert!(offset_of!(IfNet, if_collisions) == 112);
    assert!(offset_of!(IfNet, if_rcvdrops) == 116);
};

/// `struct net_status`: the reply of the `NET_STATUS` flavor.
#[repr(C)]
#[allow(missing_docs)]
pub struct NetStatus {
    pub min_packet_size: c_int,
    pub max_packet_size: c_int,
    pub header_format: c_int,
    pub header_size: c_int,
    pub address_size: c_int,
    pub flags: c_int,
    pub mapped_size: c_int,
}

const _: () = assert!(size_of::<NetStatus>() == 28);
const _: () = assert!(align_of::<NetStatus>() == 4);
const _: () = assert!(offset_of!(NetStatus, min_packet_size) == 0);
const _: () = assert!(offset_of!(NetStatus, mapped_size) == 24);

/// `struct net_rcv_msg`: the message a network receive port gets, laid over
/// the kernel-message header.
#[repr(C, align(8))]
#[allow(missing_docs)]
pub(crate) struct NetRcvMsg {
    pub(crate) msg_hdr: MachMsgHeader,
    pub(crate) header_type: MachMsgType,
    pub(crate) header: [c_char; NET_HDW_HDR_MAX],
    pub(crate) packet_type: MachMsgType,
    pub(crate) packet: [u8; NET_RCV_MAX as usize],
    pub(crate) sent: c_int,
}

const _: () = {
    assert!(size_of::<NetRcvMsg>() == 4216);
    assert!(align_of::<NetRcvMsg>() == 8);
    assert!(offset_of!(NetRcvMsg, msg_hdr) == 0);
    assert!(offset_of!(NetRcvMsg, header_type) == 32);
    assert!(offset_of!(NetRcvMsg, header) == 40);
    assert!(offset_of!(NetRcvMsg, packet_type) == 104);
    assert!(offset_of!(NetRcvMsg, packet) == 112);
    assert!(offset_of!(NetRcvMsg, sent) == 4208);
};

/// Guards the high and low send queues and `NET_THREAD_AWAKE`.
static NET_QUEUE_LOCK: SimpleLock = SimpleLock::new();
/// Guards the free message pool.
static NET_QUEUE_FREE_LOCK: SimpleLock = SimpleLock::new();
/// Guards the allocation counters.
static NET_KMSG_TOTAL_LOCK: SimpleLock = SimpleLock::new();
/// Serializes picking a free hash-header slot.
static NET_HASH_HEADER_LOCK: SimpleLock = SimpleLock::new();

/// Whether the receive thread is awake, under [`NET_QUEUE_LOCK`].
static NET_THREAD_AWAKE: SyncCell<bool> = SyncCell(UnsafeCell::new(false));
/// The high-priority send queue, under [`NET_QUEUE_LOCK`].
static NET_QUEUE_HIGH: SyncCell<IpcKmsgQueue> =
    SyncCell(UnsafeCell::new(IpcKmsgQueue {
        base: ptr::null_mut(),
    }));
/// The length of [`NET_QUEUE_HIGH`], under [`NET_QUEUE_LOCK`].
static NET_QUEUE_HIGH_SIZE: SyncCell<c_int> = SyncCell(UnsafeCell::new(0));
/// The low-priority send queue, under [`NET_QUEUE_LOCK`].
static NET_QUEUE_LOW: SyncCell<IpcKmsgQueue> =
    SyncCell(UnsafeCell::new(IpcKmsgQueue {
        base: ptr::null_mut(),
    }));
/// The length of [`NET_QUEUE_LOW`]: [`want_more`] reads it without the queue
/// lock, so it is an atomic; the queue lock still serializes its updates.
static NET_QUEUE_LOW_SIZE: AtomicI32 = AtomicI32::new(0);
/// The free message pool, under [`NET_QUEUE_FREE_LOCK`].
static NET_QUEUE_FREE: SyncCell<IpcKmsgQueue> =
    SyncCell(UnsafeCell::new(IpcKmsgQueue {
        base: ptr::null_mut(),
    }));
/// The length of [`NET_QUEUE_FREE`]: [`want_more`] reads it without the free
/// lock, so it is an atomic; the free lock still serializes its updates.
static NET_QUEUE_FREE_SIZE: AtomicI32 = AtomicI32::new(0);
/// The largest the free pool has been, under [`NET_QUEUE_FREE_LOCK`].
static NET_QUEUE_FREE_MAX: SyncCell<c_int> = SyncCell(UnsafeCell::new(0));
/// How many free buffers to keep.  [`want_more`] reads it without a lock, so
/// it is an atomic.
static NET_QUEUE_FREE_MIN: AtomicI32 = AtomicI32::new(3);
/// How often a free buffer was there, under [`NET_QUEUE_FREE_LOCK`].
static NET_QUEUE_FREE_HITS: SyncCell<c_int> = SyncCell(UnsafeCell::new(0));
/// How often a buffer was stolen from the low queue, under [`NET_QUEUE_LOCK`].
static NET_QUEUE_FREE_STEALS: SyncCell<c_int> = SyncCell(UnsafeCell::new(0));
/// A debug counter of free-pool misses, incremented without a lock.
static NET_QUEUE_FREE_MISSES: AtomicI32 = AtomicI32::new(0);
/// A debug counter of high-queue sends, incremented without a lock.
static NET_KMSG_SEND_HIGH_HITS: AtomicI32 = AtomicI32::new(0);
/// A debug counter of low-queue sends, incremented without a lock.
static NET_KMSG_SEND_LOW_HITS: AtomicI32 = AtomicI32::new(0);
/// A debug counter of high-queue send misses, touched without a lock.
static NET_KMSG_SEND_HIGH_MISSES: AtomicI32 = AtomicI32::new(0);
/// A debug counter of low-queue send misses, touched without a lock.
static NET_KMSG_SEND_LOW_MISSES: AtomicI32 = AtomicI32::new(0);
/// The times the network thread has been awakened, a debug counter.
static NET_THREAD_AWAKEN: AtomicI32 = AtomicI32::new(0);
/// The times the network AST has been taken, a debug counter.
static NET_AST_TAKEN: AtomicI32 = AtomicI32::new(0);
/// How many network messages exist.  [`want_more`] reads it without the total
/// lock, so it is an atomic.
static NET_KMSG_TOTAL: AtomicI32 = AtomicI32::new(0);
/// The allocation cap, read by [`want_more`] too.
static NET_KMSG_MAX: AtomicI32 = AtomicI32::new(0);
/// The allocation size, written once by [`init`].
static NET_KMSG_SIZE: AtomicUsize = AtomicUsize::new(0);
/// Non-zero to enable queue reordering, for a debugger to set.
static NET_FILTER_QUEUE_REORDER: AtomicI32 = AtomicI32::new(0);

/// The slab cache of [`NetRcvPort`] records.
static NET_RCV_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));
/// The slab cache of [`NetHashEntry`] records.
static NET_HASH_ENTRY_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// The address of [`NET_RCV_CACHE`], for the cache calls that take
/// `&mut self`.
fn rcv_cache() -> *mut KmemCache {
    NET_RCV_CACHE.0.get()
}

/// The address of [`NET_HASH_ENTRY_CACHE`].
fn hash_entry_cache() -> *mut KmemCache {
    NET_HASH_ENTRY_CACHE.0.get()
}

/// The address of [`NET_QUEUE_HIGH`].
fn queue_high() -> *mut IpcKmsgQueue {
    NET_QUEUE_HIGH.0.get()
}

/// The address of [`NET_QUEUE_LOW`].
fn queue_low() -> *mut IpcKmsgQueue {
    NET_QUEUE_LOW.0.get()
}

/// The address of [`NET_QUEUE_FREE`].
fn queue_free() -> *mut IpcKmsgQueue {
    NET_QUEUE_FREE.0.get()
}

/// The hash header sharing a receive port's storage.
///
/// # Safety
///
/// `port` must actually be the [`NetRcvPort`] embedded in a live
/// [`NetHashHeader`] allocation: the returned pointer aliases that header,
/// and callers dereference it as one.
const unsafe fn port_hash_header(port: *mut NetRcvPort) -> *mut NetHashHeader {
    port.cast()
}

/// The receive message over the kmsg's header.
///
/// # Safety
///
/// `kmsg` must be a live message allocated from this module's pool, whose
/// header is laid out as a [`NetRcvMsg`].
unsafe fn net_kmsg(kmsg: Kmsg) -> *mut NetRcvMsg {
    unsafe { kmsg.header().cast() }
}

/// Rounds `x` up to a multiple of the power of two `align`.
const fn p2round(x: usize, align: usize) -> usize {
    (x + (align - 1)) & !(align - 1)
}

/// Whether the pool should grow.  A misread value is not critical, so the
/// loads are `Relaxed`.
fn want_more() -> bool {
    let free = NET_QUEUE_FREE_SIZE.load(Ordering::Relaxed);
    let low = NET_QUEUE_LOW_SIZE.load(Ordering::Relaxed);
    let min = NET_QUEUE_FREE_MIN.load(Ordering::Relaxed);
    let total = NET_KMSG_TOTAL.load(Ordering::Relaxed);
    let max = NET_KMSG_MAX.load(Ordering::Relaxed);
    free.wrapping_add(low) < min && total < max
}

/// Allocates a network message buffer, or null.
///
/// # Safety
///
/// The caller must free the returned pointer, when non-null, through
/// [`kmsg_free`] with [`NET_KMSG_SIZE`] unchanged since this call, and must
/// not read it as an initialized [`NetRcvMsg`] before filling it in.
unsafe fn kmsg_alloc() -> *mut c_void {
    let size = NET_KMSG_SIZE.load(Ordering::Relaxed);
    slab::kalloc(size).map_or(ptr::null_mut(), |buf| buf.as_ptr().cast())
}

/// Frees a network message buffer.
///
/// # Safety
///
/// `kmsg` must be null or an allocation [`kmsg_alloc`] returned that this
/// call owns exclusively, sized by the [`NET_KMSG_SIZE`] still in effect.
unsafe fn kmsg_free(kmsg: *mut c_void) {
    let Some(buf) = NonNull::new(kmsg.cast::<u8>()) else {
        return;
    };
    unsafe { slab::kfree(buf, NET_KMSG_SIZE.load(Ordering::Relaxed)) };
}

/// Takes a message off the free pool, or `None` when it is empty.
///
/// # Safety
///
/// The caller must run in kernel mode with `%gs` based at the running CPU's
/// per-CPU block, as [`spl::splimp`] requires, and must hold neither
/// [`NET_QUEUE_FREE_LOCK`] nor [`NET_QUEUE_LOCK`].
pub(crate) unsafe fn kmsg_get() -> Option<Kmsg> {
    // SAFETY: this thread runs in kernel mode with `%gs` based.
    let s = unsafe { spl::splimp() };

    NET_QUEUE_FREE_LOCK.lock();
    let mut kmsg = unsafe { ipc_kmsg::dequeue(queue_free()) };
    if kmsg.is_some() {
        NET_QUEUE_FREE_SIZE.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: the free lock serializes this counter.
        unsafe { *NET_QUEUE_FREE_HITS.0.get() += 1 };
    }
    NET_QUEUE_FREE_LOCK.unlock();

    if kmsg.is_none() {
        NET_QUEUE_LOCK.lock();
        kmsg = unsafe { ipc_kmsg::dequeue(queue_low()) };
        if kmsg.is_some() {
            NET_QUEUE_LOW_SIZE.fetch_sub(1, Ordering::Relaxed);
            // SAFETY: the queue lock serializes this counter.
            unsafe { *NET_QUEUE_FREE_STEALS.0.get() += 1 };
        }
        NET_QUEUE_LOCK.unlock();
    }

    if kmsg.is_none() {
        NET_QUEUE_FREE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: `s` is the mask this thread saved.
    let _ = unsafe { spl::splx(s) };

    if want_more() || kmsg.is_none() {
        // SAFETY: this thread runs in kernel mode with `%gs` based.
        let s = unsafe { spl::splimp() };
        NET_QUEUE_LOCK.lock();
        // SAFETY: the queue lock serializes the flag.
        let awake = unsafe { *NET_THREAD_AWAKE.0.get() };
        unsafe { *NET_THREAD_AWAKE.0.get() = true };
        NET_QUEUE_LOCK.unlock();
        // SAFETY: `s` is the mask this thread saved.
        let _ = unsafe { spl::splx(s) };

        if !awake {
            unsafe {
                thread_wakeup_prim(
                    NET_THREAD_AWAKE.0.get().cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                )
            };
        }
    }

    kmsg
}

/// Returns a message to the free pool, or frees it when the pool is full.
///
/// # Safety
///
/// `kmsg` must be null or a pointer to a message this call owns
/// exclusively and that is linked into no queue; the caller must run in
/// kernel mode with `%gs` based, as [`spl::splimp`] requires, and must not
/// already hold [`NET_QUEUE_FREE_LOCK`].
pub(crate) unsafe fn kmsg_put(kmsg: *mut c_void) {
    let Some(kmsg) = NonNull::new(kmsg) else {
        return;
    };

    // SAFETY: this thread runs in kernel mode with `%gs` based.
    let s = unsafe { spl::splimp() };
    NET_QUEUE_FREE_LOCK.lock();
    unsafe { ipc_kmsg::enqueue(queue_free(), Kmsg::from_raw(kmsg.as_ptr())) };
    let size = NET_QUEUE_FREE_SIZE
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    // SAFETY: the free lock serializes the maximum.
    let max = unsafe { &mut *NET_QUEUE_FREE_MAX.0.get() };
    if size > *max {
        *max = size;
    }
    NET_QUEUE_FREE_LOCK.unlock();
    // SAFETY: `s` is the mask this thread saved.
    let _ = unsafe { spl::splx(s) };
}

/// Frees the pool's messages beyond its minimum.
///
/// # Safety
///
/// The caller must run in kernel mode with `%gs` based, as
/// [`spl::splimp`] requires, and must hold none of [`NET_QUEUE_FREE_LOCK`],
/// [`NET_QUEUE_LOCK`] or [`NET_KMSG_TOTAL_LOCK`].
pub(crate) unsafe fn kmsg_collect() {
    // SAFETY: this thread runs in kernel mode with `%gs` based.
    let mut s = unsafe { spl::splimp() };
    NET_QUEUE_FREE_LOCK.lock();
    while NET_QUEUE_FREE_SIZE.load(Ordering::Relaxed)
        > NET_QUEUE_FREE_MIN.load(Ordering::Relaxed)
    {
        // SAFETY: the free lock serializes the queue.
        let kmsg = unsafe { ipc_kmsg::dequeue(queue_free()) };
        NET_QUEUE_FREE_SIZE.fetch_sub(1, Ordering::Relaxed);
        NET_QUEUE_FREE_LOCK.unlock();
        // SAFETY: `s` is the mask this thread saved.
        let _ = unsafe { spl::splx(s) };

        if let Some(kmsg) = kmsg {
            // SAFETY: the dequeued message is this call's allocation.
            unsafe { kmsg_free(kmsg.as_ptr()) };
            NET_KMSG_TOTAL_LOCK.lock();
            NET_KMSG_TOTAL.fetch_sub(1, Ordering::Relaxed);
            NET_KMSG_TOTAL_LOCK.unlock();
        }

        // SAFETY: this thread runs in kernel mode with `%gs` based.
        s = unsafe { spl::splimp() };
        NET_QUEUE_FREE_LOCK.lock();
    }
    NET_QUEUE_FREE_LOCK.unlock();
    // SAFETY: `s` is the mask this thread saved.
    let _ = unsafe { spl::splx(s) };
}

/// Allocates messages into the free pool while it should grow.
///
/// # Safety
///
/// The caller must hold none of [`NET_QUEUE_LOCK`], [`NET_QUEUE_FREE_LOCK`]
/// or [`NET_KMSG_TOTAL_LOCK`], and must call this only where allocation is
/// allowed: the receive thread's own context, or [`deliver`] after it has
/// dropped the queue lock.
unsafe fn kmsg_more() {
    while want_more() {
        NET_KMSG_TOTAL_LOCK.lock();
        NET_KMSG_TOTAL.fetch_add(1, Ordering::Relaxed);
        NET_KMSG_TOTAL_LOCK.unlock();

        // SAFETY: the allocation is a raw pool buffer.
        let kmsg = unsafe { kmsg_alloc() };
        if kmsg.is_null() {
            // The C enqueued the null and dereferenced it; stopping keeps
            // the pool consistent instead of corrupting it.
            break;
        }
        // SAFETY: the fresh allocation is unowned.
        unsafe { kmsg_put(kmsg) };
    }
}

/// Delivers one queued message, high priority first, returning whether there
/// was one.
///
/// # Safety
///
/// Called holding [`NET_QUEUE_LOCK`] at splimp; it returns holding the lock.
unsafe fn deliver(nonblocking: bool) -> bool {
    let kmsg;
    let high_priority;
    match unsafe { ipc_kmsg::dequeue(queue_high()) } {
        Some(first) => {
            // SAFETY: the queue lock serializes the size.
            unsafe { *NET_QUEUE_HIGH_SIZE.0.get() -= 1 };
            kmsg = first;
            high_priority = true;
        }
        None => match unsafe { ipc_kmsg::dequeue(queue_low()) } {
            Some(first) => {
                NET_QUEUE_LOW_SIZE.fetch_sub(1, Ordering::Relaxed);
                kmsg = first;
                high_priority = false;
            }
            None => return false,
        },
    }
    NET_QUEUE_LOCK.unlock();
    // SAFETY: `spl0()` only opens the gates on this CPU.
    let _ = unsafe { spl::spl0() };

    let mut send_list = IpcKmsgQueue {
        base: ptr::null_mut(),
    };
    // SAFETY: the message is live and holds the interface pointer, the list
    // is an empty local queue, and only `NET_QUEUE_LOCK` is held.
    unsafe { filter(kmsg, &raw mut send_list) };

    if !nonblocking {
        // SAFETY: the queue lock is not held here.
        unsafe { kmsg_more() };
    }

    // SAFETY: the list holds messages this call owns, not queued elsewhere.
    while let Some(queued) = unsafe { ipc_kmsg::dequeue(&raw mut send_list) } {
        // SAFETY: the message is live and held by the list.
        let count = unsafe { (*net_kmsg(queued)).packet_type.number() };
        // SAFETY: the message is live and this call owns it.
        unsafe { queued.init_network() };
        // SAFETY: the message is live and this call owns it.
        let header = unsafe { queued.header() };
        let size = p2round(
            size_of::<NetRcvMsg>() - size_of::<c_int>() - NET_RCV_MAX as usize
                + count as usize,
            size_of::<usize>(),
        );
        // SAFETY: the header is live and this call owns the message.
        unsafe {
            (*header).set_bits(MACH_MSG_TYPE_PORT_SEND);
            (*header).set_size(u32::try_from(size).unwrap_or(u32::MAX));
            (*header).set_local(0);
            (*header).set_id(NET_RCV_MSG_ID);
            queued.set_header_seqno(0);

            let msg = net_kmsg(queued);
            (*msg).header_type = HEADER_TYPE;
            (*msg).packet_type = MachMsgType::new(PACKET_TYPE.word(), count);
        }

        // SAFETY: the message is live and holds the destination right.
        if unsafe { ipc_mqueue::send(queued.as_ptr(), MACH_SEND_TIMEOUT, 0) }
            .is_ok()
        {
            let counter = if high_priority {
                &NET_KMSG_SEND_HIGH_HITS
            } else {
                &NET_KMSG_SEND_LOW_HITS
            };
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let counter = if high_priority {
                &NET_KMSG_SEND_HIGH_MISSES
            } else {
                &NET_KMSG_SEND_LOW_MISSES
            };
            counter.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the send failed, so this call still owns the
            // message.
            unsafe { ipc_kmsg::destroy(queued) };
        }
    }

    // SAFETY: this thread runs in kernel mode with `%gs` based.
    let _ = unsafe { spl::splimp() };
    NET_QUEUE_LOCK.lock();
    true
}

/// Delivers the queued network messages and clears the network AST.
///
/// # Safety
///
/// The caller must run this with interrupts enabled on the current CPU,
/// and only when [`AstReason::NETWORK`] was pending for it; this call clears
/// that reason itself through [`ast::off`].
pub(crate) unsafe fn ast() {
    NET_AST_TAKEN.fetch_add(1, Ordering::Relaxed);

    // SAFETY: this thread runs in kernel mode with `%gs` based.
    let s = unsafe { spl::splimp() };
    NET_QUEUE_LOCK.lock();
    // SAFETY: the lock is held, and `deliver` returns holding it.
    while unsafe { !*NET_THREAD_AWAKE.0.get() && deliver(true) } {}
    NET_QUEUE_LOCK.unlock();
    // SAFETY: `splsched()` only changes this CPU's mask from kernel
    // mode.
    let _ = unsafe { spl::splsched() };
    ast::off(cpu_id(), AstReason::NETWORK);
    // SAFETY: `s` is the mask this thread saved.
    let _ = unsafe { spl::splx(s) };
}

/// The receive thread body, which never returns.
///
/// # Safety
///
/// Must run only as the network receive thread's body, or as the
/// continuation [`thread_continue`] re-enters after a wait, holding no
/// spin lock.
unsafe fn thread_continue_inner() -> ! {
    loop {
        NET_THREAD_AWAKEN.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the receive thread may allocate.
        unsafe { kmsg_more() };

        // SAFETY: this thread runs in kernel mode with `%gs` based.
        let s = unsafe { spl::splimp() };
        NET_QUEUE_LOCK.lock();
        // SAFETY: the lock is held, and `deliver` returns holding it.
        while unsafe { deliver(false) } {}
        // SAFETY: the queue lock serializes the flag.
        unsafe { *NET_THREAD_AWAKE.0.get() = false };
        // SAFETY: the thread is not waiting on an event yet.
        unsafe {
            assert_wait(
                NonNull::new(NET_THREAD_AWAKE.0.get().cast::<c_void>()),
                0,
            );
        };
        NET_QUEUE_LOCK.unlock();
        // SAFETY: `s` is the mask this thread saved.
        let _ = unsafe { spl::splx(s) };

        // SAFETY: the current thread holds no spin lock and has set its wait
        // state.
        unsafe { thread_block(Some(thread_continue)) };
    }
}

/// The continuation form of [`thread_continue_inner`] that `thread_block()`
/// takes.
unsafe extern "C" fn thread_continue() {
    // SAFETY: the continuation re-enters the loop, which never returns.
    unsafe { thread_continue_inner() };
}

/// Becomes the network receive thread.
///
/// # Safety
///
/// Must run only once, as the dedicated network receive thread's entry
/// point; it never returns.
pub(crate) unsafe fn thread() -> ! {
    // SAFETY: this is the current thread's own entry, and it holds no thread
    // lock.
    unsafe { Thread::set_own_priority(0) };

    // SAFETY: this thread runs in kernel mode with `%gs` based.
    let s = unsafe { spl::splimp() };
    NET_QUEUE_LOCK.lock();
    // SAFETY: the queue lock serializes the flag.
    unsafe { *NET_THREAD_AWAKE.0.get() = false };
    // SAFETY: the thread is not waiting on an event yet.
    unsafe {
        assert_wait(
            NonNull::new(NET_THREAD_AWAKE.0.get().cast::<c_void>()),
            0,
        );
    };
    NET_QUEUE_LOCK.unlock();
    // SAFETY: `s` is the mask this thread saved.
    let _ = unsafe { spl::splx(s) };

    // SAFETY: the current thread holds no spin lock and has set its wait
    // state.
    unsafe { thread_block(Some(thread_continue)) };
    // SAFETY: the receive loop re-enters and never returns.
    unsafe { thread_continue_inner() }
}

/// The kernel-thread entry of [`thread`].
///
/// # Safety
///
/// Started once as the network thread; it never returns.
pub(crate) unsafe extern "C" fn net_thread() {
    unsafe { thread() };
}

/// The operator value of each old-filter operator.
const NETF_OP_NOP: u32 = 0;
const NETF_OP_EQ: u32 = 1;
const NETF_OP_LT: u32 = 2;
const NETF_OP_LE: u32 = 3;
const NETF_OP_GT: u32 = 4;
const NETF_OP_GE: u32 = 5;
const NETF_OP_AND: u32 = 6;
const NETF_OP_OR: u32 = 7;
const NETF_OP_XOR: u32 = 8;
const NETF_OP_COR: u32 = 9;
const NETF_OP_CAND: u32 = 10;
const NETF_OP_CNOR: u32 = 11;
const NETF_OP_CNAND: u32 = 12;
const NETF_OP_NEQ: u32 = 13;
const NETF_OP_LSH: u32 = 14;
const NETF_OP_RSH: u32 = 15;
const NETF_OP_ADD: u32 = 16;
const NETF_OP_SUB: u32 = 17;

/// Runs the old filter program of `infp` over the packet, returning whether it
/// accepts it.
///
/// # Safety
///
/// `infp` must point at a live receive port whose filter the filter setup
/// accepted, and `data`/`header` must be readable for the words the program
/// addresses.
pub(crate) unsafe fn net_do_filter(
    infp: *mut NetRcvPort,
    data: *const u8,
    data_count: c_uint,
    header: *const u8,
) -> bool {
    let mut stack = [0u32; NET_FILTER_STACK_DEPTH + 1];
    let mut sp = NET_FILTER_STACK_DEPTH;
    stack[sp] = 1;

    let words = (data_count / (size_of::<u16>() as c_uint)) as usize;
    let mut fp = unsafe { (*infp).filter.as_ptr().add(1) };
    let fpe = unsafe { (*infp).filter_end };
    let ranges = FilterRanges {
        data,
        words,
        header,
    };

    while fp < fpe {
        // SAFETY: `fp < fpe` keeps the read inside the filter array.
        let word = unsafe { *fp };
        // SAFETY: `fp < fpe`, so the advance stays in the array.
        fp = unsafe { fp.add(1) };
        let op = u32::from((word >> 10) & 0x3f);
        let raw = word & 0x3ff;
        // SAFETY: `fp` points into the live filter array and the data
        // ranges match their counts.
        let Some(arg) = (unsafe {
            filter_arg(raw, &stack, &mut sp, &mut fp, fpe, &ranges)
        }) else {
            return false;
        };

        if op == NETF_OP_NOP {
            sp -= 1;
            let Some(slot) = stack.get_mut(sp) else {
                return false;
            };
            *slot = arg;
            continue;
        }
        let Some(top) = stack.get_mut(sp) else {
            return false;
        };
        match op {
            NETF_OP_AND => *top &= arg,
            NETF_OP_OR => *top |= arg,
            NETF_OP_XOR => *top ^= arg,
            NETF_OP_EQ => *top = u32::from(*top == arg),
            NETF_OP_NEQ => *top = u32::from(*top != arg),
            NETF_OP_LT => *top = u32::from(*top < arg),
            NETF_OP_LE => *top = u32::from(*top <= arg),
            NETF_OP_GT => *top = u32::from(*top > arg),
            NETF_OP_GE => *top = u32::from(*top >= arg),
            NETF_OP_COR => {
                let value = *top;
                sp += 1;
                if value == arg {
                    return true;
                }
            }
            NETF_OP_CAND => {
                let value = *top;
                sp += 1;
                if value != arg {
                    return false;
                }
            }
            NETF_OP_CNOR => {
                let value = *top;
                sp += 1;
                if value == arg {
                    return false;
                }
            }
            NETF_OP_CNAND => {
                let value = *top;
                sp += 1;
                if value != arg {
                    return true;
                }
            }
            // The C shifted an `int` by the argument; the machine masks the
            // count, which is what `wrapping_shl`/`wrapping_shr` reproduce.
            NETF_OP_LSH => *top = top.wrapping_shl(arg),
            // The C shifted a signed `int`; the machine shifts the sign bit
            // in, which the `i32` round trip reproduces.
            NETF_OP_RSH => *top = (*top as i32).wrapping_shr(arg) as u32,
            NETF_OP_ADD => *top = top.wrapping_add(arg),
            NETF_OP_SUB => *top = top.wrapping_sub(arg),
            _ => (),
        }
    }
    stack.get(sp).is_some_and(|top| *top != 0)
}

/// The packet and header ranges `net_do_filter()` fetches its operands
/// from.
#[derive(Clone, Copy)]
struct FilterRanges {
    data: *const u8,
    words: usize,
    header: *const u8,
}

/// The C's push cases of `net_do_filter()`: the `arg` a raw filter word
/// contributes, or `None` for the C's failure return.
///
/// # Safety
///
/// `fp` must point into a live filter array ending at `fpe`; `ranges` must
/// hold a `data` readable for `words` words and a `header` readable for
/// `NET_HDR_WORDS` words.
unsafe fn filter_arg(
    raw: u16,
    stack: &[u32; NET_FILTER_STACK_DEPTH + 1],
    sp: &mut usize,
    fp: &mut *const u16,
    fpe: *const u16,
    ranges: &FilterRanges,
) -> Option<u32> {
    let mut arg = u32::from(raw);
    match raw {
        NETF_NOPUSH => {
            let &top = stack.get(*sp)?;
            arg = top;
            *sp += 1;
        }
        NETF_PUSHZERO => arg = 0,
        NETF_PUSHLIT => {
            if *fp >= fpe {
                return None;
            }
            // SAFETY: `*fp < fpe`, so the literal is in the array.
            arg = u32::from(unsafe { **fp });
            // SAFETY: `*fp < fpe`, so the advance stays in the array.
            *fp = unsafe { (*fp).add(1) };
        }
        NETF_PUSHIND => {
            let &top = stack.get(*sp)?;
            *sp += 1;
            if top >= ranges.words as u32 {
                return None;
            }
            // SAFETY: the index is below the `data` word count.
            arg = u32::from(unsafe {
                ranges.data.cast::<u16>().add(top as usize).read_unaligned()
            });
        }
        NETF_PUSHHDRIND => {
            let &top = stack.get(*sp)?;
            *sp += 1;
            if top >= NET_HDR_WORDS as u32 {
                return None;
            }
            // SAFETY: the index is below the header's word count.
            arg = u32::from(unsafe {
                ranges
                    .header
                    .cast::<u16>()
                    .add(top as usize)
                    .read_unaligned()
            });
        }
        _ => {
            if arg >= u32::from(NETF_PUSHSTK) {
                let index = (arg - u32::from(NETF_PUSHSTK)) as usize;
                let &value = stack.get(*sp + index)?;
                arg = value;
            } else if arg >= u32::from(NETF_PUSHHDR) {
                let index = (arg - u32::from(NETF_PUSHHDR)) as usize;
                // SAFETY: the index is below the header's word count.
                arg = u32::from(unsafe {
                    ranges.header.cast::<u16>().add(index).read_unaligned()
                });
            } else {
                let index =
                    arg.wrapping_sub(u32::from(NETF_PUSHWORD)) as usize;
                if index >= ranges.words {
                    return None;
                }
                // SAFETY: the index is below the `data` word count.
                arg = u32::from(unsafe {
                    ranges.data.cast::<u16>().add(index).read_unaligned()
                });
            }
        }
    }
    Some(arg)
}

/// Promotes `port` ahead of an equal-priority predecessor whose count lags by
/// more than the threshold.
///
/// # Safety
///
/// `list` must head the direction `flag` names, and `port` must be a live
/// receive port linked into it.
unsafe fn reorder_prio<A>(
    list: *mut TailQueue<'static, A>,
    port: *mut NetRcvPort,
    flag: u16,
    rcount: c_int,
) where
    A: tail_queue::Adapter<Node = NetRcvPort>,
{
    if unsafe { (*port).filter[0] } & flag == 0 {
        return;
    }
    let prevfp = {
        // SAFETY: the port is linked into this list, which is an interface's
        // head, in place and guarded by the caller's list lock.
        let mut cursor = unsafe {
            Pin::new_unchecked(&mut *list)
                .cursor_mut_from_ptr(NonNull::new_unchecked(port))
        };
        cursor.move_prev();
        // The predecessor is the list head or another port.
        let Some(prevfp) = cursor.current_ptr() else {
            return;
        };
        prevfp.as_ptr()
    };
    // SAFETY: the predecessor is a live port, as above.
    let equal = unsafe { (*port).priority == (*prevfp).priority };
    let behind = NET_FILTER_QUEUE_REORDER.load(Ordering::Relaxed) != 0
        // SAFETY: the predecessor is a live port, as above.
        && 100i32.wrapping_add(unsafe { (*prevfp).rcv_count }) < rcount;
    if equal && behind {
        // Swapping the adjacent pair moves the port before its predecessor.
        // SAFETY: the port is linked, and the removal keeps `prevfp`; the
        // caller's list lock guards the list.
        unsafe {
            Pin::new_unchecked(&mut *list)
                .remove_ptr(NonNull::new_unchecked(port));
            Pin::new_unchecked(&mut *list)
                .cursor_mut_from_ptr(NonNull::new_unchecked(prevfp))
                .insert_before_ptr(NonNull::new_unchecked(port));
        }
    }
}

/// Runs `kmsg` through the interface's filters and queues a copy per matching
/// receive port.
///
/// # Safety
///
/// `kmsg` must be a live message holding the interface pointer in its remote
/// port and a receive message header; `send_list` must be an empty queue the
/// caller owns; no interface lock may be held.
pub(crate) unsafe fn filter(kmsg: Kmsg, send_list: *mut IpcKmsgQueue) {
    let count = unsafe { (*net_kmsg(kmsg)).packet_type.number() as c_int };
    // SAFETY: the sender stored the interface pointer in the remote port.
    let ifp = unsafe { kmsg.remote_port() as *mut IfNet };
    unsafe { (*send_list).base = ptr::null_mut() };

    let sent = unsafe { (*net_kmsg(kmsg)).sent != 0 };

    let mut dead_infp = pin!(NetInputList::new());
    let mut dead_entp = pin!(NetHashBucket::new());

    unsafe {
        (*ifp).if_rcv_port_list_lock.lock();
        (*ifp).if_snd_port_list_lock.lock();
    }

    {
        let mut ctx = DeliveryCtx {
            ifp,
            kmsg,
            send_list,
            dead_infp: dead_infp.as_mut(),
            dead_entp: dead_entp.as_mut(),
        };

        // SAFETY: both heads are initialized lists of live ports, and the
        // message's direction names one of them.
        if sent {
            unsafe {
                filter_ports(
                    &raw mut (*ifp).if_snd_port_list,
                    count,
                    &mut ctx,
                );
            }
        } else {
            unsafe {
                filter_ports(
                    &raw mut (*ifp).if_rcv_port_list,
                    count,
                    &mut ctx,
                );
            }
        }
    }

    // SAFETY: this call holds both interface list locks.
    unsafe {
        (*ifp).if_snd_port_list_lock.unlock();
        (*ifp).if_rcv_port_list_lock.unlock();
    }

    if !dead_infp.is_empty() {
        // SAFETY: the list holds the ports this call unlinked.
        unsafe { free_dead_infp(dead_infp.as_mut()) };
    }
    if !dead_entp.is_empty() {
        // SAFETY: the list holds the entries this call unlinked.
        unsafe { free_dead_entp(dead_entp.as_mut()) };
    }

    if unsafe { (*send_list).base.is_null() } {
        // SAFETY: no receiver took the message, so this call recycles it.
        unsafe { kmsg_put(kmsg.as_ptr()) };
    }
}

/// Walk one interface port list and deliver `kmsg` to each matching port.
///
/// # Safety
///
/// `list` must head the interface list the message's direction names, both
/// interface list locks must be held, and `ctx` must carry the live message
/// and its owned dead lists.
unsafe fn filter_ports<A>(
    list: *mut TailQueue<'static, A>,
    count: c_int,
    ctx: &mut DeliveryCtx<'_>,
) where
    A: tail_queue::Adapter<Node = NetRcvPort>,
{
    // SAFETY: the list head is initialized and its links are ports.
    let mut rcv_port = unsafe { (*list).cursor_front().current_ptr() };
    while let Some(current) = rcv_port {
        let current = current.as_ptr();
        // The body can unlink `current`, so the next port is read first. No
        // cursor outlives this read: the body reaches the list again.
        let nextfp = {
            // SAFETY: `current` is a live port on the list, which is an
            // interface's head, in place and guarded by the list locks.
            let mut cursor = unsafe {
                Pin::new_unchecked(&mut *list)
                    .cursor_mut_from_ptr(NonNull::new_unchecked(current))
            };
            cursor.move_next();
            cursor.current_ptr()
        };

        // SAFETY: `current` is a live port on the list.
        let (ret_count, dest, entp, hash_headp) =
            unsafe { match_filter(current, ctx.ifp, ctx.kmsg, count) };

        if ret_count != 0
            // SAFETY: `dest` is the port the filter selected and `entp` the
            // live entry a match named, if any; both list locks are held.
            && unsafe {
                deliver_port(ctx, current, dest, ret_count, entp, hash_headp)
            }
        {
            break;
        }

        rcv_port = nextfp;
    }
}

/// The filter of one receive port, run over `kmsg`: the delivery count and
/// destination it selects, and the hash entry and bucket a match named.
///
/// # Safety
///
/// `rcv_port` must be a live receive port on a locked list, `ifp` its live
/// interface, and `kmsg` the live message being filtered.
unsafe fn match_filter(
    rcv_port: *mut NetRcvPort,
    ifp: *mut IfNet,
    kmsg: Kmsg,
    count: c_int,
) -> (c_uint, *mut c_void, *mut NetHashEntry, *mut NetHashBucket) {
    let mut entp: *mut NetHashEntry = ptr::null_mut();
    let mut hash_headp: *mut NetHashBucket = ptr::null_mut();
    let (ret_count, dest) =
        // SAFETY: `rcv_port` is a live port on the list.
        if unsafe { (*rcv_port).filter[0] & NETF_TYPE_MASK } == NETF_BPF {
            let wirelen = count
                .wrapping_sub(size_of::<PacketHeader>() as c_int)
                as c_uint;
            let ret = unsafe {
                do_filter(
                    rcv_port,
                    (*net_kmsg(kmsg))
                        .packet
                        .as_ptr()
                        .add(size_of::<PacketHeader>()),
                    wirelen,
                    (*net_kmsg(kmsg)).header.as_ptr().cast::<u8>(),
                    c_int::from((*ifp).if_header_size) as c_uint,
                    &raw mut hash_headp,
                    &raw mut entp,
                )
            };
            let count = if ret != 0 {
                ret as c_uint + size_of::<PacketHeader>() as c_uint
            } else {
                0
            };
            let dest = if entp.is_null() {
                unsafe { (*rcv_port).rcv_port }
            } else {
                // SAFETY: a match instruction selected this live entry.
                unsafe { (*entp).rcv_port }
            };
            (count, dest)
        } else {
            let hit = unsafe {
                net_do_filter(
                    rcv_port,
                    (*net_kmsg(kmsg)).packet.as_ptr(),
                    count as c_uint,
                    (*net_kmsg(kmsg)).header.as_ptr().cast::<u8>(),
                )
            };
            let count = if hit { count as c_uint } else { 0 };
            (count, unsafe { (*rcv_port).rcv_port })
        };
    (ret_count, dest, entp, hash_headp)
}

/// The per-call context `filter()` carries through each port's delivery.
struct DeliveryCtx<'a> {
    ifp: *mut IfNet,
    kmsg: Kmsg,
    send_list: *mut IpcKmsgQueue,
    dead_infp: Pin<&'a mut NetInputList>,
    dead_entp: Pin<&'a mut NetHashBucket>,
}

/// Deliver a matching `kmsg` to `dest`, or unlink the port whose right to
/// receive it is dead.
///
/// Returns `true` when the caller must stop walking the port list, as the C
/// `break` did.
///
/// # Safety
///
/// Both interface list locks must be held; `ctx` must hold a live interface,
/// message and send list, `rcv_port` must be live, `dest` the port the
/// filter selected, and `entp` a live hash entry when it is not null.
unsafe fn deliver_port(
    ctx: &mut DeliveryCtx<'_>,
    rcv_port: *mut NetRcvPort,
    dest: *mut c_void,
    ret_count: c_uint,
    entp: *mut NetHashEntry,
    hash_headp: *mut NetHashBucket,
) -> bool {
    // SAFETY: the filter selected `dest`, a port the filter owns a right to.
    let dest = unsafe { ipc_port::copy_send(dest) };
    if IpcPort::valid(dest).is_none() {
        if entp.is_null() {
            // SAFETY: the port is live.
            if unsafe { (*rcv_port).filter[0] } & NETF_IN != 0 {
                // SAFETY: the port is linked into the receive list, and the
                // caller holds its lock.
                unsafe {
                    rcv_list(ctx.ifp)
                        .remove_ptr(NonNull::new_unchecked(rcv_port));
                }
            }
            // SAFETY: the port is live.
            if unsafe { (*rcv_port).filter[0] } & NETF_OUT != 0 {
                // SAFETY: the port is linked into the send list, and the caller
                // holds its lock.
                unsafe {
                    snd_list(ctx.ifp)
                        .remove_ptr(NonNull::new_unchecked(rcv_port));
                }
            }
            // SAFETY: the port is off both lists, so `input` was unlinked
            // here or left unlinked at creation; the dead list owns it now.
            unsafe {
                ctx.dead_infp
                    .as_mut()
                    .push_front_ptr(NonNull::new_unchecked(rcv_port));
            }
        } else {
            // SAFETY: the entry is linked into a live hash bucket.
            unsafe {
                hash_ent_remove(
                    ctx.ifp,
                    port_hash_header(rcv_port),
                    false,
                    hash_headp,
                    entp,
                    ctx.dead_entp.as_mut(),
                );
            }
        }
        return false;
    }

    let new_kmsg;
    if unsafe { (*ctx.send_list).base.is_null() } {
        new_kmsg = ctx.kmsg;
    } else {
        // SAFETY: the receive path may allocate a copy.
        let Some(allocated) = (unsafe { kmsg_get() }) else {
            if let Some(dest) = IpcPort::valid(dest) {
                // SAFETY: `dest` holds the copy `copy_send()` made.
                unsafe { ipc_port::release_send(dest) };
            }
            return true;
        };
        new_kmsg = allocated;
        // SAFETY: both messages are live, and the copied range is the
        // packet bytes and the header the source owns.
        unsafe {
            ptr::copy_nonoverlapping(
                (*net_kmsg(ctx.kmsg)).packet.as_ptr(),
                (*net_kmsg(new_kmsg)).packet.as_mut_ptr(),
                ret_count as usize,
            );
            ptr::copy_nonoverlapping(
                (*net_kmsg(ctx.kmsg)).header.as_ptr(),
                (*net_kmsg(new_kmsg)).header.as_mut_ptr(),
                NET_HDW_HDR_MAX,
            );
        }
    }
    // SAFETY: the message is live and this call owns it.
    unsafe {
        (*net_kmsg(new_kmsg)).packet_type.set_number(ret_count);
        new_kmsg.set_remote_port(dest.addr());
    }
    // SAFETY: the list holds messages this call owns.
    unsafe { ipc_kmsg::enqueue(ctx.send_list, new_kmsg) };

    // SAFETY: the port is live.
    let rcount = unsafe { (*rcv_port).rcv_count.wrapping_add(1) };
    unsafe { (*rcv_port).rcv_count = rcount };
    // SAFETY: the port is live.
    if unsafe { (*rcv_port).priority } >= NET_HI_PRI {
        // The C examined both chains; a port is only linked into the lists
        // its filter flags name.
        // SAFETY: the port is live and held by the list locks.
        unsafe {
            reorder_prio(
                &raw mut (*ctx.ifp).if_snd_port_list,
                rcv_port,
                NETF_OUT,
                rcount,
            );
        }
        unsafe {
            reorder_prio(
                &raw mut (*ctx.ifp).if_rcv_port_list,
                rcv_port,
                NETF_IN,
                rcount,
            );
        }
        return true;
    }

    false
}

/// Unlinks `entp` from `bucket` and moves it to `dead`; when it was the last
/// entry of `hp` and nothing else uses `hp`, also takes `hp` off the
/// interface's lists and returns `true`.
///
/// # Safety
///
/// `hp` and `entp` must be live filter structures, `bucket` the bucket
/// `entp` is linked into, both interface list locks must be held, and `dead`
/// a list this call owns.
pub(crate) unsafe fn hash_ent_remove(
    ifp: *mut IfNet,
    hp: *mut NetHashHeader,
    used: bool,
    bucket: *mut NetHashBucket,
    entp: *mut NetHashEntry,
    mut dead: Pin<&mut NetHashBucket>,
) -> bool {
    unsafe { (*hp).ref_count -= 1 };

    // The entry is alone in its bucket when it is the first and has no
    // successor.
    // SAFETY: the entry is linked into the bucket, which the caller guards.
    let only = unsafe {
        let first = (*bucket)
            .front()
            .is_some_and(|front| ptr::eq(front, entp.cast_const()));
        first && (*bucket).cursor_front().peek_next().is_none()
    };
    // SAFETY: the entry is linked into the bucket, and the caller's list
    // locks keep anything else from reaching it.
    unsafe { NetHashBucket::remove_ptr(NonNull::new_unchecked(entp)) };

    // The C cleaned the header's port up only when the bucket held just the
    // removed entry.
    let unused = only && unsafe { (*hp).ref_count == 0 } && !used;
    if unused {
        let port = hp.cast::<NetRcvPort>();
        // SAFETY: the header shares the port's storage and is live; the
        // caller holds both interface list locks.
        unsafe {
            if (*port).filter[0] & NETF_IN != 0 {
                rcv_list(ifp).remove_ptr(NonNull::new_unchecked(port));
            }
            if (*port).filter[0] & NETF_OUT != 0 {
                snd_list(ifp).remove_ptr(NonNull::new_unchecked(port));
            }
            (*hp).n_keys = 0;
        }
    }

    // SAFETY: the entry is off its bucket and `dead` is this call's.
    unsafe { dead.as_mut().push_front_ptr(NonNull::new_unchecked(entp)) };
    unused
}

/// Gives back the pool share of a removed receive port with queue limit
/// `qlimit`.
///
/// # Safety
///
/// `qlimit` must be the value `add_q_info()` returned for this filter.
unsafe fn del_q_info(qlimit: c_int) {
    NET_KMSG_TOTAL_LOCK.lock();
    NET_QUEUE_FREE_MIN.fetch_sub(1, Ordering::Relaxed);
    NET_KMSG_MAX.fetch_sub(qlimit.wrapping_add(1), Ordering::Relaxed);
    NET_KMSG_TOTAL_LOCK.unlock();
}

/// Frees the dead receive ports in `dead`, releasing their rights.
///
/// # Safety
///
/// `dead` must be a list of receive ports this call unlinked through
/// `input`, and no lock may be held.
pub(crate) unsafe fn free_dead_infp(mut dead: Pin<&mut NetInputList>) {
    while let Some(infp) = dead.as_mut().cursor_front_mut().remove_current() {
        let infp = ptr::from_mut(infp);
        // SAFETY: the port is live.
        if let Some(port) = IpcPort::valid(unsafe { (*infp).rcv_port }) {
            // SAFETY: the filter owns one send right to the port.
            unsafe { ipc_port::release_send(port) };
        }
        // SAFETY: the port is live.
        let qlimit = unsafe { (*infp).rcv_qlimit };
        unsafe { del_q_info(qlimit) };
        // SAFETY: the port is a live allocation of the cache.
        unsafe {
            (*rcv_cache()).free(NonNull::new_unchecked(infp.cast::<u8>()));
        }
    }
}

/// Frees the dead hash entries in `dead`, releasing their rights.
///
/// # Safety
///
/// `dead` must be a list of hash entries this call unlinked through `chain`,
/// and no lock may be held.
pub(crate) unsafe fn free_dead_entp(mut dead: Pin<&mut NetHashBucket>) {
    while let Some(entp) = dead.as_mut().cursor_front_mut().remove_current() {
        let entp = ptr::from_mut(entp);
        // SAFETY: the entry is live.
        if let Some(port) = IpcPort::valid(unsafe { (*entp).rcv_port }) {
            // SAFETY: the filter owns one send right to the port.
            unsafe { ipc_port::release_send(port) };
        }
        // SAFETY: the entry is live.
        let qlimit = unsafe { (*entp).rcv_qlimit };
        unsafe { del_q_info(qlimit) };
        // SAFETY: the entry is a live allocation of the cache.
        unsafe {
            (*hash_entry_cache())
                .free(NonNull::new_unchecked(entp.cast::<u8>()));
        }
    }
}

/// Creates the caches and the free pool, and sizes the message buffers.
///
/// # Safety
///
/// Must run once, during device initialization before the network thread
/// starts and before any other code touches this module's statics.
pub(crate) unsafe fn init() {
    // SAFETY: the caches are static storage no thread can see yet.
    unsafe {
        (*rcv_cache()).init(
            b"net_rcv_port",
            size_of::<NetRcvPort>(),
            0,
            None,
            CacheInitFlags::from_bits(0),
        );
    }
    unsafe {
        (*hash_entry_cache()).init(
            b"net_hash_entry",
            size_of::<NetHashEntry>(),
            0,
            None,
            CacheInitFlags::from_bits(0),
        );
    }

    let size = ikm_plus_overhead(size_of::<NetRcvMsg>());
    NET_KMSG_SIZE
        .store(crate::vm::vm_map::round_page(size), Ordering::Relaxed);

    NET_KMSG_TOTAL_LOCK.init();
    if NET_KMSG_MAX.load(Ordering::Relaxed) == 0 {
        NET_KMSG_MAX.store(
            NET_QUEUE_FREE_MIN.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    NET_QUEUE_FREE_LOCK.init();
    // SAFETY: this call owns the queues before threads start.
    unsafe { (*queue_free()).base = ptr::null_mut() };

    NET_QUEUE_LOCK.init();
    unsafe {
        (*queue_high()).base = ptr::null_mut();
        (*queue_low()).base = ptr::null_mut();
    }

    NET_HASH_HEADER_LOCK.init();
}
