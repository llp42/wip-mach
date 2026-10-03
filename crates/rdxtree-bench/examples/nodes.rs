// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Prints the node blocks each tree holds after a dense fill.
//!
//! Criterion times; it does not count.  This answers "does the MIT
//! rewrite use more nodes than the C it replaced?" by reading the
//! live-block counters the two node caches keep and printing the delta a
//! filled tree holds.

use core::ffi::c_void;
use core::ptr::NonNull;
use rdxtree_bench::{CTree, NewTree, Tree, c_live_blocks, host_live_blocks};

const SIZES: [usize; 4] = [64, 1024, 32768, 131072];

fn main() {
    let backing: Vec<u64> = vec![0; SIZES[SIZES.len() - 1]];
    let ptrs: Vec<NonNull<c_void>> = backing
        .iter()
        .map(|slot| NonNull::from(slot).cast::<c_void>())
        .collect();

    println!("{:>8}  {:>10}  {:>10}", "n", "c", "new");
    for &n in &SIZES {
        let old = {
            let base = c_live_blocks();
            let mut tree = CTree::new();
            for (i, &ptr) in ptrs.iter().take(n).enumerate() {
                assert!(tree.insert_named(i as u32, ptr));
            }
            let held = c_live_blocks() - base;
            drop(tree);
            held
        };
        let new = {
            let base = host_live_blocks();
            let mut tree = NewTree::new();
            for (i, &ptr) in ptrs.iter().take(n).enumerate() {
                assert!(tree.insert_named(i as u32, ptr));
            }
            let held = host_live_blocks() - base;
            drop(tree);
            held
        };
        println!("{n:>8}  {old:>10}  {new:>10}");
    }
}
