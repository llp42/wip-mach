// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Intrusive linked structures and a tree whose links live inside
//! caller-owned nodes, so no structure ever allocates or frees.
//!
//! Each shape lives in its own module, with its own link, adapter trait,
//! adapter macro, cursors and iterator; no shape shares code with
//! another.
//!
//! | shape | head | link | walk | O(1) removal of any node |
//! |---|---|---|---|---|
//! | [`singly_list::SinglyList`] | 1 word | 1 word | forward | no |
//! | [`list::List`] | 1 word | 2 words | forward | yes, without the head |
//! | [`simple_queue::SimpleQueue`] | 2 words | 1 word | forward | no |
//! | [`tail_queue::TailQueue`] | 2 words | 2 words | both ways | yes |
//! | [`rb_tree::RbTree`] | 3 words | 3 words | both ways, in key order | yes, no search |
//!
//! Every head carries the lifetime `'nodes` of the nodes they hold:
//! a push takes `&'nodes mut Node` and a removal hands the node back the same
//! way, so the borrow checker keeps a linked node alive, in place,
//! reached only through its structure, and on one structure at a time.
//! While linked, a node is reached as `&Node` only, since a `&mut Node`
//! would let safe code overwrite its link.  What stays `unsafe` is what
//! a lifetime cannot express: the `_ptr` pushes for nodes whose lifetime
//! is not `'nodes`, and operations that name a node by its address.  Heads
//! whose nodes point back into them — the list, the simple queue and the
//! tail queue — are pinned; the tree's head points only at nodes and is not.

#![no_std]

pub mod list;
pub mod rb_tree;
pub mod simple_queue;
pub mod singly_list;
pub mod tail_queue;

/// Declares the uninhabited type an `adapter!` names: an empty enum, or,
/// when the node is generic, a struct over its parameters that no value can
/// inhabit.
#[doc(hidden)]
#[macro_export]
macro_rules! __adapter_type {
    ($(#[$attr:meta])* $vis:vis $name:ident) => {
        $(#[$attr])*
        #[derive(Debug)]
        $vis enum $name {}
    };
    ($(#[$attr:meta])* $vis:vis $name:ident<$($param:ident),+>) => {
        $(#[$attr])*
        #[derive(Debug)]
        $vis struct $name<$($param),+>(
            ::core::convert::Infallible,
            ::core::marker::PhantomData<($($param,)+)>,
        );
    };
}
