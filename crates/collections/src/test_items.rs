// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The test item every shape links, and its adapters.

// The tests of every shape read and corrupt the item's fields directly.
#![expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "a test fixture shared by the shapes' test modules"
)]

use crate::{list, rb_tree, simple_queue, singly_list, tail_queue};
use core::ptr::NonNull;

/// A node that can sit on one structure of each shape at once.
#[derive(Debug)]
pub(crate) struct Item {
    pub(crate) value: u32,
    pub(crate) singly: singly_list::Link,
    pub(crate) list: list::Link,
    pub(crate) simple: simple_queue::Link,
    pub(crate) tail: tail_queue::Link,
    pub(crate) rb: rb_tree::Link,
}

impl Item {
    /// Returns an item holding `value`, on no structure.
    pub(crate) const fn new(value: u32) -> Self {
        Self {
            value,
            singly: singly_list::Link::new(),
            list: list::Link::new(),
            simple: simple_queue::Link::new(),
            tail: tail_queue::Link::new(),
            rb: rb_tree::Link::new(),
        }
    }
}

singly_list::adapter!(
    /// Links an item into a singly linked list.
    pub(crate) SinglyItem = Item { singly }
);

list::adapter!(
    /// Links an item into a list.
    pub(crate) ListItem = Item { list }
);

simple_queue::adapter!(
    /// Links an item into a simple queue.
    pub(crate) SimpleItem = Item { simple }
);

tail_queue::adapter!(
    /// Links an item into a tail queue.
    pub(crate) TailItem = Item { tail }
);

rb_tree::adapter!(
    /// Links an item into a red-black tree, ordered by its value.
    pub(crate) RbItem = Item { rb } key(u32) = |item| item.value
);

/// Returns one item per value, in one allocation that the tests never
/// grow, so every item keeps its address while it is linked.
pub(crate) fn items(values: &[u32]) -> Vec<Item> {
    values.iter().copied().map(Item::new).collect()
}

/// Returns an address to compare against or look a node up by; it
/// grants no access.
pub(crate) fn ptr(item: &Item) -> NonNull<Item> {
    NonNull::from(item)
}

/// Returns pointers that may link, read and write each item, for the
/// `_ptr` pushes and for tests that reach a linked node's link.
pub(crate) fn ptrs(items: &mut [Item]) -> Vec<NonNull<Item>> {
    items.iter_mut().map(NonNull::from).collect()
}

/// Returns the value of a node a structure handed back.
pub(crate) fn value(item: Option<&mut Item>) -> Option<u32> {
    Some(item?.value)
}
