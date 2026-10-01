// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The adapter trait and the macro that implements it.

use super::Link;
use core::ptr::NonNull;

/// Maps a node type to the [`Link`] it embeds, and back, and to the key
/// that orders it.
///
/// Adapters are uninhabited types declared by
/// [`adapter!`](super::adapter); a tree names one as its type parameter
/// and never holds a value of it.
///
/// # Safety
///
/// `link` must return a pointer to a [`Link`] inside the node it is
/// given, at the same offset for every node, and `node` must invert it.
pub unsafe trait Adapter {
    /// The node type that embeds the link.
    type Node;

    /// The type that orders the nodes.
    type Key: Ord;

    /// Returns the link embedded in `node`.
    ///
    /// # Safety
    ///
    /// `node` must point at a live node.
    unsafe fn link(node: NonNull<Self::Node>) -> NonNull<Link>;

    /// Returns the node that embeds `link`.
    ///
    /// # Safety
    ///
    /// `link` must be the link of a live node.
    unsafe fn node(link: NonNull<Link>) -> NonNull<Self::Node>;

    /// Returns the key of `node`.
    ///
    /// The key of a linked node must not change: the tree finds nodes by
    /// comparing it, and a change leaves the node where its old key put
    /// it.
    fn key(node: &Self::Node) -> Self::Key;
}

/// Declares an [`Adapter`] for a node type, one of its link fields and
/// the key that orders it.
///
/// ```text
/// rb_tree::adapter!(
///     /// Orders a region by its first address.
///     pub(crate) RegionAdapter = Region { link } key(usize) = |region| region.start
/// );
/// ```
///
/// The field must have type [`Link`]; any other type fails to compile.
#[doc(hidden)]
#[macro_export]
macro_rules! __rb_tree_adapter {
    (
        $(#[$attr:meta])* $vis:vis $name:ident = $node:ty { $field:ident }
        key($key_type:ty) = |$key_node:ident| $key:expr
    ) => {
        $(#[$attr])*
        #[derive(Debug)]
        $vis enum $name {}

        // SAFETY: both directions step by the offset of the field, whose
        // type the binding in `link` pins to the tree's link.
        unsafe impl $crate::rb_tree::Adapter for $name {
            type Node = $node;
            type Key = $key_type;

            unsafe fn link(
                node: ::core::ptr::NonNull<$node>,
            ) -> ::core::ptr::NonNull<$crate::rb_tree::Link> {
                let link: *mut $crate::rb_tree::Link =
                    unsafe { &raw mut (*node.as_ptr()).$field };
                unsafe { ::core::ptr::NonNull::new_unchecked(link) }
            }

            unsafe fn node(
                link: ::core::ptr::NonNull<$crate::rb_tree::Link>,
            ) -> ::core::ptr::NonNull<$node> {
                let offset = ::core::mem::offset_of!($node, $field);
                unsafe { link.byte_sub(offset).cast::<$node>() }
            }

            fn key($key_node: &$node) -> $key_type {
                $key
            }
        }
    };
}
