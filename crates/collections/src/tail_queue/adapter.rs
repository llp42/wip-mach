// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The adapter trait and the macro that implements it.

use super::Link;
use core::ptr::NonNull;

/// Maps a node type to the [`Link`] it embeds, and back.
///
/// Adapters are uninhabited types declared by
/// [`adapter!`](super::adapter); a queue names one as its type parameter
/// and never holds a value of it.
///
/// # Safety
///
/// `link` must return a pointer to a [`Link`] inside the node it is
/// given, at the same offset for every node, and `node` must invert it.
pub unsafe trait Adapter {
    /// The node type that embeds the link.
    type Node;

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
}

/// Declares an [`Adapter`] for a node type and one of its link fields.
///
/// ```text
/// tail_queue::adapter!(
///     /// Links a thread into its run queue.
///     pub(crate) ThreadAdapter = Thread { link }
/// );
/// ```
///
/// The field must have type [`Link`]; any other type fails to compile.
#[doc(hidden)]
#[macro_export]
macro_rules! __tail_queue_adapter {
    ($(#[$attr:meta])* $vis:vis $name:ident = $node:ty { $field:ident }) => {
        $(#[$attr])*
        #[derive(Debug)]
        $vis enum $name {}

        // SAFETY: both directions step by the offset of the field, whose
        // type the binding in `link` pins to the queue's link.
        unsafe impl $crate::tail_queue::Adapter for $name {
            type Node = $node;

            unsafe fn link(
                node: ::core::ptr::NonNull<$node>,
            ) -> ::core::ptr::NonNull<$crate::tail_queue::Link> {
                let link: *mut $crate::tail_queue::Link =
                    unsafe { &raw mut (*node.as_ptr()).$field };
                unsafe { ::core::ptr::NonNull::new_unchecked(link) }
            }

            unsafe fn node(
                link: ::core::ptr::NonNull<$crate::tail_queue::Link>,
            ) -> ::core::ptr::NonNull<$node> {
                let offset = ::core::mem::offset_of!($node, $field);
                unsafe { link.byte_sub(offset).cast::<$node>() }
            }
        }
    };
}
