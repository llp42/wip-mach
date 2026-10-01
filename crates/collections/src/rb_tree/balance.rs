// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The rebalancing of a red-black tree, on links alone.
//!
//! Nothing here reads a key or names a node type, so one copy serves
//! every tree.  A tree is its root link and the links below it: a missing
//! child is `None`, the root has no parent, and the root and every `None`
//! count as black.  The invariants are the usual ones: the root is black,
//! a red link has no red child, and every path from a link down to a
//! missing child crosses as many black links as any other.
//!
//! The fix-up rounds take the side they work on as a `bool`, and their
//! callers branch on it once and call the round with a literal: a branch
//! the predictor can follow lets the next loads start early, where a side
//! computed from data would make every load wait for the one before.
//!
//! Every function here is `unsafe` for one reason: each link it is given
//! or reaches must belong to a live node of one tree, whose root it is
//! given by the caller.

use super::{Link, Root};
use core::ptr::NonNull;

/// Returns the link `at` names.
///
/// # Safety
///
/// `at` must be the link of a live node.
#[inline]
const unsafe fn link_of<'tree>(at: NonNull<Link>) -> &'tree Link {
    unsafe { at.as_ref() }
}

/// Returns whether `link` is a missing child or a black link.
///
/// # Safety
///
/// `link` must be `None` or the link of a live node.
#[inline]
unsafe fn is_black(link: Option<NonNull<Link>>) -> bool {
    link.is_none_or(|at| unsafe { link_of(at) }.is_black())
}

/// Puts `new` where `old` is among the children of `parent`, or at the
/// root when `parent` is `None`.  `new`'s own parent word is not touched.
///
/// # Safety
///
/// `old` must be a child of `parent`, or the root when `parent` is
/// `None`.
#[inline]
unsafe fn replace_child(
    root: &mut Root,
    parent: Option<NonNull<Link>>,
    old: NonNull<Link>,
    new: Option<NonNull<Link>>,
) {
    match parent {
        None => *root = new,
        Some(above) => {
            let above_link = unsafe { link_of(above) };
            above_link
                .slot(above_link.right.get() == Some(old))
                .set(new);
        }
    }
}

/// Rotates `lower` down toward `toward`: its child on the other side takes
/// its place, and `lower` becomes that child's child on `toward`.  Colours
/// stay where they are.
///
/// # Safety
///
/// `lower` must have a child on the side opposite `toward`.
#[inline]
unsafe fn rotate(root: &mut Root, lower: NonNull<Link>, toward: bool) {
    let lower_link = unsafe { link_of(lower) };
    // SAFETY: the caller promised the child.
    let raised = unsafe { lower_link.slot(!toward).get().unwrap_unchecked() };
    let raised_link = unsafe { link_of(raised) };
    let between = raised_link.slot(toward).get();
    lower_link.slot(!toward).set(between);
    if let Some(moved) = between {
        unsafe { link_of(moved) }.set_parent(Some(lower));
    }
    let parent = lower_link.parent();
    raised_link.set_parent(parent);
    unsafe { replace_child(root, parent, lower, Some(raised)) };
    raised_link.slot(toward).set(Some(lower));
    lower_link.set_parent(Some(raised));
}

/// Restores the invariants after `leaf`, a new red leaf with its parent
/// and its slot in the parent already set, joined the tree.
///
/// # Panics
///
/// In debug builds, when the root is not black afterwards.
///
/// # Safety
///
/// `leaf` must be a red leaf of the tree rooted at `root`, and the rest
/// of the tree must hold the invariants.
pub(super) unsafe fn insert_color(root: &mut Root, leaf: NonNull<Link>) {
    let mut red = leaf;
    loop {
        let Some(parent) = (unsafe { link_of(red) }).parent() else {
            unsafe { link_of(red) }.set_black();
            break;
        };
        if unsafe { link_of(parent) }.is_black() {
            break;
        }
        // SAFETY: a red link is never the root, so it has a parent.
        let grand = unsafe { link_of(parent).parent().unwrap_unchecked() };
        let next = if unsafe { link_of(grand) }.right.get() == Some(parent) {
            unsafe { insert_round(root, red, parent, grand, true) }
        } else {
            unsafe { insert_round(root, red, parent, grand, false) }
        };
        match next {
            Some(up) => red = up,
            None => break,
        }
    }
    debug_assert!(
        unsafe { is_black(*root) },
        "rb tree: the root is not black after an insert",
    );
}

/// One round of the insert fix-up: `red` and its `parent` are both red,
/// and `parent` is the child of `grand` on the side `toward`.  Returns the
/// link to go on from, or `None` when the tree is whole again.
///
/// # Safety
///
/// As [`insert_color`], with `parent` and `grand` the links named.
#[inline]
unsafe fn insert_round(
    root: &mut Root,
    red: NonNull<Link>,
    parent: NonNull<Link>,
    grand: NonNull<Link>,
    toward: bool,
) -> Option<NonNull<Link>> {
    let parent_link = unsafe { link_of(parent) };
    let grand_link = unsafe { link_of(grand) };
    let uncle = grand_link.slot(!toward).get();
    if !unsafe { is_black(uncle) } {
        // SAFETY: a red uncle is a link, not a missing child.
        unsafe { link_of(uncle.unwrap_unchecked()) }.set_black();
        parent_link.set_black();
        grand_link.set_red();
        return Some(grand);
    }
    let top = if parent_link.slot(!toward).get() == Some(red) {
        unsafe { rotate(root, parent, toward) };
        red
    } else {
        parent
    };
    unsafe { rotate(root, grand, !toward) };
    unsafe { link_of(top) }.set_black();
    grand_link.set_red();
    None
}

/// Unlinks `node` from the tree rooted at `root` and restores the
/// invariants.  A node with two children is replaced by its successor,
/// which is relinked into its place: no node moves, so every pointer to
/// another node stays valid.
///
/// # Panics
///
/// In debug builds, when the root is not black afterwards.
///
/// # Safety
///
/// `node` must be a link of the tree rooted at `root`.
pub(super) unsafe fn erase(root: &mut Root, node: NonNull<Link>) {
    let link = unsafe { link_of(node) };
    let (low, high) = (link.left.get(), link.right.get());
    let removed_black;
    let child;
    let parent;
    if let (Some(left), Some(right)) = (low, high) {
        // The successor is the leftmost link below `right`.
        let mut successor = right;
        while let Some(next) = unsafe { link_of(successor) }.left.get() {
            successor = next;
        }
        let succ_link = unsafe { link_of(successor) };
        removed_black = succ_link.is_black();
        child = succ_link.right.get();
        if successor == right {
            parent = Some(successor);
        } else {
            // SAFETY: a link below `right` but not `right` has a parent.
            let old_parent = unsafe { succ_link.parent().unwrap_unchecked() };
            parent = Some(old_parent);
            unsafe { link_of(old_parent) }.left.set(child);
            if let Some(moved) = child {
                unsafe { link_of(moved) }.set_parent(Some(old_parent));
            }
            succ_link.right.set(Some(right));
            unsafe { link_of(right) }.set_parent(Some(successor));
        }
        let node_parent = link.parent();
        unsafe { replace_child(root, node_parent, node, Some(successor)) };
        succ_link.set_parent(node_parent);
        succ_link.set_color(link.is_black());
        succ_link.left.set(Some(left));
        unsafe { link_of(left) }.set_parent(Some(successor));
    } else {
        removed_black = link.is_black();
        child = low.or(high);
        parent = link.parent();
        unsafe { replace_child(root, parent, node, child) };
        if let Some(moved) = child {
            unsafe { link_of(moved) }.set_parent(parent);
        }
    }
    if removed_black {
        unsafe { erase_color(root, child, parent) };
    }
    debug_assert!(
        unsafe { is_black(*root) },
        "rb tree: the root is not black after a removal",
    );
}

/// Restores the invariants after a black link left the tree: `short`, the
/// link that took its place, or a missing child, is one black link short
/// on every path through it.  `above` is its parent.
///
/// # Safety
///
/// `short` must be `None` or a link of the tree rooted at `root`, with
/// parent `above`, and the tree must hold the invariants except for the
/// black link missing above `short`.
unsafe fn erase_color(
    root: &mut Root,
    short: Option<NonNull<Link>>,
    above: Option<NonNull<Link>>,
) {
    let mut short_at = short;
    let mut above_at = above;
    loop {
        if let Some(red) = short_at
            && !unsafe { link_of(red) }.is_black()
        {
            unsafe { link_of(red) }.set_black();
            return;
        }
        let Some(parent) = above_at else {
            return;
        };
        // The short link is on this side of `parent`; a missing one is the
        // empty slot.
        let carries_on = if unsafe { link_of(parent) }.right.get() == short_at
        {
            unsafe { erase_round(root, parent, true) }
        } else {
            unsafe { erase_round(root, parent, false) }
        };
        if !carries_on {
            return;
        }
        short_at = Some(parent);
        above_at = unsafe { link_of(parent) }.parent();
    }
}

/// One round of the removal fix-up: the child of `parent` on the side
/// `side` is one black link short.  Returns whether the shortage moved up
/// to `parent`.
///
/// # Safety
///
/// As [`erase_color`], with `parent` the parent of the short child.
#[inline]
unsafe fn erase_round(
    root: &mut Root,
    parent: NonNull<Link>,
    side: bool,
) -> bool {
    let parent_link = unsafe { link_of(parent) };
    // SAFETY: the short side is a black link short, so the other side is
    // not empty.
    let mut sibling =
        unsafe { parent_link.slot(!side).get().unwrap_unchecked() };
    if !unsafe { link_of(sibling) }.is_black() {
        unsafe { link_of(sibling) }.set_black();
        parent_link.set_red();
        unsafe { rotate(root, parent, side) };
        // SAFETY: the old sibling had children, being red with a black
        // link to spare on each side.
        sibling = unsafe { parent_link.slot(!side).get().unwrap_unchecked() };
    }
    let near = unsafe { link_of(sibling) }.slot(side).get();
    let far = unsafe { link_of(sibling) }.slot(!side).get();
    if unsafe { is_black(near) && is_black(far) } {
        unsafe { link_of(sibling) }.set_red();
        return true;
    }
    if unsafe { is_black(far) } {
        // SAFETY: the sibling has a child, and it is not the far one.
        unsafe { link_of(near.unwrap_unchecked()) }.set_black();
        unsafe { link_of(sibling) }.set_red();
        unsafe { rotate(root, sibling, !side) };
        sibling = unsafe { parent_link.slot(!side).get().unwrap_unchecked() };
    }
    let sibling_link = unsafe { link_of(sibling) };
    sibling_link.set_color(parent_link.is_black());
    parent_link.set_black();
    // SAFETY: the far child is red, so it is a link.
    let far_red = unsafe { sibling_link.slot(!side).get().unwrap_unchecked() };
    unsafe { link_of(far_red) }.set_black();
    unsafe { rotate(root, parent, side) };
    false
}

/// Returns the link after `at` when `toward` is `RIGHT`, the link before
/// it when `toward` is `LEFT`; `None` past the end.
///
/// # Safety
///
/// `at` must be a link of a tree.
pub(super) unsafe fn step(
    at: NonNull<Link>,
    toward: bool,
) -> Option<NonNull<Link>> {
    if let Some(below) = unsafe { link_of(at) }.slot(toward).get() {
        return unsafe { extreme(Some(below), !toward) };
    }
    let mut from = at;
    loop {
        let parent = unsafe { link_of(from) }.parent()?;
        if unsafe { link_of(parent) }.slot(!toward).get() == Some(from) {
            return Some(parent);
        }
        from = parent;
    }
}

/// Returns the first link below `top`, including it, in the direction
/// `toward`: the leftmost for `LEFT`, the rightmost for `RIGHT`.
///
/// # Safety
///
/// `top` must be `None` or a link of a tree.
pub(super) unsafe fn extreme(
    top: Option<NonNull<Link>>,
    toward: bool,
) -> Option<NonNull<Link>> {
    let mut at = top?;
    while let Some(next) = unsafe { link_of(at) }.slot(toward).get() {
        at = next;
    }
    Some(at)
}
