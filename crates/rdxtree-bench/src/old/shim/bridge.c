// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

// The benchmark's way in to the vendored reference.
//
// Half of the reference's API is `static inline` in its headers, so it
// has no symbol to call and nothing to declare on the Rust side.  These
// wrappers give each of those one, so the benchmark's foreign functions
// are all ordinary calls.  Every other entry point is already a symbol
// and is declared directly.
//
// The assertions below pin the two structures the benchmark mirrors in
// Rust.  The key's width is asserted on its own because the structures
// are the same size either way: a 64-bit key hides in the padding a
// 32-bit one leaves, so the mirror would go on type-checking while every
// key crossed the boundary wrong.

#include <stddef.h>
#include <rdxtree.h>

#ifndef RDXTREE_KEY_32
#error "the reference is built with 32-bit keys, as the kernel builds it"
#endif

_Static_assert(sizeof(rdxtree_key_t) == sizeof(uint32_t),
               "a key is one 32-bit word");
_Static_assert(sizeof(struct rdxtree) == 16, "the Rust mirror is two words");
_Static_assert(offsetof(struct rdxtree, root) == 8,
               "the root pointer is the second word");
_Static_assert(sizeof(struct rdxtree_iter) == 16,
               "the Rust iterator mirror is a pointer and a key");
_Static_assert(offsetof(struct rdxtree_iter, key) == 8,
               "the iterator's key follows its node pointer");

void rdxtree_bench_init(struct rdxtree *tree)
{
    rdxtree_init(tree);
}

int rdxtree_bench_insert(struct rdxtree *tree, rdxtree_key_t key, void *ptr)
{
    return rdxtree_insert(tree, key, ptr);
}

int rdxtree_bench_insert_alloc(struct rdxtree *tree, void *ptr,
                               rdxtree_key_t *keyp)
{
    return rdxtree_insert_alloc(tree, ptr, keyp);
}

void *rdxtree_bench_lookup(const struct rdxtree *tree, rdxtree_key_t key)
{
    return rdxtree_lookup(tree, key);
}

void **rdxtree_bench_lookup_slot(const struct rdxtree *tree,
                                 rdxtree_key_t key)
{
    return rdxtree_lookup_slot(tree, key);
}

void rdxtree_bench_iter_init(struct rdxtree_iter *iter)
{
    rdxtree_iter_init(iter);
}
