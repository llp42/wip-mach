// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

// Stands in for the kernel's slab header so the vendored reference
// compiles on the host.  `struct kmem_cache` is complete rather than
// opaque because the reference defines one at file scope, and it is what
// this shim's implementation stores: the block size, the alignment, and
// the free list head.  `slab.c` fills it in.

#ifndef RDXTREE_BENCH_KERN_SLAB_H
#define RDXTREE_BENCH_KERN_SLAB_H

#include <stddef.h>

#ifndef RDXTREE_BENCH_VM_OFFSET_T
#define RDXTREE_BENCH_VM_OFFSET_T
typedef unsigned long vm_offset_t;
#endif

struct kmem_cache {
    const char *name;
    size_t size;
    size_t align;
    void (*ctor)(void *);
    unsigned int flags;
    void *free_list;
};

void kmem_cache_init(struct kmem_cache *cache, const char *name, size_t size,
                     size_t align, void (*ctor)(void *), unsigned int flags);
vm_offset_t kmem_cache_alloc(struct kmem_cache *cache);
void kmem_cache_free(struct kmem_cache *cache, vm_offset_t obj);

// How many blocks the caches hold outstanding, which is what the
// benchmark's node-count example reads around a fill.
unsigned long rdxtree_bench_live_blocks(void);

#endif /* RDXTREE_BENCH_KERN_SLAB_H */
