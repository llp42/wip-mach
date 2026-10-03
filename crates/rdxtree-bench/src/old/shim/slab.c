// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

// A node cache the vendored reference can allocate from on the host.
//
// The kernel's cache hands out fixed-size blocks and keeps what it is
// given back, so it never returns a block to the page allocator.  This
// one keeps the block in the cache's free list for the same reason: the
// benchmark times the tree, not the allocator, and a contender that had
// to call the host allocator for every node would be timed against one
// that did not.  Blocks are chained through their own first bytes, as a
// kernel free list chains them.

#include <assert.h>
#include <kern/slab.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/// Blocks handed out and not yet given back.
static unsigned long live_blocks;

void kmem_cache_init(struct kmem_cache *cache, const char *name, size_t size,
                     size_t align, void (*ctor)(void *), unsigned int flags)
{
    // The free list chains blocks through their own room for a pointer.
    assert(size >= sizeof(void *));

    cache->name = name;
    cache->size = size;
    // A cache with no declared alignment takes the one the host
    // allocator guarantees, as the kernel's default does.
    cache->align = align == 0 ? _Alignof(max_align_t) : align;
    cache->ctor = ctor;
    cache->flags = flags;
    cache->free_list = NULL;
}

vm_offset_t kmem_cache_alloc(struct kmem_cache *cache)
{
    void *block;

    if (cache->free_list != NULL) {
        block = cache->free_list;
        memcpy(&cache->free_list, block, sizeof(cache->free_list));
    } else {
        block = malloc(cache->size);
        if (block == NULL)
            return (vm_offset_t)0;
        assert((uintptr_t)block % cache->align == 0);
    }

    live_blocks++;
    return (vm_offset_t)block;
}

void kmem_cache_free(struct kmem_cache *cache, vm_offset_t obj)
{
    void *block = (void *)obj;

    memcpy(block, &cache->free_list, sizeof(cache->free_list));
    cache->free_list = block;
    live_blocks--;
}

unsigned long rdxtree_bench_live_blocks(void)
{
    return live_blocks;
}
