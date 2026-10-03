// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

// Stands in for the kernel's assertion header so the vendored reference
// compiles on the host.  The benchmark builds with `NDEBUG`, so the
// assertions the kernel runs are the ones the contender has compiled out
// too; see `build.rs`.

#ifndef RDXTREE_BENCH_KERN_ASSERT_H
#define RDXTREE_BENCH_KERN_ASSERT_H

#include <assert.h>

#endif /* RDXTREE_BENCH_KERN_ASSERT_H */
