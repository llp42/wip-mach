// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

// The three convenience macros the vendored reference uses, stood in for
// so it compiles on the host.  `likely` and `unlikely` are the branch
// hints the kernel's build gets from its own header; keeping them means
// the reference lays its branches out as it does in the kernel.

#ifndef RDXTREE_BENCH_MACROS_H
#define RDXTREE_BENCH_MACROS_H

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define likely(expr) __builtin_expect(!!(expr), 1)
#define unlikely(expr) __builtin_expect(!!(expr), 0)

#endif /* RDXTREE_BENCH_MACROS_H */
