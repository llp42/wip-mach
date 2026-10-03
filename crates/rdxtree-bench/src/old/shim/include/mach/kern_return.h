// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

// The three results the vendored reference can return.  The kernel header
// defines about seventy more; the benchmark bridge reads a positive value
// as "the key was taken", so only the successes and the two failures the
// tree itself produces are needed.

#ifndef RDXTREE_BENCH_MACH_KERN_RETURN_H
#define RDXTREE_BENCH_MACH_KERN_RETURN_H

#define KERN_SUCCESS 0
#define KERN_INVALID_ARGUMENT 4
#define KERN_RESOURCE_SHORTAGE 6

#endif /* RDXTREE_BENCH_MACH_KERN_RETURN_H */
