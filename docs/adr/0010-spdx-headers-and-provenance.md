# SPDX headers and provenance

Every source file starts with an SPDX license line and one
`SPDX-FileCopyrightText` line per copyright holder, never a
`Copyright (c)` comment:

```
// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
```

A crate's license follows its content:

- a crate designed from the literature is `MIT` — `lock`, `clock`,
  `collections`, `kmem` — and takes derived code only from an
  MIT-licensed upstream (ADR 0053);
- a crate that carries derived code under any other licence is
  `GPL-2.0-or-later` for its original files — `kernel`, `wip-mach`,
  `mach-mig-sys`.

`collections` goes further: its shapes are the classic kernel queue
shapes and its operation names come from `std::collections::LinkedList`,
but it names no upstream anywhere — not BSD, not `queue.h`, not its
macro names.

A file derived from pre-existing code keeps that code's license
identifier and is never relicensed (e.g. `CMU-Mach` for code ported
from the Mach sources, `BSD-2-Clause` for code taken from a BSD
source). Its header lists the upstream holders first, spelled as
upstream spells them, the contributor last, then pins the source after
a blank comment line:

```
// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2023 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: i386/i386/percpu.c and i386/i386/percpu.h
```

A blank comment line opens the provenance. `Derived from` names the
upstream project pinned at the commit the code was taken from, and
`original files:` merges every upstream file into one comma-separated
list (` and ` before the last), spelled as upstream spells it.

That provenance header is the only place naming the upstream sources:
no upstream source paths (`.c`, `.h`, `.S`) and no upstream internal
names in docs or comments, so the code may change shape without
answering to the upstream layout. ABI names are not upstream internal
names: they are the contract ADR 0002 binds, and docs and code cite
them freely. ADRs are exempt from the ban where their reasoning
measures GNU Mach, the behaviour reference (ADR 0013), as "82% of GNU
Mach's lock sites" can only be said by naming what was counted; the
ban covers code, comments, READMEs and the glossary.

Non-copyrightable files (JSON, data) are exempt. License texts live in
`LICENCES/`. ADR and other root `docs/` records are notes, not source,
and carry no SPDX header.

## Consequences

- Relegating attribution to a `Copyright (c)` comment or a README is
  not enough: the header is per file, machine-readable, and the
  provenance pins the exact upstream commit.
- A PR that relocates upstream-derived code must keep the provenance
  block and must not start naming upstream files in prose.
- Derived code moves into an MIT crate only from an MIT-licensed
  upstream (ADR 0053); any other derived code stays in a GPL crate.
