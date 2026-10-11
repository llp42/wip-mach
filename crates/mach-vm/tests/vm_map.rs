// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! VM maps over the fake platform.

use mach_fake::{Fake, PMAPS};
use mach_vm::platform::Platform;
use mach_vm::vm_map::VmMap;

#[test]
fn the_last_reference_to_an_empty_map_frees_its_pmap() {
    // SAFETY: the fake pmaps need no setup.
    let pmap = unsafe { Fake::pmap_create(0) };
    let map = VmMap::<Fake>::create(pmap, 0x1000, 0x10_0000).unwrap();
    // SAFETY: the map is fresh and only this test holds it.
    let header = unsafe { &(*map.as_ptr()).hdr };
    assert_eq!(header.nentries, 0);
    assert_eq!(header.links.start, 0x1000);
    assert_eq!(header.links.end, 0x10_0000);

    VmMap::deallocate(map);
    PMAPS.with(|pmaps| {
        assert_eq!(pmaps.created.get(), 1);
        assert_eq!(pmaps.destroyed.get(), 1);
    });
}
