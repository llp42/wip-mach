// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `mach_port_*` calls on a space, over the fake platform.

use core::ffi::c_uint;
use mach_fake::Fake;
use mach_ipc::IpcSpace;
use mach_ipc::error::Error;
use mach_ipc::mach_port::{
    allocate, allocate_name, deallocate, destroy, port_type, set_ktype,
};
use mach_ipc::types::PortType;
use mach_ipc::{ipc_init, ipc_space};
use std::sync::Once;

/// `MACH_PORT_RIGHT_SEND`, a right no space holds alone.
const RIGHT_SEND: c_uint = 0;
/// `MACH_PORT_RIGHT_RECEIVE`.
const RIGHT_RECEIVE: c_uint = 1;
/// `MACH_PORT_RIGHT_PORT_SET`.
const RIGHT_PORT_SET: c_uint = 3;
/// `MACH_PORT_RIGHT_DEAD_NAME`.
const RIGHT_DEAD_NAME: c_uint = 4;

/// `MACH_PORT_KTYPE_NONE`.
const KTYPE_NONE: c_uint = 0;
/// `MACH_PORT_KTYPE_USER_DEVICE`.
const KTYPE_USER_DEVICE: c_uint = 28;

/// A fresh space, after IPC's boot setup has run once for the process.
fn space() -> IpcSpace {
    static BOOT: Once = Once::new();
    // SAFETY: `Once` runs the bootstrap once, before any space exists.
    BOOT.call_once(|| unsafe { ipc_init::ipc_bootstrap::<Fake>() });
    ipc_space::create::<Fake>().unwrap()
}

/// Destroys `space` and drops the two references `create` gave it.
fn finish(space: IpcSpace) {
    // SAFETY: the test owns the space and holds nothing locked.
    unsafe {
        ipc_space::destroy::<Fake>(space);
        ipc_space::release::<Fake>(space);
        ipc_space::release::<Fake>(space);
    }
}

#[test]
fn a_receive_right_lives_until_it_is_destroyed() {
    let space = space();
    // SAFETY: the space is live and unlocked.
    unsafe {
        let name = allocate::<Fake>(Some(space), RIGHT_RECEIVE).unwrap();
        assert_eq!(
            port_type::<Fake>(Some(space), name),
            Ok(PortType::RECEIVE)
        );
        destroy::<Fake>(Some(space), name).unwrap();
        assert_eq!(
            port_type::<Fake>(Some(space), name),
            Err(Error::InvalidName)
        );
    }
    finish(space);
}

#[test]
fn a_port_set_and_a_dead_name_take_their_types() {
    let space = space();
    // SAFETY: the space is live and unlocked.
    unsafe {
        let set = allocate::<Fake>(Some(space), RIGHT_PORT_SET).unwrap();
        let dead = allocate::<Fake>(Some(space), RIGHT_DEAD_NAME).unwrap();
        assert_ne!(set, dead);
        assert_eq!(
            port_type::<Fake>(Some(space), set),
            Ok(PortType::PORT_SET)
        );
        assert_eq!(
            port_type::<Fake>(Some(space), dead),
            Ok(PortType::DEAD_NAME)
        );
        deallocate::<Fake>(Some(space), dead).unwrap();
        assert_eq!(
            port_type::<Fake>(Some(space), dead),
            Err(Error::InvalidName)
        );
    }
    // The port set goes with the space.
    finish(space);
}

#[test]
fn a_chosen_name_is_taken_once() {
    let space = space();
    // SAFETY: the space is live and unlocked.
    unsafe {
        allocate_name::<Fake>(Some(space), RIGHT_RECEIVE, 0x77).unwrap();
        assert_eq!(
            allocate_name::<Fake>(Some(space), RIGHT_RECEIVE, 0x77),
            Err(Error::NameExists)
        );
        assert_eq!(
            port_type::<Fake>(Some(space), 0x77),
            Ok(PortType::RECEIVE)
        );
    }
    finish(space);
}

#[test]
fn rights_a_space_cannot_hold_alone_are_refused() {
    let space = space();
    // SAFETY: the space is live and unlocked.
    unsafe {
        assert_eq!(
            allocate::<Fake>(Some(space), RIGHT_SEND),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            allocate::<Fake>(Some(space), 99),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            allocate_name::<Fake>(Some(space), RIGHT_RECEIVE, 0),
            Err(Error::InvalidValue)
        );
    }
    finish(space);
}

#[test]
fn only_a_port_takes_a_kernel_object_type() {
    let space = space();
    // SAFETY: the space is live and unlocked.
    unsafe {
        let port = allocate::<Fake>(Some(space), RIGHT_RECEIVE).unwrap();
        assert_eq!(
            set_ktype::<Fake>(
                Some(space),
                port,
                RIGHT_RECEIVE,
                KTYPE_USER_DEVICE
            ),
            Ok(())
        );
        assert_eq!(
            set_ktype::<Fake>(Some(space), port, RIGHT_RECEIVE, KTYPE_NONE),
            Ok(())
        );

        // A port set is smaller than a port, so a kernel object written into
        // one lands past its end.
        let set = allocate::<Fake>(Some(space), RIGHT_PORT_SET).unwrap();
        assert_eq!(
            set_ktype::<Fake>(
                Some(space),
                set,
                RIGHT_PORT_SET,
                KTYPE_USER_DEVICE
            ),
            Err(Error::InvalidRight)
        );

        // A dead name has no object at all.
        let dead = allocate::<Fake>(Some(space), RIGHT_DEAD_NAME).unwrap();
        assert_eq!(
            set_ktype::<Fake>(Some(space), dead, RIGHT_DEAD_NAME, KTYPE_NONE),
            Err(Error::InvalidRight)
        );
    }
    finish(space);
}

#[test]
fn a_dead_space_holds_nothing() {
    // SAFETY: a null space is never dereferenced.
    unsafe {
        assert_eq!(
            allocate::<Fake>(None, RIGHT_RECEIVE),
            Err(Error::DeadSpace)
        );
        assert_eq!(port_type::<Fake>(None, 1), Err(Error::DeadSpace));
        assert_eq!(deallocate::<Fake>(None, 1), Err(Error::DeadSpace));
    }
}
