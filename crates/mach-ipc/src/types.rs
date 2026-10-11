// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! IPC's plain data: the option word a message call carries and the type
//! of a port right.

use core::ffi::c_uint;

bitflags::bitflags! {
    /// `mach_msg_option_t`: what a message call does and how it waits.
    ///
    /// The bits the kernel does not name pass through untouched, as the C
    /// ignored them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MsgOption: c_uint {
        /// Send a message.
        const SEND_MSG = 0x0000_0001;
        /// Receive a message.
        const RCV_MSG = 0x0000_0002;
        /// Give up the send after the timeout.
        const SEND_TIMEOUT = 0x0000_0010;
        /// Ask for a msg-accepted notification when the queue is full.
        const SEND_NOTIFY = 0x0000_0020;
        /// Cancel a msg-accepted request instead of sending.
        const SEND_CANCEL = 0x0000_0080;
        /// Give up the receive after the timeout.
        const RCV_TIMEOUT = 0x0000_0100;
        /// Name a reply destination in the notify name.
        const RCV_NOTIFY = 0x0000_0200;
        /// Report the needed size instead of discarding an oversized
        /// message.
        const RCV_LARGE = 0x0000_0800;
        /// The kernel's send, which ignores the queue limit.
        const SEND_ALWAYS = 0x0001_0000;
    }
}

bitflags::bitflags! {
    /// `mach_port_type_t`: the rights a name denotes, one bit per right, as
    /// `mach_port_type` reports them and an entry holds them.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PortType: u32 {
        /// A send right.
        const SEND = 1 << 16;
        /// A receive right.
        const RECEIVE = 1 << 17;
        /// A send-once right.
        const SEND_ONCE = 1 << 18;
        /// A port set.
        const PORT_SET = 1 << 19;
        /// A dead name.
        const DEAD_NAME = 1 << 20;
        /// The dummy bit reported for a pending msg-accepted request.
        const MAREQUEST = 0x4000_0000;
        /// The dummy bit reported for a dead-name request.
        const DNREQUEST = 0x8000_0000;
    }
}

impl PortType {
    /// No right.
    pub const NONE: Self = Self::empty();
    /// A send right and a receive right together.
    pub const SEND_RECEIVE: Self = Self::SEND.union(Self::RECEIVE);
    /// The rights that can send: send and send-once.
    pub const SEND_RIGHTS: Self = Self::SEND.union(Self::SEND_ONCE);
    /// The port rights: send, receive and send-once.
    pub const PORT_RIGHTS: Self = Self::SEND_RIGHTS.union(Self::RECEIVE);
    /// The port rights and dead names.
    pub const PORT_OR_DEAD: Self = Self::PORT_RIGHTS.union(Self::DEAD_NAME);

    /// The type bit of the right numbered `right`: `1 << (right + 16)`.
    #[must_use]
    pub const fn of_right(right: c_uint) -> Self {
        // The C shifts by `right + 16`; the target masks the count the same
        // way.
        Self::from_bits_retain(1u32.wrapping_shl(right.wrapping_add(16)))
    }
}

/// What an entry holds: the rights it names, the user references to them,
/// and whether a msg-accepted request is pending on it.  A free entry holds
/// the default: no right, no reference, no request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryBits {
    /// The rights the entry names.
    pub type_: PortType,
    /// The user references to those rights.
    pub urefs: u16,
    /// A msg-accepted request is pending on the entry.
    pub marequest: bool,
}

bitflags::bitflags! {
    /// `mach_msg_bits_t`: a message header's flags, with the remote port's
    /// disposition in the low byte and the local port's in the next.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MsghBits: u32 {
        /// `MACH_MSGH_BITS_COMPLEX`: the body carries rights or out-of-line
        /// memory.
        const COMPLEX = 0x8000_0000;
        /// `MACH_MSGH_BITS_CIRCULAR`: the kernel's mark of a circular
        /// message.
        const CIRCULAR = 0x4000_0000;
        // The two dispositions, and the bits a sender may set.
        const _ = !0;
    }
}

impl MsghBits {
    /// `MACH_MSGH_BITS(remote, local)`: the two dispositions and no flag.
    #[must_use]
    pub const fn new(remote: u32, local: u32) -> Self {
        Self::from_bits_retain(remote | (local << 8))
    }

    /// `MACH_MSGH_BITS_REMOTE`: the remote port's disposition.
    #[must_use]
    pub const fn remote(self) -> u32 {
        self.bits() & 0xff
    }

    /// `MACH_MSGH_BITS_LOCAL`: the local port's disposition.
    #[must_use]
    pub const fn local(self) -> u32 {
        (self.bits() >> 8) & 0xff
    }

    /// `MACH_MSGH_BITS_PORTS`: the two dispositions alone.
    #[must_use]
    pub const fn ports(self) -> Self {
        Self::from_bits_retain(self.bits() & 0xffff)
    }

    /// `MACH_MSGH_BITS_OTHER`: everything but the two dispositions.
    #[must_use]
    pub const fn other(self) -> Self {
        Self::from_bits_retain(self.bits() & !0xffff)
    }
}

bitflags::bitflags! {
    /// An IPC object's header word: the active and protected-payload flags,
    /// with the object type in bits 16 to 29 and the kernel-object type in
    /// the low half.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ObjectBits: u32 {
        /// The object is live.
        const ACTIVE = 0x8000_0000;
        /// The port delivers a protected payload in place of its name.
        const PROTECTED_PAYLOAD = 0x4000_0000;
        // The object-type and kernel-object-type fields.
        const _ = !0;
    }
}
