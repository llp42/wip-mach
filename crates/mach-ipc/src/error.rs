// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The errors the IPC system reports: one for the operations on rights and
//! spaces, and one for each half of a message transfer.

/// A failed operation on a right, a port or an IPC space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The space is null or no longer active.
    DeadSpace,
    /// The name denotes no right in the space.
    InvalidName,
    /// The name denotes a right, but not one this call takes.
    InvalidRight,
    /// A value is out of range for the right it applies to.
    InvalidValue,
    /// The change would overflow the right's user-reference count.
    UrefsOverflow,
    /// The name already denotes a right in the space.
    NameExists,
    /// The space already holds the right under another name.
    RightExists,
    /// The receive right is not a member of a port set.
    NotInSet,
    /// The port capability is dead, or not the one the call expects.
    InvalidCapability,
    /// The space or the map has no room for another name or region.
    NoSpace,
    /// A kernel resource could not be allocated.
    ResourceShortage,
    /// An argument does not apply to this call.
    InvalidArgument,
    /// The host argument is not the host.
    InvalidHost,
    /// The address is not valid in the space's map.
    InvalidAddress,
    /// The call could not be performed.
    Failure,
}

bitflags::bitflags! {
    /// The rights or memory a message copyout destroyed because the receiver
    /// or the kernel ran out of room for them.
    ///
    /// The bits are the ones a `mach_msg` return code carries.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Shortage: u32 {
        /// `MACH_MSG_IPC_SPACE`: the receiver's space had no room for a
        /// right.
        const IPC_SPACE = 0x0000_2000;
        /// `MACH_MSG_VM_SPACE`: the receiver's map had no room for
        /// out-of-line memory.
        const VM_SPACE = 0x0000_1000;
        /// `MACH_MSG_IPC_KERNEL`: the kernel ran short handling a right.
        const IPC_KERNEL = 0x0000_0800;
        /// `MACH_MSG_VM_KERNEL`: the kernel ran short handling out-of-line
        /// memory.
        const VM_KERNEL = 0x0000_0400;
    }
}

/// A message the kernel could not queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The message body could not be read.
    InvalidData,
    /// The destination is not a send or send-once right.
    InvalidDest,
    /// The destination queue stayed full for the whole timeout.
    TimedOut,
    /// The queue is full and a msg-accepted notification will follow.
    WillNotify,
    /// A msg-accepted notification for this port is already pending.
    NotifyInProgress,
    /// The wait for room in the queue was interrupted.
    Interrupted,
    /// The message is smaller than its header or its own descriptors.
    MsgTooSmall,
    /// The reply port is not a valid right to carry.
    InvalidReply,
    /// A port right in the body is not one the sender holds.
    InvalidRight,
    /// The notify port is not a valid right.
    InvalidNotify,
    /// Out-of-line memory in the body could not be copied in.
    InvalidMemory,
    /// The kernel had no buffer for the message.
    NoBuffer,
    /// No msg-accepted notification could be set up.
    NoNotify,
    /// A type descriptor in the body is malformed.
    InvalidType,
    /// The header's size or bits are malformed.
    InvalidHeader,
}

/// A message the kernel could not hand to a receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    /// The receive name denotes no receive right or port set.
    InvalidName,
    /// No message arrived within the timeout.
    TimedOut,
    /// The message is larger than the receive buffer.
    TooLarge,
    /// The wait for a message was interrupted.
    Interrupted,
    /// The port moved into a port set during the wait.
    PortChanged,
    /// The notify name is not a valid destination.
    InvalidNotify,
    /// The receive buffer could not be written.
    InvalidData,
    /// The port died during the wait.
    PortDied,
    /// The port is a member of a port set and cannot be received from.
    InSet,
    /// The header could not be copied out; the message was destroyed.
    Header(Shortage),
    /// Parts of the body could not be copied out and were destroyed.
    Body(Shortage),
}

/// A failed `mach_msg` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgError {
    /// The send failed, after the pseudo-copyout that hands the message
    /// back lost what the `Shortage` names.
    Send(SendError, Shortage),
    /// The receive failed.
    Receive(ReceiveError),
}

impl From<SendError> for MsgError {
    fn from(error: SendError) -> Self {
        Self::Send(error, Shortage::empty())
    }
}

impl From<ReceiveError> for MsgError {
    fn from(error: ReceiveError) -> Self {
        Self::Receive(error)
    }
}
