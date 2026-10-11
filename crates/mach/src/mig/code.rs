// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The C result codes of the Mach ABI, and the one conversion from each
//! kernel error type to the code a trap or MIG caller sees.
//!
//! A `mach_msg_return_t` shares the integer space of a `kern_return_t`:
//! both succeed with zero, and every conversion below lands in that one
//! space.

use crate::arch::x86_64::error::Error as MachineError;
use crate::kern::error::Error as KernelError;
use core::ffi::c_int;
use mach_device::r#return::{DeviceError, Reply, ReplyResult};
use mach_host::error::Error as HostError;
use mach_ipc::error::{Error as IpcError, MsgError, ReceiveError, SendError};
use mach_thread::error::Error as TaskError;
use mach_trap::error::Error as TrapError;
use mach_vm::error::Error as VmError;

/// `KERN_SUCCESS`: the call succeeded.
pub(crate) const KERN_SUCCESS: c_int = 0;
/// `KERN_INVALID_ADDRESS`.
pub(crate) const KERN_INVALID_ADDRESS: c_int = 1;
/// `KERN_PROTECTION_FAILURE`.
pub(crate) const KERN_PROTECTION_FAILURE: c_int = 2;
/// `KERN_NO_SPACE`.
pub(crate) const KERN_NO_SPACE: c_int = 3;
/// `KERN_INVALID_ARGUMENT`.
pub(crate) const KERN_INVALID_ARGUMENT: c_int = 4;
/// `KERN_FAILURE`.
pub(crate) const KERN_FAILURE: c_int = 5;
/// `KERN_RESOURCE_SHORTAGE`.
pub(crate) const KERN_RESOURCE_SHORTAGE: c_int = 6;
/// `KERN_NO_ACCESS`.
pub(crate) const KERN_NO_ACCESS: c_int = 8;
/// `KERN_MEMORY_FAILURE`.
pub(crate) const KERN_MEMORY_FAILURE: c_int = 9;
/// `KERN_MEMORY_ERROR`.
pub(crate) const KERN_MEMORY_ERROR: c_int = 10;
/// `KERN_NOT_IN_SET`.
pub(crate) const KERN_NOT_IN_SET: c_int = 12;
/// `KERN_NAME_EXISTS`.
pub(crate) const KERN_NAME_EXISTS: c_int = 13;
/// `KERN_ABORTED`.
pub(crate) const KERN_ABORTED: c_int = 14;
/// `KERN_INVALID_NAME`.
pub(crate) const KERN_INVALID_NAME: c_int = 15;
/// `KERN_INVALID_TASK`.
pub(crate) const KERN_INVALID_TASK: c_int = 16;
/// `KERN_INVALID_RIGHT`.
pub(crate) const KERN_INVALID_RIGHT: c_int = 17;
/// `KERN_INVALID_VALUE`.
pub(crate) const KERN_INVALID_VALUE: c_int = 18;
/// `KERN_UREFS_OVERFLOW`.
pub(crate) const KERN_UREFS_OVERFLOW: c_int = 19;
/// `KERN_INVALID_CAPABILITY`.
pub(crate) const KERN_INVALID_CAPABILITY: c_int = 20;
/// `KERN_RIGHT_EXISTS`.
pub(crate) const KERN_RIGHT_EXISTS: c_int = 21;
/// `KERN_INVALID_HOST`.
pub(crate) const KERN_INVALID_HOST: c_int = 22;
/// `KERN_MEMORY_PRESENT`.
pub(crate) const KERN_MEMORY_PRESENT: c_int = 23;
/// `KERN_WRITE_PROTECTION_FAILURE`.
pub(crate) const KERN_WRITE_PROTECTION_FAILURE: c_int = 24;
/// `KERN_TIMEDOUT`.
pub(crate) const KERN_TIMEDOUT: c_int = 27;
/// `KERN_INTERRUPTED`.
pub(crate) const KERN_INTERRUPTED: c_int = 28;

/// The return code of an emulation call whose task is null.
const EML_BAD_TASK: c_int = 0x8001;

/// `MACH_SEND_INVALID_DATA`.
const MACH_SEND_INVALID_DATA: c_int = 0x1000_0002;
/// `MACH_SEND_INVALID_DEST`.
const MACH_SEND_INVALID_DEST: c_int = 0x1000_0003;
/// `MACH_SEND_TIMED_OUT`.
const MACH_SEND_TIMED_OUT: c_int = 0x1000_0004;
/// `MACH_SEND_WILL_NOTIFY`.
const MACH_SEND_WILL_NOTIFY: c_int = 0x1000_0005;
/// `MACH_SEND_NOTIFY_IN_PROGRESS`.
const MACH_SEND_NOTIFY_IN_PROGRESS: c_int = 0x1000_0006;
/// `MACH_SEND_INTERRUPTED`.
pub(crate) const MACH_SEND_INTERRUPTED: c_int = 0x1000_0007;
/// `MACH_SEND_MSG_TOO_SMALL`.
const MACH_SEND_MSG_TOO_SMALL: c_int = 0x1000_0008;
/// `MACH_SEND_INVALID_REPLY`.
const MACH_SEND_INVALID_REPLY: c_int = 0x1000_0009;
/// `MACH_SEND_INVALID_RIGHT`.
const MACH_SEND_INVALID_RIGHT: c_int = 0x1000_000a;
/// `MACH_SEND_INVALID_NOTIFY`.
const MACH_SEND_INVALID_NOTIFY: c_int = 0x1000_000b;
/// `MACH_SEND_INVALID_MEMORY`.
const MACH_SEND_INVALID_MEMORY: c_int = 0x1000_000c;
/// `MACH_SEND_NO_BUFFER`.
const MACH_SEND_NO_BUFFER: c_int = 0x1000_000d;
/// `MACH_SEND_NO_NOTIFY`.
const MACH_SEND_NO_NOTIFY: c_int = 0x1000_000e;
/// `MACH_SEND_INVALID_TYPE`.
const MACH_SEND_INVALID_TYPE: c_int = 0x1000_000f;
/// `MACH_SEND_INVALID_HEADER`.
const MACH_SEND_INVALID_HEADER: c_int = 0x1000_0010;

/// `MACH_RCV_INVALID_NAME`.
const MACH_RCV_INVALID_NAME: c_int = 0x1000_4002;
/// `MACH_RCV_TIMED_OUT`.
const MACH_RCV_TIMED_OUT: c_int = 0x1000_4003;
/// `MACH_RCV_TOO_LARGE`.
const MACH_RCV_TOO_LARGE: c_int = 0x1000_4004;
/// `MACH_RCV_INTERRUPTED`.
pub(crate) const MACH_RCV_INTERRUPTED: c_int = 0x1000_4005;
const _: () =
    assert!(MACH_RCV_INTERRUPTED == mach_thread::thread::MACH_RCV_INTERRUPTED);
/// `MACH_RCV_PORT_CHANGED`.
const MACH_RCV_PORT_CHANGED: c_int = 0x1000_4006;
/// `MACH_RCV_INVALID_NOTIFY`.
const MACH_RCV_INVALID_NOTIFY: c_int = 0x1000_4007;
/// `MACH_RCV_INVALID_DATA`.
const MACH_RCV_INVALID_DATA: c_int = 0x1000_4008;
/// `MACH_RCV_PORT_DIED`.
const MACH_RCV_PORT_DIED: c_int = 0x1000_4009;
/// `MACH_RCV_IN_SET`.
const MACH_RCV_IN_SET: c_int = 0x1000_400a;
/// `MACH_RCV_HEADER_ERROR`.
const MACH_RCV_HEADER_ERROR: c_int = 0x1000_400b;
/// `MACH_RCV_BODY_ERROR`.
const MACH_RCV_BODY_ERROR: c_int = 0x1000_400c;

/// `D_SUCCESS`: the device call succeeded.
const D_SUCCESS: c_int = 0;
/// `D_IO_ERROR`.
const D_IO_ERROR: c_int = 2500;
/// `D_WOULD_BLOCK`.
const D_WOULD_BLOCK: c_int = 2501;
/// `D_NO_SUCH_DEVICE`.
const D_NO_SUCH_DEVICE: c_int = 2502;
/// `D_ALREADY_OPEN`.
const D_ALREADY_OPEN: c_int = 2503;
/// `D_DEVICE_DOWN`.
const D_DEVICE_DOWN: c_int = 2504;
/// `D_INVALID_OPERATION`.
const D_INVALID_OPERATION: c_int = 2505;
/// `D_INVALID_RECNUM`.
const D_INVALID_RECNUM: c_int = 2506;
/// `D_INVALID_SIZE`.
const D_INVALID_SIZE: c_int = 2507;
/// `D_NO_MEMORY`.
const D_NO_MEMORY: c_int = 2508;
/// `D_READ_ONLY`.
const D_READ_ONLY: c_int = 2509;

/// No server routine has the message's id.
pub(crate) const MIG_BAD_ID: c_int = -303;
/// The server routine sends no reply of its own.
pub(crate) const MIG_NO_REPLY: c_int = -305;

/// The answer to an interface kept only for compatibility.  Not part of any
/// upstream Mach: the value sits at the far end of the `MIG_*` block, which
/// upstream fills upward from -300.
pub(crate) const WIPMACH_DEPRECATED: c_int = -399;

/// The code of a result: zero for `Ok`, which is both `KERN_SUCCESS` and
/// `MACH_MSG_SUCCESS`, and the error's code otherwise.
pub(crate) fn kern_return<E>(result: Result<(), E>) -> c_int
where
    c_int: From<E>,
{
    match result {
        Ok(()) => KERN_SUCCESS,
        Err(error) => c_int::from(error),
    }
}

/// The `kern_return_t` of a task, thread or processor error, which is
/// `mach-task`'s, so the conversion is a function rather than a `From`
/// impl.
pub(crate) fn task_return(error: TaskError) -> c_int {
    c_int::from(KernelError::from(error))
}

/// The `kern_return_t` of a host error, which is `mach-host`'s, so the
/// conversion is a function rather than a `From` impl.
pub(crate) fn host_return(error: HostError) -> c_int {
    c_int::from(KernelError::from(error))
}

/// The `kern_return_t` of a VM error.  VM's error type is another crate's,
/// so the conversion is a function rather than a `From` impl.
pub(crate) const fn vm_return(error: VmError) -> c_int {
    match error {
        VmError::InvalidAddress => KERN_INVALID_ADDRESS,
        VmError::ProtectionFailure => KERN_PROTECTION_FAILURE,
        VmError::NoSpace => KERN_NO_SPACE,
        VmError::InvalidArgument => KERN_INVALID_ARGUMENT,
        VmError::Failure => KERN_FAILURE,
        VmError::ResourceShortage => KERN_RESOURCE_SHORTAGE,
        VmError::NoAccess => KERN_NO_ACCESS,
        VmError::MemoryError => KERN_MEMORY_ERROR,
        VmError::InvalidName => KERN_INVALID_NAME,
        VmError::InvalidTask => KERN_INVALID_TASK,
        VmError::InvalidHost => KERN_INVALID_HOST,
        VmError::MemoryPresent => KERN_MEMORY_PRESENT,
        VmError::WriteProtectionFailure => KERN_WRITE_PROTECTION_FAILURE,
        VmError::Interrupted => MACH_SEND_INTERRUPTED,
    }
}

/// The `kern_return_t` of an IPC error.
pub(crate) const fn ipc_return(error: IpcError) -> c_int {
    match error {
        IpcError::DeadSpace => KERN_INVALID_TASK,
        IpcError::InvalidName => KERN_INVALID_NAME,
        IpcError::InvalidRight => KERN_INVALID_RIGHT,
        IpcError::InvalidValue => KERN_INVALID_VALUE,
        IpcError::UrefsOverflow => KERN_UREFS_OVERFLOW,
        IpcError::NameExists => KERN_NAME_EXISTS,
        IpcError::RightExists => KERN_RIGHT_EXISTS,
        IpcError::NotInSet => KERN_NOT_IN_SET,
        IpcError::InvalidCapability => KERN_INVALID_CAPABILITY,
        IpcError::NoSpace => KERN_NO_SPACE,
        IpcError::ResourceShortage => KERN_RESOURCE_SHORTAGE,
        IpcError::InvalidArgument => KERN_INVALID_ARGUMENT,
        IpcError::InvalidHost => KERN_INVALID_HOST,
        IpcError::InvalidAddress => KERN_INVALID_ADDRESS,
        IpcError::Failure => KERN_FAILURE,
    }
}

/// The `mach_msg_return_t` of a send error.
pub(crate) const fn send_return(error: SendError) -> c_int {
    match error {
        SendError::InvalidData => MACH_SEND_INVALID_DATA,
        SendError::InvalidDest => MACH_SEND_INVALID_DEST,
        SendError::TimedOut => MACH_SEND_TIMED_OUT,
        SendError::WillNotify => MACH_SEND_WILL_NOTIFY,
        SendError::NotifyInProgress => MACH_SEND_NOTIFY_IN_PROGRESS,
        SendError::Interrupted => MACH_SEND_INTERRUPTED,
        SendError::MsgTooSmall => MACH_SEND_MSG_TOO_SMALL,
        SendError::InvalidReply => MACH_SEND_INVALID_REPLY,
        SendError::InvalidRight => MACH_SEND_INVALID_RIGHT,
        SendError::InvalidNotify => MACH_SEND_INVALID_NOTIFY,
        SendError::InvalidMemory => MACH_SEND_INVALID_MEMORY,
        SendError::NoBuffer => MACH_SEND_NO_BUFFER,
        SendError::NoNotify => MACH_SEND_NO_NOTIFY,
        SendError::InvalidType => MACH_SEND_INVALID_TYPE,
        SendError::InvalidHeader => MACH_SEND_INVALID_HEADER,
    }
}

/// The `mach_msg_return_t` of a receive error.
pub(crate) const fn receive_return(error: ReceiveError) -> c_int {
    match error {
        ReceiveError::InvalidName => MACH_RCV_INVALID_NAME,
        ReceiveError::TimedOut => MACH_RCV_TIMED_OUT,
        ReceiveError::TooLarge => MACH_RCV_TOO_LARGE,
        ReceiveError::Interrupted => MACH_RCV_INTERRUPTED,
        ReceiveError::PortChanged => MACH_RCV_PORT_CHANGED,
        ReceiveError::InvalidNotify => MACH_RCV_INVALID_NOTIFY,
        ReceiveError::InvalidData => MACH_RCV_INVALID_DATA,
        ReceiveError::PortDied => MACH_RCV_PORT_DIED,
        ReceiveError::InSet => MACH_RCV_IN_SET,
        ReceiveError::Header(shortage) => {
            MACH_RCV_HEADER_ERROR | shortage.bits() as c_int
        }
        ReceiveError::Body(shortage) => {
            MACH_RCV_BODY_ERROR | shortage.bits() as c_int
        }
    }
}

/// The `mach_msg_return_t` of a `mach_msg` error.
pub(crate) const fn msg_return(error: MsgError) -> c_int {
    match error {
        MsgError::Send(error, shortage) => {
            send_return(error) | shortage.bits() as c_int
        }
        MsgError::Receive(error) => receive_return(error),
    }
}

/// The result of a message a MIG user stub sent through
/// `mach_msg_send_from_kernel()`.
///
/// `MACH_SEND_INVALID_DATA`, and any code outside the `MACH_SEND_*` set,
/// read as [`SendError::InvalidData`]: the only other code a stub returns
/// is the inband device reply's `MIG_ARRAY_TOO_LARGE`, which a count its
/// caller already bounded never produces.
pub(crate) const fn send_result(code: c_int) -> Result<(), SendError> {
    match code {
        KERN_SUCCESS => Ok(()),
        MACH_SEND_INVALID_DEST => Err(SendError::InvalidDest),
        MACH_SEND_TIMED_OUT => Err(SendError::TimedOut),
        MACH_SEND_WILL_NOTIFY => Err(SendError::WillNotify),
        MACH_SEND_NOTIFY_IN_PROGRESS => Err(SendError::NotifyInProgress),
        MACH_SEND_INTERRUPTED => Err(SendError::Interrupted),
        MACH_SEND_MSG_TOO_SMALL => Err(SendError::MsgTooSmall),
        MACH_SEND_INVALID_REPLY => Err(SendError::InvalidReply),
        MACH_SEND_INVALID_RIGHT => Err(SendError::InvalidRight),
        MACH_SEND_INVALID_NOTIFY => Err(SendError::InvalidNotify),
        MACH_SEND_INVALID_MEMORY => Err(SendError::InvalidMemory),
        MACH_SEND_NO_BUFFER => Err(SendError::NoBuffer),
        MACH_SEND_NO_NOTIFY => Err(SendError::NoNotify),
        MACH_SEND_INVALID_TYPE => Err(SendError::InvalidType),
        MACH_SEND_INVALID_HEADER => Err(SendError::InvalidHeader),
        _ => Err(SendError::InvalidData),
    }
}

/// The `io_return_t` of a device call's result: `D_SUCCESS` for `Ok`, and
/// the error's code otherwise.
pub(crate) const fn device_result(result: Result<(), DeviceError>) -> c_int {
    match result {
        Ok(()) => D_SUCCESS,
        Err(error) => device_return(error),
    }
}

/// The `io_return_t` of a failed device call.
pub(crate) const fn device_return(error: DeviceError) -> c_int {
    match error {
        DeviceError::IoError => D_IO_ERROR,
        DeviceError::WouldBlock => D_WOULD_BLOCK,
        DeviceError::NoSuchDevice => D_NO_SUCH_DEVICE,
        DeviceError::AlreadyOpen => D_ALREADY_OPEN,
        DeviceError::DeviceDown => D_DEVICE_DOWN,
        DeviceError::InvalidOperation => D_INVALID_OPERATION,
        DeviceError::InvalidRecnum => D_INVALID_RECNUM,
        DeviceError::InvalidSize => D_INVALID_SIZE,
        DeviceError::NoMemory => D_NO_MEMORY,
        DeviceError::ReadOnly => D_READ_ONLY,
        DeviceError::ResourceShortage => KERN_RESOURCE_SHORTAGE,
        DeviceError::InvalidArgument => KERN_INVALID_ARGUMENT,
        DeviceError::InvalidValue => KERN_INVALID_VALUE,
        DeviceError::Vm(error) => vm_return(error),
    }
}

/// The `io_return_t` a device server routine or trap returns: `D_SUCCESS`
/// when its reply carries the outcome, `MIG_NO_REPLY` when it sends none.
pub(crate) const fn io_return(result: ReplyResult) -> c_int {
    match result {
        Ok(Reply::Now) => D_SUCCESS,
        Ok(Reply::Withheld) => MIG_NO_REPLY,
        Err(error) => device_return(error),
    }
}

impl From<MachineError> for c_int {
    fn from(error: MachineError) -> Self {
        match error {
            MachineError::InvalidArgument => KERN_INVALID_ARGUMENT,
            MachineError::NoFpu | MachineError::NotSupported => KERN_FAILURE,
            MachineError::PortsTaken => KERN_PROTECTION_FAILURE,
            MachineError::NoSpace => KERN_NO_SPACE,
            MachineError::ResourceShortage => KERN_RESOURCE_SHORTAGE,
            MachineError::Vm(error) => vm_return(error),
        }
    }
}

impl From<KernelError> for c_int {
    fn from(error: KernelError) -> Self {
        match error {
            KernelError::InvalidArgument => KERN_INVALID_ARGUMENT,
            KernelError::Failure | KernelError::NotImplemented => KERN_FAILURE,
            KernelError::ResourceShortage => KERN_RESOURCE_SHORTAGE,
            KernelError::InvalidHost => KERN_INVALID_HOST,
            KernelError::InvalidTask => KERN_INVALID_TASK,
            KernelError::NoEmulationTask => EML_BAD_TASK,
            KernelError::InvalidAddress => KERN_INVALID_ADDRESS,
            KernelError::MemoryFailure => KERN_MEMORY_FAILURE,
            KernelError::NoAccess => KERN_NO_ACCESS,
            KernelError::NoSpace => KERN_NO_SPACE,
            KernelError::ProtectionFailure => KERN_PROTECTION_FAILURE,
            KernelError::Aborted => KERN_ABORTED,
            KernelError::Interrupted => KERN_INTERRUPTED,
            KernelError::TimedOut => KERN_TIMEDOUT,
            KernelError::Ipc(error) => ipc_return(error),
            KernelError::Vm(error) => vm_return(error),
            KernelError::Machine(error) => Self::from(error),
        }
    }
}

/// The `kern_return_t` of a trap error, which is `mach-trap`'s, so the
/// conversion is a function rather than a `From` impl.
pub(crate) fn trap_return(error: TrapError) -> c_int {
    match error {
        TrapError::NotKernelObject => MACH_SEND_INTERRUPTED,
        TrapError::Task(error) => task_return(error),
        TrapError::Ipc(error) => ipc_return(error),
        TrapError::Vm(error) => vm_return(error),
        TrapError::Device(error) => device_return(error),
    }
}
