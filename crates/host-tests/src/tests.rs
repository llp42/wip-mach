// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Smoke tests pinning each included module's interface and basic behavior.

use crate::arch::types::RpcPhysAddr;
use crate::arch::vm_param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::error::Error as MachineError;
use crate::device::r#return::{DeviceError, Reply};
use crate::ipc::error::{
    Error as IpcError, MsgError, ReceiveError, SendError, Shortage,
};
use crate::kern::error::{Error as KernelError, RpcError};
use crate::kern::policy::POLICY_TIMESHARE;
use crate::mig::code::{MIG_NO_REPLY, io_return, kern_return, send_result};
use crate::mig::time_value::{
    RpcTimeValue, TimeValue, TimeValue64, TimeValueError,
};
use crate::utils::cell::SyncCell;
use crate::utils::kd_queue::{KdEvent, KdEventQueue};
use crate::vm::error::Error as VmError;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::time::Duration;

#[test]
fn rpc_phys_addr_round_trips() {
    assert_eq!(RpcPhysAddr::ZERO.bits(), 0);
    assert_eq!(RpcPhysAddr::from_bits(0xdead_beef).bits(), 0xdead_beef);
    assert_eq!(RpcPhysAddr::from_vm_offset(0x1000).bits(), 0x1000);
}

#[test]
fn page_geometry_is_4k() {
    assert_eq!(PAGE_SHIFT, 12);
    assert_eq!(PAGE_SIZE, 1 << PAGE_SHIFT);
    assert_eq!(PAGE_MASK, PAGE_SIZE - 1);
}

#[test]
fn success_is_zero() {
    assert_eq!(kern_return::<VmError>(Ok(())), 0);
    assert_eq!(kern_return::<MsgError>(Ok(())), 0);
}

#[test]
fn vm_errors_take_their_kern_return_codes() {
    let codes = [
        (VmError::InvalidAddress, 1),
        (VmError::ProtectionFailure, 2),
        (VmError::NoSpace, 3),
        (VmError::InvalidArgument, 4),
        (VmError::Failure, 5),
        (VmError::ResourceShortage, 6),
        (VmError::NoAccess, 8),
        (VmError::MemoryError, 10),
        (VmError::InvalidName, 15),
        (VmError::InvalidTask, 16),
        (VmError::InvalidHost, 22),
        (VmError::MemoryPresent, 23),
        (VmError::WriteProtectionFailure, 24),
        (VmError::Interrupted, 0x1000_0007),
    ];
    for (error, code) in codes {
        assert_eq!(c_int::from(error), code, "{error:?}");
    }
}

#[test]
fn ipc_errors_take_their_kern_return_codes() {
    let codes = [
        (IpcError::DeadSpace, 16),
        (IpcError::InvalidName, 15),
        (IpcError::InvalidRight, 17),
        (IpcError::InvalidValue, 18),
        (IpcError::UrefsOverflow, 19),
        (IpcError::NameExists, 13),
        (IpcError::RightExists, 21),
        (IpcError::NotInSet, 12),
        (IpcError::InvalidCapability, 20),
        (IpcError::NoSpace, 3),
        (IpcError::ResourceShortage, 6),
        (IpcError::InvalidArgument, 4),
        (IpcError::InvalidHost, 22),
        (IpcError::InvalidAddress, 1),
        (IpcError::Failure, 5),
    ];
    for (error, code) in codes {
        assert_eq!(c_int::from(error), code, "{error:?}");
    }
}

#[test]
fn message_errors_take_their_mach_msg_codes() {
    assert_eq!(c_int::from(SendError::InvalidData), 0x1000_0002);
    assert_eq!(c_int::from(SendError::InvalidHeader), 0x1000_0010);
    assert_eq!(c_int::from(ReceiveError::InvalidName), 0x1000_4002);
    assert_eq!(c_int::from(ReceiveError::InSet), 0x1000_400a);
    assert_eq!(
        c_int::from(ReceiveError::Header(Shortage::IPC_SPACE)),
        0x1000_400b | 0x2000
    );
    assert_eq!(
        c_int::from(ReceiveError::Body(
            Shortage::VM_SPACE | Shortage::IPC_KERNEL
        )),
        0x1000_400c | 0x1000 | 0x0800
    );
    assert_eq!(
        c_int::from(MsgError::Send(SendError::TimedOut, Shortage::VM_KERNEL)),
        0x1000_0004 | 0x0400
    );
}

#[test]
fn kernel_send_results_read_back() {
    for error in [
        SendError::InvalidData,
        SendError::InvalidDest,
        SendError::TimedOut,
        SendError::WillNotify,
        SendError::NotifyInProgress,
        SendError::Interrupted,
        SendError::MsgTooSmall,
        SendError::InvalidReply,
        SendError::InvalidRight,
        SendError::InvalidNotify,
        SendError::InvalidMemory,
        SendError::NoBuffer,
        SendError::NoNotify,
        SendError::InvalidType,
        SendError::InvalidHeader,
    ] {
        assert_eq!(send_result(c_int::from(error)), Err(error));
    }
    assert_eq!(send_result(0), Ok(()));
    assert_eq!(send_result(-307), Err(SendError::InvalidData));
}

#[test]
fn device_results_take_their_io_return_codes() {
    assert_eq!(c_int::from(DeviceError::IoError), 2500);
    assert_eq!(c_int::from(DeviceError::ReadOnly), 2509);
    assert_eq!(c_int::from(DeviceError::ResourceShortage), 6);
    assert_eq!(c_int::from(DeviceError::InvalidValue), 18);
    assert_eq!(c_int::from(DeviceError::Vm(VmError::NoSpace)), 3);
    assert_eq!(io_return(Ok(Reply::Now)), 0);
    assert_eq!(io_return(Ok(Reply::Withheld)), MIG_NO_REPLY);
    assert_eq!(io_return(Err(DeviceError::NoSuchDevice)), 2502);
}

#[test]
fn kernel_and_machine_errors_take_their_codes() {
    assert_eq!(c_int::from(KernelError::InvalidArgument), 4);
    assert_eq!(c_int::from(KernelError::TimedOut), 27);
    assert_eq!(c_int::from(KernelError::NoEmulationTask), 0x8001);
    assert_eq!(c_int::from(KernelError::Ipc(IpcError::DeadSpace)), 16);
    assert_eq!(
        c_int::from(KernelError::Machine(MachineError::PortsTaken)),
        2
    );
    assert_eq!(c_int::from(MachineError::NoFpu), 5);
    assert_eq!(c_int::from(RpcError::NotKernelObject), 0x1000_0007);
    assert_eq!(c_int::from(RpcError::Device(DeviceError::DeviceDown)), 2504);
}

#[test]
fn policy_timeshare_is_one() {
    assert_eq!(POLICY_TIMESHARE, 1);
}

#[test]
fn time_value64_arithmetic_carries() {
    let a = TimeValue64 {
        seconds: 1,
        nanoseconds: 999_999_999,
    };
    let b = TimeValue64 {
        seconds: 2,
        nanoseconds: 2,
    };
    assert_eq!(
        a.add(b),
        TimeValue64 {
            seconds: 4,
            nanoseconds: 1
        }
    );

    let minuend = TimeValue64 {
        seconds: 2,
        nanoseconds: 1,
    };
    let subtrahend = TimeValue64 {
        seconds: 1,
        nanoseconds: 2,
    };
    assert_eq!(
        minuend.sub(subtrahend),
        TimeValue64 {
            seconds: 0,
            nanoseconds: 999_999_999
        }
    );
}

#[test]
fn time_value_converts_to_and_from_duration() {
    let value = TimeValue64 {
        seconds: 3,
        nanoseconds: 500,
    };
    let duration = Duration::try_from(value).unwrap();
    assert_eq!(duration, Duration::new(3, 500));
    assert_eq!(TimeValue64::try_from(duration), Ok(value));
    assert_eq!(
        Duration::try_from(TimeValue64 {
            seconds: -1,
            nanoseconds: 0
        }),
        Err(TimeValueError::Negative)
    );
}

#[test]
fn time_value_legacy_conversions_keep_the_fields() {
    let legacy = TimeValue {
        seconds: 7,
        microseconds: 42,
    };
    let rpc = RpcTimeValue::from(legacy);
    assert_eq!((rpc.seconds, rpc.microseconds), (7, 42));
    assert_eq!(TimeValue::from(rpc), legacy);
}

#[test]
fn mach_atoi_parses_the_leading_digits() {
    let mut value: c_int = 0;
    let used = unsafe {
        crate::utils::atoi::mach_atoi(c"1234abc".as_ptr().cast(), &mut value)
    };
    assert_eq!((used, value), (4, 1234));

    let mut value: c_int = 7;
    let used = unsafe {
        crate::utils::atoi::mach_atoi(c"".as_ptr().cast(), &mut value)
    };
    assert_eq!((used, value), (0, -1));
}

#[test]
fn kd_event_queue_round_trips() {
    let mut queue = KdEventQueue::new();
    assert!(queue.is_empty());
    queue.push_back(KdEvent::scancode(0x1e));
    assert!(!queue.is_empty());
    assert!(queue.pop_front().is_some());
    assert!(queue.is_empty());

    for sc in 0..99u8 {
        queue.push_back(KdEvent::scancode(sc));
    }
    assert!(queue.is_full());
    assert!(queue.pop_front().is_some());
    assert!(!queue.is_full());
}

#[test]
fn sync_cell_holds_a_value() {
    let cell = SyncCell(UnsafeCell::new(5u32));
    assert_eq!(unsafe { *cell.0.get() }, 5);
    unsafe { *cell.0.get() = 6 };
    assert_eq!(unsafe { *cell.0.get() }, 6);
}

#[test]
fn delay_zero_returns() {
    crate::utils::delay::delay(0);
}
