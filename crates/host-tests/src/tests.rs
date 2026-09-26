// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Smoke tests pinning each included module's interface and basic behavior.

use crate::arch::types::RpcPhysAddr;
use crate::arch::vm_param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::device::r#return::DeviceError;
use crate::glue::time_value::{
    RpcTimeValue, TimeValue, TimeValue64, TimeValueError,
};
use crate::kern::policy::POLICY_TIMESHARE;
use crate::kern::types::KernError;
use crate::utils::cell::SyncCell;
use crate::utils::kd_queue::{KdEvent, KdEventQueue};
use crate::utils::string::{memcmp, memmove, strcmp, strcpy, strlen, strncpy};
use crate::vm::error::{Error, error_from_kern_return, kern_return};
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
fn kern_return_codes_round_trip() {
    assert_eq!(kern_return(Ok(())), 0);
    assert_eq!(Error::InvalidAddress.as_kern_return(), 1);
    assert_eq!(error_from_kern_return(1), Err(Error::InvalidAddress));
    assert_eq!(
        error_from_kern_return(0x1000_0007),
        Err(Error::SendInterrupted)
    );
    assert_eq!(error_from_kern_return(4242), Err(Error::Failure));
}

#[test]
fn kern_error_values_are_the_abi_ones() {
    assert_eq!(KernError::InvalidAddress as u8, 1);
    assert_eq!(KernError::Failure as u8, 5);
}

#[test]
fn device_error_values_are_the_abi_ones() {
    assert_eq!(DeviceError::IoError as i32, 2500);
    assert_eq!(DeviceError::WouldBlock as i32, 2501);
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
fn string_routines_round_trip() {
    let src = c"hello";
    let mut dst = [0u8; 16];
    unsafe { strcpy(dst.as_mut_ptr().cast(), src.as_ptr()) };
    assert_eq!(unsafe { strlen(dst.as_ptr().cast()) }, 5);
    assert_eq!(unsafe { strcmp(dst.as_ptr().cast(), src.as_ptr()) }, 0);
    assert_eq!(
        unsafe { memcmp(dst.as_ptr().cast(), src.as_ptr().cast(), 6) },
        0
    );
    assert!(
        unsafe { memcmp(c"a".as_ptr().cast(), c"b".as_ptr().cast(), 1) } < 0
    );

    let mut padded = [0xAAu8; 8];
    unsafe { strncpy(padded.as_mut_ptr().cast(), c"hi".as_ptr(), 8) };
    assert_eq!(padded, *b"hi\0\0\0\0\0\0");

    let mut overlap = *b"abcdef";
    unsafe {
        memmove(
            overlap.as_mut_ptr().add(2).cast(),
            overlap.as_ptr().cast(),
            4,
        );
    }
    assert_eq!(overlap, *b"ababcd");
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
