// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`Fake`] as IPC's platform: a thread record per host thread, heap caches
//! and the global allocator under the name tables; every function no test
//! reaches panics with its name.

use crate::fake::Fake;
use crate::heap::HostHeap;
use crate::types::FakeThread;
use core::alloc::Layout;
use core::ffi::c_uint;
use core::ptr::NonNull;
use mach_ipc::ipc_kmsg::Kmsg;
use mach_ipc::ipc_thread::{SavedReceive, ThreadIpc, ThreadRef};
use mach_ipc::platform::{IpcCache, MessageEvent, Platform};
use mach_ipc::{IpcPort, IpcSpace};
use std::alloc;

std::thread_local! {
    /// The running thread's record; leaked, so a `ThreadRef` stays valid.
    static THREAD: NonNull<FakeThread> = NonNull::from(Box::leak(Box::new(
        // SAFETY: zero is a thread outside any message transfer, as the
        // kernel's thread template starts.
        unsafe { core::mem::zeroed::<FakeThread>() },
    )));
}

/// The layout of every fake cache record, roomy enough for the largest.
const RECORD: Layout = match Layout::from_size_align(512, 16) {
    Ok(layout) => layout,
    Err(_) => panic!("the fake record layout is invalid"),
};

// SAFETY: the implemented functions keep the trait's contracts on the heap
// and in per-thread records; the rest panic before doing anything.
unsafe impl Platform for Fake {
    const RECEIVE_CONTINUE: unsafe extern "C" fn() = receive_continue;
    const MSG_CONTINUE: unsafe extern "C" fn() = msg_continue;

    fn current_thread() -> ThreadRef {
        // SAFETY: the record is leaked, so it outlives every use.
        THREAD.with(|thread| unsafe { ThreadRef::new(thread.as_ptr().cast()) })
    }

    unsafe fn thread_ipc(thread: ThreadRef) -> NonNull<ThreadIpc> {
        let thread = thread.as_ptr().cast::<FakeThread>();
        // SAFETY: every `ThreadRef` of the fake names a live `FakeThread`.
        unsafe { NonNull::new_unchecked(&raw mut (*thread).ipc) }
    }

    unsafe fn saved_receive(thread: ThreadRef) -> NonNull<SavedReceive> {
        let thread = thread.as_ptr().cast::<FakeThread>();
        // SAFETY: every `ThreadRef` of the fake names a live `FakeThread`.
        unsafe { NonNull::new_unchecked(&raw mut (*thread).saved) }
    }

    unsafe fn thread_go(_thread: ThreadRef) {
        unimplemented!("thread_go")
    }

    unsafe fn will_wait(_timeout: Option<c_uint>) {
        unimplemented!("will_wait")
    }

    fn current_space() -> IpcSpace {
        unimplemented!("current_space")
    }

    fn count_message(_event: MessageEvent) {
        unimplemented!("count_message")
    }

    unsafe fn kobject_server(_request: Kmsg) -> Option<Kmsg> {
        unimplemented!("kobject_server")
    }

    unsafe fn kobject_destroy(_port: IpcPort) {
        unimplemented!("kobject_destroy")
    }

    type Heap = HostHeap;

    unsafe fn ipc_cache_init(
        _cache: IpcCache,
        _name: &'static [u8],
        size: usize,
    ) {
        assert!(size <= RECORD.size(), "a record outgrew the fake cache");
    }

    unsafe fn ipc_cache_alloc(_cache: IpcCache) -> Option<NonNull<u8>> {
        // SAFETY: the record layout has a nonzero size.
        NonNull::new(unsafe { alloc::alloc_zeroed(RECORD) })
    }

    unsafe fn ipc_cache_free(_cache: IpcCache, record: NonNull<u8>) {
        // SAFETY: the record came from `ipc_cache_alloc`, with this layout.
        unsafe { alloc::dealloc(record.as_ptr(), RECORD) };
    }
}

/// The fake's receive continuation, which no test blocks long enough to
/// reach.
unsafe extern "C" fn receive_continue() {
    unimplemented!("receive_continue")
}

/// The fake's send-and-receive continuation, which no test reaches.
unsafe extern "C" fn msg_continue() {
    unimplemented!("msg_continue")
}
