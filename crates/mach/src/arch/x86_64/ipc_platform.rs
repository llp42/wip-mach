// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel's IPC [`Platform`]: the running thread and task, IPC's waits
//! and wakeups, the continuations a blocked receive resumes through, the
//! kernel objects, and IPC's slab caches.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::platform::MachPlatform;
use crate::kern::kheap::Kalloc;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::kern::{ipc_kobject, ipc_mig};
use core::ffi::c_uint;
use core::ptr::{self, NonNull};
use mach_ipc::ipc_kmsg::Kmsg;
use mach_ipc::ipc_thread::{SavedReceive, ThreadIpc, ThreadRef};
use mach_ipc::platform::{IpcCache, MessageEvent, Platform};
use mach_ipc::{IpcPort, IpcSpace};
use mach_thread::thread::Thread;
use mach_thread::{ipc_sched, task};

const _: () = {
    assert!(IpcCache::Marequest as usize + 1 == IpcCache::COUNT);
};

/// The slab cache behind each of IPC's [`IpcCache`]s.
static IPC_CACHES: [KmemCache; IpcCache::COUNT] =
    [const { KmemCache::zeroed() }; IpcCache::COUNT];

/// The slab cache behind `cache`.
fn ipc_cache(cache: IpcCache) -> &'static KmemCache {
    &IPC_CACHES[cache as usize]
}

// SAFETY: each function forwards to the kernel routine IPC called before the
// seam, whose contract the trait restates.
unsafe impl Platform for MachPlatform {
    const RECEIVE_CONTINUE: unsafe extern "C" fn() =
        ipc_mig::mach_msg_receive_continue;
    const MSG_CONTINUE: unsafe extern "C" fn() = ipc_mig::mach_msg_continue;

    fn current_thread() -> ThreadRef {
        let thread = per_cpu::thread();
        assert!(!thread.is_null(), "current_thread: no current thread");
        // SAFETY: a non-null per-CPU thread is the live one this CPU runs.
        unsafe { ThreadRef::new(thread.cast()) }
    }

    unsafe fn thread_ipc(thread: ThreadRef) -> NonNull<ThreadIpc> {
        let thread = thread.as_ptr().cast::<Thread<Self>>();
        // SAFETY: the caller passes a live thread.
        unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*thread).ipc)) }
    }

    unsafe fn saved_receive(thread: ThreadRef) -> NonNull<SavedReceive> {
        let thread = thread.as_ptr().cast::<Thread<Self>>();
        // SAFETY: the caller passes a live thread; the receive arm is the
        // one a message transfer reads and writes.
        unsafe {
            NonNull::new_unchecked(ptr::addr_of_mut!((*thread).saved.receive))
        }
    }

    unsafe fn thread_go(thread: ThreadRef) {
        unsafe {
            ipc_sched::thread_go::<Self>(thread.as_ptr().cast());
        };
    }

    unsafe fn will_wait(timeout: Option<c_uint>) {
        let thread = per_cpu::thread();
        // SAFETY: thread context, so the running thread is live.
        match timeout {
            Some(msecs) => unsafe {
                ipc_sched::thread_will_wait_with_timeout(thread, msecs);
            },
            None => unsafe { ipc_sched::thread_will_wait(thread) },
        }
    }

    fn current_space() -> IpcSpace {
        ipc_mig::current_space()
    }

    fn count_message(event: MessageEvent) {
        let task = task::current_task::<Self>().as_ptr();
        // SAFETY: the running task is live, and the counts are statistics.
        unsafe {
            match event {
                MessageEvent::Sent => {
                    (*task).messages_sent =
                        (*task).messages_sent.wrapping_add(1);
                }
                MessageEvent::Received => {
                    (*task).messages_received =
                        (*task).messages_received.wrapping_add(1);
                }
            }
        }
    }

    unsafe fn kobject_server(request: Kmsg) -> Option<Kmsg> {
        unsafe { ipc_kobject::server(request) }
    }

    unsafe fn kobject_destroy(port: IpcPort) {
        unsafe { ipc_kobject::destroy(port.as_ptr()) };
    }

    type Heap = Kalloc;

    unsafe fn ipc_cache_init(
        cache: IpcCache,
        name: &'static [u8],
        size: usize,
    ) {
        ipc_cache(cache).init(name, size, 0, None, CacheInitFlags::empty());
    }

    unsafe fn ipc_cache_alloc(cache: IpcCache) -> Option<NonNull<u8>> {
        ipc_cache(cache).alloc()
    }

    unsafe fn ipc_cache_free(cache: IpcCache, record: NonNull<u8>) {
        // SAFETY: the record came from this cache, as the caller promises.
        unsafe { ipc_cache(cache).free(record) };
    }
}
