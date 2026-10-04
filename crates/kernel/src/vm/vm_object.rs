// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_object.c and vm/vm_object.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The virtual-memory object module, which `vm/vm_object.c` used to define
//! and `vm/vm_object.h` declares.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::mp_desc::simple_lock_pause;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::pmap::pmap_is_modified;
use crate::arch::x86_64::pmap::pmap_page_protect;
use crate::glue::{
    memory_object_copy, memory_object_create, memory_object_init,
    memory_object_terminate,
};
use crate::ipc::{IpcPort, ipc_port, ipc_space};
use crate::kern::console::kprint;
use crate::kern::debug::{kpanic, soft_debugger};
use crate::kern::ipc_kobject;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_sleep,
    thread_wakeup_prim,
};
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::utils::cell::SyncCell;
use crate::vm::error::{Error, KERN_SUCCESS, MACH_SEND_INTERRUPTED};
use crate::vm::memory_object::default_manager;
use crate::vm::types::{Pmap, VmObject, VmObjectCachedList, VmPage, VmProt};
use crate::vm::vm_page::{self, ListqList};
use crate::vm::vm_pageout::vm_pageout_page;
use crate::vm::vm_resident::VM_PAGE_FICTITIOUS_ADDR;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm::vm_user::VM_STAT;
use crate::vm::{vm_external, vm_fault, vm_resident};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull, addr_of, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicI32, AtomicIsize, AtomicU32, Ordering};

/// `VM_OBJECT_EVENT_*` of <`vm/vm_object.h>`: the `all_wanted` bit an event
/// waiting on the object sets.
const EVENT_INITIALIZED: u32 = 0;
pub(crate) const EVENT_PAGER_READY: u32 = 1;
const EVENT_PAGING_IN_PROGRESS: u32 = 2;
const EVENT_ABSENT_COUNT: u32 = 3;

/// `IKOT_*` of <`kern/ipc_kobject.h`>.
const IKOT_NONE: c_uint = 0;
const IKOT_PAGER: c_uint = 8;
const IKOT_PAGING_REQUEST: c_uint = 9;
const IKOT_PAGER_TERMINATING: c_uint = 15;
const IKOT_PAGING_NAME: c_uint = 16;

/// `MEMORY_OBJECT_COPY_*` of <`mach/memory_object.h>`: the copy strategies
/// `vm_object_copy_strategically()` dispatches over.
const MEMORY_OBJECT_COPY_NONE: c_int = 0;
const MEMORY_OBJECT_COPY_CALL: c_int = 1;
const MEMORY_OBJECT_COPY_DELAY: c_int = 2;

/// `VM_FAULT_*` of <`vm/vm_fault.h`>, the values `vm_fault_page()` returns.
const VM_FAULT_SUCCESS: c_int = 0;
const VM_FAULT_INTERRUPTED: c_int = 2;
const VM_FAULT_MEMORY_SHORTAGE: c_int = 3;
const VM_FAULT_FICTITIOUS_SHORTAGE: c_int = 4;
const VM_FAULT_MEMORY_ERROR: c_int = 5;

/// `VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS` of
/// <`machine/vm_param.h`>, the size the kernel object and the submap
/// placeholder are created with.
const KERNEL_OBJECT_SIZE: VmSize = 0x7fff_ffff;

/// `vm_object_cache` of `vm/vm_object.c`: the `struct vm_object` slab cache.
static mut VM_OBJECT_CACHE: KmemCache = KmemCache::zeroed();

/// `vm_object_cached_list`: the objects whose `can_persist` kept them after
/// their last reference went away.
static VM_OBJECT_CACHED_LIST: SyncCell<VmObjectCachedList> =
    SyncCell(UnsafeCell::new(VmObjectCachedList::new()));

/// The live cached-object list head.
///
/// # Safety
///
/// The caller must hold the cache lock for as long as it uses the list.
unsafe fn cached_list() -> Pin<&'static mut VmObjectCachedList> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the list.
    unsafe { Pin::new_unchecked(&mut *VM_OBJECT_CACHED_LIST.0.get()) }
}

/// `vm_object_cached_lock_data`: serializes the cached list and the port
/// associations.
static VM_OBJECT_CACHED_LOCK: crate::kern::lock::SimpleLock =
    crate::kern::lock::SimpleLock::new();

/// `vm_object_template`: the image `_vm_object_setup()` copies into a fresh
/// object.
static mut VM_OBJECT_TEMPLATE: VmObject = VmObject::zeroed();

/// `kernel_object_store`, file-private in the C.
static mut KERNEL_OBJECT_STORE: VmObject = VmObject::zeroed();

/// `vm_submap_object_store`, file-private in `vm/vm_map_glue.c`.
static mut VM_SUBMAP_OBJECT_STORE: VmObject = VmObject::zeroed();

/// `vm_submap_object` of <`vm/vm_map.h>`: the placeholder object dropped into
/// a submap's range until `vm_map_submap()` creates the submap.
pub static mut VM_SUBMAP_OBJECT: *mut VmObject =
    &raw mut VM_SUBMAP_OBJECT_STORE;

/// `kernel_object` of <`vm/vm_object.h>`: the single object all wired-down
/// kernel memory belongs to.
pub static mut KERNEL_OBJECT: *mut VmObject = &raw mut KERNEL_OBJECT_STORE;

/// `vm_object_pmap_protect_by_page` of `vm/vm_object.c`.
static VM_OBJECT_PMAP_PROTECT_BY_PAGE: AtomicI32 = AtomicI32::new(0);

/// `object_collapses` and `object_bypasses` of `vm/vm_object.c`: debugging
/// counters, written for a debugger to read and never synchronized against.
static OBJECT_COLLAPSES: AtomicIsize = AtomicIsize::new(0);
static OBJECT_BYPASSES: AtomicIsize = AtomicIsize::new(0);

/// `vm_object_collapse_debug`, `vm_object_collapse_allowed` and
/// `vm_object_collapse_bypass_allowed`: the collapse switch a debugger sets.
static VM_OBJECT_COLLAPSE_DEBUG: AtomicI32 = AtomicI32::new(0);
static VM_OBJECT_COLLAPSE_ALLOWED: AtomicI32 = AtomicI32::new(1);
static VM_OBJECT_COLLAPSE_BYPASS_ALLOWED: AtomicI32 = AtomicI32::new(1);

/// `vm_object_page_remove_lookup` and `vm_object_page_remove_iterate` of
/// `vm/vm_object.c`: how each removal path was taken.
static PAGE_REMOVE_LOOKUP: AtomicU32 = AtomicU32::new(0);
static PAGE_REMOVE_ITERATE: AtomicU32 = AtomicU32::new(0);

/// `panic()` of `vm/vm_object.c`.
fn die(func: &'static str, message: &'static str) -> ! {
    kpanic!(func, "{}", message)
}

/// [`KmemCache::alloc`] of the object cache.
///
/// # Safety
///
/// The caller must run after `vm_object_bootstrap()` has initialized the
/// object cache.
unsafe fn cache_alloc() -> *mut VmObject {
    let Some(buf) = (unsafe { (*addr_of_mut!(VM_OBJECT_CACHE)).alloc() })
    else {
        return null_mut();
    };
    buf.as_ptr().cast::<VmObject>()
}

/// `kmem_cache_free(&vm_object_cache, object)` of the C.
///
/// # Safety
///
/// `object` must be a dead object that came from [`cache_alloc()`] and has
/// no other holder.
unsafe fn cache_free(object: *mut VmObject) {
    unsafe {
        (*addr_of_mut!(VM_OBJECT_CACHE))
            .free(NonNull::new_unchecked(object.cast::<u8>()));
    };
}

/// `vm_object_cached_lock_data` acquisition.
///
/// # Safety
///
/// Nothing else may hold the lock in this thread, and the caller must keep
/// it until it unlocks.
unsafe fn cache_lock() {
    unsafe { (*addr_of!(VM_OBJECT_CACHED_LOCK)).lock() };
}

/// `vm_object_cached_lock_data` release.
///
/// # Safety
///
/// This thread must hold the lock.
unsafe fn cache_unlock() {
    unsafe { (*addr_of!(VM_OBJECT_CACHED_LOCK)).unlock() };
}

/// `vm_object_cache_add()` of the C.
///
/// # Safety
///
/// The cache lock and the object lock must be held.
unsafe fn cache_add(object: *mut VmObject) {
    unsafe {
        cached_list().push_front_ptr(NonNull::new_unchecked(object));
        (*object).set_cached(true);
    }
}

/// `vm_object_cache_remove()` of the C.
///
/// # Safety
///
/// The cache lock and the object lock must be held, and the object must be
/// on the cached list.
unsafe fn cache_remove(object: *mut VmObject) {
    unsafe {
        VmObjectCachedList::remove_ptr(NonNull::new_unchecked(object));
        (*object).set_cached(false);
    }
}

/// `IP_VALID()` of <`ipc/ipc_object.h`>.
fn port_valid(port: *mut c_void) -> bool {
    !port.is_null() && port as usize != usize::MAX
}

/// The event key `(vm_offset_t) object + event` every object wait uses.
const fn event_ptr(object: *const VmObject, event: u32) -> *mut c_void {
    // The event is at most three, far below the object's own alignment.
    object
        .cast::<u8>()
        .wrapping_add(event as usize)
        .cast_mut()
        .cast::<c_void>()
}

/// `atop()` of `<vm/vm_page.h>`.
const fn atop(address: VmOffset) -> usize {
    address >> PAGE_SHIFT
}

/// The page after `page` in the resident list headed by `head`, or `None`
/// when `page` is the last.
///
/// # Safety
///
/// `page` must be linked into `head`'s list through the `VmPage.listq`
/// field.
pub(crate) unsafe fn next_page(
    head: *mut ListqList,
    page: *mut VmPage,
) -> Option<NonNull<VmPage>> {
    // SAFETY: `head` is the live head of the page's object, which never
    // moves, and the caller holds the object lock; `page` is linked into it.
    unsafe {
        let mut cursor = Pin::new_unchecked(&mut *head)
            .cursor_mut_from_ptr(NonNull::new_unchecked(page));
        cursor.move_next();
        cursor.current_ptr()
    }
}

/// `vm_object_wait()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held; the call releases it as the C macro did.
unsafe fn wait(object: *mut VmObject, event: u32, interruptible: bool) {
    unsafe {
        (*object).want(event);
        thread_sleep(
            event_ptr(object, event),
            addr_of_mut!((*object).lock),
            c_int::from(interruptible),
        );
    }
}

/// `vm_object_assert_wait()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn assert_wait_event(
    object: *mut VmObject,
    event: u32,
    interruptible: bool,
) {
    unsafe {
        (*object).want(event);
        assert_wait(
            NonNull::new(event_ptr(object, event)),
            c_int::from(interruptible),
        );
    }
}

/// `vm_object_absent_assert_wait()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn absent_assert_wait(
    object: *mut VmObject,
    interruptible: bool,
) {
    unsafe { assert_wait_event(object, EVENT_ABSENT_COUNT, interruptible) };
}

/// `vm_object_wakeup()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn wakeup(object: *mut VmObject, event: u32) {
    unsafe {
        if (*object).wants(event) {
            thread_wakeup_prim(event_ptr(object, event), 0, THREAD_AWAKENED);
        }
        (*object).clear_want(event);
    }
}

/// `vm_object_wakeup(object, VM_OBJECT_EVENT_ABSENT_COUNT)` of the C.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn absent_release(object: *mut VmObject) {
    unsafe {
        (*object).absent_count = (*object).absent_count.wrapping_sub(1);
        wakeup(object, EVENT_ABSENT_COUNT);
    }
}

/// `vm_object_wakeup(object, VM_OBJECT_EVENT_PAGER_READY)` of the C.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn wakeup_pager_ready(object: *mut VmObject) {
    unsafe { wakeup(object, EVENT_PAGER_READY) };
}

/// `vm_object_paging_begin()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn paging_begin(object: *mut VmObject) {
    unsafe {
        (*object).set_paging_in_progress((*object).paging_in_progress() + 1);
    };
}

/// `vm_object_paging_end()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn paging_end(object: *mut VmObject) {
    unsafe {
        let count = (*object).paging_in_progress() - 1;
        (*object).set_paging_in_progress(count);
        if count == 0 {
            wakeup(object, EVENT_PAGING_IN_PROGRESS);
        }
    }
}

/// `vm_object_paging_wait()` of <`vm/vm_object.h`>.
///
/// # Safety
///
/// The object lock must be held; the call may drop and retake it.
unsafe fn paging_wait(object: *mut VmObject, interruptible: bool) {
    while unsafe { (*object).paging_in_progress() } != 0 {
        unsafe {
            wait(object, EVENT_PAGING_IN_PROGRESS, interruptible);
            (*object).lock.lock();
        }
    }
}

/// `vm_map_glue_object_make_shared()` in C.
///
/// # Safety
///
/// `object` must be a live object.
pub(crate) unsafe fn make_shared(object: *mut VmObject) {
    unsafe {
        (*object).lock.lock();
        (*object).set_use_shared_copy(true);
        (*object).ref_count += 1;
        (*object).lock.unlock();
    }
}

/// `VM_PAGE_FREE()` of <`vm/vm_page.h`>.
///
/// # Safety
///
/// `page` must be a live page that the caller owns, and the page-queues lock
/// must not be held.
pub(crate) unsafe fn page_free(page: *mut VmPage) {
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        vm_resident::free(NonNull::new_unchecked(page));
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// `PAGE_WAKEUP()` of <`vm/vm_page.h`>.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
pub(crate) unsafe fn page_wakeup(page: *mut VmPage) {
    unsafe {
        if (*page).is_wanted() {
            (*page).set_wanted(false);
            thread_wakeup_prim(page.cast(), 0, THREAD_AWAKENED);
        }
    }
}

/// `PAGE_WAKEUP_DONE()` of <`vm/vm_page.h`>.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
pub(crate) unsafe fn page_wakeup_done(page: *mut VmPage) {
    unsafe {
        (*page).set_busy(false);
        page_wakeup(page);
    }
}

/// `_vm_object_setup()` of the C: stamp the template on a fresh object.
///
/// # Safety
///
/// `object` must be writable storage for a `VmObject` that no other thread
/// can see yet.
unsafe fn setup(object: *mut VmObject, size: VmSize) {
    unsafe {
        ptr::copy_nonoverlapping(addr_of!(VM_OBJECT_TEMPLATE), object, 1);
        (*object).memq = ListqList::new();
        (*object).lock.init();
        (*object).size = size;
    }
}

/// `_vm_object_allocate()` of the C.
///
/// # Safety
///
/// The caller must run after `vm_object_bootstrap()`, as [`cache_alloc()`]
/// requires.
unsafe fn allocate_internal(size: VmSize) -> *mut VmObject {
    let object = unsafe { cache_alloc() };
    if object.is_null() {
        return null_mut();
    }
    // SAFETY: the fresh object is unshared storage.
    unsafe { setup(object, size) };
    object
}

/// `vm_object_allocate()` of the C.
///
/// # Safety
///
/// The slab allocator and the IPC space must be up; the C panicked when
/// either allocation failed.
pub(crate) unsafe fn allocate(size: VmSize) -> NonNull<VmObject> {
    let object = unsafe { allocate_internal(size) };
    let object = NonNull::new(object)
        .unwrap_or_else(|| die("vm_object_allocate", "vm_object_allocate"));

    unsafe {
        let port = ipc_port::alloc_special(ipc_space::kernel())
            .map_or(null_mut(), IpcPort::as_ptr);
        if port.is_null() {
            die("vm_object_allocate", "vm_object_allocate");
        }
        (*object.as_ptr()).pager_name = port;
        ipc_kobject::set(port, object.as_ptr().addr(), IKOT_PAGING_NAME);
    }

    object
}

/// `vm_object_allocate()` of the C.
///
/// # Safety
///
/// The slab and IPC packages must be initialized, as the C assumed.
pub(crate) unsafe fn vm_object_allocate(size: VmSize) -> *mut VmObject {
    unsafe { allocate(size) }.as_ptr()
}

/// `vm_object_bootstrap()` of the C.
pub(crate) fn bootstrap() {
    // SAFETY: the call runs once in the bootstrap sequence, after the slab
    // package is up and before any allocation from the cache.
    unsafe {
        (*addr_of_mut!(VM_OBJECT_CACHE)).init(
            b"vm_object",
            size_of::<VmObject>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }

    // SAFETY: no object exists yet, so the template is unshared; the C's
    // assignments are written in the declaration order.
    unsafe {
        let template = addr_of_mut!(VM_OBJECT_TEMPLATE);
        (*template).ref_count = 1;
        (*template).size = 0;
        (*template).resident_page_count = 0;
        (*template).copy = null_mut();
        (*template).shadow = null_mut();
        (*template).shadow_offset = 0;
        (*template).pager = null_mut();
        (*template).paging_offset = 0;
        (*template).pager_request = null_mut();
        (*template).pager_name = null_mut();
        (*template).set_pager_created(false);
        (*template).set_pager_initialized(false);
        (*template).set_pager_ready(false);
        (*template).copy_strategy = MEMORY_OBJECT_COPY_NONE;
        (*template).set_use_shared_copy(false);
        (*template).set_shadowed(false);
        (*template).absent_count = 0;
        (*template).all_wanted = 0;
        (*template).set_paging_in_progress(0);
        (*template).set_used_for_pageout(false);
        (*template).set_can_persist(false);
        (*template).set_cached(false);
        (*template).set_internal(true);
        (*template).set_temporary(true);
        (*template).set_alive(true);
        (*template).last_alloc = 0;
        (*template).existence_info = null_mut();
    }

    // SAFETY: the two objects are the boot storage; nothing else has their
    // addresses yet.
    unsafe {
        setup(addr_of_mut!(KERNEL_OBJECT_STORE), KERNEL_OBJECT_SIZE);
        setup(addr_of_mut!(VM_SUBMAP_OBJECT_STORE), KERNEL_OBJECT_SIZE);
    }

    // SAFETY: the external map caches are part of the same bootstrap.
    unsafe { vm_external::vm_external_module_initialize() };
}

/// `vm_object_init()` of the C.
pub(crate) fn init() {
    // SAFETY: the kernel object is the boot storage, live and unshared at
    // this point in the sequence.
    unsafe {
        let object = addr_of_mut!(KERNEL_OBJECT_STORE);
        let port = ipc_port::alloc_special(ipc_space::kernel())
            .map_or(null_mut(), IpcPort::as_ptr);
        (*object).pager_name = port;
        ipc_kobject::set(port, object.addr(), IKOT_PAGING_NAME);
    }
}

/// `vm_object_collect()` of the C.
///
/// # Safety
///
/// The object lock must be held, and the caller must own a reference to the
/// object.
pub(crate) unsafe fn collect(object: *mut VmObject) {
    unsafe {
        (*object).lock.unlock();
        cache_lock();
        (*object).lock.lock();
        if !(*object).is_collectable() {
            (*object).lock.unlock();
            cache_unlock();
            return;
        }
        cache_remove(object);
        terminate(object);
    }
}

/// `vm_object_reference()` of the C.
///
/// # Safety
///
/// `object` must be null or a live object.
pub(crate) unsafe fn reference(object: *mut VmObject) {
    if object.is_null() {
        return;
    }
    unsafe {
        (*object).lock.lock();
        (*object).ref_count += 1;
        (*object).lock.unlock();
    }
}

/// `vm_object_deallocate()` of the C.
///
/// # Safety
///
/// `object` must be null or a live object the caller holds a reference to;
/// no lock of the caller's may be held.
pub(crate) unsafe fn deallocate(object: *mut VmObject) {
    let mut object = object;
    while !object.is_null() {
        unsafe {
            cache_lock();
            (*object).lock.lock();
            (*object).ref_count -= 1;
            if (*object).ref_count > 0 {
                (*object).lock.unlock();
                cache_unlock();
                return;
            }

            let persist =
                (*object).can_persist() && (*object).resident_page_count > 0;
            if persist {
                cache_add(object);
                cache_unlock();
                (*object).lock.unlock();
                return;
            }

            if (*object).is_pager_created()
                && !(*object).is_pager_initialized()
            {
                (*object).ref_count += 1;
                assert_wait_event(object, EVENT_INITIALIZED, false);
                (*object).lock.unlock();
                cache_unlock();
                thread_block(None);
                continue;
            }

            let shadow = (*object).shadow;
            terminate(object);
            object = shadow;
        }
    }
}

/// `vm_object_terminate()` of the C.
///
/// # Safety
///
/// On entry the object lock and the cache lock must be held, the object
/// must be live and out of references, and its shadow reference is left
/// alone; on exit the cache and the object are unlocked.
pub(crate) unsafe fn terminate(object: *mut VmObject) {
    unsafe {
        (*object).set_alive(false);
        remove(object);
        cache_unlock();
    }

    // SAFETY: the storage is live until the free at the end, and its
    // lock is held.
    let shadow = unsafe { (*object).shadow };
    if !shadow.is_null() {
        // SAFETY: the shadow is a live object the terminated object's chain
        // points at.
        unsafe {
            (*shadow).lock.lock();
            (*shadow).copy = null_mut();
            (*shadow).lock.unlock();
        }
    }

    // SAFETY: the object is dead but its lock is still held by the caller's
    // thread until the wait below.
    unsafe { paging_wait(object, false) };

    // SAFETY: the object is live until the free at the end.
    unsafe {
        let temporary = (*object).is_temporary();
        let pager = (*object).pager;
        let head = addr_of_mut!((*object).memq);

        if temporary || pager.is_null() {
            while let Some(entry) = (*head).cursor_front().current_ptr() {
                let page = entry.as_ptr();
                vm_page::check(page);
                page_free(page);
            }
        } else {
            while let Some(entry) = (*head).cursor_front().current_ptr() {
                let page = entry.as_ptr();
                vm_page::check(page);
                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::queues_remove(page);
                VM_PAGE_QUEUE_LOCK.unlock();

                if (*page).is_absent() || (*page).is_private() {
                    page_free(page);
                    continue;
                }

                if !(*page).is_dirty() {
                    (*page)
                        .set_dirty(pmap_is_modified((*page).phys_addr) != 0);
                }

                if (*page).is_dirty() || (*page).is_precious() {
                    (*page).set_busy(true);
                    vm_pageout_page(page, 0, 1);
                } else {
                    page_free(page);
                }
            }
        }

        if !(*object).is_internal() {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::VM_OBJECT_EXTERNAL_COUNT
                .fetch_sub(1, Ordering::Relaxed);
            VM_PAGE_QUEUE_LOCK.unlock();
        }

        (*object).lock.unlock();

        let pager = (*object).pager;
        if !pager.is_null() {
            memory_object_release(
                pager,
                (*object).pager_request,
                (*object).pager_name,
            );
        } else if !(*object).pager_name.is_null() {
            ipc_port::dealloc_special(IpcPort::from_raw((*object).pager_name));
        }

        vm_external::vm_external_destroy((*object).existence_info.cast());
    }
    // SAFETY: the object is dead and owned here, as the C's free required.
    unsafe { cache_free(object) };
}

/// `vm_object_pager_wakeup()` of the C.
///
/// # Safety
///
/// `pager` must be null or a live port.
pub(crate) unsafe fn pager_wakeup(pager: *mut c_void) {
    let Some(port) = IpcPort::new(pager) else {
        return;
    };

    unsafe {
        cache_lock();
        let someone_waiting = !port.kobject().is_null();
        if port.is_active() {
            ipc_kobject::set(pager, 0, IKOT_NONE);
        }
        cache_unlock();
        if someone_waiting {
            thread_wakeup_prim(pager, 0, THREAD_AWAKENED);
        }
    }
}

/// `memory_object_release()` of the C.
///
/// # Safety
///
/// `pager` must be null or a live memory-object port; `pager_request` and
/// `pager_name` are its ports, consumed by the call.
pub(crate) unsafe fn memory_object_release(
    pager: *mut c_void,
    pager_request: *mut c_void,
    pager_name: *mut c_void,
) {
    let Some(port) = IpcPort::new(pager) else {
        return;
    };

    unsafe {
        port.reference();
        memory_object_terminate(pager, pager_request, pager_name);
        pager_wakeup(pager);
        port.release();
    }
}

/// `vm_object_abort_activity()` of the C.
///
/// # Safety
///
/// The object lock must be held.
unsafe fn abort_activity(object: *mut VmObject) {
    unsafe {
        let head = addr_of_mut!((*object).memq);
        let mut entry = (*head).cursor_front().current_ptr();
        while let Some(e) = entry {
            let page = e.as_ptr();
            let next = next_page(head, page);

            if (*page).is_busy() && (*page).is_absent() {
                page_free(page);
            } else {
                if (*page).unlock_request() != VmProt::NONE {
                    (*page).set_unlock_request(VmProt::NONE);
                }
                page_wakeup(page);
            }

            entry = next;
        }

        (*object).set_pager_ready(true);
        wakeup(object, EVENT_PAGER_READY);
    }
}

/// `memory_object_destroy()` of the C.
///
/// # Safety
///
/// `object` must be null or a live object, and the caller must own a
/// reference to it.
pub(crate) unsafe fn memory_object_destroy(object: *mut VmObject) {
    if object.is_null() {
        return;
    }

    unsafe {
        cache_lock();
        (*object).lock.lock();
        remove(object);
        (*object).set_can_persist(false);
        cache_unlock();

        let old_object = (*object).pager;
        (*object).pager = null_mut();
        let old_control = (*object).pager_request;
        (*object).pager_request = null_mut();
        let old_name = (*object).pager_name;
        (*object).pager_name = null_mut();

        paging_wait(object, false);
        (*object).lock.unlock();

        if !old_object.is_null() {
            memory_object_release(old_object, old_control, old_name);
        } else if !old_name.is_null() {
            // The C reads the already-cleared field here; the null is kept
            // so the two halves behave alike.
            ipc_port::dealloc_special(IpcPort::from_raw((*object).pager_name));
        }

        deallocate(object);
    }
}

/// `vm_object_pmap_protect()` of the C.
///
/// # Safety
///
/// `object` must be null or a live object; `pmap` must be null or a live
/// physical map, as the C's callers guaranteed.
pub(crate) unsafe fn pmap_protect(
    mut object: *mut VmObject,
    mut offset: VmOffset,
    size: VmSize,
    pmap: *mut Pmap,
    pmap_start: VmOffset,
    prot: VmProt,
) {
    if object.is_null() {
        return;
    }

    unsafe { (*object).lock.lock() };

    loop {
        // SAFETY: the object is live and locked.
        unsafe {
            if (*object).resident_page_count > atop(size) / 2
                && !pmap.is_null()
            {
                (*object).lock.unlock();
                crate::arch::x86_64::pmap::pmap_protect(
                    NonNull::new(pmap),
                    pmap_start,
                    pmap_start.wrapping_add(size),
                    prot.bits(),
                );
                return;
            }

            let end = offset.wrapping_add(size);
            let head = addr_of_mut!((*object).memq);
            let mut cursor = (*head).cursor_front();
            while let Some(e) = cursor.current_ptr() {
                cursor.move_next();
                let page = e.as_ptr();
                if !(*page).is_fictitious()
                    && offset <= (*page).offset
                    && (*page).offset < end
                {
                    if pmap.is_null()
                        || VM_OBJECT_PMAP_PROTECT_BY_PAGE
                            .load(Ordering::Relaxed)
                            != 0
                    {
                        pmap_page_protect(
                            (*page).phys_addr,
                            prot.bits() & !(*page).page_lock().bits(),
                        );
                    } else {
                        let start =
                            pmap_start.wrapping_add((*page).offset - offset);
                        crate::arch::x86_64::pmap::pmap_protect(
                            NonNull::new(pmap),
                            start,
                            start.wrapping_add(PAGE_SIZE),
                            prot.bits(),
                        );
                    }
                }
            }

            if prot == VmProt::NONE {
                let next_object = (*object).shadow;
                if next_object.is_null() {
                    break;
                }
                offset = offset.wrapping_add((*object).shadow_offset);
                (*next_object).lock.lock();
                (*object).lock.unlock();
                object = next_object;
                continue;
            }
            break;
        }
    }

    // SAFETY: the lock was taken above and the chain walk keeps it held.
    unsafe { (*object).lock.unlock() };
}

/// `vm_object_pmap_protect()` of the C.
///
/// # Safety
///
/// `object` must be null or a live object; `pmap` must be null or a live
/// physical map over the range the C's caller checked.
pub(crate) unsafe fn vm_object_pmap_protect(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
    pmap: *mut Pmap,
    pmap_start: VmOffset,
    prot: c_int,
) {
    unsafe {
        pmap_protect(
            object,
            offset,
            size,
            pmap,
            pmap_start,
            VmProt::from_bits(prot),
        );
    };
}

/// `vm_object_pmap_remove()` of the C.
///
/// # Safety
///
/// `object` must be null or a live object, and the caller must hold no lock
/// of it.
pub(crate) unsafe fn pmap_remove(
    mut object: *mut VmObject,
    mut start: VmOffset,
    mut end: VmOffset,
) {
    if object.is_null() {
        return;
    }

    unsafe { (*object).lock.lock() };

    loop {
        // SAFETY: the object is live and locked.
        unsafe {
            let head = addr_of_mut!((*object).memq);
            let mut cursor = (*head).cursor_front();
            while let Some(e) = cursor.current_ptr() {
                cursor.move_next();
                let page = e.as_ptr();
                if !(*page).is_fictitious()
                    && start <= (*page).offset
                    && (*page).offset < end
                {
                    pmap_page_protect((*page).phys_addr, VmProt::NONE.bits());
                }
            }

            let shadow = (*object).shadow;
            if shadow.is_null() {
                break;
            }
            let prev_object = object;
            start = start.wrapping_add((*object).shadow_offset);
            end = end.wrapping_add((*object).shadow_offset);
            object = shadow;
            (*object).lock.lock();
            (*prev_object).lock.unlock();
        }
    }

    // SAFETY: the lock was taken above and the chain walk keeps it held.
    unsafe { (*object).lock.unlock() };
}

/// Copy the fault's result page into `new_page`, wake the waiters and clean
/// the fault up: the success arm of `vm_object_copy_slowly()`.
///
/// # Safety
///
/// `result_page` must be the page the fault left locked with its paging
/// reference, `top_page` the fault's top page, and `new_page` this call's
/// fresh page.
unsafe fn copy_slowly_done(
    result_page: *mut VmPage,
    top_page: *mut VmPage,
    new_page: NonNull<VmPage>,
) {
    // SAFETY: the fault left the result page's object locked and holds its
    // paging reference.
    unsafe {
        (*(*result_page).object).lock.unlock();
        vm_resident::copy(NonNull::new_unchecked(result_page), new_page);
        (*new_page.as_ptr()).set_busy(false);
        (*new_page.as_ptr()).set_dirty(true);
        (*(*result_page).object).lock.lock();
        page_wakeup_done(result_page);
        VM_PAGE_QUEUE_LOCK.lock();
        if !(*result_page).is_active() && !(*result_page).is_inactive() {
            vm_page::activate(result_page);
        }
        vm_page::activate(new_page.as_ptr());
        VM_PAGE_QUEUE_LOCK.unlock();
        vm_fault::cleanup((*result_page).object, NonNull::new(top_page));
    }
}

/// `vm_object_copy_slowly()` of the C.
///
/// # Safety
///
/// On entry the source object must be live, locked, and hold a reference;
/// on exit it is unlocked.  The returned object is owned by the caller.
pub(crate) unsafe fn copy_slowly(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
    interruptible: bool,
) -> Result<NonNull<VmObject>, Error> {
    if size == 0 {
        unsafe { (*src_object).lock.unlock() };
        return Err(Error::InvalidArgument);
    }

    unsafe {
        (*src_object).ref_count += 1;
        (*src_object).lock.unlock();
    }

    let new_object = unsafe { allocate(size) };

    let mut src_offset = src_offset;
    let mut new_offset: VmOffset = 0;
    let mut remaining = size;

    while remaining != 0 {
        // SAFETY: the new object is live and owned here.
        let new_page = unsafe {
            (*new_object.as_ptr()).lock.lock();
            loop {
                if let Some(page) = vm_resident::alloc(new_object, new_offset)
                {
                    break page;
                }
                (*new_object.as_ptr()).lock.unlock();
                vm_page::wait(None);
                (*new_object.as_ptr()).lock.lock();
            }
        };
        // SAFETY: the page was allocated for this object and the lock
        // guarded the allocation.
        unsafe { (*new_object.as_ptr()).lock.unlock() };

        loop {
            // SAFETY: the source object is live and unlocked between the
            // page allocations, as the C's lock protocol has it.
            let fault = unsafe {
                (*src_object).lock.lock();
                paging_begin(src_object);
                vm_fault::fault_page(
                    src_object,
                    src_offset,
                    VmProt::READ,
                    false,
                    interruptible,
                    VmProt::READ,
                    false,
                    None,
                )
            };

            match fault.result {
                VM_FAULT_SUCCESS => {
                    // SAFETY: the fault left the result page's object
                    // locked and holds its paging reference; `new_page` is
                    // this call's fresh page.
                    unsafe {
                        copy_slowly_done(
                            fault.result_page,
                            fault.top_page,
                            new_page,
                        );
                    }
                    break;
                }
                VM_FAULT_MEMORY_SHORTAGE => {
                    // SAFETY: the page wait takes no continuation.
                    unsafe { vm_page::wait(None) };
                }
                VM_FAULT_FICTITIOUS_SHORTAGE => {
                    // SAFETY: the slab package is up in this path.
                    unsafe { vm_resident::more_fictitious() };
                }
                VM_FAULT_INTERRUPTED => {
                    // SAFETY: the fresh page belongs to this call.
                    unsafe {
                        vm_resident::free(new_page);
                        deallocate(new_object.as_ptr());
                        deallocate(src_object);
                    }
                    return Err(Error::SendInterrupted);
                }
                VM_FAULT_MEMORY_ERROR => {
                    // SAFETY: the fresh page belongs to this call.
                    unsafe {
                        vm_resident::free(new_page);
                        deallocate(new_object.as_ptr());
                        deallocate(src_object);
                    }
                    return Err(Error::MemoryError);
                }
                _ => (),
            }
        }

        src_offset = src_offset.wrapping_add(PAGE_SIZE);
        new_offset = new_offset.wrapping_add(PAGE_SIZE);
        remaining = remaining.wrapping_sub(PAGE_SIZE);
    }

    // SAFETY: the extra reference taken above.
    unsafe { deallocate(src_object) };

    Ok(new_object)
}

/// `vm_object_copy_slowly()` of the C.
///
/// # Safety
///
/// The source object must be live and locked on entry and holds a reference;
/// `result_object` must be writable.
pub(crate) unsafe fn vm_object_copy_slowly(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
    interruptible: c_int,
    result_object: *mut *mut VmObject,
) -> c_int {
    let result = unsafe {
        copy_slowly(src_object, src_offset, size, interruptible != 0)
    };

    match result {
        Ok(object) => {
            unsafe { result_object.write(object.as_ptr()) };
            KERN_SUCCESS
        }
        Err(error) => {
            unsafe { result_object.write(null_mut()) };
            error.as_kern_return()
        }
    }
}

/// What `vm_object_copy_temporary()` hands back when it can copy without
/// blocking.
pub(crate) struct TemporaryCopy {
    /// The object the caller's slot becomes.
    pub object: *mut VmObject,
    /// The source must make a shadow.
    pub src_needs_copy: bool,
    /// The destination must make a shadow.
    pub dst_needs_copy: bool,
}

/// `vm_object_copy_temporary()` of the C.
///
/// # Safety
///
/// A non-null `object` must be a live object, unlocked.
pub(crate) unsafe fn copy_temporary(
    object: Option<NonNull<VmObject>>,
) -> Option<TemporaryCopy> {
    let Some(object) = object else {
        return Some(TemporaryCopy {
            object: null_mut(),
            src_needs_copy: false,
            dst_needs_copy: false,
        });
    };
    let object = object.as_ptr();

    unsafe {
        (*object).lock.lock();

        if (*object).is_temporary() {
            if (*object).use_shared_copy() {
                (*object).lock.unlock();
                let object = copy_delayed(object).as_ptr();
                return Some(TemporaryCopy {
                    object,
                    src_needs_copy: false,
                    dst_needs_copy: true,
                });
            }

            (*object).ref_count += 1;
            (*object).set_shadowed(true);
            (*object).lock.unlock();

            return Some(TemporaryCopy {
                object,
                src_needs_copy: true,
                dst_needs_copy: true,
            });
        }

        // The C's `XXX Do something intelligent` arm changed nothing.
        (*object).lock.unlock();
    }

    None
}

/// `vm_object_copy_temporary()` of the C.
///
/// # Safety
///
/// `object` and `offset` must be the caller's writable slots; on success the
/// other two slots are written too, as the C wrote them.
pub(crate) unsafe fn vm_object_copy_temporary(
    object: *mut *mut VmObject,
    _offset: *mut VmOffset,
    src_needs_copy: *mut c_int,
    dst_needs_copy: *mut c_int,
) -> c_int {
    unsafe { copy_temporary(NonNull::new(*object)) }.map_or_else(
        || c_int::from(false),
        |copy| {
            unsafe {
                object.write(copy.object);
                src_needs_copy.write(c_int::from(copy.src_needs_copy));
                dst_needs_copy.write(c_int::from(copy.dst_needs_copy));
            }
            c_int::from(true)
        },
    )
}

/// `vm_object_copy_call()` of the C.
///
/// # Safety
///
/// The source object must be live and locked on entry and is unlocked on
/// exit; the returned object is owned by the caller.
unsafe fn copy_call(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
) -> Result<NonNull<VmObject>, Error> {
    let src_end = src_offset.wrapping_add(size);

    // SAFETY: the kernel space is live for the kernel's lifetime.
    let new_memory_object = unsafe {
        ipc_port::alloc_special(ipc_space::kernel())
            .map_or(null_mut(), IpcPort::as_ptr)
    };
    if new_memory_object.is_null() {
        return Err(Error::ResourceShortage);
    }

    unsafe {
        (*src_object).ref_count += 1;
        paging_begin(src_object);
        (*src_object).lock.unlock();

        ipc_port::make_send(IpcPort::from_raw(new_memory_object)).as_ptr();

        memory_object_copy(
            (*src_object).pager,
            (*src_object).pager_request,
            src_offset,
            size,
            new_memory_object,
        );

        (*src_object).lock.lock();
        paging_end(src_object);

        let head = addr_of_mut!((*src_object).memq);
        let mut cursor = (*head).cursor_front();
        while let Some(e) = cursor.current_ptr() {
            cursor.move_next();
            let page = e.as_ptr();
            if !(*page).is_fictitious()
                && src_offset <= (*page).offset
                && (*page).offset < src_end
                && !(*page).page_lock().contains(VmProt::WRITE)
            {
                (*page).set_page_lock((*page).page_lock() | VmProt::WRITE);
                pmap_page_protect(
                    (*page).phys_addr,
                    (VmProt::ALL
                        & VmProt::from_bits(!(*page).page_lock().bits()))
                    .bits(),
                );
            }
        }

        (*src_object).lock.unlock();
    }

    // SAFETY: the new port carries the object the C looked up.
    let Some(new_object) = (unsafe { enter(new_memory_object, size, false) })
    else {
        die("vm_object_copy_call", "vm_object_enter");
    };

    // SAFETY: the object is fresh and owned here.
    unsafe {
        (*new_object.as_ptr()).shadow = src_object;
        (*new_object.as_ptr()).shadow_offset = src_offset;
        ipc_port::release_send(IpcPort::from_raw(new_memory_object));
    }

    Ok(new_object)
}

/// `vm_object_copy_delayed()` of the C.
///
/// # Safety
///
/// The source object must be live and unlocked; the returned object is
/// owned by the caller.
pub(crate) unsafe fn copy_delayed(
    src_object: *mut VmObject,
) -> NonNull<VmObject> {
    let new_copy = unsafe { allocate((*src_object).size) };

    // SAFETY: the source is live and unlocked on entry, as the C requires.
    unsafe {
        (*src_object).lock.lock();

        loop {
            let old_copy = (*src_object).copy;
            if !old_copy.is_null() {
                if !(*old_copy).lock.try_lock() {
                    (*src_object).lock.unlock();
                    simple_lock_pause();
                    (*src_object).lock.lock();
                    continue;
                }

                if (*old_copy).resident_page_count == 0
                    && !(*old_copy).is_pager_created()
                {
                    (*old_copy).ref_count += 1;
                    (*old_copy).lock.unlock();
                    (*src_object).lock.unlock();

                    deallocate(new_copy.as_ptr());

                    return NonNull::new_unchecked(old_copy);
                }

                (*src_object).ref_count -= 1;
                (*old_copy).shadow = new_copy.as_ptr();
                (*new_copy.as_ptr()).ref_count += 1;
                (*old_copy).lock.unlock();
            }

            (*new_copy.as_ptr()).shadow = src_object;
            (*new_copy.as_ptr()).shadow_offset = 0;
            (*new_copy.as_ptr()).set_shadowed(true);
            (*src_object).ref_count += 1;
            (*src_object).copy = new_copy.as_ptr();

            let head = addr_of_mut!((*src_object).memq);
            let mut cursor = (*head).cursor_front();
            while let Some(e) = cursor.current_ptr() {
                cursor.move_next();
                let page = e.as_ptr();
                if !(*page).is_fictitious() {
                    pmap_page_protect(
                        (*page).phys_addr,
                        (VmProt::ALL
                            & VmProt::from_bits(!VmProt::WRITE.bits())
                            & VmProt::from_bits(!(*page).page_lock().bits()))
                        .bits(),
                    );
                }
            }

            (*src_object).lock.unlock();

            return new_copy;
        }
    }
}

/// What `copy_strategically()` wrote through the C's out-parameters before
/// returning.
pub(crate) enum StrategicResult {
    /// The copy succeeded and all three slots are set.
    Copied {
        object: NonNull<VmObject>,
        offset: VmOffset,
        needs_copy: bool,
    },
    /// The ready wait was interrupted: the C wrote null, zero and false.
    Interrupted,
    /// `copy_slowly()` failed after writing a null object; the other slots
    /// are untouched.
    NullObject(Error),
    /// The copy failed without touching the caller's slots.
    Failed(Error),
    /// The strategy was not one of the three: success, slots untouched.
    Unchanged,
}

/// `vm_object_copy_strategically()` of the C.
///
/// # Safety
///
/// The source object must be live and unlocked, and the caller must own a
/// reference to it.
pub(crate) unsafe fn copy_strategically(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
) -> StrategicResult {
    let interruptible = true;

    unsafe {
        (*src_object).lock.lock();

        while !(*src_object).is_pager_ready() {
            wait(src_object, EVENT_PAGER_READY, interruptible);
            if interruptible
                && (*per_cpu::thread()).wait_result != THREAD_AWAKENED
            {
                return StrategicResult::Interrupted;
            }
            (*src_object).lock.lock();
        }

        if (*src_object).is_temporary() {
            (*src_object).copy_strategy = MEMORY_OBJECT_COPY_DELAY;
        }

        match (*src_object).copy_strategy {
            MEMORY_OBJECT_COPY_NONE => {
                match copy_slowly(src_object, src_offset, size, interruptible)
                {
                    Ok(object) => StrategicResult::Copied {
                        object,
                        offset: 0,
                        needs_copy: false,
                    },
                    Err(error) => StrategicResult::NullObject(error),
                }
            }
            MEMORY_OBJECT_COPY_CALL => {
                match copy_call(src_object, src_offset, size) {
                    Ok(object) => StrategicResult::Copied {
                        object,
                        offset: 0,
                        needs_copy: false,
                    },
                    Err(error) => StrategicResult::Failed(error),
                }
            }
            MEMORY_OBJECT_COPY_DELAY => {
                (*src_object).lock.unlock();
                let object = copy_delayed(src_object);
                StrategicResult::Copied {
                    object,
                    offset: src_offset,
                    needs_copy: true,
                }
            }
            _ => StrategicResult::Unchanged,
        }
    }
}

/// `vm_object_copy_strategically()` of the C.
///
/// # Safety
///
/// The source object must be live and unlocked; the three slots are written
/// as the C wrote them, which is not on every failure path.
pub(crate) unsafe fn vm_object_copy_strategically(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
    dst_object: *mut *mut VmObject,
    dst_offset: *mut VmOffset,
    dst_needs_copy: *mut c_int,
) -> c_int {
    match unsafe { copy_strategically(src_object, src_offset, size) } {
        StrategicResult::Copied {
            object,
            offset,
            needs_copy,
        } => {
            unsafe {
                dst_object.write(object.as_ptr());
                dst_offset.write(offset);
                dst_needs_copy.write(c_int::from(needs_copy));
            }
            KERN_SUCCESS
        }
        StrategicResult::Interrupted => {
            unsafe {
                dst_object.write(null_mut());
                dst_offset.write(0);
                dst_needs_copy.write(c_int::from(false));
            }
            MACH_SEND_INTERRUPTED
        }
        StrategicResult::NullObject(error) => {
            unsafe { dst_object.write(null_mut()) };
            error.as_kern_return()
        }
        StrategicResult::Failed(error) => error.as_kern_return(),
        StrategicResult::Unchanged => KERN_SUCCESS,
    }
}

/// `vm_object_shadow()` of the C.
///
/// # Safety
///
/// `source` must be null or a live object the caller holds a reference to;
/// the reference moves to the returned object.
pub(crate) unsafe fn shadow(
    source: *mut VmObject,
    offset: VmOffset,
    length: VmSize,
) -> NonNull<VmObject> {
    let result = unsafe { allocate(length) };

    // SAFETY: the object is fresh and owned here.
    unsafe {
        (*result.as_ptr()).shadow = source;
        (*result.as_ptr()).shadow_offset = offset;
    }

    result
}

/// `vm_object_shadow()` of the C.
///
/// # Safety
///
/// `object` and `offset` must be writable slots for a live-in object and an
/// offset; the object's reference moves to the shadow created here.
pub(crate) unsafe fn vm_object_shadow(
    object: *mut *mut VmObject,
    offset: *mut VmOffset,
    length: VmSize,
) {
    unsafe {
        let source = *object;
        let shadow = shadow(source, *offset, length);
        object.write(shadow.as_ptr());
        offset.write(0);
    }
}

/// The `vm_object_lookup()`/`vm_object_lookup_name()` body.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
unsafe fn lookup_kotype(
    port: *mut c_void,
    kotype: c_uint,
) -> Option<NonNull<VmObject>> {
    if !port_valid(port) {
        return None;
    }
    let port = IpcPort::new(port)?;

    // SAFETY: `port_valid()` promises a live port.
    unsafe {
        port.lock();

        let mut object: *mut VmObject = null_mut();
        if port.is_active() && port.kotype() == kotype {
            cache_lock();
            object = port.kobject().cast::<VmObject>();
            (*object).lock.lock();

            if (*object).ref_count == 0 {
                cache_remove(object);
            }
            (*object).ref_count += 1;
            (*object).lock.unlock();
            cache_unlock();
        }

        port.unlock();
        NonNull::new(object)
    }
}

/// `vm_object_lookup()` of the C.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
pub(crate) unsafe fn lookup(port: *mut c_void) -> Option<NonNull<VmObject>> {
    unsafe { lookup_kotype(port, IKOT_PAGING_REQUEST) }
}

/// `vm_object_lookup_name()` of the C.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
pub(crate) unsafe fn lookup_name(
    port: *mut c_void,
) -> Option<NonNull<VmObject>> {
    unsafe { lookup_kotype(port, IKOT_PAGING_NAME) }
}

/// `vm_object_destroy()` of the C.
///
/// # Safety
///
/// `pager` must be null, dead, or a live memory-object port.
pub(crate) unsafe fn destroy(pager: *mut c_void) {
    let Some(port) = IpcPort::new(pager) else {
        return;
    };

    unsafe {
        cache_lock();
        if port.kotype() != IKOT_PAGER {
            cache_unlock();
            return;
        }

        let object = port.kobject().cast::<VmObject>();
        (*object).lock.lock();
        if (*object).ref_count == 0 {
            cache_remove(object);
        }
        (*object).ref_count += 1;
        (*object).set_can_persist(false);

        (*object).pager = null_mut();
        remove(object);
        let old_request = (*object).pager_request;
        (*object).pager_request = null_mut();
        let old_name = (*object).pager_name;
        (*object).pager_name = null_mut();

        (*object).lock.unlock();
        cache_unlock();

        ipc_port::release_send(IpcPort::from_raw(pager));
        if !old_request.is_null() {
            ipc_port::dealloc_special(IpcPort::from_raw(old_request));
        }
        if !old_name.is_null() {
            ipc_port::dealloc_special(IpcPort::from_raw(old_name));
        }

        (*object).lock.lock();
        abort_activity(object);
        (*object).lock.unlock();

        deallocate(object);
    }
}

/// Initialize a fresh object's pager association and wait for the pager,
/// the `must_init` tail of [`enter()`].
///
/// # Safety
///
/// `object` must be the live object the pager association produced, `pager`
/// the live pager port, and the caller must hold the cache lock.
unsafe fn enter_init(
    object: *mut VmObject,
    pager: *mut c_void,
    internal: bool,
    must_init: bool,
) {
    unsafe {
        if must_init {
            let pager = ipc_port::copy_send(pager);
            if !port_valid(pager) {
                die("vm_object_enter", "vm_object_enter: port died");
            }

            (*object).set_pager_created(true);
            (*object).pager = pager;

            let request = ipc_port::alloc_special(ipc_space::kernel())
                .map_or(null_mut(), IpcPort::as_ptr);
            if request.is_null() {
                die("vm_object_enter", "vm_object_enter: pager request alloc");
            }
            (*object).pager_request = request;
            ipc_kobject::set(request, object.addr(), IKOT_PAGING_REQUEST);

            if internal {
                let dmm = default_manager::reference();
                (*object).set_internal(true);
                (*object).set_pager_ready(true);
                memory_object_create(
                    dmm.as_ptr(),
                    pager,
                    (*object).size,
                    (*object).pager_request,
                    (*object).pager_name,
                    PAGE_SIZE,
                );
            } else {
                (*object).set_internal(false);
                (*object).set_temporary(false);
                vm_resident::VM_OBJECT_EXTERNAL_COUNT
                    .fetch_add(1, Ordering::Relaxed);
                (*object).set_pager_ready(false);
                memory_object_init(
                    pager,
                    (*object).pager_request,
                    (*object).pager_name,
                    PAGE_SIZE,
                );
            }

            (*object).lock.lock();
            (*object).set_pager_initialized(true);
            wakeup(object, EVENT_INITIALIZED);
        } else {
            (*object).lock.lock();
        }

        while !(*object).is_pager_initialized() {
            wait(object, EVENT_INITIALIZED, false);
            (*object).lock.lock();
        }
        (*object).lock.unlock();
    }
}

/// `vm_object_enter()` of the C.
///
/// # Safety
///
/// `pager` must be null, dead, or a live port; the returned object is owned
/// by the caller.
pub(crate) unsafe fn enter(
    pager: *mut c_void,
    size: VmSize,
    internal: bool,
) -> Option<NonNull<VmObject>> {
    if !port_valid(pager) {
        return Some(unsafe { allocate(size) });
    }

    let mut new_object: *mut VmObject = null_mut();
    let mut must_init = false;

    'restart: loop {
        // SAFETY: `port_valid()` promised a live port, and the cache lock
        // guards the association, as the C requires.
        unsafe {
            cache_lock();
            let mut po;
            loop {
                po = IpcPort::from_raw(pager).kotype();

                if po == IKOT_PAGER_TERMINATING {
                    IpcPort::from_raw(pager).set_kobject(pager);
                    assert_wait(NonNull::new(pager), 0);
                    cache_unlock();
                    thread_block(None);
                    continue 'restart;
                }

                if po != IKOT_NONE {
                    break;
                }

                if new_object.is_null() {
                    cache_unlock();
                    let object = allocate(size);
                    new_object = object.as_ptr();
                    cache_lock();
                } else {
                    ipc_kobject::set(pager, new_object.addr(), IKOT_PAGER);
                    new_object = null_mut();
                    must_init = true;
                }
            }

            if internal {
                must_init = true;
            }

            let object = if po == IKOT_PAGER {
                IpcPort::from_raw(pager).kobject().cast::<VmObject>()
            } else {
                null_mut()
            };

            if !object.is_null() && !must_init {
                (*object).lock.lock();
                if (*object).ref_count == 0 {
                    cache_remove(object);
                }
                (*object).ref_count += 1;
                (*object).lock.unlock();

                VM_STAT.hits += 1;
            }
            VM_STAT.lookups += 1;
            cache_unlock();

            if !new_object.is_null() {
                deallocate(new_object);
            }

            if object.is_null() {
                return None;
            }

            // SAFETY: `object` is the live object the pager association
            // produced, `pager` the live port, and the cache lock is held.
            enter_init(object, pager, internal, must_init);

            return NonNull::new(object);
        }
    }
}

/// `vm_object_pager_create()` of the C.
///
/// # Safety
///
/// The object must be live and locked on entry and is locked on exit.
pub(crate) unsafe fn pager_create(object: *mut VmObject) {
    unsafe {
        if (*object).is_pager_created() {
            while !(*object).is_pager_initialized() {
                wait(object, EVENT_PAGER_READY, false);
                (*object).lock.lock();
            }
            return;
        }

        (*object).set_pager_created(true);
        paging_begin(object);
        (*object).lock.unlock();

        (*object).existence_info = vm_external::vm_external_create(
            (*object).size.wrapping_add((*object).paging_offset),
        )
        .cast();

        let pager = ipc_port::alloc_special(ipc_space::kernel())
            .map_or(null_mut(), IpcPort::as_ptr);
        if pager.is_null() {
            die(
                "vm_object_pager_create",
                "vm_object_pager_create: allocate pager port",
            );
        }

        ipc_port::make_send(IpcPort::from_raw(pager)).as_ptr();
        ipc_kobject::set(pager, object.addr(), IKOT_PAGER);

        if enter(pager, (*object).size, true).map(NonNull::as_ptr)
            != Some(object)
        {
            die("vm_object_pager_create", "vm_object_pager_create: mismatch");
        }

        ipc_port::release_send(IpcPort::from_raw(pager));

        (*object).lock.lock();
        paging_end(object);
    }
}

/// `vm_object_remove()` of the C.
///
/// # Safety
///
/// The cache lock must be held and `object` must be a live object.
pub(crate) unsafe fn remove(object: *mut VmObject) {
    unsafe {
        let pager = (*object).pager;
        if !pager.is_null() {
            let port = IpcPort::from_raw(pager);
            let kotype = port.kotype();
            if kotype == IKOT_PAGER {
                ipc_kobject::set(pager, 0, IKOT_PAGER_TERMINATING);
            } else if kotype != IKOT_NONE {
                die("vm_object_remove", "vm_object_remove: bad object port");
            }
        }

        let request = (*object).pager_request;
        if !request.is_null() {
            let port = IpcPort::from_raw(request);
            let kotype = port.kotype();
            if kotype == IKOT_PAGING_REQUEST {
                ipc_kobject::set(request, 0, IKOT_NONE);
            } else if kotype != IKOT_NONE {
                die("vm_object_remove", "vm_object_remove: bad request port");
            }
        }

        let name = (*object).pager_name;
        if !name.is_null() {
            let port = IpcPort::from_raw(name);
            let kotype = port.kotype();
            if kotype == IKOT_PAGING_NAME {
                ipc_kobject::set(name, 0, IKOT_NONE);
            } else if kotype != IKOT_NONE {
                die("vm_object_remove", "vm_object_remove: bad name port");
            }
        }
    }
}

/// Move the backing object's resident pages into `object`, the page walk of
/// `vm_object_collapse()`'s sole-reference arm.
///
/// # Safety
///
/// Both objects must be live, `object` must hold the object lock, and the
/// cached-object lock must be held; `backing_offset` and `size` must be
/// `object`'s shadow offset and size.
unsafe fn collapse_pages(
    object: *mut VmObject,
    backing_object: *mut VmObject,
    backing_offset: VmOffset,
    size: VmSize,
) {
    unsafe {
        let head = addr_of_mut!((*backing_object).memq);
        while let Some(entry) = (*head).cursor_front().current_ptr() {
            let page = entry.as_ptr();
            let new_offset = (*page).offset.wrapping_sub(backing_offset);

            if (*page).offset < backing_offset || new_offset >= size {
                page_free(page);
            } else {
                let pp = vm_resident::lookup(
                    NonNull::new_unchecked(object),
                    new_offset,
                );
                if pp.is_some_and(|pp| !(*pp.as_ptr()).is_absent()) {
                    page_free(page);
                } else {
                    vm_resident::rename(
                        NonNull::new_unchecked(page),
                        NonNull::new_unchecked(object),
                        new_offset,
                    );
                }
            }
        }
    }
}

/// The `VM_OBJECT_COLLAPSE_DEBUG` report of `vm_object_collapse()`.
///
/// # Safety
///
/// Both objects must be live.
unsafe fn collapse_debug(
    backing_object: *mut VmObject,
    object: *mut VmObject,
) {
    unsafe {
        match VM_OBJECT_COLLAPSE_DEBUG.load(Ordering::Relaxed) {
            0 => (),
            1 => {
                if !(*backing_object).pager.is_null()
                    || !(*backing_object).pager_request.is_null()
                {
                    collapse_print(backing_object, object);
                }
            }
            debug => {
                collapse_print(backing_object, object);
                if debug > 2 {
                    soft_debugger(c"vm_object_collapse".as_ptr());
                }
            }
        }
    }
}

/// Move the backing object's pager state onto `object` and free the backing
/// object, the tail of `vm_object_collapse()`'s sole-reference arm.
///
/// # Safety
///
/// Both objects must be live, `object` must hold the object lock, the
/// backing object's lock must be held, and the cached-object lock must be
/// held.
unsafe fn collapse_swap(
    object: *mut VmObject,
    backing_object: *mut VmObject,
    backing_offset: VmOffset,
) {
    unsafe {
        (*object).pager = (*backing_object).pager;
        if !(*object).pager.is_null() {
            ipc_kobject::set((*object).pager, object.addr(), IKOT_PAGER);
        }
        (*object)
            .set_pager_initialized((*backing_object).is_pager_initialized());
        (*object).set_pager_ready((*backing_object).is_pager_ready());
        (*object).set_pager_created((*backing_object).is_pager_created());

        (*object).pager_request = (*backing_object).pager_request;
        if !(*object).pager_request.is_null() {
            ipc_kobject::set(
                (*object).pager_request,
                object.addr(),
                IKOT_PAGING_REQUEST,
            );
        }
        let old_name_port = (*object).pager_name;
        if !old_name_port.is_null() {
            ipc_kobject::set(old_name_port, 0, IKOT_NONE);
        }
        (*object).pager_name = (*backing_object).pager_name;
        if !(*object).pager_name.is_null() {
            ipc_kobject::set(
                (*object).pager_name,
                object.addr(),
                IKOT_PAGING_NAME,
            );
        }

        cache_unlock();

        if !(*object).pager.is_null() {
            (*object).paging_offset =
                (*backing_object).paging_offset.wrapping_add(backing_offset);
        }

        (*object).existence_info = (*backing_object).existence_info;

        (*object).shadow = (*backing_object).shadow;
        (*object).shadow_offset = (*object)
            .shadow_offset
            .wrapping_add((*backing_object).shadow_offset);
        if !(*object).shadow.is_null() && !(*(*object).shadow).copy.is_null() {
            die(
                "vm_object_collapse",
                "vm_object_collapse: we collapsed a copy-object!",
            );
        }

        (*backing_object).set_alive(false);
        (*backing_object).lock.unlock();

        (*object).lock.unlock();
        if !old_name_port.is_null() {
            ipc_port::dealloc_special(IpcPort::from_raw(old_name_port));
        }
        cache_free(backing_object);
        (*object).lock.lock();

        OBJECT_COLLAPSES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bypass the backing object, the non-sole-reference arm of
/// `vm_object_collapse()`.
///
/// Returns `false` when the caller's `vm_object_collapse()` must return,
/// `true` when the loop may collapse another level.
///
/// # Safety
///
/// Both objects must be live, `object` must hold the object lock, and the
/// backing object's lock must be held.
unsafe fn collapse_bypass(
    object: *mut VmObject,
    backing_object: *mut VmObject,
    backing_offset: VmOffset,
    size: VmSize,
) -> bool {
    unsafe {
        if VM_OBJECT_COLLAPSE_BYPASS_ALLOWED.load(Ordering::Relaxed) == 0 {
            (*backing_object).lock.unlock();
            return false;
        }

        if (*backing_object).is_pager_created() {
            (*backing_object).lock.unlock();
            return false;
        }

        let head = addr_of_mut!((*backing_object).memq);
        let mut cursor = (*head).cursor_front();
        while let Some(e) = cursor.current_ptr() {
            cursor.move_next();
            let page = e.as_ptr();
            let new_offset = (*page).offset.wrapping_sub(backing_offset);

            if (*page).offset >= backing_offset
                && new_offset <= size
                && vm_resident::lookup(
                    NonNull::new_unchecked(object),
                    new_offset,
                )
                .is_none()
            {
                (*backing_object).lock.unlock();
                return false;
            }
        }

        (*object).shadow = (*backing_object).shadow;
        reference((*object).shadow);
        (*object).shadow_offset = (*object)
            .shadow_offset
            .wrapping_add((*backing_object).shadow_offset);

        if (*backing_object).copy == object {
            (*backing_object).copy = null_mut();
        }

        (*backing_object).ref_count -= 1;
        (*backing_object).lock.unlock();

        OBJECT_BYPASSES.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// `vm_object_collapse()` of the C.
///
/// # Safety
///
/// The object lock must be held on entry and is held on exit; the caller
/// must own a reference to the object.
pub(crate) unsafe fn collapse(object: *mut VmObject) {
    if VM_OBJECT_COLLAPSE_ALLOWED.load(Ordering::Relaxed) == 0 {
        return;
    }

    loop {
        unsafe {
            if object.is_null()
                || (*object).is_pager_created()
                || (*object).paging_in_progress() != 0
                || (*object).absent_count != 0
            {
                return;
            }

            let backing_object = (*object).shadow;
            if backing_object.is_null() {
                return;
            }

            (*backing_object).lock.lock();

            if !(*backing_object).is_internal()
                || (*backing_object).paging_in_progress() != 0
            {
                (*backing_object).lock.unlock();
                return;
            }

            if !(*backing_object).shadow.is_null()
                && !(*(*backing_object).shadow).copy.is_null()
            {
                (*backing_object).lock.unlock();
                return;
            }

            let backing_offset = (*object).shadow_offset;
            let size = (*object).size;

            if (*backing_object).ref_count == 1 {
                if !(*addr_of!(VM_OBJECT_CACHED_LOCK)).try_lock() {
                    (*backing_object).lock.unlock();
                    return;
                }

                // SAFETY: both objects are live, `object` holds its lock,
                // and the cached-object lock is held.
                collapse_pages(object, backing_object, backing_offset, size);
                // SAFETY: both objects are live.
                collapse_debug(backing_object, object);
                // SAFETY: both objects are live, `object` holds its lock,
                // the backing lock is held, and the cached-object lock is
                // held.
                collapse_swap(object, backing_object, backing_offset);
            } else {
                // SAFETY: both objects are live, `object` holds its lock,
                // and the backing lock is held.
                let collapsed = collapse_bypass(
                    object,
                    backing_object,
                    backing_offset,
                    size,
                );
                if !collapsed {
                    return;
                }
            }
        }
    }
}

/// The `printf` of `vm_object_collapse()`'s debug switch.
///
/// # Safety
///
/// Both objects must be live.
unsafe fn collapse_print(
    backing_object: *mut VmObject,
    object: *mut VmObject,
) {
    let (pager, request) =
        unsafe { ((*backing_object).pager, (*backing_object).pager_request) };
    kprint!(
        "vm_object_collapse: {:x} (pager {:x}, request {:x}) up to {:x}\n",
        backing_object.expose_provenance(),
        pager.expose_provenance(),
        request.expose_provenance(),
        object.expose_provenance(),
    );
}

/// `vm_object_page_remove()` of the C.
///
/// # Safety
///
/// The object must be live and locked.
pub(crate) unsafe fn page_remove(
    object: *mut VmObject,
    start: VmOffset,
    end: VmOffset,
) {
    unsafe {
        if atop(end.wrapping_sub(start)) < (*object).resident_page_count / 16 {
            PAGE_REMOVE_LOOKUP.fetch_add(1, Ordering::Relaxed);

            let mut start = start;
            while start < end {
                let page =
                    vm_resident::lookup(NonNull::new_unchecked(object), start);
                if let Some(page) = page {
                    if !(*page.as_ptr()).is_fictitious() {
                        pmap_page_protect(
                            (*page.as_ptr()).phys_addr,
                            VmProt::NONE.bits(),
                        );
                    }
                    page_free(page.as_ptr());
                }
                start = start.wrapping_add(PAGE_SIZE);
            }
        } else {
            PAGE_REMOVE_ITERATE.fetch_add(1, Ordering::Relaxed);

            let head = addr_of_mut!((*object).memq);
            let mut entry = (*head).cursor_front().current_ptr();
            while let Some(e) = entry {
                let page = e.as_ptr();
                let next = next_page(head, page);
                if start <= (*page).offset && (*page).offset < end {
                    if !(*page).is_fictitious() {
                        pmap_page_protect(
                            (*page).phys_addr,
                            VmProt::NONE.bits(),
                        );
                    }
                    page_free(page);
                }
                entry = next;
            }
        }
    }
}

/// `vm_object_coalesce()` of the C.
///
/// # Safety
///
/// A non-null object must be live, and the references move exactly as the
/// C's did.
pub(crate) unsafe fn coalesce(
    prev_object: Option<NonNull<VmObject>>,
    next_object: Option<NonNull<VmObject>>,
    prev_offset: VmOffset,
    next_offset: VmOffset,
    prev_size: VmSize,
    next_size: VmSize,
) -> Option<(*mut VmObject, VmOffset)> {
    if prev_object == next_object {
        let Some(prev_object) = prev_object else {
            return Some((null_mut(), 0));
        };

        if prev_offset.wrapping_add(prev_size) == next_offset {
            // SAFETY: the caller held a reference for each object, so one
            // of the two is dropped here, as the C drops it.
            unsafe { deallocate(prev_object.as_ptr()) };
            return Some((prev_object.as_ptr(), prev_offset));
        }

        return None;
    }

    let (object, is_prev) = match (prev_object, next_object) {
        (None, Some(next_object)) => (next_object, false),
        (Some(prev_object), None) => (prev_object, true),
        _ => return None,
    };
    let object = object.as_ptr();

    // SAFETY: the chosen object is live and unlocked, as the C requires.
    unsafe {
        (*object).lock.lock();
        collapse(object);

        if (*object).ref_count > 1
            || (*object).is_pager_created()
            || (*object).is_used_for_pageout()
            || !(*object).shadow.is_null()
            || !(*object).copy.is_null()
            || (*object).paging_in_progress() != 0
        {
            (*object).lock.unlock();
            return None;
        }

        let new_offset = if is_prev {
            page_remove(
                object,
                prev_offset.wrapping_add(prev_size),
                prev_offset.wrapping_add(prev_size).wrapping_add(next_size),
            );

            let newsize =
                prev_offset.wrapping_add(prev_size).wrapping_add(next_size);
            if newsize > (*object).size {
                (*object).size = newsize;
            }

            prev_offset
        } else {
            if next_offset < prev_size {
                (*object).lock.unlock();
                return None;
            }

            page_remove(
                object,
                next_offset.wrapping_sub(prev_size),
                next_offset,
            );

            next_offset.wrapping_sub(prev_size)
        };

        (*object).lock.unlock();
        Some((object, new_offset))
    }
}

/// `vm_object_coalesce()` of the C.
///
/// # Safety
///
/// Both objects must be null or live, and their references move as the C's
/// did; `new_object` and `new_offset` must be writable, and are written only
/// when the C wrote them.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn vm_object_coalesce(
    prev_object: *mut VmObject,
    next_object: *mut VmObject,
    prev_offset: VmOffset,
    next_offset: VmOffset,
    prev_size: VmSize,
    next_size: VmSize,
    new_object: *mut *mut VmObject,
    new_offset: *mut VmOffset,
) -> c_int {
    match unsafe {
        coalesce(
            NonNull::new(prev_object),
            NonNull::new(next_object),
            prev_offset,
            next_offset,
            prev_size,
            next_size,
        )
    } {
        Some((object, offset)) => {
            unsafe {
                new_object.write(object);
                new_offset.write(offset);
            }
            c_int::from(true)
        }
        None => c_int::from(false),
    }
}

/// `vm_object_name()` of the C.
///
/// # Safety
///
/// A non-null `object` must be a live object.
pub(crate) unsafe fn name(object: Option<NonNull<VmObject>>) -> *mut c_void {
    let Some(mut object) = object else {
        return null_mut();
    };

    unsafe {
        (*object.as_ptr()).lock.lock();

        loop {
            let next = (*object.as_ptr()).shadow;
            let Some(next) = NonNull::new(next) else {
                break;
            };
            (*next.as_ptr()).lock.lock();
            (*object.as_ptr()).lock.unlock();
            object = next;
        }

        let mut port = (*object.as_ptr()).pager_name;
        if !port.is_null() {
            port = ipc_port::make_send(IpcPort::from_raw(port)).as_ptr();
        }
        (*object.as_ptr()).lock.unlock();

        port
    }
}

/// `vm_object_page_map()` of the C.
///
/// # Safety
///
/// `object` must be a live object, and `map_fn` must be the C callback that
/// names each page's physical address.
pub(crate) unsafe fn page_map(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
    map_fn: Option<unsafe fn(*mut c_void, VmOffset) -> VmOffset>,
    map_fn_data: *mut c_void,
) -> Result<(), Error> {
    let Some(map_fn) = map_fn else {
        die("vm_object_page_map", "vm_object_page_map: no map function");
    };

    let num_pages = atop(size);
    let mut offset = offset;

    for _ in 0..num_pages {
        let addr = unsafe { map_fn(map_fn_data, offset) };
        if addr == VM_PAGE_FICTITIOUS_ADDR {
            return Err(Error::NoAccess);
        }

        let page = loop {
            let page = unsafe { vm_resident::grab_fictitious() };
            if let Some(page) = page {
                break page.as_ptr();
            }
            unsafe { vm_resident::more_fictitious() };
        };

        // SAFETY: the object is live, and the page is the fresh one just
        // grabbed.
        unsafe {
            (*object).lock.lock();

            let old_page =
                vm_resident::lookup(NonNull::new_unchecked(object), offset);
            if let Some(old_page) = old_page {
                page_free(old_page.as_ptr());
            }

            vm_resident::init(&mut *page);
            (*page).phys_addr = addr;
            (*page).set_private(true);
            (*page).set_wire_count(1);

            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::insert(
                NonNull::new_unchecked(page),
                NonNull::new_unchecked(object),
                offset,
            );
            VM_PAGE_QUEUE_LOCK.unlock();

            page_wakeup_done(page);
            (*object).lock.unlock();
        }

        offset = offset.wrapping_add(PAGE_SIZE);
    }

    Ok(())
}
