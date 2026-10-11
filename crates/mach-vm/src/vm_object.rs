// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The virtual-memory object module.

use crate::cell::SyncCell;
use crate::error::Error;
use crate::memory_object::default_manager;
use crate::param::{PAGE_SHIFT, PAGE_SIZE};
use crate::param::{VmOffset, VmSize};
use crate::platform::{CacheFlags, Platform, Port, THREAD_AWAKENED, VmCache};
use crate::types::{VmObject, VmObjectCachedList, VmPage, VmProt};
use crate::vm_fault::FaultError;
use crate::vm_page::{self, ListqList};
use crate::vm_pageout::vm_pageout_page;
use crate::vm_resident::VM_PAGE_FICTITIOUS_ADDR;
use crate::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm_user::VM_STAT;
use crate::{vm_external, vm_fault, vm_resident};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{NonNull, addr_of, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicI32, AtomicIsize, AtomicU32, Ordering};

/// The bit in an object's `all_wanted` mask that a thread waiting for each
/// event sets.
const EVENT_INITIALIZED: u32 = 0;
pub(crate) const EVENT_PAGER_READY: u32 = 1;
const EVENT_PAGING_IN_PROGRESS: u32 = 2;
const EVENT_ABSENT_COUNT: u32 = 3;

/// The kernel-object types of the ports a memory object is reached through:
/// none, pager, pager request, terminating pager and pager name.
const IKOT_NONE: c_uint = 0;
const IKOT_PAGER: c_uint = 8;
const IKOT_PAGING_REQUEST: c_uint = 9;
const IKOT_PAGER_TERMINATING: c_uint = 15;
const IKOT_PAGING_NAME: c_uint = 16;

/// `MEMORY_OBJECT_COPY_*`: the copy strategies [`copy_strategically`]
/// dispatches over.
const MEMORY_OBJECT_COPY_NONE: c_int = 0;
const MEMORY_OBJECT_COPY_CALL: c_int = 1;
const MEMORY_OBJECT_COPY_DELAY: c_int = 2;

/// The size of the kernel's virtual address range, which the kernel object and
/// the submap placeholder are created with.
const KERNEL_OBJECT_SIZE: VmSize = 0x7fff_ffff;

/// The objects whose `can_persist` kept them after their last reference went
/// away.
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

/// Serializes the cached list and the port associations.
static VM_OBJECT_CACHED_LOCK: crate::simple_lock::SimpleLock =
    crate::simple_lock::SimpleLock::new();

/// The storage of [`kernel_object()`].
static KERNEL_OBJECT_STORE: SyncCell<VmObject> =
    SyncCell(UnsafeCell::new(VmObject::fresh(KERNEL_OBJECT_SIZE)));

/// The storage of [`vm_submap_object()`].
static VM_SUBMAP_OBJECT_STORE: SyncCell<VmObject> =
    SyncCell(UnsafeCell::new(VmObject::fresh(KERNEL_OBJECT_SIZE)));

/// The single object all wired-down kernel memory belongs to.
pub(crate) const fn kernel_object() -> *mut VmObject {
    KERNEL_OBJECT_STORE.0.get()
}

/// The placeholder object dropped into a submap's range until
/// `VmMap::submap()` creates the submap.
pub(crate) const fn vm_submap_object() -> *mut VmObject {
    VM_SUBMAP_OBJECT_STORE.0.get()
}

/// When set, [`pmap_protect`] protects page by page instead of by range.
static VM_OBJECT_PMAP_PROTECT_BY_PAGE: AtomicI32 = AtomicI32::new(0);

/// Debugging counters of collapses and bypasses, written for a debugger to
/// read and never synchronized against.
static OBJECT_COLLAPSES: AtomicIsize = AtomicIsize::new(0);
static OBJECT_BYPASSES: AtomicIsize = AtomicIsize::new(0);

/// The collapse switches a debugger sets: tracing, collapsing and bypassing.
static VM_OBJECT_COLLAPSE_DEBUG: AtomicI32 = AtomicI32::new(0);
static VM_OBJECT_COLLAPSE_ALLOWED: AtomicI32 = AtomicI32::new(1);
static VM_OBJECT_COLLAPSE_BYPASS_ALLOWED: AtomicI32 = AtomicI32::new(1);

/// How often each page-removal path was taken: lookups by offset and walks of
/// the page list.
static PAGE_REMOVE_LOOKUP: AtomicU32 = AtomicU32::new(0);
static PAGE_REMOVE_ITERATE: AtomicU32 = AtomicU32::new(0);

/// Halts the kernel with `message`, under the `func` tag.
fn die(func: &'static str, message: &'static str) -> ! {
    panic!("{func}: {message}")
}

/// An allocation from the object cache.
///
/// # Safety
///
/// The caller must run after [`bootstrap()`] has initialized the object cache.
unsafe fn cache_alloc<P: Platform>() -> *mut VmObject {
    let Some(buf) = (unsafe { P::cache_alloc(VmCache::Object) }) else {
        return null_mut();
    };
    buf.as_ptr().cast::<VmObject>()
}

/// Returns `object` to the cache.
///
/// # Safety
///
/// `object` must be a dead object that came from [`cache_alloc()`] and has
/// no other holder.
unsafe fn cache_free<P: Platform>(object: *mut VmObject) {
    unsafe {
        P::cache_free(
            VmCache::Object,
            NonNull::new_unchecked(object.cast::<u8>()),
        );
    };
}

/// Takes the lock of the cached list and the port associations.
///
/// # Safety
///
/// Nothing else may hold the lock in this thread, and the caller must keep
/// it until it unlocks.
unsafe fn cache_lock() {
    unsafe { (*addr_of!(VM_OBJECT_CACHED_LOCK)).lock() };
}

/// Releases the lock of the cached list and the port associations.
///
/// # Safety
///
/// This thread must hold the lock.
unsafe fn cache_unlock() {
    unsafe { (*addr_of!(VM_OBJECT_CACHED_LOCK)).unlock() };
}

/// Puts an unreferenced, persistent object on the cached list.
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

/// Takes `object` off the cached list.
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

/// Whether `port` is neither null nor dead.
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

/// The page number of `address`.
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

/// Waits for `event` on `object`, releasing the object lock.
///
/// # Safety
///
/// The object lock must be held; the call releases it as the C macro did.
unsafe fn wait<P: Platform>(
    object: *mut VmObject,
    event: u32,
    interruptible: bool,
) {
    unsafe {
        (*object).want(event);
        P::assert_wait(
            NonNull::new(event_ptr(object, event)),
            c_int::from(interruptible),
        );
        (*object).lock.unlock();
        P::thread_block(None);
    }
}

/// Declares that the current thread waits for `event` on `object`.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn assert_wait_event<P: Platform>(
    object: *mut VmObject,
    event: u32,
    interruptible: bool,
) {
    unsafe {
        (*object).want(event);
        P::assert_wait(
            NonNull::new(event_ptr(object, event)),
            c_int::from(interruptible),
        );
    }
}

/// Declares that the current thread waits for the object's absent-page count
/// to drop.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn absent_assert_wait<P: Platform>(
    object: *mut VmObject,
    interruptible: bool,
) {
    unsafe {
        assert_wait_event::<P>(object, EVENT_ABSENT_COUNT, interruptible);
    };
}

/// Wakes the threads waiting for `event` on `object`.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn wakeup<P: Platform>(object: *mut VmObject, event: u32) {
    unsafe {
        if (*object).wants(event) {
            P::thread_wakeup_prim(
                event_ptr(object, event),
                0,
                THREAD_AWAKENED,
            );
        }
        (*object).clear_want(event);
    }
}

/// Drops one absent page from the object's count and wakes the threads waiting
/// for it to drop.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn absent_release<P: Platform>(object: *mut VmObject) {
    unsafe {
        (*object).absent_count = (*object).absent_count.wrapping_sub(1);
        wakeup::<P>(object, EVENT_ABSENT_COUNT);
    }
}

/// Wakes the threads waiting for the object's pager to be ready.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn wakeup_pager_ready<P: Platform>(object: *mut VmObject) {
    unsafe { wakeup::<P>(object, EVENT_PAGER_READY) };
}

/// Takes a paging reference on `object`.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn paging_begin(object: *mut VmObject) {
    unsafe {
        (*object).set_paging_in_progress((*object).paging_in_progress() + 1);
    };
}

/// Drops a paging reference on `object`, waking the threads waiting for paging
/// to finish.
///
/// # Safety
///
/// The object lock must be held.
pub(crate) unsafe fn paging_end<P: Platform>(object: *mut VmObject) {
    unsafe {
        let count = (*object).paging_in_progress() - 1;
        (*object).set_paging_in_progress(count);
        if count == 0 {
            wakeup::<P>(object, EVENT_PAGING_IN_PROGRESS);
        }
    }
}

/// Waits until no paging is in progress on `object`.
///
/// # Safety
///
/// The object lock must be held; the call may drop and retake it.
unsafe fn paging_wait<P: Platform>(
    object: *mut VmObject,
    interruptible: bool,
) {
    while unsafe { (*object).paging_in_progress() } != 0 {
        unsafe {
            wait::<P>(object, EVENT_PAGING_IN_PROGRESS, interruptible);
            (*object).lock.lock();
        }
    }
}

/// Marks `object` as shared through a copy and takes a reference for the
/// sharer.
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

/// Frees `page` under the page-queues lock.
///
/// # Safety
///
/// `page` must be a live page that the caller owns, and the page-queues lock
/// must not be held.
pub(crate) unsafe fn page_free<P: Platform>(page: *mut VmPage) {
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        vm_resident::free::<P>(NonNull::new_unchecked(page));
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// Wakes anything waiting for `page`, when something is.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
pub(crate) unsafe fn page_wakeup<P: Platform>(page: *mut VmPage) {
    unsafe {
        if (*page).is_wanted() {
            (*page).set_wanted(false);
            P::thread_wakeup_prim(page.cast(), 0, THREAD_AWAKENED);
        }
    }
}

/// Clears `page`'s busy bit and wakes anything waiting for it.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
pub(crate) unsafe fn page_wakeup_done<P: Platform>(page: *mut VmPage) {
    unsafe {
        (*page).set_busy(false);
        page_wakeup::<P>(page);
    }
}

/// Writes a fresh object of `size` bytes into `object`.
///
/// # Safety
///
/// `object` must be writable storage for a `VmObject` that no other thread
/// can see yet.
const unsafe fn setup(object: *mut VmObject, size: VmSize) {
    unsafe { object.write(VmObject::fresh(size)) };
}

/// Allocates an object of `size` bytes from the cache and stamps the template
/// on it.
///
/// # Safety
///
/// The caller must run after [`bootstrap()`], as [`cache_alloc()`] requires.
unsafe fn allocate_internal<P: Platform>(size: VmSize) -> *mut VmObject {
    let object = unsafe { cache_alloc::<P>() };
    if object.is_null() {
        return null_mut();
    }
    // SAFETY: the fresh object is unshared storage.
    unsafe { setup(object, size) };
    object
}

/// Allocates an anonymous object of `size` bytes, with one reference.
///
/// # Safety
///
/// The slab allocator and the IPC space must be up; the C panicked when
/// either allocation failed.
pub(crate) unsafe fn allocate<P: Platform>(size: VmSize) -> NonNull<VmObject> {
    let object = unsafe { allocate_internal::<P>(size) };
    let object = NonNull::new(object)
        .unwrap_or_else(|| die("vm_object_allocate", "vm_object_allocate"));

    unsafe {
        let port = P::port_alloc().map_or(null_mut(), Port::as_ptr);
        if port.is_null() {
            die("vm_object_allocate", "vm_object_allocate");
        }
        (*object.as_ptr()).pager_name = port;
        P::kobject_set(port, object.as_ptr().addr(), IKOT_PAGING_NAME);
    }

    object
}

/// [`allocate`] over a raw pointer.
///
/// # Safety
///
/// The slab and IPC packages must be initialized, as the C assumed.
pub(crate) unsafe fn vm_object_allocate<P: Platform>(
    size: VmSize,
) -> *mut VmObject {
    unsafe { allocate::<P>(size) }.as_ptr()
}

/// Sets up the object cache, the template, the kernel object and the submap
/// placeholder.
pub(crate) fn bootstrap<P: Platform>() {
    // SAFETY: the call runs once in the bootstrap sequence, after the slab
    // package is up and before any allocation from the cache.
    unsafe {
        P::cache_init(
            VmCache::Object,
            b"vm_object",
            size_of::<VmObject>(),
            CacheFlags::empty(),
        );
    }

    // SAFETY: the external map caches are part of the same bootstrap.
    unsafe { vm_external::vm_external_module_initialize::<P>() };
}

/// Finishes the object package once ports can be allocated.
pub(crate) fn init<P: Platform>() {
    // SAFETY: the kernel object is the boot storage, live and unshared at
    // this point in the sequence.
    unsafe {
        let object = kernel_object();
        let port = P::port_alloc().map_or(null_mut(), Port::as_ptr);
        (*object).pager_name = port;
        P::kobject_set(port, object.addr(), IKOT_PAGING_NAME);
    }
}

/// Frees `object` when it holds neither references nor pages, or leaves it to
/// the caller otherwise.
///
/// # Safety
///
/// The object lock must be held, and the caller must own a reference to the
/// object.
pub(crate) unsafe fn collect<P: Platform>(object: *mut VmObject) {
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
        terminate::<P>(object);
    }
}

/// Takes a reference on `object`, when it is not null.
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

/// Drops a reference on `object`, caching or terminating it on the last one
/// and walking down its shadow chain.
///
/// # Safety
///
/// `object` must be null or a live object the caller holds a reference to;
/// no lock of the caller's may be held.
pub unsafe fn deallocate<P: Platform>(object: *mut VmObject) {
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
                assert_wait_event::<P>(object, EVENT_INITIALIZED, false);
                (*object).lock.unlock();
                cache_unlock();
                P::thread_block(None);
                continue;
            }

            let shadow = (*object).shadow;
            terminate::<P>(object);
            object = shadow;
        }
    }
}

/// Frees an object out of references: cleans its pages, tells its pager, and
/// frees the record.
///
/// # Safety
///
/// On entry the object lock and the cache lock must be held, the object
/// must be live and out of references, and its shadow reference is left
/// alone; on exit the cache and the object are unlocked.
pub(crate) unsafe fn terminate<P: Platform>(object: *mut VmObject) {
    unsafe {
        (*object).set_alive(false);
        remove::<P>(object);
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
    unsafe { paging_wait::<P>(object, false) };

    // SAFETY: the object is live until the free at the end.
    unsafe {
        let temporary = (*object).is_temporary();
        let pager = (*object).pager;
        let head = addr_of_mut!((*object).memq);

        if temporary || pager.is_null() {
            while let Some(entry) = (*head).cursor_front().current_ptr() {
                let page = entry.as_ptr();
                vm_page::check(page);
                page_free::<P>(page);
            }
        } else {
            while let Some(entry) = (*head).cursor_front().current_ptr() {
                let page = entry.as_ptr();
                vm_page::check(page);
                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::queues_remove(page);
                VM_PAGE_QUEUE_LOCK.unlock();

                if (*page).is_absent() || (*page).is_private() {
                    page_free::<P>(page);
                    continue;
                }

                if !(*page).is_dirty() {
                    (*page).set_dirty(P::pmap_is_modified((*page).phys_addr));
                }

                if (*page).is_dirty() || (*page).is_precious() {
                    (*page).set_busy(true);
                    vm_pageout_page::<P>(page, 0, 1);
                } else {
                    page_free::<P>(page);
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
            memory_object_release::<P>(
                pager,
                (*object).pager_request,
                (*object).pager_name,
            );
        } else if !(*object).pager_name.is_null() {
            P::port_dealloc(Port::from_raw((*object).pager_name));
        }

        vm_external::vm_external_destroy::<P>((*object).existence_info.cast());
    }
    // SAFETY: the object is dead and owned here, as the C's free required.
    unsafe { cache_free::<P>(object) };
}

/// Wakes the threads waiting for the object of the memory-object port `pager`
/// to be set up.
///
/// # Safety
///
/// `pager` must be null or a live port.
pub unsafe fn pager_wakeup<P: Platform>(pager: *mut c_void) {
    let Some(port) = Port::new(pager) else {
        return;
    };

    unsafe {
        cache_lock();
        let someone_waiting = !P::port_kobject(port).is_null();
        if P::port_is_active(port) {
            P::kobject_set(pager, 0, IKOT_NONE);
        }
        cache_unlock();
        if someone_waiting {
            P::thread_wakeup_prim(pager, 0, THREAD_AWAKENED);
        }
    }
}

/// Sends the manager of `pager` its termination and gives up the object's
/// three ports.
///
/// # Safety
///
/// `pager` must be null or a live memory-object port; `pager_request` and
/// `pager_name` are its ports, consumed by the call.
pub(crate) unsafe fn memory_object_release<P: Platform>(
    pager: *mut c_void,
    pager_request: *mut c_void,
    pager_name: *mut c_void,
) {
    let Some(port) = Port::new(pager) else {
        return;
    };

    unsafe {
        P::port_reference(port);
        let _ = P::memory_object_terminate(pager, pager_request, pager_name);
        pager_wakeup::<P>(pager);
        P::port_release(port);
    }
}

/// Frees the object's pages that are neither busy nor absent, and marks the
/// absent ones as failed, once its pager is gone.
///
/// # Safety
///
/// The object lock must be held.
unsafe fn abort_activity<P: Platform>(object: *mut VmObject) {
    unsafe {
        let head = addr_of_mut!((*object).memq);
        let mut entry = (*head).cursor_front().current_ptr();
        while let Some(e) = entry {
            let page = e.as_ptr();
            let next = next_page(head, page);

            if (*page).is_busy() && (*page).is_absent() {
                page_free::<P>(page);
            } else {
                if (*page).unlock_request() != VmProt::empty() {
                    (*page).set_unlock_request(VmProt::empty());
                }
                page_wakeup::<P>(page);
            }

            entry = next;
        }

        (*object).set_pager_ready(true);
        wakeup::<P>(object, EVENT_PAGER_READY);
    }
}

/// Shuts `object` down at its manager's request: drops its pager and aborts
/// the activity waiting for it.
///
/// # Safety
///
/// `object` must be null or a live object, and the caller must own a
/// reference to it.
pub unsafe fn memory_object_destroy<P: Platform>(object: *mut VmObject) {
    if object.is_null() {
        return;
    }

    unsafe {
        cache_lock();
        (*object).lock.lock();
        remove::<P>(object);
        (*object).set_can_persist(false);
        cache_unlock();

        let old_object = (*object).pager;
        (*object).pager = null_mut();
        let old_control = (*object).pager_request;
        (*object).pager_request = null_mut();
        let old_name = (*object).pager_name;
        (*object).pager_name = null_mut();

        paging_wait::<P>(object, false);
        (*object).lock.unlock();

        if !old_object.is_null() {
            memory_object_release::<P>(old_object, old_control, old_name);
        } else if !old_name.is_null() {
            // The C reads the already-cleared field here; the null is kept
            // so the two halves behave alike.
            P::port_dealloc(Port::from_raw((*object).pager_name));
        }

        deallocate::<P>(object);
    }
}

/// Write-protects the mappings of a range of an object's pages in `pmap`.
///
/// # Safety
///
/// `object` must be null or a live object; `pmap` must be null or a live
/// physical map, as the C's callers guaranteed.
pub(crate) unsafe fn pmap_protect<P: Platform>(
    mut object: *mut VmObject,
    mut offset: VmOffset,
    size: VmSize,
    pmap: *mut P::Pmap,
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
                P::pmap_protect(
                    NonNull::new(pmap),
                    pmap_start,
                    pmap_start.wrapping_add(size),
                    prot,
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
                        P::pmap_page_protect(
                            (*page).phys_addr,
                            prot & !(*page).page_lock(),
                        );
                    } else {
                        let start =
                            pmap_start.wrapping_add((*page).offset - offset);
                        P::pmap_protect(
                            NonNull::new(pmap),
                            start,
                            start.wrapping_add(PAGE_SIZE),
                            prot,
                        );
                    }
                }
            }

            if prot == VmProt::empty() {
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

/// [`pmap_protect`] over raw pointers.
///
/// # Safety
///
/// `object` must be null or a live object; `pmap` must be null or a live
/// physical map over the range the C's caller checked.
pub(crate) unsafe fn vm_object_pmap_protect<P: Platform>(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
    pmap: *mut P::Pmap,
    pmap_start: VmOffset,
    prot: c_int,
) {
    unsafe {
        pmap_protect::<P>(
            object,
            offset,
            size,
            pmap,
            pmap_start,
            VmProt::from_bits_retain(prot),
        );
    };
}

/// Removes every mapping of a range of an object's pages.
///
/// # Safety
///
/// `object` must be null or a live object, and the caller must hold no lock
/// of it.
pub(crate) unsafe fn pmap_remove<P: Platform>(
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
                    P::pmap_page_protect((*page).phys_addr, VmProt::empty());
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

/// Copies the fault's result page into `new_page`, wakes the waiters and
/// cleans the fault up: the success arm of [`copy_slowly`].
///
/// # Safety
///
/// `result_page` must be the page the fault left locked with its paging
/// reference, `top_page` the fault's top page, and `new_page` this call's
/// fresh page.
unsafe fn copy_slowly_done<P: Platform>(
    result_page: *mut VmPage,
    top_page: *mut VmPage,
    new_page: NonNull<VmPage>,
) {
    // SAFETY: the fault left the result page's object locked and holds its
    // paging reference.
    unsafe {
        (*(*result_page).object).lock.unlock();
        vm_resident::copy::<P>(NonNull::new_unchecked(result_page), new_page);
        (*new_page.as_ptr()).set_busy(false);
        (*new_page.as_ptr()).set_dirty(true);
        (*(*result_page).object).lock.lock();
        page_wakeup_done::<P>(result_page);
        VM_PAGE_QUEUE_LOCK.lock();
        if !(*result_page).is_active() && !(*result_page).is_inactive() {
            vm_page::activate(result_page);
        }
        vm_page::activate(new_page.as_ptr());
        VM_PAGE_QUEUE_LOCK.unlock();
        vm_fault::cleanup::<P>((*result_page).object, NonNull::new(top_page));
    }
}

/// Copies a range of an object into a new object page by page, faulting each
/// page in.
///
/// # Safety
///
/// On entry the source object must be live, locked, and hold a reference;
/// on exit it is unlocked.  The returned object is owned by the caller.
pub(crate) unsafe fn copy_slowly<P: Platform>(
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

    let new_object = unsafe { allocate::<P>(size) };

    let mut src_offset = src_offset;
    let mut new_offset: VmOffset = 0;
    let mut remaining = size;

    while remaining != 0 {
        // SAFETY: the new object is live and owned here.
        let new_page = unsafe {
            (*new_object.as_ptr()).lock.lock();
            loop {
                if let Some(page) =
                    vm_resident::alloc::<P>(new_object, new_offset)
                {
                    break page;
                }
                (*new_object.as_ptr()).lock.unlock();
                vm_page::wait::<P>(None);
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
                vm_fault::fault_page::<P>(
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
                Ok(()) => {
                    // SAFETY: the fault left the result page's object
                    // locked and holds its paging reference; `new_page` is
                    // this call's fresh page.
                    unsafe {
                        copy_slowly_done::<P>(
                            fault.result_page,
                            fault.top_page,
                            new_page,
                        );
                    }
                    break;
                }
                Err(FaultError::MemoryShortage) => {
                    // SAFETY: the page wait takes no continuation.
                    unsafe { vm_page::wait::<P>(None) };
                }
                Err(FaultError::FictitiousShortage) => {
                    // SAFETY: the slab package is up in this path.
                    unsafe { vm_resident::more_fictitious::<P>() };
                }
                Err(FaultError::Interrupted) => {
                    // SAFETY: the fresh page belongs to this call.
                    unsafe {
                        vm_resident::free::<P>(new_page);
                        deallocate::<P>(new_object.as_ptr());
                        deallocate::<P>(src_object);
                    }
                    return Err(Error::Interrupted);
                }
                Err(FaultError::MemoryError) => {
                    // SAFETY: the fresh page belongs to this call.
                    unsafe {
                        vm_resident::free::<P>(new_page);
                        deallocate::<P>(new_object.as_ptr());
                        deallocate::<P>(src_object);
                    }
                    return Err(Error::MemoryError);
                }
                Err(FaultError::Retry) => (),
            }
        }

        src_offset = src_offset.wrapping_add(PAGE_SIZE);
        new_offset = new_offset.wrapping_add(PAGE_SIZE);
        remaining = remaining.wrapping_sub(PAGE_SIZE);
    }

    // SAFETY: the extra reference taken above.
    unsafe { deallocate::<P>(src_object) };

    Ok(new_object)
}

/// What [`copy_temporary`] hands back when it can copy without blocking.
pub(crate) struct TemporaryCopy {
    /// The object the caller's slot becomes.
    pub object: *mut VmObject,
    /// The source must make a shadow.
    pub src_needs_copy: bool,
    /// The destination must make a shadow.
    pub dst_needs_copy: bool,
}

/// Copies a temporary object by sharing it copy-on-write, when that needs no
/// blocking.
///
/// # Safety
///
/// A non-null `object` must be a live object, unlocked.
pub(crate) unsafe fn copy_temporary<P: Platform>(
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
                let object = copy_delayed::<P>(object).as_ptr();
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

/// Copies a range through the manager's copy call: the new object's pager is
/// the copy the manager provides.
///
/// # Safety
///
/// The source object must be live and locked on entry and is unlocked on
/// exit; the returned object is owned by the caller.
unsafe fn copy_call<P: Platform>(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
) -> Result<NonNull<VmObject>, Error> {
    let src_end = src_offset.wrapping_add(size);

    // SAFETY: the kernel space is live for the kernel's lifetime.
    let new_memory_object =
        unsafe { P::port_alloc().map_or(null_mut(), Port::as_ptr) };
    if new_memory_object.is_null() {
        return Err(Error::ResourceShortage);
    }

    unsafe {
        (*src_object).ref_count += 1;
        paging_begin(src_object);
        (*src_object).lock.unlock();

        P::port_make_send(Port::from_raw(new_memory_object));

        let _ = P::memory_object_copy(
            (*src_object).pager,
            (*src_object).pager_request,
            src_offset,
            size,
            new_memory_object,
        );

        (*src_object).lock.lock();
        paging_end::<P>(src_object);

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
                P::pmap_page_protect(
                    (*page).phys_addr,
                    VmProt::ALL & !(*page).page_lock(),
                );
            }
        }

        (*src_object).lock.unlock();
    }

    // SAFETY: the new port carries the object the C looked up.
    let Some(new_object) =
        (unsafe { enter::<P>(new_memory_object, size, false) })
    else {
        die("vm_object_copy_call", "vm_object_enter");
    };

    // SAFETY: the object is fresh and owned here.
    unsafe {
        (*new_object.as_ptr()).shadow = src_object;
        (*new_object.as_ptr()).shadow_offset = src_offset;
        P::port_release_send(Port::from_raw(new_memory_object));
    }

    Ok(new_object)
}

/// Copies an object copy-on-write through a copy object that stands between it
/// and its copies.
///
/// # Safety
///
/// The source object must be live and unlocked; the returned object is
/// owned by the caller.
pub(crate) unsafe fn copy_delayed<P: Platform>(
    src_object: *mut VmObject,
) -> NonNull<VmObject> {
    let new_copy = unsafe { allocate::<P>((*src_object).size) };

    // SAFETY: the source is live and unlocked on entry, as the C requires.
    unsafe {
        (*src_object).lock.lock();

        loop {
            let old_copy = (*src_object).copy;
            if !old_copy.is_null() {
                if !(*old_copy).lock.try_lock() {
                    (*src_object).lock.unlock();
                    P::lock_pause();
                    (*src_object).lock.lock();
                    continue;
                }

                if (*old_copy).resident_page_count == 0
                    && !(*old_copy).is_pager_created()
                {
                    (*old_copy).ref_count += 1;
                    (*old_copy).lock.unlock();
                    (*src_object).lock.unlock();

                    deallocate::<P>(new_copy.as_ptr());

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
                    P::pmap_page_protect(
                        (*page).phys_addr,
                        VmProt::ALL & !VmProt::WRITE & !(*page).page_lock(),
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

/// Copies a range of an object with the strategy its manager chose.
///
/// # Safety
///
/// The source object must be live and unlocked, and the caller must own a
/// reference to it.
pub(crate) unsafe fn copy_strategically<P: Platform>(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    size: VmSize,
) -> StrategicResult {
    let interruptible = true;

    unsafe {
        (*src_object).lock.lock();

        while !(*src_object).is_pager_ready() {
            wait::<P>(src_object, EVENT_PAGER_READY, interruptible);
            if interruptible && P::wait_result() != THREAD_AWAKENED {
                return StrategicResult::Interrupted;
            }
            (*src_object).lock.lock();
        }

        if (*src_object).is_temporary() {
            (*src_object).copy_strategy = MEMORY_OBJECT_COPY_DELAY;
        }

        match (*src_object).copy_strategy {
            MEMORY_OBJECT_COPY_NONE => {
                match copy_slowly::<P>(
                    src_object,
                    src_offset,
                    size,
                    interruptible,
                ) {
                    Ok(object) => StrategicResult::Copied {
                        object,
                        offset: 0,
                        needs_copy: false,
                    },
                    Err(error) => StrategicResult::NullObject(error),
                }
            }
            MEMORY_OBJECT_COPY_CALL => {
                match copy_call::<P>(src_object, src_offset, size) {
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
                let object = copy_delayed::<P>(src_object);
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

/// Makes a new object of `length` bytes that shadows `source` at `offset`,
/// moving the caller's reference to it.
///
/// # Safety
///
/// `source` must be null or a live object the caller holds a reference to;
/// the reference moves to the returned object.
pub(crate) unsafe fn shadow<P: Platform>(
    source: *mut VmObject,
    offset: VmOffset,
    length: VmSize,
) -> NonNull<VmObject> {
    let result = unsafe { allocate::<P>(length) };

    // SAFETY: the object is fresh and owned here.
    unsafe {
        (*result.as_ptr()).shadow = source;
        (*result.as_ptr()).shadow_offset = offset;
    }

    result
}

/// [`shadow`] over raw pointers.
///
/// # Safety
///
/// `object` and `offset` must be writable slots for a live-in object and an
/// offset; the object's reference moves to the shadow created here.
pub(crate) unsafe fn vm_object_shadow<P: Platform>(
    object: *mut *mut VmObject,
    offset: *mut VmOffset,
    length: VmSize,
) {
    unsafe {
        let source = *object;
        let shadow = shadow::<P>(source, *offset, length);
        object.write(shadow.as_ptr());
        offset.write(0);
    }
}

/// The `vm_object_lookup()`/`vm_object_lookup_name()` body.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
unsafe fn lookup_kotype<P: Platform>(
    port: *mut c_void,
    kotype: c_uint,
) -> Option<NonNull<VmObject>> {
    if !port_valid(port) {
        return None;
    }
    let port = Port::new(port)?;

    // SAFETY: `port_valid()` promises a live port.
    unsafe {
        P::port_lock(port);

        let mut object: *mut VmObject = null_mut();
        if P::port_is_active(port) && P::port_kotype(port) == kotype {
            cache_lock();
            object = P::port_kobject(port).cast::<VmObject>();
            (*object).lock.lock();

            if (*object).ref_count == 0 {
                cache_remove(object);
            }
            (*object).ref_count += 1;
            (*object).lock.unlock();
            cache_unlock();
        }

        P::port_unlock(port);
        NonNull::new(object)
    }
}

/// The object the pager request port `port` names, with a reference.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
pub unsafe fn lookup<P: Platform>(
    port: *mut c_void,
) -> Option<NonNull<VmObject>> {
    unsafe { lookup_kotype::<P>(port, IKOT_PAGING_REQUEST) }
}

/// The object the pager name port `port` names, with a reference.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
pub unsafe fn lookup_name<P: Platform>(
    port: *mut c_void,
) -> Option<NonNull<VmObject>> {
    unsafe { lookup_kotype::<P>(port, IKOT_PAGING_NAME) }
}

/// Detaches the object of the memory-object port `pager` from its manager and
/// aborts the activity waiting for it.
///
/// # Safety
///
/// `pager` must be null, dead, or a live memory-object port.
pub unsafe fn destroy<P: Platform>(pager: *mut c_void) {
    let Some(port) = Port::new(pager) else {
        return;
    };

    unsafe {
        cache_lock();
        if P::port_kotype(port) != IKOT_PAGER {
            cache_unlock();
            return;
        }

        let object = P::port_kobject(port).cast::<VmObject>();
        (*object).lock.lock();
        if (*object).ref_count == 0 {
            cache_remove(object);
        }
        (*object).ref_count += 1;
        (*object).set_can_persist(false);

        (*object).pager = null_mut();
        remove::<P>(object);
        let old_request = (*object).pager_request;
        (*object).pager_request = null_mut();
        let old_name = (*object).pager_name;
        (*object).pager_name = null_mut();

        (*object).lock.unlock();
        cache_unlock();

        P::port_release_send(Port::from_raw(pager));
        if !old_request.is_null() {
            P::port_dealloc(Port::from_raw(old_request));
        }
        if !old_name.is_null() {
            P::port_dealloc(Port::from_raw(old_name));
        }

        (*object).lock.lock();
        abort_activity::<P>(object);
        (*object).lock.unlock();

        deallocate::<P>(object);
    }
}

/// Initialize a fresh object's pager association and wait for the pager,
/// the `must_init` tail of [`enter()`].
///
/// # Safety
///
/// `object` must be the live object the pager association produced, `pager`
/// the live pager port, and the caller must hold the cache lock.
unsafe fn enter_init<P: Platform>(
    object: *mut VmObject,
    pager: *mut c_void,
    internal: bool,
    must_init: bool,
) {
    unsafe {
        if must_init {
            let pager = P::port_copy_send(pager);
            if !port_valid(pager) {
                die("vm_object_enter", "vm_object_enter: port died");
            }

            (*object).set_pager_created(true);
            (*object).pager = pager;

            let request = P::port_alloc().map_or(null_mut(), Port::as_ptr);
            if request.is_null() {
                die("vm_object_enter", "vm_object_enter: pager request alloc");
            }
            (*object).pager_request = request;
            P::kobject_set(request, object.addr(), IKOT_PAGING_REQUEST);

            if internal {
                let dmm = default_manager::reference::<P>();
                (*object).set_internal(true);
                (*object).set_pager_ready(true);
                let _ = P::memory_object_create(
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
                let _ = P::memory_object_init(
                    pager,
                    (*object).pager_request,
                    (*object).pager_name,
                    PAGE_SIZE,
                );
            }

            (*object).lock.lock();
            (*object).set_pager_initialized(true);
            wakeup::<P>(object, EVENT_INITIALIZED);
        } else {
            (*object).lock.lock();
        }

        while !(*object).is_pager_initialized() {
            wait::<P>(object, EVENT_INITIALIZED, false);
            (*object).lock.lock();
        }
        (*object).lock.unlock();
    }
}

/// The object of the memory-object port `pager`, set up and referenced, or a
/// fresh anonymous object when `pager` is not valid.
///
/// # Safety
///
/// `pager` must be null, dead, or a live port; the returned object is owned
/// by the caller.
pub(crate) unsafe fn enter<P: Platform>(
    pager: *mut c_void,
    size: VmSize,
    internal: bool,
) -> Option<NonNull<VmObject>> {
    if !port_valid(pager) {
        return Some(unsafe { allocate::<P>(size) });
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
                po = P::port_kotype(Port::from_raw(pager));

                if po == IKOT_PAGER_TERMINATING {
                    P::port_set_kobject(Port::from_raw(pager), pager);
                    P::assert_wait(NonNull::new(pager), 0);
                    cache_unlock();
                    P::thread_block(None);
                    continue 'restart;
                }

                if po != IKOT_NONE {
                    break;
                }

                if new_object.is_null() {
                    cache_unlock();
                    let object = allocate::<P>(size);
                    new_object = object.as_ptr();
                    cache_lock();
                } else {
                    P::kobject_set(pager, new_object.addr(), IKOT_PAGER);
                    new_object = null_mut();
                    must_init = true;
                }
            }

            if internal {
                must_init = true;
            }

            let object = if po == IKOT_PAGER {
                P::port_kobject(Port::from_raw(pager)).cast::<VmObject>()
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

                VM_STAT.hits.fetch_add(1, Ordering::Relaxed);
            }
            VM_STAT.lookups.fetch_add(1, Ordering::Relaxed);
            cache_unlock();

            if !new_object.is_null() {
                deallocate::<P>(new_object);
            }

            if object.is_null() {
                return None;
            }

            // SAFETY: `object` is the live object the pager association
            // produced, `pager` the live port, and the cache lock is held.
            enter_init::<P>(object, pager, internal, must_init);

            return NonNull::new(object);
        }
    }
}

/// Gives a temporary object a pager from the default memory manager.
///
/// # Safety
///
/// The object must be live and locked on entry and is locked on exit.
pub(crate) unsafe fn pager_create<P: Platform>(object: *mut VmObject) {
    unsafe {
        if (*object).is_pager_created() {
            while !(*object).is_pager_initialized() {
                wait::<P>(object, EVENT_PAGER_READY, false);
                (*object).lock.lock();
            }
            return;
        }

        (*object).set_pager_created(true);
        paging_begin(object);
        (*object).lock.unlock();

        (*object).existence_info = vm_external::vm_external_create::<P>(
            (*object).size.wrapping_add((*object).paging_offset),
        )
        .cast();

        let pager = P::port_alloc().map_or(null_mut(), Port::as_ptr);
        if pager.is_null() {
            die(
                "vm_object_pager_create",
                "vm_object_pager_create: allocate pager port",
            );
        }

        P::port_make_send(Port::from_raw(pager));
        P::kobject_set(pager, object.addr(), IKOT_PAGER);

        if enter::<P>(pager, (*object).size, true).map(NonNull::as_ptr)
            != Some(object)
        {
            die("vm_object_pager_create", "vm_object_pager_create: mismatch");
        }

        P::port_release_send(Port::from_raw(pager));

        (*object).lock.lock();
        paging_end::<P>(object);
    }
}

/// Drops the port associations of `object`.
///
/// # Safety
///
/// The cache lock must be held and `object` must be a live object.
pub(crate) unsafe fn remove<P: Platform>(object: *mut VmObject) {
    unsafe {
        let pager = (*object).pager;
        if !pager.is_null() {
            let port = Port::from_raw(pager);
            let kotype = P::port_kotype(port);
            if kotype == IKOT_PAGER {
                P::kobject_set(pager, 0, IKOT_PAGER_TERMINATING);
            } else if kotype != IKOT_NONE {
                die("vm_object_remove", "vm_object_remove: bad object port");
            }
        }

        let request = (*object).pager_request;
        if !request.is_null() {
            let port = Port::from_raw(request);
            let kotype = P::port_kotype(port);
            if kotype == IKOT_PAGING_REQUEST {
                P::kobject_set(request, 0, IKOT_NONE);
            } else if kotype != IKOT_NONE {
                die("vm_object_remove", "vm_object_remove: bad request port");
            }
        }

        let name = (*object).pager_name;
        if !name.is_null() {
            let port = Port::from_raw(name);
            let kotype = P::port_kotype(port);
            if kotype == IKOT_PAGING_NAME {
                P::kobject_set(name, 0, IKOT_NONE);
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
unsafe fn collapse_pages<P: Platform>(
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
                page_free::<P>(page);
            } else {
                let pp = vm_resident::lookup(
                    NonNull::new_unchecked(object),
                    new_offset,
                );
                if pp.is_some_and(|pp| !(*pp.as_ptr()).is_absent()) {
                    page_free::<P>(page);
                } else {
                    vm_resident::rename::<P>(
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
unsafe fn collapse_debug<P: Platform>(
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
                    collapse_print::<P>(backing_object, object);
                }
            }
            debug => {
                collapse_print::<P>(backing_object, object);
                if debug > 2 {
                    P::soft_debugger(c"vm_object_collapse");
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
unsafe fn collapse_swap<P: Platform>(
    object: *mut VmObject,
    backing_object: *mut VmObject,
    backing_offset: VmOffset,
) {
    unsafe {
        (*object).pager = (*backing_object).pager;
        if !(*object).pager.is_null() {
            P::kobject_set((*object).pager, object.addr(), IKOT_PAGER);
        }
        (*object)
            .set_pager_initialized((*backing_object).is_pager_initialized());
        (*object).set_pager_ready((*backing_object).is_pager_ready());
        (*object).set_pager_created((*backing_object).is_pager_created());

        (*object).pager_request = (*backing_object).pager_request;
        if !(*object).pager_request.is_null() {
            P::kobject_set(
                (*object).pager_request,
                object.addr(),
                IKOT_PAGING_REQUEST,
            );
        }
        let old_name_port = (*object).pager_name;
        if !old_name_port.is_null() {
            P::kobject_set(old_name_port, 0, IKOT_NONE);
        }
        (*object).pager_name = (*backing_object).pager_name;
        if !(*object).pager_name.is_null() {
            P::kobject_set(
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
            P::port_dealloc(Port::from_raw(old_name_port));
        }
        cache_free::<P>(backing_object);
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

/// Collapses `object`'s shadow chain into it where no one else uses the
/// shadow.
///
/// # Safety
///
/// The object lock must be held on entry and is held on exit; the caller
/// must own a reference to the object.
pub(crate) unsafe fn collapse<P: Platform>(object: *mut VmObject) {
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
                collapse_pages::<P>(
                    object,
                    backing_object,
                    backing_offset,
                    size,
                );
                // SAFETY: both objects are live.
                collapse_debug::<P>(backing_object, object);
                // SAFETY: both objects are live, `object` holds its lock,
                // the backing lock is held, and the cached-object lock is
                // held.
                collapse_swap::<P>(object, backing_object, backing_offset);
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
unsafe fn collapse_print<P: Platform>(
    backing_object: *mut VmObject,
    object: *mut VmObject,
) {
    let (pager, request) =
        unsafe { ((*backing_object).pager, (*backing_object).pager_request) };
    P::print(format_args!(
        "vm_object_collapse: {:x} (pager {:x}, request {:x}) up to {:x}\n",
        backing_object.expose_provenance(),
        pager.expose_provenance(),
        request.expose_provenance(),
        object.expose_provenance(),
    ));
}

/// Frees the resident pages of `object` in `start..end`.
///
/// # Safety
///
/// The object must be live and locked.
pub(crate) unsafe fn page_remove<P: Platform>(
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
                        P::pmap_page_protect(
                            (*page.as_ptr()).phys_addr,
                            VmProt::empty(),
                        );
                    }
                    page_free::<P>(page.as_ptr());
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
                        P::pmap_page_protect(
                            (*page).phys_addr,
                            VmProt::empty(),
                        );
                    }
                    page_free::<P>(page);
                }
                entry = next;
            }
        }
    }
}

/// Extends `prev_object` to cover the next range instead of making a new
/// object, when nothing else uses it.
///
/// # Safety
///
/// A non-null object must be live, and the references move exactly as the
/// C's did.
pub(crate) unsafe fn coalesce<P: Platform>(
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
            unsafe { deallocate::<P>(prev_object.as_ptr()) };
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
        collapse::<P>(object);

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
            page_remove::<P>(
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

            page_remove::<P>(
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

/// A send right for the name port of `object`, or null.
///
/// # Safety
///
/// A non-null `object` must be a live object.
pub(crate) unsafe fn name<P: Platform>(
    object: Option<NonNull<VmObject>>,
) -> *mut c_void {
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
            port = P::port_make_send(Port::from_raw(port)).as_ptr();
        }
        (*object.as_ptr()).lock.unlock();

        port
    }
}

/// Fills a range of `object` with fictitious pages at the physical addresses
/// `map_fn` names.
///
/// # Safety
///
/// `object` must be a live object, and `map_fn` must be the C callback that
/// names each page's physical address.
pub unsafe fn page_map<P: Platform>(
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
            unsafe { vm_resident::more_fictitious::<P>() };
        };

        // SAFETY: the object is live, and the page is the fresh one just
        // grabbed.
        unsafe {
            (*object).lock.lock();

            let old_page =
                vm_resident::lookup(NonNull::new_unchecked(object), offset);
            if let Some(old_page) = old_page {
                page_free::<P>(old_page.as_ptr());
            }

            vm_resident::init(&mut *page);
            (*page).phys_addr = addr;
            (*page).set_private(true);
            (*page).set_wire_count(1);

            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::insert::<P>(
                NonNull::new_unchecked(page),
                NonNull::new_unchecked(object),
                offset,
            );
            VM_PAGE_QUEUE_LOCK.unlock();

            page_wakeup_done::<P>(page);
            (*object).lock.unlock();
        }

        offset = offset.wrapping_add(PAGE_SIZE);
    }

    Ok(())
}
