// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kernel services VM calls, supplied as a zero-sized type.
//!
//! [`Platform`] gathers everything VM asks of the rest of the kernel.  It is
//! implemented on a zero-sized marker type and called through associated
//! functions, so VM holds no platform value.

use crate::error::Error;
use crate::param::{VmOffset, VmSize};
use crate::state::VmState;
use crate::types::VmProt;
use crate::vm_map::VmMap;
use core::ffi::{CStr, c_int, c_uint, c_void};
use core::fmt;
use core::ptr::{self, NonNull};
use zerocopy::{FromBytes, IntoBytes};

/// The result a wait ends with when a wakeup ended it.
pub const THREAD_AWAKENED: c_int = 0;

/// The result a wait ends with when something interrupted it.
pub const THREAD_INTERRUPTED: c_int = 2;

/// The result a wait ends with when the waiter must start over.
pub const THREAD_RESTART: c_int = 3;

/// Where a blocked thread resumes instead of returning from its block.
pub type Continuation = Option<unsafe extern "C" fn()>;

/// A kernel port VM holds a right to, as a handle it never looks inside.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port(NonNull<c_void>);

/// The dead port value, which names no port.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

impl Port {
    /// A port from the C side, or `None` for `IP_NULL`.
    pub fn new(port: *mut c_void) -> Option<Self> {
        NonNull::new(port).map(Self)
    }

    /// The port `port` is, when it is neither null nor dead.
    pub fn valid(port: *mut c_void) -> Option<Self> {
        if ptr::eq(port, IO_DEAD) {
            return None;
        }
        NonNull::new(port).map(Self)
    }

    /// A port from the C side whose validity the caller already established.
    ///
    /// # Safety
    ///
    /// `port` must be non-null and not `IP_DEAD`.
    pub const unsafe fn from_raw(port: *mut c_void) -> Self {
        Self(unsafe { NonNull::new_unchecked(port) })
    }

    /// The port as the C side spells it.
    #[must_use]
    pub const fn as_ptr(self) -> *mut c_void {
        self.0.as_ptr()
    }

    /// The port as a non-null pointer.
    #[must_use]
    pub const fn as_non_null(self) -> NonNull<c_void> {
        self.0
    }
}

/// A slab cache VM's records come from; the platform keeps one of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmCache {
    /// VM maps.
    Map,
    /// Map entries.
    MapEntry,
    /// Map copies.
    MapCopy,
    /// VM objects.
    Object,
    /// Page records outside the boot table.
    Page,
    /// The state a blocked fault keeps for its continuation.
    FaultState,
    /// Existence-map headers.
    External,
    /// Existence bitmaps of small objects.
    SmallExistenceMap,
    /// Existence bitmaps of large objects.
    LargeExistenceMap,
    /// Proxy memory objects.
    Proxy,
}

impl VmCache {
    /// The number of caches.
    pub const COUNT: usize = 10;
}

bitflags::bitflags! {
    /// How a cache lays out its slabs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CacheFlags: c_int {
        /// Keeps each slab's bookkeeping inside the slab.
        const NOOFFSLAB = 0x1;
        /// Takes slabs straight from physical memory, bypassing the kernel
        /// map.
        const PHYSMEM = 0x2;
    }
}

/// A user address a copy could not reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault;

/// A count in the running task's statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskEvent {
    /// A page fault.
    Fault,
    /// A page a fault filled with zeroes.
    ZeroFill,
    /// A page taken back off the inactive queue.
    Reactivation,
    /// A page read in from its pager.
    Pagein,
    /// A copy-on-write fault.
    CowFault,
}

/// The kernel services VM calls.
///
/// # Safety
///
/// VM's correctness rests on each function keeping the contract its
/// documentation states, as the kernel's own callers rely on it.
pub unsafe trait Platform: Sized + 'static {
    /// The lock platform of the sleeping and spin locks VM keeps.
    type Lock: lock::Platform;

    /// A physical map: the machine's translation of one VM map, which VM
    /// creates, hands to the functions below and never looks inside.
    type Pmap;

    /// Returns VM's global state, which the platform stores.
    fn state() -> &'static VmState<Self>;

    // The physical maps.

    /// Returns the kernel's physical map.
    fn kernel_pmap() -> *mut Self::Pmap;

    /// Creates an empty physical map.
    ///
    /// # Safety
    ///
    /// [`Self::pmap_init`] must have run, and the caller must hold none of
    /// the pmap's locks.
    unsafe fn pmap_create(size: VmSize) -> *mut Self::Pmap;

    /// Drops a reference to `pmap`, freeing it with the last one.
    ///
    /// # Safety
    ///
    /// `pmap` must be `None` or a live map.
    unsafe fn pmap_destroy(pmap: Option<NonNull<Self::Pmap>>);

    /// Takes a reference to `pmap`.
    ///
    /// # Safety
    ///
    /// `pmap` must be `None` or a live map.
    unsafe fn pmap_reference(pmap: Option<NonNull<Self::Pmap>>);

    /// Removes the mappings of `start..end` from `pmap`.
    ///
    /// # Safety
    ///
    /// `pmap` must be `None` or a live map.
    unsafe fn pmap_remove(
        pmap: Option<NonNull<Self::Pmap>>,
        start: VmOffset,
        end: VmOffset,
    );

    /// Lowers every mapping of the physical page `phys` to `prot`.
    ///
    /// An address that is not a managed page is ignored.
    fn pmap_page_protect(phys: VmOffset, prot: VmProt);

    /// Lowers the mappings of `start..end` in `pmap` to `prot`.
    ///
    /// # Safety
    ///
    /// `pmap` must be `None` or a live map.
    unsafe fn pmap_protect(
        pmap: Option<NonNull<Self::Pmap>>,
        start: VmOffset,
        end: VmOffset,
        prot: VmProt,
    );

    /// Maps the virtual page `va` of `pmap` to the physical page `pa`.
    ///
    /// # Safety
    ///
    /// `pmap` must be `None` or a live map, and `pa` a physical address the
    /// kernel may map.
    unsafe fn pmap_enter(
        pmap: Option<NonNull<Self::Pmap>>,
        va: VmOffset,
        pa: VmOffset,
        prot: VmProt,
        wired: c_int,
    );

    /// Sets whether the mapping of `va` in `pmap` is wired.
    ///
    /// # Safety
    ///
    /// `pmap` must be a live map that maps `va`.
    unsafe fn pmap_change_wiring(
        pmap: *mut Self::Pmap,
        va: VmOffset,
        wired: c_int,
    );

    /// Returns the physical address `va` maps to in `pmap`, or zero.
    ///
    /// # Safety
    ///
    /// `pmap` must be a live map.
    unsafe fn pmap_extract(pmap: *mut Self::Pmap, va: VmOffset) -> VmOffset;

    /// Clears the modified bit of the physical page `phys`.
    ///
    /// An address that is not a managed page is ignored.
    fn pmap_clear_modify(phys: VmOffset);

    /// Returns whether the physical page `phys` was written.
    ///
    /// An address that is not a managed page is ignored.
    fn pmap_is_modified(phys: VmOffset) -> bool;

    /// Clears the referenced bit of the physical page `phys`.
    ///
    /// An address that is not a managed page is ignored.
    fn pmap_clear_reference(phys: VmOffset);

    /// Returns whether the physical page `phys` was accessed.
    ///
    /// An address that is not a managed page is ignored.
    fn pmap_is_referenced(phys: VmOffset) -> bool;

    /// Tells `pmap` whether `start..end` may be paged.
    fn pmap_pageable(
        pmap: *mut Self::Pmap,
        start: VmOffset,
        end: VmOffset,
        pageable: c_int,
    );

    /// Maps the physical range `start..end` at `virt` in the kernel map,
    /// bypassing VM, and returns the end of the mapping.
    ///
    /// # Safety
    ///
    /// `virt` must name a free kernel-virtual range covering `start` to
    /// `end`.
    unsafe fn pmap_map_bd(
        virt: VmOffset,
        start: VmOffset,
        end: VmOffset,
        prot: VmProt,
    ) -> VmOffset;

    /// Removes a mapping [`Self::pmap_map_bd`] made.
    ///
    /// # Safety
    ///
    /// `virt..end` must be a range [`Self::pmap_map_bd`] mapped, which
    /// nothing uses afterwards.
    unsafe fn pmap_unmap_bd(virt: VmOffset, end: VmOffset);

    /// The kernel virtual space the pmap leaves to VM, as its start and end.
    fn pmap_virtual_space() -> (VmOffset, VmOffset);

    /// Finishes the pmap's setup once VM manages physical memory.
    fn pmap_init();

    /// The number of resident pages `pmap` maps.
    ///
    /// # Safety
    ///
    /// `pmap` must be a live physical map.
    unsafe fn pmap_resident_count(pmap: *mut Self::Pmap) -> c_int;

    /// Returns the first kernel virtual address the pmap maps.
    fn kernel_virtual_start() -> VmOffset;

    /// Returns the end of the kernel virtual addresses the pmap maps.
    fn kernel_virtual_end() -> VmOffset;

    /// Fills the physical page `pa` with zeroes.
    ///
    /// # Safety
    ///
    /// `pa` must be a page the caller owns.
    unsafe fn zero_page(pa: VmOffset);

    /// Copies the physical page `src` to `dst`.
    ///
    /// # Safety
    ///
    /// `src` must be readable and `dst` a page the caller owns.
    unsafe fn copy_page(src: VmOffset, dst: VmOffset);

    // Threads and the scheduler.

    /// The clock interrupt rate, in ticks a second.
    const CLOCK_HZ: c_int;

    /// Declares that the running thread waits for `event`.
    ///
    /// # Safety
    ///
    /// Thread context, at a level that keeps the wakeup from being lost,
    /// with the running thread not already waiting.
    unsafe fn assert_wait(
        event: Option<NonNull<c_void>>,
        interruptible: c_int,
    );

    /// Blocks the running thread and runs the next one, resuming at
    /// `continuation` when there is one.
    ///
    /// # Safety
    ///
    /// The caller must hold no spin lock, and must have declared its wait
    /// first when it means to block.
    unsafe fn thread_block(continuation: Continuation);

    /// Wakes the threads waiting for `event`, only the first when
    /// `one_thread` is nonzero, with `result`, and returns whether one was
    /// waiting.
    ///
    /// `event` is an opaque key the call never dereferences, and it takes
    /// the locks it needs itself.
    fn thread_wakeup_prim(
        event: *mut c_void,
        one_thread: c_int,
        result: c_int,
    ) -> bool;

    /// Bounds the running thread's declared wait to `ticks` clock ticks.
    ///
    /// # Safety
    ///
    /// Must be called between [`Self::assert_wait`] and
    /// [`Self::thread_block`].
    unsafe fn thread_set_timeout(ticks: c_int);

    /// Ends the running thread's declared wait with `result`; with
    /// `interrupt_only`, an uninterruptible wait is left alone.
    ///
    /// # Safety
    ///
    /// Thread context, holding none of the scheduler's locks.
    unsafe fn clear_wait(result: c_int, interrupt_only: c_int);

    /// Returns the result the running thread's last wait ended with.
    ///
    /// # Safety
    ///
    /// Thread context.
    unsafe fn wait_result() -> c_int;

    /// Returns whether a thread runs on this CPU, which is false early in
    /// boot.
    fn has_thread() -> bool;

    /// Returns the running thread's VM privilege count; while it is nonzero
    /// the thread may take the pages kept in reserve.
    ///
    /// # Safety
    ///
    /// A thread must run, as [`Self::has_thread`] reports.
    unsafe fn vm_privilege() -> c_uint;

    /// Sets the running thread's VM privilege count.
    ///
    /// # Safety
    ///
    /// A thread must run, as [`Self::has_thread`] reports.
    unsafe fn set_vm_privilege(privilege: c_uint);

    /// Returns the state the running thread saved before a fault blocked
    /// with a continuation.
    ///
    /// # Safety
    ///
    /// Thread context.
    unsafe fn fault_state() -> *mut c_void;

    /// Saves the running thread's fault state for its continuation.
    ///
    /// # Safety
    ///
    /// Thread context.
    unsafe fn set_fault_state(state: *mut c_void);

    /// Gives the running thread a stack of its own, kept across switches.
    ///
    /// # Safety
    ///
    /// Thread context.
    unsafe fn stack_privilege();

    /// Sets the running thread's priority.
    ///
    /// # Safety
    ///
    /// Thread context, holding no thread lock.
    unsafe fn set_own_priority(priority: c_int);

    /// Counts `event` in the running task's statistics; before a thread
    /// runs it counts nothing.
    fn count(event: TaskEvent);

    /// Returns this CPU's number, below [`MAX_NCPUS`].
    ///
    /// [`MAX_NCPUS`]: crate::param::MAX_NCPUS
    fn cpu_id() -> usize;

    /// Pauses a CPU that spins on a lock.
    fn lock_pause();

    /// Returns the running task's map.
    fn current_map() -> *mut VmMap<Self>;

    /// Frees what the kernel caches outside VM: spare stacks, network
    /// message buffers, the task collector's due work and empty slabs.
    ///
    /// # Safety
    ///
    /// Thread context, holding no lock.
    unsafe fn collect();

    // Ports.

    /// Takes `port`'s lock.
    ///
    /// # Safety
    ///
    /// `port` must be live, and the caller must not hold its lock.
    unsafe fn port_lock(port: Port);

    /// Releases `port`'s lock.
    ///
    /// # Safety
    ///
    /// `port` must be live, and the caller must hold its lock.
    unsafe fn port_unlock(port: Port);

    /// Returns whether `port` is still active.
    ///
    /// # Safety
    ///
    /// `port` must be live.
    unsafe fn port_is_active(port: Port) -> bool;

    /// Returns the type of the kernel object `port` names.
    ///
    /// # Safety
    ///
    /// `port` must be live.
    unsafe fn port_kotype(port: Port) -> c_uint;

    /// Returns the kernel object `port` names.
    ///
    /// # Safety
    ///
    /// `port` must be live.
    unsafe fn port_kobject(port: Port) -> *mut c_void;

    /// Sets the kernel object `port` names, keeping its type.
    ///
    /// # Safety
    ///
    /// `port` must be live, and the caller must hold whatever lock makes
    /// the update atomic.
    unsafe fn port_set_kobject(port: Port, kobject: *mut c_void);

    /// Returns the space holding `port`'s receive right.
    ///
    /// # Safety
    ///
    /// `port` must be live.
    unsafe fn port_receiver(port: Port) -> *mut c_void;

    /// Takes a reference on `port`.
    ///
    /// # Safety
    ///
    /// `port` must be live.
    unsafe fn port_reference(port: Port);

    /// Drops a reference on `port`, freeing it with the last one.
    ///
    /// # Safety
    ///
    /// `port` must be live, and the caller must hold the reference.
    unsafe fn port_release(port: Port);

    /// Allocates a port in the kernel's space, with one reference.
    ///
    /// # Safety
    ///
    /// The kernel's IPC must be set up.
    unsafe fn port_alloc() -> Option<Port>;

    /// Destroys a port [`Self::port_alloc`] made, consuming a reference.
    ///
    /// # Safety
    ///
    /// `port` must be a live port of the kernel's space.
    unsafe fn port_dealloc(port: Port);

    /// Makes a send right from `port`'s receive right.
    ///
    /// # Safety
    ///
    /// `port` must be live and active, and nothing may be locked.
    unsafe fn port_make_send(port: Port) -> Port;

    /// Releases a send right, consuming a reference.
    ///
    /// # Safety
    ///
    /// `port` must be a live port holding the right, and nothing may be
    /// locked.
    unsafe fn port_release_send(port: Port);

    /// Copies a send right: null stays null, a dead value or a dead port
    /// becomes the dead value, and a live port gains a right.
    ///
    /// # Safety
    ///
    /// `port` must be `IP_NULL`, `IP_DEAD` or a live port, and nothing may
    /// be locked.
    unsafe fn port_copy_send(port: *mut c_void) -> *mut c_void;

    /// Makes a send-once right from `port`'s receive right.
    ///
    /// # Safety
    ///
    /// `port` must be live and active, and nothing may be locked.
    unsafe fn port_make_sonce(port: Port) -> Port;

    /// Installs `notify` as `port`'s no-senders request, consuming its
    /// reference, and returns the previous request.
    ///
    /// # Safety
    ///
    /// `port` must be live, active and locked; `notify` must be `IP_NULL`
    /// or a live send-once right.
    unsafe fn port_nsrequest(
        port: Port,
        sync: c_uint,
        notify: Option<NonNull<c_void>>,
    ) -> Option<NonNull<c_void>>;

    /// Names the kernel object `kobject`, of type `kotype`, in `port`.
    ///
    /// # Safety
    ///
    /// `port` must be a live, active port, and nothing may be locked.
    unsafe fn kobject_set(
        port: *mut c_void,
        kobject: VmOffset,
        kotype: c_uint,
    );

    // Allocation.

    /// Sets up `cache` for records of `size` bytes, reported as `name`.
    ///
    /// # Safety
    ///
    /// Once per cache, before its first allocation.
    unsafe fn cache_init(
        cache: VmCache,
        name: &'static [u8],
        size: usize,
        flags: CacheFlags,
    );

    /// Allocates a record from `cache`, or `None` when memory is short.
    ///
    /// # Safety
    ///
    /// [`Self::cache_init`] must have set `cache` up.
    unsafe fn cache_alloc(cache: VmCache) -> Option<NonNull<u8>>;

    /// Returns a record to `cache`.
    ///
    /// # Safety
    ///
    /// `record` must have come from `cache` and not be used again.
    unsafe fn cache_free(cache: VmCache, record: NonNull<u8>);

    /// Allocates `size` bytes from the general-purpose caches.
    fn kalloc(size: usize) -> Option<NonNull<u8>>;

    /// Returns `size` bytes [`Self::kalloc`] gave.
    ///
    /// # Safety
    ///
    /// `data` must have come from [`Self::kalloc`] for `size` bytes and not
    /// be used again.
    unsafe fn kfree(data: NonNull<u8>, size: usize);

    /// Frees the empty slabs of every cache.
    fn slab_collect();

    /// Sets up the slab allocator and the general-purpose caches, once the
    /// kernel map exists.
    fn allocators_init();

    // Physical segments, user memory and the console.

    /// The end of the DMA segment.
    const DMA_LIMIT: VmOffset;

    /// The end of the DMA32 segment.
    const DMA32_LIMIT: VmOffset;

    /// The end of the physical memory the direct map covers.
    const DIRECTMAP_LIMIT: VmOffset;

    /// Copies `len` bytes from the user address `user` to `kernel`.
    ///
    /// # Errors
    ///
    /// Returns [`UserFault`] instead of copying when the user read faults.
    ///
    /// # Safety
    ///
    /// `user` must be in the running task's map, and `kernel` writable
    /// kernel memory for `len` bytes.
    unsafe fn copyin(
        user: *const c_void,
        kernel: *mut c_void,
        len: usize,
    ) -> Result<(), UserFault>;

    /// Copies `kernel`'s bytes in from the user address `user`.
    ///
    /// `FromBytes` makes any bytes the task wrote a valid `T`, so only the
    /// user side is the caller's to vouch for.
    ///
    /// # Errors
    ///
    /// Returns [`UserFault`] when the user read faults.
    ///
    /// # Safety
    ///
    /// `user` must be in the running task's map for `size_of_val(kernel)`
    /// bytes.
    unsafe fn copyin_into<T: FromBytes + IntoBytes + ?Sized>(
        user: *const c_void,
        kernel: &mut T,
    ) -> Result<(), UserFault> {
        let bytes = kernel.as_mut_bytes();
        // SAFETY: the caller vouches for the user side, and `bytes` is
        // writable kernel memory of the same length.
        unsafe { Self::copyin(user, bytes.as_mut_ptr().cast(), bytes.len()) }
    }

    /// Copies `len` bytes from `kernel` to the user address `user`.
    ///
    /// # Errors
    ///
    /// Returns [`UserFault`] instead of copying when the user write faults.
    ///
    /// # Safety
    ///
    /// `kernel` must be readable kernel memory, and `user` in the running
    /// task's map, for `len` bytes.
    unsafe fn copyout(
        kernel: *const c_void,
        user: *mut c_void,
        len: usize,
    ) -> Result<(), UserFault>;

    /// Writes `args` to the kernel console.
    fn print(args: fmt::Arguments<'_>);

    /// Reports a debugger entry with `message` and continues.
    fn soft_debugger(message: &CStr);
    // Pager messages.

    /// The reason the kernel could not queue a pager message.
    type SendError: Copy + Eq + fmt::Debug;

    /// The send error of an interrupted wait for room in the queue.
    const SEND_INTERRUPTED: Self::SendError;

    /// Sends `memory_object_data_request()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The memory object and control ports must be live, and `offset`/`length`
    /// must describe a valid range of the object.
    unsafe fn memory_object_data_request(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        desired_access: VmProt,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_data_unlock()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The memory object and control ports must be live, and `offset`/`length`
    /// must describe a valid range of the object.
    unsafe fn memory_object_data_unlock(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        desired_access: VmProt,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_data_return()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The memory object and control ports must be live, and `data` a page-list
    /// copy of `data_cnt` bytes the message consumes.
    unsafe fn memory_object_data_return(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        data: VmOffset,
        data_cnt: c_uint,
        dirty: c_int,
        kernel_copy: c_int,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_data_initialize()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The memory object and control ports must be live, and `data` a page-list
    /// copy of `data_cnt` bytes the message consumes.
    unsafe fn memory_object_data_initialize(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        data: VmOffset,
        data_cnt: c_uint,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_lock_completed()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// `memory_object` must be a live reply right of type `memory_object_poly`
    /// the message consumes, and `memory_control` the object's request port.
    unsafe fn memory_object_lock_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_supply_completed()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// `memory_object` must be a live reply right of type `memory_object_poly`
    /// the message consumes, and `memory_control` the object's request port.
    unsafe fn memory_object_supply_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        result: Result<(), Error>,
        error_offset: VmOffset,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_change_completed()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// `memory_object` must be a live reply right of type `memory_object_poly`
    /// the message consumes.
    unsafe fn memory_object_change_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        may_cache: c_int,
        copy_strategy: c_int,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_init()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The three ports must be live; the message carries send rights to the
    /// request and name ports.
    unsafe fn memory_object_init(
        pager: *mut c_void,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
        page_size: VmSize,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_create()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The ports must be live; the message carries the new pager and send
    /// rights to the request and name ports.
    unsafe fn memory_object_create(
        memory_object: *mut c_void,
        pager: *mut c_void,
        size: VmSize,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
        page_size: VmSize,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_copy()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The ports must be live; the message carries a send right to
    /// `new_memory_object`.
    unsafe fn memory_object_copy(
        memory_object: *mut c_void,
        pager_request: *mut c_void,
        offset: VmOffset,
        size: VmSize,
        new_memory_object: *mut c_void,
    ) -> Result<(), Self::SendError>;

    /// Sends `memory_object_terminate()` to a pager.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel could not queue the message.
    ///
    /// # Safety
    ///
    /// The three ports must be live; the message consumes the request and name
    /// rights.
    unsafe fn memory_object_terminate(
        pager: *mut c_void,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
    ) -> Result<(), Self::SendError>;
}
