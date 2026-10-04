// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 1992-1989 Carnegie Mellon University
// SPDX-FileCopyrightText: 1995-1993 The University of Utah and the Computer Systems Laboratory (CSL)
// SPDX-FileCopyrightText: 2013 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: kern/bootstrap.c and kern/bootstrap.h

//! The first user processes: the kernel loads a Multiboot module into a
//! fresh task, builds the argument and environment vectors on the user
//! stack, and starts the task's first thread.
//!
//! A single module whose command line carries nothing but the module name
//! takes the compatibility path and is loaded directly; otherwise the
//! module lines spell a boot script, which [`create()`] parses and runs
//! against the [`BootstrapHost`] kernel operations.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::model_dep::{boot_modules, kernel_cmdline};
use crate::arch::x86_64::multiboot::MultibootModule;
use crate::arch::x86_64::pcb::{self, set_user_regs, user_stack_low};
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::user_access;
use crate::ipc::ipc_port;
use crate::ipc::mach_port;
use crate::ipc::{IpcPort, IpcSpace};
use crate::kern::boot_script::{self, Command, Host, Script};
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::host;
use crate::kern::kheap::Kalloc;
use crate::kern::lock::SimpleLock;
use crate::kern::printf;
use crate::kern::sched_prim::{self, THREAD_AWAKENED};
use crate::kern::task::{self, BASEPRI_USER, MapSource, Task, current_task};
use crate::kern::thread::Thread;
use crate::vm::types::{VmInherit, VmProt};
use crate::vm::vm_map::{VmMap, round_page, trunc_page};
use crate::vm::vm_user;
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{
    self, NonNull, addr_of_mut, null_mut, with_exposed_provenance_mut,
};
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use elf_load;
use kmem::{KBox, KCString, KCStringError, KVec};

/// The send-right type the port insertion calls take.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;

/// The size of the user stack the first user thread gets.
const STACK_SIZE: VmSize = 2 * 64 * 1024;

/// The null port the stack mapping uses as its memory object.
const IP_NULL: *mut c_void = null_mut();

/// `boot_host_port` and `boot_device_port`: the local names the
/// compatibility path inserts for the user bootstrap.
///
/// The stores happen before `Thread::resume()` publishes the bootstrap
/// thread, and `user_bootstrap_compat()` runs only after that publish, so
/// `Release`/`Acquire` record the hand-off.
static BOOT_HOST_PORT: AtomicU32 = AtomicU32::new(0);
static BOOT_DEVICE_PORT: AtomicU32 = AtomicU32::new(0);

/// Finds the boot script in the Multiboot modules and runs it.
pub(crate) fn create() {
    let Ok(mut modules) = boot_modules() else {
        kpanic!("bootstrap_create", "cannot copy the boot modules");
    };
    if modules.is_empty() {
        kpanic!(
            "bootstrap_create",
            "No bootstrap code loaded with the kernel!"
        );
    }
    if modules.len() == 1 && is_compat(modules[0].command_line()) {
        let first = CStrArg::from(modules[0].command_line());
        kprint!(
            "Loading single multiboot module in compat mode: {}\n",
            first
        );
        let module = modules
            .remove(0)
            .and_then(|module| KBox::try_new(module, Kalloc).ok());
        let Some(module) = module else {
            kpanic!("bootstrap_create", "cannot keep the bootstrap module");
        };
        exec_compat(module);
    } else {
        let cmdline = kernel_cmdline();
        let mut host = BootstrapHost;
        let mut script = Script::new();
        set_boot_variables(&mut script, cmdline);
        set_cmdline_variables(&mut script, cmdline);
        parse_and_exec_modules(&modules, script, &mut host);
    }
}

/// Whether the single module's line looks like a bare program: it has no
/// blanks after its first space, or no space at all.
fn is_compat(line: &CStr) -> bool {
    let bytes = line.to_bytes();
    bytes
        .iter()
        .position(|&byte| byte == b' ')
        .is_none_or(|position| {
            bytes[position + 1..]
                .iter()
                .all(|&byte| matches!(byte, b' ' | b'\n'))
        })
}

/// Loads the single module into a fresh task and starts a thread in it.
///
/// The thread takes ownership of the module, so its image stays mapped
/// until the image has been copied into the task.
fn exec_compat(module: KBox<MultibootModule, Kalloc>) {
    // SAFETY: creation may block and the caller holds no locks.
    let Ok(task) =
        (unsafe { task::create_kernel_task(None, MapSource::Fresh) })
    else {
        kpanic!("bootstrap_exec_compat", "cannot create the bootstrap task")
    };
    // SAFETY: the task is live and fresh.
    let _ = unsafe { task::set_name(task, b"bootstrap") };
    // SAFETY: the parent task is live, and creation may block.
    let Ok(thread) = (unsafe { Thread::create(task) }) else {
        kpanic!(
            "bootstrap_exec_compat",
            "cannot create the bootstrap thread"
        )
    };
    // SAFETY: the thread is live.
    let _ = unsafe { Thread::set_name(thread, c"bootstrap".as_ptr()) };

    let module = KBox::into_raw(module);
    // SAFETY: the host object and the device port are live, and the fresh
    // task's space receives one send right each.
    unsafe {
        let host_port = make_send(host::host_priv_self());
        let name = insert_send_right(task, host_port);
        BOOT_HOST_PORT.store(name, Ordering::Release);
        let device_port =
            make_send(crate::device::device_init::master_device_port());
        let name = insert_send_right(task, device_port);
        BOOT_DEVICE_PORT.store(name, Ordering::Release);

        (*thread).saved.other = module.cast();
        (*thread).start(Some(user_bootstrap_compat));
    }
    // SAFETY: the thread is live and startable.
    let _ = unsafe { Thread::resume(thread) };
}

/// The kernel half of the first user thread in compatibility mode.
///
/// # Safety
///
/// The launcher must have handed this thread the boxed module it stored in
/// the thread's saved state, and must not touch it again.
unsafe extern "C" fn user_bootstrap_compat() {
    let thread = per_cpu::thread();
    // SAFETY: the launcher handed this thread the box and never touches it
    // again.
    let module = unsafe { (*thread).saved.other }.cast::<MultibootModule>();
    // SAFETY: the launcher handed this thread the live module.
    let exec_info = load_bootstrap(unsafe { &*module });
    // SAFETY: the box came from the launcher, and the image was already
    // copied into the task.
    unsafe { drop(KBox::from_raw(module, Kalloc)) };

    let host = port_name(BOOT_HOST_PORT.load(Ordering::Acquire));
    let device = port_name(BOOT_DEVICE_PORT.load(Ordering::Acquire));
    let cmdline = kernel_cmdline();
    let compat = compat_strings(cmdline);

    let argv: [*const c_char; 5] = [
        c"bootstrap".as_ptr(),
        compat.flags.as_ptr(),
        host.as_ptr().cast(),
        device.as_ptr().cast(),
        compat.root.as_ptr(),
    ];
    let vars = [EnvVar {
        name: b"MULTIBOOT_CMDLINE=",
        value: cmdline.to_bytes(),
    }];
    let environment: &[EnvVar<'_>] = if cmdline.to_bytes().is_empty() {
        &[]
    } else {
        &vars
    };
    unsafe { build_args_and_stack(&exec_info, &argv, environment) };

    unsafe { crate::arch::x86_64::locore::thread_bootstrap_return() };
}

/// The kernel operations the boot script drives.
struct BootstrapHost;

impl Host for BootstrapHost {
    fn create_task(
        &mut self,
        command: &mut Command,
    ) -> Result<(), boot_script::Error> {
        // SAFETY: creation may block and the caller holds no locks.
        let created = match unsafe {
            task::create_kernel_task(None, MapSource::Fresh)
        } {
            Ok(task) => task,
            Err(error) => {
                kprint!(
                    "boot script task creation failed with {:x}\n",
                    c_int::from(error)
                );
                return Err(boot_script::Error::Host);
            }
        };
        let Some(task) = NonNull::new(created) else {
            return Err(boot_script::Error::Host);
        };
        command.task = Some(task);
        // SAFETY: the task is live and fresh.
        let _ =
            unsafe { task::set_name(task.as_ptr(), command.path.to_bytes()) };
        let host = host::host_self();
        // SAFETY: the task is live and the caller holds no locks.
        let _ = unsafe {
            task::max_priority(host, task.as_ptr(), BASEPRI_USER, true, true)
        };
        Ok(())
    }

    fn resume_task(
        &mut self,
        command: &Command,
    ) -> Result<(), boot_script::Error> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::Host);
        };
        // SAFETY: the task is live and the caller holds no locks.
        match unsafe { task::resume(task.as_ptr()) } {
            Ok(()) => {
                let path = CStrArg::from(command.path.as_c_str());
                kprint!("\nstart {}: ", path);
                Ok(())
            }
            Err(error) => {
                kprint!(
                    "boot script task resume failed with {:x}\n",
                    c_int::from(error)
                );
                Err(boot_script::Error::Host)
            }
        }
    }

    fn prompt_resume_task(
        &mut self,
        command: &Command,
    ) -> Result<(), boot_script::Error> {
        let path = CStrArg::from(command.path.as_c_str());
        kprint!("Pausing for {}...\n", path);
        kprint!("Hit <return> to resume bootstrap.");
        let mut line = [0; 5];
        // SAFETY: the buffer holds five bytes and the reader stops inside
        // them.
        unsafe { printf::safe_gets(line.as_mut_ptr(), 5) };
        self.resume_task(command)
    }

    unsafe fn insert_port(
        &mut self,
        command: &Command,
        port: *mut c_void,
    ) -> Result<u32, boot_script::Error> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::Host);
        };
        Ok(unsafe { insert_send_right(task.as_ptr(), make_send(port)) })
    }

    unsafe fn insert_task_port(
        &mut self,
        command: &Command,
        target: *mut Task,
    ) -> Result<u32, boot_script::Error> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::Host);
        };
        let port = unsafe { make_send((*target).itk_sself) };
        Ok(unsafe { insert_send_right(task.as_ptr(), port) })
    }

    fn exec_command(
        &mut self,
        command: &Command,
        argv: &[*const c_char],
    ) -> Result<(), boot_script::Error> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::Host);
        };
        // SAFETY: the hook is the live module the parse recorded, the
        // task is live, and the script keeps the arguments alive until
        // `exec_cmd` returns.
        unsafe { exec_cmd(command.hook, task, argv) };
        Ok(())
    }

    unsafe fn free_task(&mut self, task: NonNull<Task>, aborting: bool) {
        unsafe { reap_task(task.as_ptr(), aborting) };
    }
}

/// Takes one send right to `port`.
///
/// # Safety
///
/// `port` must be a live active port.
unsafe fn make_send(port: *mut c_void) -> *mut c_void {
    unsafe { ipc_port::make_send(IpcPort::from_raw(port)) }.as_ptr()
}

/// Names `port` in `task`'s space, retrying the names the space already
/// holds.
///
/// # Safety
///
/// `task` must be a live task and `port` a live port the call consumes one
/// reference to.
unsafe fn insert_send_right(task: *mut Task, port: *mut c_void) -> c_uint {
    let mut name: c_uint = 1;
    loop {
        let space = unsafe { (*task).itk_space };
        let result = unsafe {
            mach_port::insert_right(
                IpcSpace::new(space),
                name,
                port,
                MACH_MSG_TYPE_PORT_SEND,
            )
        };
        if result.is_ok() {
            return name;
        }
        name = name.wrapping_add(1);
    }
}

/// Terminates `task` when aborting, then drops one reference to it.
///
/// # Safety
///
/// `task` must be the live task a `task-create` call made; the caller must
/// hold no locks, because termination may block.
unsafe fn reap_task(task: *mut Task, aborting: bool) {
    if aborting {
        let _ = unsafe { task::terminate(task) };
    }
    unsafe { task::deallocate(task) };
}

/// Publishes the standard ports and the kernel command line as boot-script
/// variables, before the modules are parsed.
fn set_boot_variables(script: &mut Script, cmdline: &CStr) {
    set_port(script, c"host-port", host::host_priv_self());
    let device_port = crate::device::device_init::master_device_port();
    set_port(script, c"device-port", device_port);
    set_port(script, c"kernel-task", task::kernel_task_self_port());

    set_str(script, c"kernel-command-line", cmdline.to_bytes());
    let compat = compat_strings(cmdline);
    set_str(script, c"boot-args", compat.flags.to_bytes());
    set_str(script, c"root-device", compat.root.to_bytes());
}

/// Defines the string variable `name`, halting the kernel on failure.
fn set_str(script: &mut Script, name: &CStr, value: &[u8]) {
    if let Err(error) = script.set_str(name.to_bytes(), value) {
        let name = CStrArg::from(name);
        kpanic!(
            "bootstrap_create",
            "cannot set boot-script variable {}: {}",
            name,
            error
        );
    }
}

/// Defines the port variable `name`, halting the kernel on failure.
fn set_port(script: &mut Script, name: &CStr, port: *mut c_void) {
    if let Err(error) = script.set_port(name.to_bytes(), port) {
        let name = CStrArg::from(name);
        kpanic!(
            "bootstrap_create",
            "cannot set boot-script variable {}: {}",
            name,
            error
        );
    }
}

/// Turns each `FOO=BAR` word of the kernel command line into a boot-script
/// variable.
fn set_cmdline_variables(script: &mut Script, cmdline: &CStr) {
    for word in cmdline
        .to_bytes()
        .split(|&byte| matches!(byte, b' ' | b'\t'))
    {
        let Some(position) = word.iter().position(|&byte| byte == b'=') else {
            continue;
        };
        if let Err(error) =
            script.set_str(&word[..position], &word[position + 1..])
        {
            kpanic!(
                "bootstrap_create",
                "cannot set a boot-script variable from the command line: {}",
                error
            );
        }
    }
}

/// Parses each module's boot-script line and runs the resulting script,
/// halting on a parse or execution error.
fn parse_and_exec_modules(
    modules: &[MultibootModule],
    mut script: Script,
    host: &mut BootstrapHost,
) {
    let mut losers = 0usize;
    for (index, module) in modules.iter().enumerate() {
        let line = module.command_line();
        let line_arg = CStrArg::from(line);
        kprint!("module {}: {}\n", index, line_arg);
        let result = script.parse_line(
            host,
            ptr::from_ref(module).cast_mut().cast(),
            line.to_bytes(),
        );
        if let Err(error) = result {
            kprint!("\n\tERROR: {}", error);
            losers += 1;
        }
    }
    kprint!("{} multiboot modules\n", modules.len());
    if losers != 0 {
        kpanic!(
            "bootstrap_create",
            "{} of {} boot script commands could not be parsed",
            losers,
            modules.len()
        );
    }
    if let Err(error) = script.exec(host) {
        kpanic!(
            "bootstrap_create",
            "ERROR in executing boot script: {}",
            error
        );
    }
}

/// The flag and root strings the old user bootstrap expects, derived from
/// the boot command line.
struct CompatStrings {
    /// The `-`-prefixed flags, `-x` when the command line carries none.
    flags: KCString<Kalloc>,
    /// The `root=` value with any `/dev/` prefix removed, `UNKNOWN` when
    /// the command line names none.
    root: KCString<Kalloc>,
}

impl CompatStrings {
    /// Collects the flags and the root name from `cmdline`.
    ///
    /// The C compared `char`, signed on `x86_64`: a byte above 0x7f ends
    /// a word.  A word the flags do not care about is skipped whole; the
    /// C's loop cannot step over a separator it does not know, such as a
    /// tab, so the skip advances the first byte before scanning the rest.
    ///
    /// # Errors
    ///
    /// [`KCStringError::Alloc`] when the heap cannot hold the strings.
    fn from_cmdline(cmdline: &[u8]) -> Result<Self, KCStringError> {
        const fn ends_word(byte: u8) -> bool {
            (byte as i8) <= b' ' as i8
        }

        let mut flags = KVec::try_with_capacity(cmdline.len() + 2, Kalloc)?;
        flags.try_push(b'-')?;
        let mut root = KVec::new(Kalloc);
        root.extend_from_slice(b"UNKNOWN")?;
        let mut position = 0;
        while position < cmdline.len() {
            let byte = cmdline[position];
            if byte == b' ' {
                position += 1;
            } else if byte == b'-' {
                position += 1;
                while !ends_word(cmdline.get(position).copied().unwrap_or(0)) {
                    flags.try_push(cmdline[position])?;
                    position += 1;
                }
            } else if cmdline[position..].starts_with(b"root=") {
                position += 5;
                if cmdline[position..].starts_with(b"/dev/") {
                    position += 5;
                }
                root.clear();
                while !ends_word(cmdline.get(position).copied().unwrap_or(0)) {
                    root.try_push(cmdline[position])?;
                    position += 1;
                }
            } else {
                position += 1;
                while !ends_word(cmdline.get(position).copied().unwrap_or(0)) {
                    position += 1;
                }
            }
        }
        if flags.len() == 1 {
            flags.try_push(b'x')?;
        }
        Ok(Self {
            flags: KCString::try_new(&flags, Kalloc)?,
            root: KCString::try_new(&root, Kalloc)?,
        })
    }
}

/// [`CompatStrings::from_cmdline`] of the boot command line, halting the
/// kernel on failure.
fn compat_strings(cmdline: &CStr) -> CompatStrings {
    match CompatStrings::from_cmdline(cmdline.to_bytes()) {
        Ok(compat) => compat,
        Err(error) => kpanic!(
            "bootstrap_create",
            "cannot copy the boot command line: {}",
            error
        ),
    }
}

/// The decimal name the user bootstrap reads for a port, NUL-padded.
fn port_name(port: u32) -> [u8; 11] {
    let mut name = [0; 11];
    let digits = port.checked_ilog10().unwrap_or(0) as usize + 1;
    let mut value = port;
    for slot in name[..digits].iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
    name
}

/// The module image the ELF loader reads from and places into.
struct ModuleImage<'a> {
    module: &'a MultibootModule,
}

impl elf_load::ElfImage for ModuleImage<'_> {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> usize {
        // A range the module does not cover is a short read: the
        // loader classifies it as a malformed image.
        let Some(source) = self.module.image_at(offset, buf.len()) else {
            return 0;
        };
        // SAFETY: `image_at` covers `buf.len()` bytes at `source`, and
        // `buf` is writable for that many.
        unsafe {
            ptr::copy_nonoverlapping(
                source.cast::<u8>(),
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
        buf.len()
    }
}

impl ModuleImage<'_> {
    /// Allocates the segment's pages, copies its file bytes and applies
    /// its protection, halting on any failure.
    fn place(&self, segment: elf_load::Segment) {
        let Some(source) =
            self.module.image_at(segment.offset(), segment.file_len())
        else {
            kpanic!(
                "read_exec",
                "the bootstrap module does not cover the section at {:#x}",
                segment.offset()
            );
        };

        let addr = segment.addr();
        // SAFETY: runs on the thread that receives the image; its task
        // and map are live.
        let map = unsafe { (*current_task()).map }.cast::<VmMap>();
        let mut start_page = trunc_page(addr);
        let end_page = round_page(addr.wrapping_add(segment.mem_len()));
        let page_count = end_page - start_page;
        if let Some(mut map) = NonNull::new(map) {
            let result = unsafe {
                vm_user::allocate(
                    map.as_mut(),
                    &mut start_page,
                    page_count,
                    false,
                )
            };
            if let Err(error) = result {
                kpanic!(
                    "read_exec",
                    "cannot allocate the bootstrap section: {:x}",
                    error.as_kern_return()
                );
            }
        }

        if segment.file_len() > 0 {
            // SAFETY: `image_at` covers `file_len` bytes, and the
            // user address is the segment just allocated above.
            unsafe {
                user_access::copyout(
                    source,
                    user_ptr(addr),
                    segment.file_len(),
                );
            }
        }

        let mem_prot = vm_prot(segment.sectype().protection());
        if mem_prot != VmProt::ALL
            && let Some(mut map) = NonNull::new(map)
        {
            let result = unsafe {
                vm_user::protect(
                    map.as_mut(),
                    start_page,
                    page_count,
                    false,
                    mem_prot,
                )
            };
            if let Err(error) = result {
                kpanic!(
                    "read_exec",
                    "cannot protect the bootstrap section: {:x}",
                    error.as_kern_return()
                );
            }
        }
    }
}

/// The `VmProt` the loader's protection bits name.
fn vm_prot(prot: elf_load::Prot) -> VmProt {
    let mut result = VmProt::NONE;
    if prot.contains(elf_load::Prot::READ) {
        result |= VmProt::READ;
    }
    if prot.contains(elf_load::Prot::WRITE) {
        result |= VmProt::WRITE;
    }
    if prot.contains(elf_load::Prot::EXECUTE) {
        result |= VmProt::EXECUTE;
    }
    result
}

/// Parses the image of `module` and places its segments into the current
/// task's map, or halts.
fn load_bootstrap(module: &MultibootModule) -> elf_load::ExecInfo {
    let image = ModuleImage { module };
    let info = match elf_load::parse(&image) {
        Ok(info) => info,
        Err(err) => kpanic!(
            "copy_bootstrap",
            "Cannot load user-bootstrap image: {err:?}"
        ),
    };
    for segment in info.segments(&image) {
        let segment = match segment {
            Ok(segment) => segment,
            Err(err) => kpanic!(
                "copy_bootstrap",
                "Cannot read user-bootstrap image: {err:?}"
            ),
        };
        image.place(segment);
    }
    info
}

/// One environment entry: a name ending in `=`, and a value.
struct EnvVar<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

/// Copies one value to the user stack.
///
/// # Safety
///
/// `to` must be a writable user address of `size_of::<T>()` bytes.
unsafe fn copyout_value<T>(value: &T, to: VmOffset) {
    unsafe {
        user_access::copyout(
            ptr::from_ref(value).cast(),
            user_ptr(to),
            size_of::<T>(),
        );
    }
}

/// Copies raw bytes to the user stack.
///
/// # Safety
///
/// `from` must be readable for `len` bytes and `to` a writable user
/// address of that many bytes.
unsafe fn copyout_bytes(from: *const c_void, to: VmOffset, len: usize) {
    unsafe { user_access::copyout(from, user_ptr(to), len) };
}

/// Allocates the user stack and writes the argument and environment
/// vectors into it.
///
/// # Safety
///
/// Runs on the current thread, whose pcb and map are live; `info` must be
/// the record the ELF loader filled, and every string must outlive the
/// call.
unsafe fn build_args_and_stack(
    info: &elf_load::ExecInfo,
    argv: &[*const c_char],
    envp: &[EnvVar<'_>],
) {
    let mut arg_len = 0usize;
    for &arg in argv {
        arg_len += unsafe { CStr::from_ptr(arg) }.to_bytes().len() + 1;
    }
    for env in envp {
        arg_len += env.name.len() + env.value.len() + 1;
    }
    // The count, one pointer per argument and its terminator, one pointer
    // per environment variable and its terminator.
    let pointer_bytes = size_of::<VmOffset>()
        + (argv.len() + 1 + envp.len() + 1) * size_of::<VmOffset>();
    arg_len += pointer_bytes;

    let stack_size = round_page(STACK_SIZE);
    let mut stack_base = user_stack_low(stack_size);
    let _ = unsafe {
        vm_user::map(
            &mut *(*current_task()).map.cast::<VmMap>(),
            &mut vm_user::MapRequest {
                address: &mut stack_base,
                size: stack_size,
                mask: 0,
                anywhere: false,
                memory_object: IP_NULL,
                offset: 0,
                copy: false,
                cur_protection: vm_prot(info.stack_prot()),
                max_protection: VmProt::ALL,
                inheritance: VmInherit::COPY,
            },
        )
    };

    let regs = pcb::ExecInfo {
        format: 0,
        entry: info.entry(),
        init_dp: 0,
        interp: 0,
        stack_prot: 0,
    };
    let mut arg_pos = unsafe {
        set_user_regs(stack_base, stack_size, ptr::from_ref(&regs), arg_len)
    };
    let mut string_pos = arg_pos + pointer_bytes;

    let count = argv.len();
    unsafe { copyout_value(&count, arg_pos) };
    arg_pos += size_of::<VmOffset>();
    for &arg in argv {
        let bytes = unsafe { CStr::from_ptr(arg) }.to_bytes_with_nul();
        unsafe {
            copyout_value(&string_pos, arg_pos);
            arg_pos += size_of::<VmOffset>();
            copyout_bytes(arg.cast(), string_pos, bytes.len());
        }
        string_pos += bytes.len();
    }

    let zero: VmOffset = 0;
    unsafe {
        copyout_value(&zero, arg_pos);
        arg_pos += size_of::<VmOffset>();
    }
    for env in envp {
        unsafe {
            copyout_value(&string_pos, arg_pos);
            arg_pos += size_of::<VmOffset>();
            copyout_bytes(
                env.name.as_ptr().cast(),
                string_pos,
                env.name.len(),
            );
            string_pos += env.name.len();
            copyout_bytes(
                env.value.as_ptr().cast(),
                string_pos,
                env.value.len(),
            );
            string_pos += env.value.len();
            let nul: u8 = 0;
            copyout_bytes(ptr::from_ref(&nul).cast(), string_pos, 1);
        }
        string_pos += 1;
    }
    unsafe { copyout_value(&zero, arg_pos) };
}

/// What the waiting bootstrap thread hands the first user thread.
///
/// The lock is the kernel's [`SimpleLock`], not a spin mutex, because the
/// wait protocol hands it straight to `sched_prim::thread_sleep()`.
struct UserBootstrapInfo {
    module: *mut c_void,
    argv: *const [*const c_char],
    done: AtomicI32,
    lock: SimpleLock,
}

/// Runs one boot-script command in a fresh thread and waits until that
/// thread has copied the arguments, so the script's buffers may die.
///
/// # Safety
///
/// `hook` must be the live module the parse recorded, `task` a live task,
/// and `argv` a vector that stays valid until this returns.
unsafe fn exec_cmd(
    hook: *mut c_void,
    task: NonNull<Task>,
    argv: &[*const c_char],
) {
    let mut info = UserBootstrapInfo {
        module: hook,
        argv: ptr::from_ref(argv),
        done: AtomicI32::new(0),
        lock: SimpleLock::new(),
    };
    let info = addr_of_mut!(info);

    let Ok(thread) = (unsafe { Thread::create(task.as_ptr()) }) else {
        kpanic!("boot_script_exec_cmd", "cannot create the bootstrap thread")
    };

    unsafe {
        (*info).lock.lock();
        (*thread).saved.other = info.cast();
        (*thread).start(Some(user_bootstrap));
        let _ = Thread::resume(thread);

        // Block this thread until the new one has finished referring to
        // the local state.
        while (*info).done.load(Ordering::Relaxed) == 0 {
            sched_prim::thread_sleep(
                info.cast(),
                addr_of_mut!((*info).lock),
                0,
            );
            (*info).lock.lock();
        }
        (*info).lock.unlock();
        Thread::deallocate(thread);
    }
    kprint!("\n");
}

/// The kernel half of the first user thread: loads the module, builds the
/// stack, then parks until the launcher releases it.
///
/// # Safety
///
/// The launcher must have stored the info record in the thread's saved
/// state and must keep it, and the arguments it points at, alive until
/// `done` is set.
unsafe extern "C" fn user_bootstrap() {
    let thread = per_cpu::thread();
    let info = unsafe { (*thread).saved.other.cast::<UserBootstrapInfo>() };
    // SAFETY: the launcher stored the live module pointer in `info`.
    let exec_info =
        load_bootstrap(unsafe { &*(*info).module.cast::<MultibootModule>() });

    kprint!("task loaded:");
    let argv = unsafe { &*(*info).argv };
    unsafe { build_args_and_stack(&exec_info, argv, &[]) };
    for &argument in argv {
        let argument = unsafe { CStrArg::from_ptr(argument) };
        kprint!(" {}", argument);
    }

    // SAFETY: runs on the current task.
    let _ = unsafe { task::suspend(current_task()) };

    unsafe {
        (*info).lock.lock();
        (*info).done.store(1, Ordering::Relaxed);
        (*info).lock.unlock();
        sched_prim::thread_wakeup_prim(info.cast(), 0, THREAD_AWAKENED);
    }
    unsafe { crate::arch::x86_64::locore::thread_bootstrap_return() };
}

/// The user address a kernel value denotes, both targets' identity
/// conversion.
const fn user_ptr(address: VmOffset) -> *mut c_void {
    with_exposed_provenance_mut(address)
}
