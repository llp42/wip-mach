// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The first user processes: the kernel loads a Multiboot module into a
//! fresh task, builds the argument and environment vectors on the user
//! stack, and starts the task's first thread.
//!
//! A single module whose command line carries nothing but the module name
//! takes the compatibility path and is loaded directly; otherwise the
//! module lines spell a boot script, which [`create()`] parses and runs
//! against the `BootstrapHost` operations.

use crate::boot_script::{self, Command, Host, Script};
use crate::platform::{Module, Platform};
use crate::text::Text;
use crate::types::{BootInfo, Heap};
use core::ffi::{CStr, c_char, c_uint, c_void};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::{
    self, NonNull, addr_of_mut, null_mut, with_exposed_provenance_mut,
};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};
use kmem::{KBox, KCString, KCStringError, KVec};
use mach_ipc::ipc_port;
use mach_ipc::mach_port;
use mach_ipc::{IpcPort, IpcSpace};
use mach_task::task::BASEPRI_USER;
use mach_thread::sched_prim::{self, THREAD_AWAKENED};
use mach_thread::task;
use mach_thread::task::{Task, current_task};
use mach_thread::thread::Thread;
use mach_thread::types::MapSource;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::simple_lock::SimpleLock;
use mach_vm::types::{VmInherit, VmProt};
use mach_vm::vm_map::{VmMap, round_page, trunc_page};
use mach_vm::vm_user;

/// The send-right type the port insertion calls take.
const MACH_MSG_TYPE_PORT_SEND: c_uint = 17;

/// The size of the user stack the first user thread gets.
const STACK_SIZE: VmSize = 2 * 64 * 1024;

/// The null port the stack mapping uses as its memory object.
const IP_NULL: *mut c_void = null_mut();

/// The local names the compatibility path inserts for the host and device
/// ports of the user bootstrap.
///
/// The stores happen before `Thread::resume()` publishes the bootstrap
/// thread, and `user_bootstrap_compat()` runs only after that publish, so
/// `Release`/`Acquire` record the hand-off.
static BOOT_HOST_PORT: AtomicU32 = AtomicU32::new(0);
static BOOT_DEVICE_PORT: AtomicU32 = AtomicU32::new(0);

/// The kernel command line, which the compatibility thread passes on.
/// [`create()`] stores it before any thread starts, so `Release`/`Acquire`
/// record the hand-off as for the port names.
static CMDLINE: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

/// The kernel command line [`create()`] stored.
fn kernel_cmdline() -> &'static CStr {
    // SAFETY: `create()` stored the `'static` line before any reader ran.
    unsafe { CStr::from_ptr(CMDLINE.load(Ordering::Acquire)) }
}

/// The running task's map.
fn current_map<P: Platform>() -> *mut VmMap<P> {
    // SAFETY: the running thread's task is live. Task creation sets its
    // `map` before the task has a thread, and nothing writes the field
    // again.
    unsafe { (*current_task::<P>().as_ptr()).map.cast() }
}

/// Finds the boot script in the boot modules and runs it.
///
/// # Panics
///
/// When there is no module, or the modules cannot be loaded and started:
/// the kernel has nothing to run.
pub fn create<P: Platform>(info: BootInfo<P>) {
    let BootInfo {
        mut modules,
        cmdline,
        host_port,
        host_priv_port,
        device_port,
    } = info;
    CMDLINE.store(cmdline.as_ptr().cast_mut(), Ordering::Release);
    assert!(
        !modules.is_empty(),
        "No bootstrap code loaded with the kernel!"
    );
    if modules.len() == 1 && is_compat(modules[0].command_line()) {
        let first = Text(modules[0].command_line());
        P::print(format_args!(
            "Loading single multiboot module in compat mode: {first}\n"
        ));
        let module = modules.remove(0).and_then(|module| {
            KBox::try_new(module, Heap::<P>::default()).ok()
        });
        let Some(module) = module else {
            panic!("cannot keep the bootstrap module");
        };
        exec_compat::<P>(module, host_priv_port, device_port);
    } else {
        let mut host = BootstrapHost::<P> {
            host_port,
            _platform: PhantomData,
        };
        let mut script = Script::<P>::new();
        set_boot_variables(&mut script, cmdline, host_priv_port, device_port);
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
fn exec_compat<P: Platform>(
    module: KBox<P::Module, Heap<P>>,
    host_priv_port: *mut c_void,
    device_port: *mut c_void,
) {
    // SAFETY: creation may block and the caller holds no locks.
    let Ok(task) =
        (unsafe { task::create_kernel_task(None, MapSource::Fresh) })
    else {
        panic!("cannot create the bootstrap task")
    };
    // SAFETY: the task is live and fresh.
    let _ = unsafe { task::set_name(task, b"bootstrap") };
    // SAFETY: the parent task is live, and creation may block.
    let Ok(thread) = (unsafe { Thread::<P>::create(task) }) else {
        panic!("cannot create the bootstrap thread")
    };
    // SAFETY: the thread is live.
    let _ = unsafe { Thread::<P>::set_name(thread, c"bootstrap".as_ptr()) };

    let module = KBox::into_raw(module);
    // SAFETY: the host object and the device port are live, and the fresh
    // task's space receives one send right each.
    unsafe {
        let host_port = make_send(host_priv_port);
        let name = insert_send_right(task, host_port);
        BOOT_HOST_PORT.store(name, Ordering::Release);
        let device_port = make_send(device_port);
        let name = insert_send_right(task, device_port);
        BOOT_DEVICE_PORT.store(name, Ordering::Release);

        (*thread).saved.other = module.cast();
        (*thread).start(Some(user_bootstrap_compat::<P>));
    }
    // SAFETY: the thread is live and startable.
    let _ = unsafe { Thread::<P>::resume(thread) };
}

/// The kernel half of the first user thread in compatibility mode.
///
/// # Safety
///
/// The launcher must have handed this thread the boxed module it stored in
/// the thread's saved state, and must not touch it again.
unsafe extern "C" fn user_bootstrap_compat<P: Platform>() {
    let thread = P::cpu_thread();
    // SAFETY: the launcher handed this thread the box and never touches it
    // again.
    let module = unsafe { (*thread).saved.other }.cast::<P::Module>();
    // SAFETY: the launcher handed this thread the live module.
    let exec_info = load_bootstrap::<P>(unsafe { &*module });
    // SAFETY: the box came from the launcher, and the image was already
    // copied into the task.
    unsafe { drop(KBox::from_raw(module, Heap::<P>::default())) };

    let host = port_name(BOOT_HOST_PORT.load(Ordering::Acquire));
    let device = port_name(BOOT_DEVICE_PORT.load(Ordering::Acquire));
    let cmdline = kernel_cmdline();
    let compat = compat_strings::<P>(cmdline);

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
    unsafe { build_args_and_stack::<P>(&exec_info, &argv, environment) };

    unsafe { (P::BOOTSTRAP_RETURN)() };
}

/// The kernel operations the boot script drives.
struct BootstrapHost<P> {
    /// The host port a task's priority limit is set through.
    host_port: *mut c_void,
    _platform: PhantomData<P>,
}

impl<P: Platform> Host<P> for BootstrapHost<P> {
    fn create_task(
        &mut self,
        command: &mut Command<P>,
    ) -> Result<(), boot_script::Error<P>> {
        // SAFETY: creation may block and the caller holds no locks.
        let created = match unsafe {
            task::create_kernel_task(None, MapSource::Fresh)
        } {
            Ok(task) => task,
            Err(error) => {
                P::print(format_args!(
                    "boot script task creation failed with {error:?}\n"
                ));
                return Err(boot_script::Error::<P>::Host);
            }
        };
        let Some(task) = NonNull::new(created) else {
            return Err(boot_script::Error::<P>::Host);
        };
        command.task = Some(task);
        // SAFETY: the task is live and fresh.
        let _ =
            unsafe { task::set_name(task.as_ptr(), command.path.to_bytes()) };
        // SAFETY: the task is live and the caller holds no locks.
        let _ = unsafe {
            task::max_priority(
                self.host_port,
                task.as_ptr(),
                BASEPRI_USER,
                true,
                true,
            )
        };
        Ok(())
    }

    fn resume_task(
        &mut self,
        command: &Command<P>,
    ) -> Result<(), boot_script::Error<P>> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::<P>::Host);
        };
        // SAFETY: the task is live and the caller holds no locks.
        match unsafe { task::resume(task.as_ptr()) } {
            Ok(()) => {
                let path = Text(command.path.as_c_str());
                P::print(format_args!("\nstart {path}: "));
                Ok(())
            }
            Err(error) => {
                P::print(format_args!(
                    "boot script task resume failed with {error:?}\n"
                ));
                Err(boot_script::Error::<P>::Host)
            }
        }
    }

    fn prompt_resume_task(
        &mut self,
        command: &Command<P>,
    ) -> Result<(), boot_script::Error<P>> {
        let path = Text(command.path.as_c_str());
        P::print(format_args!("Pausing for {path}...\n"));
        P::print(format_args!("Hit <return> to resume bootstrap."));
        let mut line = [0; 5];
        P::read_line(&mut line);
        self.resume_task(command)
    }

    unsafe fn insert_port(
        &mut self,
        command: &Command<P>,
        port: *mut c_void,
    ) -> Result<u32, boot_script::Error<P>> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::<P>::Host);
        };
        Ok(unsafe { insert_send_right(task.as_ptr(), make_send(port)) })
    }

    unsafe fn insert_task_port(
        &mut self,
        command: &Command<P>,
        target: *mut Task<P>,
    ) -> Result<u32, boot_script::Error<P>> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::<P>::Host);
        };
        let port = unsafe { make_send((*target).itk_sself) };
        Ok(unsafe { insert_send_right(task.as_ptr(), port) })
    }

    fn exec_command(
        &mut self,
        command: &Command<P>,
        argv: &[*const c_char],
    ) -> Result<(), boot_script::Error<P>> {
        let Some(task) = command.task else {
            return Err(boot_script::Error::<P>::Host);
        };
        // SAFETY: the hook is the live module the parse recorded, the
        // task is live, and the script keeps the arguments alive until
        // `exec_cmd` returns.
        unsafe { exec_cmd(command.hook, task, argv) };
        Ok(())
    }

    /// Terminates `task` when aborting, then drops one reference to it.
    ///
    /// # Safety
    ///
    /// `task` must be the live task a `task-create` call made; the caller
    /// must hold no locks, because termination may block.
    unsafe fn free_task(&mut self, task: NonNull<Task<P>>, aborting: bool) {
        let task = task.as_ptr();
        if aborting {
            let _ = unsafe { task::terminate(task) };
        }
        unsafe { task::deallocate(task) };
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
unsafe fn insert_send_right<P: Platform>(
    task: *mut Task<P>,
    port: *mut c_void,
) -> c_uint {
    let mut name: c_uint = 1;
    loop {
        let space = unsafe { (*task).itk_space };
        let result = unsafe {
            mach_port::insert_right::<P>(
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

/// Publishes the standard ports and the kernel command line as boot-script
/// variables, before the modules are parsed.
fn set_boot_variables<P: Platform>(
    script: &mut Script<P>,
    cmdline: &CStr,
    host_priv_port: *mut c_void,
    device_port: *mut c_void,
) {
    set_port(script, c"host-port", host_priv_port);
    set_port(script, c"device-port", device_port);
    set_port(script, c"kernel-task", task::kernel_task_self_port::<P>());

    set_str(script, c"kernel-command-line", cmdline.to_bytes());
    let compat = compat_strings::<P>(cmdline);
    set_str(script, c"boot-args", compat.flags.to_bytes());
    set_str(script, c"root-device", compat.root.to_bytes());
}

/// Defines the string variable `name`, halting the kernel on failure.
fn set_str<P: Platform>(script: &mut Script<P>, name: &CStr, value: &[u8]) {
    if let Err(error) = script.set_str(name.to_bytes(), value) {
        let name = Text(name);
        panic!("cannot set boot-script variable {name}: {error}");
    }
}

/// Defines the port variable `name`, halting the kernel on failure.
fn set_port<P: Platform>(
    script: &mut Script<P>,
    name: &CStr,
    port: *mut c_void,
) {
    if let Err(error) = script.set_port(name.to_bytes(), port) {
        let name = Text(name);
        panic!("cannot set boot-script variable {name}: {error}");
    }
}

/// Turns each `FOO=BAR` word of the kernel command line into a boot-script
/// variable.
fn set_cmdline_variables<P: Platform>(script: &mut Script<P>, cmdline: &CStr) {
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
            panic!(
                "cannot set a boot-script variable from the command line: {error}"
            );
        }
    }
}

/// Parses each module's boot-script line and runs the resulting script,
/// halting on a parse or execution error.
fn parse_and_exec_modules<P: Platform>(
    modules: &[P::Module],
    mut script: Script<P>,
    host: &mut BootstrapHost<P>,
) {
    let mut losers = 0usize;
    for (index, module) in modules.iter().enumerate() {
        let line = module.command_line();
        let line_arg = Text(line);
        P::print(format_args!("module {index}: {line_arg}\n"));
        let result = script.parse_line(
            host,
            ptr::from_ref(module).cast_mut().cast(),
            line.to_bytes(),
        );
        if let Err(error) = result {
            P::print(format_args!("\n\tERROR: {error}"));
            losers += 1;
        }
    }
    P::print(format_args!("{} multiboot modules\n", modules.len()));
    assert!(
        losers == 0,
        "{} of {} boot script commands could not be parsed",
        losers,
        modules.len()
    );
    if let Err(error) = script.exec(host) {
        panic!("ERROR in executing boot script: {error}");
    }
}

/// The flag and root strings the old user bootstrap expects, derived from
/// the boot command line.
struct CompatStrings<P: Platform> {
    /// The `-`-prefixed flags, `-x` when the command line carries none.
    flags: KCString<Heap<P>>,
    /// The `root=` value with any `/dev/` prefix removed, `UNKNOWN` when
    /// the command line names none.
    root: KCString<Heap<P>>,
}

impl<P: Platform> CompatStrings<P> {
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
            byte.cast_signed() <= b' '.cast_signed()
        }

        let mut flags =
            KVec::try_with_capacity(cmdline.len() + 2, Heap::<P>::default())?;
        flags.try_push(b'-')?;
        let mut root = KVec::new(Heap::<P>::default());
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
            flags: KCString::try_new(&flags, Heap::<P>::default())?,
            root: KCString::try_new(&root, Heap::<P>::default())?,
        })
    }
}

/// [`CompatStrings::from_cmdline`] of the boot command line, halting the
/// kernel on failure.
fn compat_strings<P: Platform>(cmdline: &CStr) -> CompatStrings<P> {
    match CompatStrings::<P>::from_cmdline(cmdline.to_bytes()) {
        Ok(compat) => compat,
        Err(error) => panic!("cannot copy the boot command line: {error}"),
    }
}

/// The decimal name the user bootstrap reads for a port, NUL-padded.
fn port_name(port: u32) -> [u8; 11] {
    let mut name = [0; 11];
    let mut digits = itoa::Buffer::new();
    for (slot, digit) in name.iter_mut().zip(digits.format(port).bytes()) {
        *slot = digit;
    }
    name
}

/// Allocates the pages of `segment` of `image`, copies its file bytes and
/// applies its protection, halting on any failure.
fn place<P: Platform>(image: &[u8], segment: elf_load::Segment) {
    let Some(source) = image.get(
        segment.offset()..segment.offset().wrapping_add(segment.file_len()),
    ) else {
        panic!(
            "the bootstrap module does not cover the section at {:#x}",
            segment.offset()
        );
    };

    let addr = segment.addr();
    let map = current_map::<P>();
    let mut start_page = trunc_page(addr);
    let end_page = round_page(addr.wrapping_add(segment.mem_len()));
    let page_count = end_page - start_page;
    if let Some(mut map) = NonNull::new(map) {
        // SAFETY: the running task's map is live while this thread runs.
        let result = unsafe {
            vm_user::allocate(map.as_mut(), &mut start_page, page_count, false)
        };
        if let Err(error) = result {
            panic!("cannot allocate the bootstrap section: {error:?}");
        }
    }

    if segment.file_len() > 0 {
        // SAFETY: `source` holds `file_len` bytes, and the user address
        // is the segment just allocated above.
        unsafe {
            let _ = P::copyout(
                source.as_ptr().cast(),
                user_ptr(addr),
                segment.file_len(),
            );
        }
    }

    let mem_prot = vm_prot(segment.sectype().protection());
    if mem_prot != VmProt::ALL
        && let Some(mut map) = NonNull::new(map)
    {
        // SAFETY: the running task's map is live while this thread runs.
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
            panic!("cannot protect the bootstrap section: {error:?}");
        }
    }
}

/// The `VmProt` the loader's protection bits name.
fn vm_prot(prot: elf_load::Prot) -> VmProt {
    let mut result = VmProt::empty();
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
fn load_bootstrap<P: Platform>(module: &P::Module) -> elf_load::ExecInfo<'_> {
    let image = module.image();
    let info = match elf_load::parse(image) {
        Ok(info) => info,
        Err(err) => panic!("Cannot load user-bootstrap image: {err:?}"),
    };
    for segment in info.segments() {
        place::<P>(image, segment);
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
unsafe fn copyout_value<T, P: Platform>(value: &T, to: VmOffset) {
    unsafe {
        let _ = P::copyout(
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
unsafe fn copyout_bytes<P: Platform>(
    from: *const c_void,
    to: VmOffset,
    len: usize,
) {
    let _ = unsafe { P::copyout(from, user_ptr(to), len) };
}

/// Allocates the user stack and writes the argument and environment
/// vectors into it.
///
/// # Safety
///
/// Runs on the current thread, whose pcb is live; `info` must be the record
/// the ELF loader filled, and every string must outlive the call.
unsafe fn build_args_and_stack<P: Platform>(
    info: &elf_load::ExecInfo<'_>,
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
    let mut stack_base = P::USER_ADDRESS_END.wrapping_sub(stack_size);
    let _ = unsafe {
        vm_user::map(
            &mut *current_map::<P>(),
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

    let mut arg_pos = unsafe {
        P::set_user_regs(stack_base, stack_size, info.entry(), arg_len)
    };
    let mut string_pos = arg_pos + pointer_bytes;

    let count = argv.len();
    unsafe { copyout_value::<_, P>(&count, arg_pos) };
    arg_pos += size_of::<VmOffset>();
    for &arg in argv {
        let bytes = unsafe { CStr::from_ptr(arg) }.to_bytes_with_nul();
        unsafe {
            copyout_value::<_, P>(&string_pos, arg_pos);
            arg_pos += size_of::<VmOffset>();
            copyout_bytes::<P>(arg.cast(), string_pos, bytes.len());
        }
        string_pos += bytes.len();
    }

    let zero: VmOffset = 0;
    unsafe {
        copyout_value::<_, P>(&zero, arg_pos);
        arg_pos += size_of::<VmOffset>();
    }
    for env in envp {
        unsafe {
            copyout_value::<_, P>(&string_pos, arg_pos);
            arg_pos += size_of::<VmOffset>();
            copyout_bytes::<P>(
                env.name.as_ptr().cast(),
                string_pos,
                env.name.len(),
            );
            string_pos += env.name.len();
            copyout_bytes::<P>(
                env.value.as_ptr().cast(),
                string_pos,
                env.value.len(),
            );
            string_pos += env.value.len();
            let nul: u8 = 0;
            copyout_bytes::<P>(ptr::from_ref(&nul).cast(), string_pos, 1);
        }
        string_pos += 1;
    }
    unsafe { copyout_value::<_, P>(&zero, arg_pos) };
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
unsafe fn exec_cmd<P: Platform>(
    hook: *mut c_void,
    task: NonNull<Task<P>>,
    argv: &[*const c_char],
) {
    let mut info = UserBootstrapInfo {
        module: hook,
        argv: ptr::from_ref(argv),
        done: AtomicI32::new(0),
        lock: SimpleLock::new(),
    };
    let info = addr_of_mut!(info);

    let Ok(thread) = (unsafe { Thread::<P>::create(task.as_ptr()) }) else {
        panic!("cannot create the bootstrap thread")
    };

    unsafe {
        (*info).lock.lock();
        (*thread).saved.other = info.cast();
        (*thread).start(Some(user_bootstrap::<P>));
        let _ = Thread::<P>::resume(thread);

        // Block this thread until the new one has finished referring to
        // the local state.
        while (*info).done.load(Ordering::Relaxed) == 0 {
            sched_prim::thread_sleep::<P>(
                info.cast(),
                addr_of_mut!((*info).lock),
                0,
            );
            (*info).lock.lock();
        }
        (*info).lock.unlock();
        Thread::<P>::deallocate(thread);
    }
    P::print(format_args!("\n"));
}

/// The kernel half of the first user thread: loads the module, builds the
/// stack, then parks until the launcher releases it.
///
/// # Safety
///
/// The launcher must have stored the info record in the thread's saved
/// state and must keep it, and the arguments it points at, alive until
/// `done` is set.
unsafe extern "C" fn user_bootstrap<P: Platform>() {
    let thread = P::cpu_thread();
    let info = unsafe { (*thread).saved.other.cast::<UserBootstrapInfo>() };
    // SAFETY: the launcher stored the live module pointer in `info`.
    let exec_info =
        load_bootstrap::<P>(unsafe { &*(*info).module.cast::<P::Module>() });

    P::print(format_args!("task loaded:"));
    let argv = unsafe { &*(*info).argv };
    unsafe { build_args_and_stack::<P>(&exec_info, argv, &[]) };
    for &argument in argv {
        let argument = unsafe { Text::from_ptr(argument) };
        P::print(format_args!(" {argument}"));
    }

    // SAFETY: the current task is live, and nothing is locked.
    let _ = unsafe { task::suspend(current_task::<P>().as_ptr()) };

    unsafe {
        (*info).lock.lock();
        (*info).done.store(1, Ordering::Relaxed);
        (*info).lock.unlock();
        sched_prim::thread_wakeup_prim::<P>(info.cast(), 0, THREAD_AWAKENED);
    }
    unsafe { (P::BOOTSTRAP_RETURN)() };
}

/// The user address a kernel value denotes, both targets' identity
/// conversion.
const fn user_ptr(address: VmOffset) -> *mut c_void {
    with_exposed_provenance_mut(address)
}
