// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The boot script: the small command language the boot loader leaves in
//! the Multiboot module strings.
//!
//! Each module string names a program and its arguments. An argument is
//! literal text, a `${name}` value, or a `$(...)` expression that may call
//! the `task-create`, `task-resume` and `prompt-task-resume` functions and
//! assign their results to names. Parsing fills a [`Script`] with commands
//! and symbols; [`Script::exec`] then loads each command's module into the
//! task it created, names the ports its arguments mention and resumes it.

use crate::platform::Platform;
use crate::text::Text;
use crate::types::Heap;
use core::ffi::{CStr, c_char, c_void};
use core::fmt;
use core::ptr::NonNull;
use kmem::{AllocError, KCString, KCStringError, KVec};
use mach_thread::task::Task;

/// A boot-script failure.
pub enum Error<P: Platform> {
    /// The heap ran out while the script was built or run.
    OutOfMemory,
    /// The line does not follow the language.
    Syntax,
    /// A function name appeared where only a value fits.
    InvalidSymbol,
    /// An assignment targeted a function name.
    InvalidAssignment,
    /// A value expression named a symbol that never received a value.
    UndefinedSymbol(KCString<Heap<P>>),
    /// The kernel operation behind a function or a load failed.
    Host,
}

impl<P: Platform> fmt::Display for Error<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => {
                formatter.write_str("not enough memory for the boot script")
            }
            Self::Syntax => {
                formatter.write_str("syntax error in the boot script")
            }
            Self::InvalidSymbol => formatter
                .write_str("function name where the language wants a value"),
            Self::InvalidAssignment => {
                formatter.write_str("cannot assign to a function name")
            }
            Self::UndefinedSymbol(name) => write!(
                formatter,
                "boot script references undefined symbol '{}'",
                Text(name.as_c_str())
            ),
            Self::Host => {
                formatter.write_str("boot script kernel operation failed")
            }
        }
    }
}

impl<P: Platform> From<AllocError> for Error<P> {
    fn from(_: AllocError) -> Self {
        Self::OutOfMemory
    }
}

impl<P: Platform> From<KCStringError> for Error<P> {
    fn from(error: KCStringError) -> Self {
        match error {
            KCStringError::InteriorNul => Self::Syntax,
            KCStringError::Alloc(_) => Self::OutOfMemory,
        }
    }
}

/// The kernel operations a boot script drives.
///
/// The script itself owns no kernel logic: the implementation creates and
/// resumes tasks, names ports and loads modules.
pub trait Host<P: Platform> {
    /// Creates the task `command` names and stores it in the command.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the task cannot be created or named.
    fn create_task(
        &mut self,
        command: &mut Command<P>,
    ) -> Result<(), Error<P>>;

    /// Resumes the task `command` created.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the task cannot be resumed.
    fn resume_task(&mut self, command: &Command<P>) -> Result<(), Error<P>>;

    /// Asks on the console, then resumes the task `command` created.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the task cannot be resumed.
    fn prompt_resume_task(
        &mut self,
        command: &Command<P>,
    ) -> Result<(), Error<P>>;

    /// Names `port` with a send right in the task `command` created and
    /// returns the local name.
    ///
    /// # Safety
    ///
    /// `port` must be a live port.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the command has no task.
    unsafe fn insert_port(
        &mut self,
        command: &Command<P>,
        port: *mut c_void,
    ) -> Result<u32, Error<P>>;

    /// Names `task`'s self port in the task `command` created and returns
    /// the local name.
    ///
    /// # Safety
    ///
    /// `task` must be a live task.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the command has no task.
    unsafe fn insert_task_port(
        &mut self,
        command: &Command<P>,
        task: *mut Task<P>,
    ) -> Result<u32, Error<P>>;

    /// Loads the module `command` names into its task and starts the load
    /// thread.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the module cannot be loaded.
    fn exec_command(
        &mut self,
        command: &Command<P>,
        argv: &[*const c_char],
    ) -> Result<(), Error<P>>;

    /// Terminates `task` when `aborting`, then drops one reference to it.
    ///
    /// # Safety
    ///
    /// `task` must be a live task this script created.
    unsafe fn free_task(&mut self, task: NonNull<Task<P>>, aborting: bool);
}

/// The commands one boot script parsed, and its symbol table.
pub struct Script<P: Platform> {
    commands: KVec<Command<P>, Heap<P>>,
    symbols: KVec<Symbol<P>, Heap<P>>,
}

/// One parsed command: the program, the task made for it and its argv.
pub struct Command<P: Platform> {
    /// The boot loader's opaque module handle.
    pub(crate) hook: *mut c_void,
    /// The path the line named.
    pub(crate) path: KCString<Heap<P>>,
    /// The task `task-create` made, if it ran.
    pub(crate) task: Option<NonNull<Task<P>>>,
    /// The arguments, in order.
    args: KVec<Arg<P>, Heap<P>>,
    /// The functions to run once the module has loaded, in order.
    exec_funcs: KVec<Builtin, Heap<P>>,
}

/// One argument: its text, its value, or both.
///
/// Text and value concatenate into one argv word; the language lets a value
/// sit inside a text argument, as in `disk${root-device}`.
struct Arg<P: Platform> {
    text: Option<KCString<Heap<P>>>,
    value: Option<Value<P>>,
}

/// The value of a symbol or argument.
enum Value<P: Platform> {
    /// A string the boot sequence published or an expression computed.
    Str(KCString<Heap<P>>),
    /// A port the boot sequence published.
    Port(*mut c_void),
    /// A task a `task-create` call made.
    Task(NonNull<Task<P>>),
    /// A symbol named before it had a value; resolved at exec.
    Pending(usize),
}

impl<P: Platform> Value<P> {
    /// A copy of the value; a string is copied onto the heap.
    fn try_clone(&self) -> Result<Self, Error<P>> {
        Ok(match self {
            Self::Str(string) => Self::Str(KCString::try_from_c_str(
                string,
                Heap::<P>::default(),
            )?),
            Self::Port(port) => Self::Port(*port),
            Self::Task(task) => Self::Task(*task),
            Self::Pending(index) => Self::Pending(*index),
        })
    }
}

/// A resolved value: a [`Value`] with no references left.
enum Resolved<'a, P: Platform> {
    /// A string, by reference into the symbol table.
    Str(&'a CStr),
    /// A port handle.
    Port(*mut c_void),
    /// A task handle.
    Task(NonNull<Task<P>>),
}

/// One symbol-table entry.
struct Symbol<P: Platform> {
    name: KCString<Heap<P>>,
    state: SymbolState<P>,
}

/// What a symbol currently holds.
enum SymbolState<P: Platform> {
    /// Named, but no value yet.
    Unset,
    /// The value the last assignment stored.
    Defined(Value<P>),
}

/// The language's functions.
#[derive(Clone, Copy)]
enum Builtin {
    /// Makes the command's task at parse time.
    Create,
    /// Resumes the task once the module has loaded.
    Resume,
    /// Prompts, then resumes the task once the module has loaded.
    PromptResume,
}

impl Builtin {
    /// The function `name` denotes, if it denotes one.
    const fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"task-create" => Some(Self::Create),
            b"task-resume" => Some(Self::Resume),
            b"prompt-task-resume" => Some(Self::PromptResume),
            _ => None,
        }
    }
}

/// Skips the blanks at `*position`.
fn skip_blanks(line: &[u8], position: &mut usize) {
    while let Some(&byte) = line.get(*position) {
        if !matches!(byte, b' ' | b'\t') {
            break;
        }
        *position += 1;
    }
}

/// Appends `argument` to `command`'s argument list.
fn push_argument<P: Platform>(
    command: &mut Command<P>,
    argument: Arg<P>,
) -> Result<(), Error<P>> {
    Ok(command.args.try_push(argument)?)
}

impl<P: Platform> Script<P> {
    /// Returns an empty script with no symbols.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            commands: KVec::new(Heap::<P>::default()),
            symbols: KVec::new(Heap::<P>::default()),
        }
    }

    /// Defines the string variable `name` as a copy of `value`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the symbol table cannot grow, or
    /// [`Error::Syntax`] if the bytes hold a NUL.
    pub(crate) fn set_str(
        &mut self,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), Error<P>> {
        let value = KCString::try_new(value, Heap::<P>::default())?;
        let index = self.intern(name)?;
        self.symbols[index].state =
            SymbolState::<P>::Defined(Value::<P>::Str(value));
        Ok(())
    }

    /// Defines the port variable `name` as `port`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the symbol table cannot grow, or
    /// [`Error::Syntax`] if the name holds a NUL.
    pub(crate) fn set_port(
        &mut self,
        name: &[u8],
        port: *mut c_void,
    ) -> Result<(), Error<P>> {
        let index = self.intern(name)?;
        self.symbols[index].state =
            SymbolState::<P>::Defined(Value::<P>::Port(port));
        Ok(())
    }

    /// Parses one boot-script line and appends the command it spells.
    ///
    /// A line starts with the program path and holds arguments separated by
    /// blanks. An empty line and a line whose first non-blank byte is `#`
    /// parse to nothing. NUL and newline end the line.
    ///
    /// On a failure other than [`Error::InvalidSymbol`] the script discards
    /// every command parsed so far and frees their tasks with the aborting
    /// kill; the `InvalidSymbol` error keeps them, as a value expression
    /// that failed must not tear down tasks the line already made.
    ///
    /// # Errors
    ///
    /// The syntax and symbol errors of the language, or
    /// [`Error::OutOfMemory`] when a table cannot grow.
    pub(crate) fn parse_line(
        &mut self,
        host: &mut dyn Host<P>,
        hook: *mut c_void,
        line: &[u8],
    ) -> Result<(), Error<P>> {
        let mut command = Command::<P> {
            hook,
            path: KCString::empty(Heap::<P>::default()),
            task: None,
            args: KVec::new(Heap::<P>::default()),
            exec_funcs: KVec::new(Heap::<P>::default()),
        };
        match self.scan_line(&mut command, host, line) {
            Ok(()) => {
                let pushed = match self.commands.try_reserve(1) {
                    Ok(()) => self.commands.push_within_capacity(command),
                    Err(AllocError) => Err(command),
                };
                pushed.map_err(|command| {
                    self.discard(host, &command);
                    Error::<P>::OutOfMemory
                })
            }
            Err(Error::<P>::InvalidSymbol) => Err(Error::<P>::InvalidSymbol),
            Err(error) => {
                self.discard(host, &command);
                Err(error)
            }
        }
    }

    /// Runs every parsed command in order, then releases the task
    /// references.
    ///
    /// Each command whose task exists gets its argv built, its module
    /// loaded and its queued functions run. On a failure every task the
    /// script holds is terminated.
    ///
    /// # Errors
    ///
    /// Any [`Error`] the expressions, the host or the heap raise.
    pub(crate) fn exec(self, host: &mut dyn Host<P>) -> Result<(), Error<P>> {
        let result = self.run(host);
        let aborting = result.is_err();
        for command in self.commands.iter() {
            if let Some(task) = command.task {
                // SAFETY: `task` is the task `Host::create_task` made for
                // this command and the script holds its only reference.
                unsafe { host.free_task(task, aborting) };
            }
        }
        result
    }

    /// Adds `name` to the symbol table if it is missing and returns its
    /// index.
    fn intern(&mut self, name: &[u8]) -> Result<usize, Error<P>> {
        if let Some(index) = self
            .symbols
            .iter()
            .position(|symbol| symbol.name.to_bytes() == name)
        {
            return Ok(index);
        }
        let name = KCString::try_new(name, Heap::<P>::default())?;
        self.symbols.try_push(Symbol::<P> {
            name,
            state: SymbolState::<P>::Unset,
        })?;
        Ok(self.symbols.len() - 1)
    }

    /// Parses one line into `command`, without listing it.
    fn scan_line(
        &mut self,
        command: &mut Command<P>,
        host: &mut dyn Host<P>,
        line: &[u8],
    ) -> Result<(), Error<P>> {
        let mut position = 0;
        skip_blanks(line, &mut position);
        let first = line.get(position).copied().unwrap_or(0);
        if first == 0 || first == b'#' || first == b'\n' {
            return Ok(());
        }

        let start = position;
        while let Some(&byte) = line.get(position) {
            if matches!(byte, b' ' | b'\t' | b'\n') {
                break;
            }
            position += 1;
        }
        command.path =
            KCString::try_new(&line[start..position], Heap::<P>::default())?;

        while position < line.len() {
            skip_blanks(line, &mut position);
            let byte = line.get(position).copied().unwrap_or(0);
            if byte == 0 || byte == b'\n' {
                return Ok(());
            }
            self.scan_argument(command, host, line, &mut position)?;
        }
        Ok(())
    }

    /// Parses the argument at `*position` into `command`.
    fn scan_argument(
        &mut self,
        command: &mut Command<P>,
        host: &mut dyn Host<P>,
        line: &[u8],
        position: &mut usize,
    ) -> Result<(), Error<P>> {
        let byte = line.get(*position).copied().unwrap_or(0);
        let next = line.get(*position + 1).copied();

        if byte == b'$' && next == Some(b'(') {
            self.scan_expression(command, host, line, position, b')')?;
            return Ok(());
        }
        if byte == b'$' && next == Some(b'{') {
            let value = self
                .scan_expression(command, host, line, position, b'}')?
                .ok_or(Error::<P>::Syntax)?;
            return push_argument(
                command,
                Arg::<P> {
                    text: None,
                    value: Some(value),
                },
            );
        }

        let start = *position;
        while let Some(&current) = line.get(*position) {
            if matches!(current, b' ' | b'\t' | b'\n') {
                break;
            }
            if current == b'$' && line.get(*position + 1) == Some(&b'{') {
                break;
            }
            *position += 1;
        }
        let text =
            KCString::try_new(&line[start..*position], Heap::<P>::default())?;
        let mut argument = Arg::<P> {
            text: Some(text),
            value: None,
        };
        if line.get(*position) == Some(&b'$') {
            argument.value =
                self.scan_expression(command, host, line, position, b'}')?;
        }
        push_argument(command, argument)
    }

    /// Parses the `$(...)` or `${...}` at `*position`, whose `end` byte
    /// closes it. Returns the value of the last item, which a `}` always
    /// has and a `)` may not.
    fn scan_expression(
        &mut self,
        command: &mut Command<P>,
        host: &mut dyn Host<P>,
        line: &[u8],
        position: &mut usize,
        end: u8,
    ) -> Result<Option<Value<P>>, Error<P>> {
        *position += 2;
        let mut target: Option<usize> = None;
        let mut result: Option<Value<P>> = None;

        loop {
            let start = *position;
            while let Some(&byte) = line.get(*position) {
                if matches!(byte, b'=' | b'\n') || byte == end {
                    break;
                }
                *position += 1;
            }
            let terminator = line.get(*position).copied().unwrap_or(0);
            if start == *position
                || terminator == 0
                || terminator == b'\n'
                || (end == b'}' && terminator != b'}')
            {
                return Err(Error::<P>::Syntax);
            }
            let name = &line[start..*position];

            let mut next_target = target;
            let mut assigned = false;
            let mut produced = None;
            if let Some(builtin) = Builtin::from_name(name) {
                if end == b'}' {
                    return Err(Error::<P>::InvalidSymbol);
                }
                if terminator == b'=' {
                    return Err(Error::<P>::InvalidAssignment);
                }
                match builtin {
                    Builtin::Create => {
                        host.create_task(command)?;
                        produced = Some(Value::<P>::Task(
                            command.task.ok_or(Error::<P>::Host)?,
                        ));
                        assigned = true;
                    }
                    Builtin::Resume | Builtin::PromptResume => {
                        command.exec_funcs.try_push(builtin)?;
                    }
                }
            } else {
                let index = self.intern(name)?;
                produced = Some(match &self.symbols[index].state {
                    SymbolState::<P>::Unset => Value::<P>::Pending(index),
                    SymbolState::<P>::Defined(value) => value.try_clone()?,
                });
                assigned = true;
                next_target = Some(index);
            }

            if assigned {
                let value = produced.ok_or(Error::<P>::Syntax)?;
                if let Some(previous) = target {
                    self.symbols[previous].state =
                        SymbolState::<P>::Defined(value.try_clone()?);
                }
                result = Some(value);
            }
            target = next_target;

            *position += 1;
            if terminator == end {
                return Ok(result);
            }
        }
    }

    /// Releases `command` and every command parsed before it.
    fn discard(&mut self, host: &mut dyn Host<P>, command: &Command<P>) {
        if let Some(task) = command.task {
            // SAFETY: `task` is the task `Host::create_task` made for this
            // command and nothing else holds a reference to it.
            unsafe { host.free_task(task, true) };
        }
        for command in self.commands.drain(..).into_iter().flatten() {
            if let Some(task) = command.task {
                // SAFETY: `task` is the task `Host::create_task` made for
                // this command and nothing else holds a reference to it.
                unsafe { host.free_task(task, true) };
            }
        }
        self.symbols.clear();
    }

    /// Loads and starts every command and then runs its queued functions.
    fn run(&self, host: &mut dyn Host<P>) -> Result<(), Error<P>> {
        for command in self.commands.iter() {
            if command.task.is_none() {
                continue;
            }
            let mut argv: KVec<*const c_char, Heap<P>> =
                KVec::try_with_capacity(
                    command.args.len() + 1,
                    Heap::<P>::default(),
                )?;
            let mut storage: KVec<KVec<u8, Heap<P>>, Heap<P>> =
                KVec::try_with_capacity(
                    command.args.len(),
                    Heap::<P>::default(),
                )?;
            // The program sees its path as argv[0], then one entry per
            // argument.
            argv.try_push(command.path.as_ptr())?;
            for argument in command.args.iter() {
                let mut buffer = KVec::new(Heap::<P>::default());
                if let Some(text) = &argument.text {
                    buffer.extend_from_slice(text.to_bytes())?;
                }
                if let Some(value) = &argument.value {
                    self.render(host, command, value, &mut buffer)?;
                }
                buffer.try_push(0)?;
                argv.try_push(buffer.as_ptr().cast::<c_char>())?;
                // The buffer's heap allocation does not move when the
                // `KVec` header moves into `storage`, so the argv pointer
                // taken above stays valid.
                storage.try_push(buffer)?;
            }
            host.exec_command(command, &argv)?;
        }

        for command in self.commands.iter() {
            for builtin in command.exec_funcs.iter() {
                match builtin {
                    Builtin::Create => (),
                    Builtin::Resume => host.resume_task(command)?,
                    Builtin::PromptResume => {
                        host.prompt_resume_task(command)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Appends the resolved form of `value` to `buffer`.
    fn render(
        &self,
        host: &mut dyn Host<P>,
        command: &Command<P>,
        value: &Value<P>,
        buffer: &mut KVec<u8, Heap<P>>,
    ) -> Result<(), Error<P>> {
        match self.resolve(value)? {
            Resolved::Str(string) => {
                buffer.extend_from_slice(string.to_bytes())?;
            }
            Resolved::Port(port) => {
                // SAFETY: ports enter the table only through `set_port`,
                // which the boot sequence fills with live ports.
                let name = unsafe { host.insert_port(command, port) }?;
                buffer.extend_from_slice(
                    itoa::Buffer::new().format(name).as_bytes(),
                )?;
            }
            Resolved::Task(task) => {
                // SAFETY: tasks enter commands only through
                // `Host::create_task`.
                let name =
                    unsafe { host.insert_task_port(command, task.as_ptr()) }?;
                buffer.extend_from_slice(
                    itoa::Buffer::new().format(name).as_bytes(),
                )?;
            }
        }
        Ok(())
    }

    /// Follows the references of `value` until a concrete one appears.
    ///
    /// The hop bound stops a chain that names itself, which a sequence of
    /// assignments such as `$(a=b)` then `$(b=a)` can build; without it the
    /// walk would never end.
    fn resolve<'a>(
        &'a self,
        value: &'a Value<P>,
    ) -> Result<Resolved<'a, P>, Error<P>> {
        let mut current = value;
        let mut hops = 0;
        loop {
            match current {
                Value::<P>::Str(string) => return Ok(Resolved::Str(string)),
                Value::<P>::Port(port) => return Ok(Resolved::Port(*port)),
                Value::<P>::Task(task) => return Ok(Resolved::Task(*task)),
                Value::<P>::Pending(index) => {
                    let symbol = &self.symbols[*index];
                    if hops > self.symbols.len() {
                        let name = KCString::try_from_c_str(
                            &symbol.name,
                            Heap::<P>::default(),
                        )?;
                        return Err(Error::<P>::UndefinedSymbol(name));
                    }
                    hops += 1;
                    match &symbol.state {
                        SymbolState::<P>::Unset => {
                            let name = KCString::try_from_c_str(
                                &symbol.name,
                                Heap::<P>::default(),
                            )?;
                            return Err(Error::<P>::UndefinedSymbol(name));
                        }
                        SymbolState::<P>::Defined(value) => current = value,
                    }
                }
            }
        }
    }
}
