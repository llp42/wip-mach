// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2001 Free Software Foundation, Inc.
// SPDX-FileContributor: Shantanu Goel <goel@cs.columbia.edu>
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: kern/boot_script.c and kern/boot_script.h

//! The boot script: the small command language the boot loader leaves in
//! the Multiboot module strings.
//!
//! Each module string names a program and its arguments. An argument is
//! literal text, a `${name}` value, or a `$(...)` expression that may call
//! the `task-create`, `task-resume` and `prompt-task-resume` functions and
//! assign their results to names. Parsing fills a [`Script`] with commands
//! and symbols; [`Script::exec`] then loads each command's module into the
//! task it created, names the ports its arguments mention and resumes it.

use crate::kern::task::Task;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::fmt;
use core::ptr::NonNull;

/// A boot-script failure.
#[derive(Debug)]
pub(crate) enum Error {
    /// The heap ran out while the script was built or run.
    OutOfMemory,
    /// The line does not follow the language.
    Syntax,
    /// A function name appeared where only a value fits.
    InvalidSymbol,
    /// An assignment targeted a function name.
    InvalidAssignment,
    /// A value expression named a symbol that never received a value.
    UndefinedSymbol(CString),
    /// The kernel operation behind a function or a load failed.
    Host,
}

impl fmt::Display for Error {
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
                name.to_string_lossy()
            ),
            Self::Host => {
                formatter.write_str("boot script kernel operation failed")
            }
        }
    }
}

/// The kernel operations a boot script drives.
///
/// The script itself owns no kernel logic: the implementation creates and
/// resumes tasks, names ports and loads modules.
pub(crate) trait Host {
    /// Creates the task `command` names and stores it in the command.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the task cannot be created or named.
    fn create_task(&mut self, command: &mut Command) -> Result<(), Error>;

    /// Resumes the task `command` created.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the task cannot be resumed.
    fn resume_task(&mut self, command: &Command) -> Result<(), Error>;

    /// Asks on the console, then resumes the task `command` created.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the task cannot be resumed.
    fn prompt_resume_task(&mut self, command: &Command) -> Result<(), Error>;

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
        command: &Command,
        port: *mut c_void,
    ) -> Result<u32, Error>;

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
        command: &Command,
        task: *mut Task,
    ) -> Result<u32, Error>;

    /// Loads the module `command` names into its task and starts the load
    /// thread.
    ///
    /// # Errors
    ///
    /// [`Error::Host`] if the module cannot be loaded.
    fn exec_command(
        &mut self,
        command: &Command,
        argv: &[*const c_char],
    ) -> Result<(), Error>;

    /// Terminates `task` when `aborting`, then drops one reference to it.
    ///
    /// # Safety
    ///
    /// `task` must be a live task this script created.
    unsafe fn free_task(&mut self, task: NonNull<Task>, aborting: bool);
}

/// The commands one boot script parsed, and its symbol table.
pub(crate) struct Script {
    commands: Vec<Command>,
    symbols: Vec<Symbol>,
}

/// One parsed command: the program, the task made for it and its argv.
pub(crate) struct Command {
    /// The boot loader's opaque module handle.
    pub(crate) hook: *mut c_void,
    /// The path the line named.
    pub(crate) path: CString,
    /// The task `task-create` made, if it ran.
    pub(crate) task: Option<NonNull<Task>>,
    /// The arguments, in order.
    args: Vec<Arg>,
    /// The functions to run once the module has loaded, in order.
    exec_funcs: Vec<Builtin>,
}

/// One argument: its text, its value, or both.
///
/// Text and value concatenate into one argv word; the language lets a value
/// sit inside a text argument, as in `disk${root-device}`.
struct Arg {
    text: Option<CString>,
    value: Option<Value>,
}

/// The value of a symbol or argument.
#[derive(Clone)]
enum Value {
    /// A string the boot sequence published or an expression computed.
    Str(CString),
    /// A port the boot sequence published.
    Port(*mut c_void),
    /// A task a `task-create` call made.
    Task(NonNull<Task>),
    /// A symbol named before it had a value; resolved at exec.
    Pending(usize),
}

/// A resolved value: a [`Value`] with no references left.
enum Resolved<'a> {
    /// A string, by reference into the symbol table.
    Str(&'a CString),
    /// A port handle.
    Port(*mut c_void),
    /// A task handle.
    Task(NonNull<Task>),
}

/// One symbol-table entry.
struct Symbol {
    name: CString,
    state: SymbolState,
}

/// What a symbol currently holds.
enum SymbolState {
    /// Named, but no value yet.
    Unset,
    /// The value the last assignment stored.
    Defined(Value),
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

/// Appends the decimal spelling of `value` to `buffer`.
fn push_decimal(buffer: &mut Vec<u8>, mut value: u32) {
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    buffer.extend_from_slice(&digits[start..]);
}

/// Appends `argument` to `command`'s argument list.
fn push_argument(command: &mut Command, argument: Arg) -> Result<(), Error> {
    command
        .args
        .try_reserve(1)
        .map_err(|_| Error::OutOfMemory)?;
    command.args.push(argument);
    Ok(())
}

impl Script {
    /// Returns an empty script with no symbols.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            commands: Vec::new(),
            symbols: Vec::new(),
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
    ) -> Result<(), Error> {
        let value = CString::new(value).map_err(|_| Error::Syntax)?;
        let index = self.intern(name)?;
        self.symbols[index].state = SymbolState::Defined(Value::Str(value));
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
    ) -> Result<(), Error> {
        let index = self.intern(name)?;
        self.symbols[index].state = SymbolState::Defined(Value::Port(port));
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
        host: &mut dyn Host,
        hook: *mut c_void,
        line: &[u8],
    ) -> Result<(), Error> {
        let mut command = Command {
            hook,
            path: CString::default(),
            task: None,
            args: Vec::new(),
            exec_funcs: Vec::new(),
        };
        match self.scan_line(&mut command, host, line) {
            Ok(()) => {
                if self.commands.try_reserve(1).is_err() {
                    self.discard(host, &command);
                    return Err(Error::OutOfMemory);
                }
                self.commands.push(command);
                Ok(())
            }
            Err(Error::InvalidSymbol) => Err(Error::InvalidSymbol),
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
    pub(crate) fn exec(self, host: &mut dyn Host) -> Result<(), Error> {
        let result = self.run(host);
        let aborting = result.is_err();
        for command in &self.commands {
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
    fn intern(&mut self, name: &[u8]) -> Result<usize, Error> {
        if let Some(index) = self
            .symbols
            .iter()
            .position(|symbol| symbol.name.as_bytes() == name)
        {
            return Ok(index);
        }
        let name = CString::new(name).map_err(|_| Error::Syntax)?;
        self.symbols
            .try_reserve(1)
            .map_err(|_| Error::OutOfMemory)?;
        self.symbols.push(Symbol {
            name,
            state: SymbolState::Unset,
        });
        Ok(self.symbols.len() - 1)
    }

    /// Parses one line into `command`, without listing it.
    fn scan_line(
        &mut self,
        command: &mut Command,
        host: &mut dyn Host,
        line: &[u8],
    ) -> Result<(), Error> {
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
            CString::new(&line[start..position]).map_err(|_| Error::Syntax)?;

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
        command: &mut Command,
        host: &mut dyn Host,
        line: &[u8],
        position: &mut usize,
    ) -> Result<(), Error> {
        let byte = line.get(*position).copied().unwrap_or(0);
        let next = line.get(*position + 1).copied();

        if byte == b'$' && next == Some(b'(') {
            self.scan_expression(command, host, line, position, b')')?;
            return Ok(());
        }
        if byte == b'$' && next == Some(b'{') {
            let value = self
                .scan_expression(command, host, line, position, b'}')?
                .ok_or(Error::Syntax)?;
            return push_argument(
                command,
                Arg {
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
        let text = CString::new(&line[start..*position])
            .map_err(|_| Error::Syntax)?;
        let mut argument = Arg {
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
        command: &mut Command,
        host: &mut dyn Host,
        line: &[u8],
        position: &mut usize,
        end: u8,
    ) -> Result<Option<Value>, Error> {
        *position += 2;
        let mut target: Option<usize> = None;
        let mut result: Option<Value> = None;

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
                return Err(Error::Syntax);
            }
            let name = &line[start..*position];

            let mut next_target = target;
            let mut assigned = false;
            let mut produced = None;
            if let Some(builtin) = Builtin::from_name(name) {
                if end == b'}' {
                    return Err(Error::InvalidSymbol);
                }
                if terminator == b'=' {
                    return Err(Error::InvalidAssignment);
                }
                match builtin {
                    Builtin::Create => {
                        host.create_task(command)?;
                        produced = Some(Value::Task(
                            command.task.ok_or(Error::Host)?,
                        ));
                        assigned = true;
                    }
                    Builtin::Resume | Builtin::PromptResume => {
                        command
                            .exec_funcs
                            .try_reserve(1)
                            .map_err(|_| Error::OutOfMemory)?;
                        command.exec_funcs.push(builtin);
                    }
                }
            } else {
                let index = self.intern(name)?;
                produced = Some(match &self.symbols[index].state {
                    SymbolState::Unset => Value::Pending(index),
                    SymbolState::Defined(value) => value.clone(),
                });
                assigned = true;
                next_target = Some(index);
            }

            if assigned {
                let value = produced.ok_or(Error::Syntax)?;
                if let Some(previous) = target {
                    self.symbols[previous].state =
                        SymbolState::Defined(value.clone());
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
    fn discard(&mut self, host: &mut dyn Host, command: &Command) {
        if let Some(task) = command.task {
            // SAFETY: `task` is the task `Host::create_task` made for this
            // command and nothing else holds a reference to it.
            unsafe { host.free_task(task, true) };
        }
        for command in self.commands.drain(..) {
            if let Some(task) = command.task {
                // SAFETY: `task` is the task `Host::create_task` made for
                // this command and nothing else holds a reference to it.
                unsafe { host.free_task(task, true) };
            }
        }
        self.symbols.clear();
    }

    /// Loads and starts every command and then runs its queued functions.
    fn run(&self, host: &mut dyn Host) -> Result<(), Error> {
        for command in &self.commands {
            if command.task.is_none() {
                continue;
            }
            let mut argv: Vec<*const c_char> = Vec::new();
            let mut storage: Vec<Vec<u8>> = Vec::new();
            argv.try_reserve(command.args.len() + 1)
                .map_err(|_| Error::OutOfMemory)?;
            storage
                .try_reserve(command.args.len())
                .map_err(|_| Error::OutOfMemory)?;
            // The program sees its path as argv[0], then one entry per
            // argument.
            argv.push(command.path.as_ptr());
            for argument in &command.args {
                let mut buffer: Vec<u8> = Vec::new();
                if let Some(text) = &argument.text {
                    buffer
                        .try_reserve(text.as_bytes().len())
                        .map_err(|_| Error::OutOfMemory)?;
                    buffer.extend_from_slice(text.as_bytes());
                }
                if let Some(value) = &argument.value {
                    self.render(host, command, value, &mut buffer)?;
                }
                buffer.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                buffer.push(0);
                argv.push(buffer.as_ptr().cast::<c_char>());
                // The buffer's heap allocation does not move when the
                // `Vec` header moves into `storage`, so the argv pointer
                // taken above stays valid.
                storage.push(buffer);
            }
            host.exec_command(command, &argv)?;
        }

        for command in &self.commands {
            for builtin in &command.exec_funcs {
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
        host: &mut dyn Host,
        command: &Command,
        value: &Value,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        match self.resolve(value)? {
            Resolved::Str(string) => {
                buffer
                    .try_reserve(string.as_bytes().len())
                    .map_err(|_| Error::OutOfMemory)?;
                buffer.extend_from_slice(string.as_bytes());
            }
            Resolved::Port(port) => {
                // SAFETY: ports enter the table only through `set_port`,
                // which the boot sequence fills with live ports.
                let name = unsafe { host.insert_port(command, port) }?;
                push_decimal(buffer, name);
            }
            Resolved::Task(task) => {
                // SAFETY: tasks enter commands only through
                // `Host::create_task`.
                let name =
                    unsafe { host.insert_task_port(command, task.as_ptr()) }?;
                push_decimal(buffer, name);
            }
        }
        Ok(())
    }

    /// Follows the references of `value` until a concrete one appears.
    ///
    /// The hop bound stops a chain that names itself, which a sequence of
    /// assignments such as `$(a=b)` then `$(b=a)` can build; without it the
    /// walk would never end.
    fn resolve<'a>(&'a self, value: &'a Value) -> Result<Resolved<'a>, Error> {
        let mut current = value;
        let mut hops = 0;
        loop {
            match current {
                Value::Str(string) => return Ok(Resolved::Str(string)),
                Value::Port(port) => return Ok(Resolved::Port(*port)),
                Value::Task(task) => return Ok(Resolved::Task(*task)),
                Value::Pending(index) => {
                    if hops > self.symbols.len() {
                        let name = self.symbols[*index].name.clone();
                        return Err(Error::UndefinedSymbol(name));
                    }
                    hops += 1;
                    match &self.symbols[*index].state {
                        SymbolState::Unset => {
                            let name = self.symbols[*index].name.clone();
                            return Err(Error::UndefinedSymbol(name));
                        }
                        SymbolState::Defined(value) => current = value,
                    }
                }
            }
        }
    }
}
