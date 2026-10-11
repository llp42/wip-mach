// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the task record asks of the kernel.

/// The kernel services the task record needs beyond IPC's platform: the
/// machine's part of a task.
///
/// The kernel implements it on the same zero-sized type as the other
/// platforms; the thread crate's platform extends it.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform: mach_ipc::Platform {
    /// The machine part of a task.
    type MachineTask;

    /// Readies what the machine parts of tasks allocate from.
    ///
    /// # Safety
    ///
    /// Runs once at boot, before the first task is created.
    unsafe fn machine_task_module_init();
    /// Starts a new task's machine part.
    fn machine_task_init(machine: &mut Self::MachineTask);
    /// Frees the machine part of a task going away.
    fn machine_task_terminate(machine: &Self::MachineTask);
    /// Frees what a task's machine part holds but no longer uses.
    fn machine_task_collect(machine: &mut Self::MachineTask);
}
