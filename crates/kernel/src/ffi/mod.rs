// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `extern "C"` entry points C still calls, one module per interface
//! definition file, and the records those entry points exchange.

pub mod device;
pub mod device_pager;
pub mod gnumach;
pub mod host_info;
pub mod mach;
pub mod mach4;
pub mod mach_debug;
pub mod mach_host;
pub mod mach_i386;
pub mod mach_port;
pub mod processor_info;
pub mod processor_set_info;
pub mod task_info;
pub mod thread_info;
