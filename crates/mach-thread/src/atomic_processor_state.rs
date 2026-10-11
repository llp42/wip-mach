// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! A processor's state, readable from any CPU.

use crate::types::ProcessorState;
use core::sync::atomic::{AtomicU8, Ordering};

/// The `state` member of a [`Processor`](crate::processor::Processor): one [`ProcessorState`] in a
/// byte, published with `Release` and read with `Acquire` as the struct's
/// comment documents.
#[repr(transparent)]
pub struct AtomicProcessorState(AtomicU8);

impl AtomicProcessorState {
    /// Returns the processor's state.
    ///
    /// # Panics
    ///
    /// If the byte is not a state this kernel stores, which only a bug can
    /// leave behind.
    pub fn load(&self, order: Ordering) -> ProcessorState {
        match self.0.load(order) {
            0 => ProcessorState::OffLine,
            1 => ProcessorState::Running,
            2 => ProcessorState::Idle,
            3 => ProcessorState::Dispatching,
            4 => ProcessorState::Assign,
            5 => ProcessorState::Shutdown,
            _ => panic!("processor state: invalid processor state byte"),
        }
    }

    /// Sets the processor's state.
    pub fn store(&self, state: ProcessorState, order: Ordering) {
        self.0.store(state as u8, order);
    }
}
