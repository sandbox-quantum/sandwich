// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! FFI I/O interface for tunnels.

use std::ffi::{c_int, c_void};
use std::io::{Read, Result, Write};

use protobuf::Enum;

use crate::ffi::support;
use crate::tunnel;

/// A function that indicates the state of the tunnel.
pub type SetStateFn = extern "C" fn(uarg: *mut c_void, tunnel_state: c_int);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IO {
    /// The parent IO.
    base: crate::ffi::IO,

    /// The function to indicates the state of the tunnel.
    set_state: Option<SetStateFn>,
}

impl std::fmt::Debug for IO {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "TunnelIO(base={base:?}, set_state={set_state:?})",
            base = self.base,
            set_state = self.set_state,
        )
    }
}

impl Read for IO {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.base.read(buffer)
    }
}

impl Write for IO {
    fn write(&mut self, buffer: &[u8]) -> Result<usize> {
        self.base.write(buffer)
    }

    fn flush(&mut self) -> Result<()> {
        self.base.flush()
    }
}

impl tunnel::IO for IO {
    fn set_state(&mut self, state: pb::State) {
        let Some(set_state) = self.set_state else {
            return;
        };
        set_state(self.base.uarg, support::to_c_int(state.value()));
    }
}
