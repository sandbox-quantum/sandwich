// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! FFI I/O interface for tunnels.

use std::ffi::{c_int, c_void};
use std::io::{Read, Result, Write};

use protobuf::Enum;

#[allow(unused_imports)]
use crate::ffi::io::helpers as io_helpers;
use crate::ffi::io::{OwnedIo, OwnedIoUarg};
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

/// Trampoline for Turbo `set_state` implementation designed for FFI.
#[cfg(feature = "turbo")]
extern "C" fn turbo_trampoline_set_state(uarg: *mut c_void, tunnel_state: c_int) {
    use tunnel::IO as _;
    let owned_io_uarg: &mut OwnedIoUarg = unsafe { &mut *uarg.cast() };
    let tunnel_state =
        pb::State::from_i32(support::to_i32(tunnel_state)).unwrap_or(pb::State::STATE_ERROR);
    match owned_io_uarg {
        OwnedIoUarg::TurboClient(turbo_client) => turbo_client.set_state(tunnel_state),
        OwnedIoUarg::TurboServer(turbo_server) => turbo_server.set_state(tunnel_state),
        _ => {}
    }
}

/// Converts an owned IO into a tunnel IO.
#[no_mangle]
pub extern "C" fn sandwich_owned_io_to_tunnel_io(owned_io: *const OwnedIo) -> IO {
    let owned_io: &OwnedIo = unsafe { &*owned_io };
    let owned_io_uarg: &OwnedIoUarg = owned_io.as_ref();
    IO {
        base: *owned_io.as_ref(),
        set_state: match owned_io_uarg {
            #[cfg(feature = "turbo")]
            OwnedIoUarg::TurboClient(_) | OwnedIoUarg::TurboServer(_) => {
                Some(turbo_trampoline_set_state)
            }
            _ => None,
        },
    }
}
