// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich I/O module for FFI.

use std::ffi::{c_int, c_void};
use std::io::Result;

use pb::IOError;

use crate::ffi::support;
use crate::io::error;

mod helpers;
mod listener;

/// A read function.
pub type ReadFn = extern "C" fn(
    uarg: *mut c_void,
    buf: *mut c_void,
    count: usize,
    tunnel_state: c_int,
    err: *mut c_int,
) -> usize;

/// A write function.
pub type WriteFn = extern "C" fn(
    uarg: *mut c_void,
    buf: *const c_void,
    count: usize,
    tunnel_state: c_int,
    err: *mut c_int,
) -> usize;

/// Settings for a generic I/O interface, using pointers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Settings {
    /// A user supplied read function.
    readfn: ReadFn,
    /// A user supploed write function.
    writefn: WriteFn,
    /// A user argument which will be passed to the given
    /// read and written functions when called.
    uarg: *mut c_void,
}

/// Settings is Sendable.
unsafe impl Send for Settings {}

/// Implements [`crate::IO`] for [`Settings`].
impl crate::IO for Settings {
    fn read(&mut self, buf: &mut [u8], tunnel_state: pb::State) -> Result<usize> {
        use protobuf::Enum;

        let mut err = support::to_c_int(IOError::IOERROR_UNKNOWN.value());
        let n = (self.readfn)(
            self.uarg,
            buf.as_mut_ptr().cast(),
            buf.len(),
            tunnel_state.value(),
            &mut err as *mut c_int,
        );
        let err = IOError::from_i32(support::to_i32(err)).unwrap_or(IOError::IOERROR_UNKNOWN);
        if err == IOError::IOERROR_OK {
            Ok(n)
        } else {
            Err(error::error_kind_from_io_error(err).into())
        }
    }

    fn write(&mut self, buf: &[u8], tunnel_state: pb::State) -> Result<usize> {
        use protobuf::Enum;

        let mut err = support::to_c_int(IOError::IOERROR_UNKNOWN.value());
        let n = (self.writefn)(
            self.uarg,
            buf.as_ptr().cast(),
            buf.len(),
            tunnel_state.value(),
            &mut err as *mut c_int,
        );
        let err = IOError::from_i32(support::to_i32(err)).unwrap_or(IOError::IOERROR_UNKNOWN);
        if err == IOError::IOERROR_OK {
            Ok(n)
        } else {
            Err(error::error_kind_from_io_error(err).into())
        }
    }
}
