// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich I/O module for FFI.

use std::ffi::c_void;

use pb::IOError;

use crate::io::Result as IOResult;

/// A read function.
pub type ReadFn = extern "C" fn(
    uarg: *mut c_void,
    buf: *mut c_void,
    count: usize,
    tunnel_state: i32,
    err: *mut i32,
) -> usize;

/// A write function.
pub type WriteFn = extern "C" fn(
    uarg: *mut c_void,
    buf: *const c_void,
    count: usize,
    tunnel_state: i32,
    err: *mut i32,
) -> usize;

/// Settings for a generic I/O interface, using pointers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Settings {
    readfn: ReadFn,
    writefn: WriteFn,
    uarg: *mut c_void,
}

/// Settings is Sendable.
unsafe impl Send for Settings {}

/// Implements [`crate::IO`] for [`Settings`].
impl crate::IO for Settings {
    fn read(&mut self, buf: &mut [u8], tunnel_state: pb::State) -> IOResult<usize> {
        use protobuf::Enum;

        let mut err = IOError::IOERROR_UNKNOWN.value();
        let n = (self.readfn)(
            self.uarg,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            tunnel_state.value(),
            &mut err as *mut i32,
        );
        if err != IOError::IOERROR_OK.value() {
            Err(IOError::from_i32(err).unwrap().into())
        } else {
            Ok(n)
        }
    }
    fn write(&mut self, buf: &[u8], tunnel_state: pb::State) -> IOResult<usize> {
        use protobuf::Enum;

        let mut err = IOError::IOERROR_UNKNOWN.value();
        let n = (self.writefn)(
            self.uarg,
            buf.as_ptr() as *const c_void,
            buf.len(),
            tunnel_state.value(),
            &mut err as *mut i32,
        );
        if err != IOError::IOERROR_OK.value() {
            Err(IOError::from_i32(err).unwrap().into())
        } else {
            Ok(n)
        }
    }
}
