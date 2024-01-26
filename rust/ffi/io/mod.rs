// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich I/O module for FFI.

use std::ffi::{c_int, c_void};
use std::io::{Read, Result, Write};

use protobuf::Enum;

use pb::IOError;

use crate::ffi::support;
use crate::io::error;

mod helpers;
mod listener;

/// A read function.
pub type ReadFn =
    extern "C" fn(uarg: *mut c_void, buf: *mut c_void, count: usize, err: *mut c_int) -> usize;

/// A write function.
pub type WriteFn =
    extern "C" fn(uarg: *mut c_void, buf: *const c_void, count: usize, err: *mut c_int) -> usize;

/// A flush function.
pub type FlushFn = extern "C" fn(uarg: *mut c_void) -> c_int;

/// IO for a generic I/O interface, using pointers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IO {
    /// A user supplied read function.
    readfn: ReadFn,

    /// A user supplied write function.
    writefn: WriteFn,

    /// A user supplied flush function.
    flushfn: Option<FlushFn>,

    /// A user argument which will be passed to the given
    /// read, write and flush functions when called.
    pub(crate) uarg: *mut c_void,
}

impl std::fmt::Debug for IO {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ForeignIO(readfn={readfn:p}, writefn={writefn:p}, flushfn={flushfn:?}, uarg={uarg:p})",
            readfn = self.readfn,
            writefn = self.writefn,
            flushfn = self.flushfn,
            uarg = self.uarg,
        )
    }
}

/// IO is Sendable.
unsafe impl Send for IO {}

impl Read for IO {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut err = support::to_c_int(IOError::IOERROR_UNKNOWN.value());
        let n = (self.readfn)(
            self.uarg,
            buf.as_mut_ptr().cast(),
            buf.len(),
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

impl Write for IO {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut err = support::to_c_int(IOError::IOERROR_UNKNOWN.value());
        let n = (self.writefn)(
            self.uarg,
            buf.as_ptr().cast(),
            buf.len(),
            &mut err as *mut c_int,
        );
        let err = IOError::from_i32(support::to_i32(err)).unwrap_or(IOError::IOERROR_UNKNOWN);
        if err == IOError::IOERROR_OK {
            Ok(n)
        } else {
            Err(error::error_kind_from_io_error(err).into())
        }
    }

    fn flush(&mut self) -> Result<()> {
        let Some(flush) = self.flushfn else {
            return Ok(());
        };
        let err = IOError::from_i32(support::to_i32((flush)(self.uarg)))
            .unwrap_or(IOError::IOERROR_UNKNOWN);
        if err == IOError::IOERROR_OK {
            Ok(())
        } else {
            Err(error::error_kind_from_io_error(err).into())
        }
    }
}
