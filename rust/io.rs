// Copyright 2022 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Sandwich IO interface.
//!
//! This API provides the required abstraction for the Sandwich IO interface,
//! defined by saq::sandwich::io::IO.
//!
//! Author: thb-sb

extern crate protobuf;
extern crate sandwich_c;
extern crate sandwich_rust_proto;

use super::errors;
use super::pimpl;

/// An IO result.
pub type IOResult<T> = Result<T, errors::IOError>;

/// The Sandwich I/O interface.
pub trait IO {
    /// Reads some bytes from the I/O interface.
    fn read(&mut self, buf: &mut [u8], tunnel_state: sandwich_rust_proto::State)
        -> IOResult<usize>;

    /// Write some bytes to the I/O interface.
    fn write(&mut self, buf: &[u8], tunnel_state: sandwich_rust_proto::State) -> IOResult<usize>;

    /// Close the I/O interface.
    fn close(&mut self);
}

/// Bridge function between C and Rust for Read i/o.
extern "C" fn c_io_read<Io: IO>(
    uarg: *mut std::os::raw::c_void,
    buf: *mut std::os::raw::c_void,
    size: u64,
    tunnel_state: u32,
    err: *mut u32,
) -> u64 {
    let (io, ioerr) = unsafe {
        (
            &mut *std::mem::transmute::<*mut std::os::raw::c_void, *mut Io>(uarg),
            &mut *err,
        )
    };
    let slice = unsafe {
        std::slice::from_raw_parts_mut(
            std::mem::transmute::<*mut std::os::raw::c_void, *mut u8>(buf),
            size as usize,
        )
    };
    match io.read(
        slice,
        <sandwich_rust_proto::State as protobuf::ProtobufEnum>::from_i32(tunnel_state as i32)
            .unwrap(),
    ) {
        Ok(n) => {
            *ioerr = sandwich_rust_proto::IOError::IOERROR_OK as u32;
            n as u64
        }
        Err(e) => {
            *ioerr = <errors::IOError as Into<u32>>::into(e);
            0u64
        }
    }
}

/// Bridge function between C and Rust for Write i/o.
extern "C" fn c_io_write<Io: IO>(
    uarg: *mut std::os::raw::c_void,
    buf: *const std::os::raw::c_void,
    size: u64,
    tunnel_state: u32,
    err: *mut u32,
) -> u64 {
    let (io, ioerr) = unsafe {
        (
            &mut *std::mem::transmute::<*mut std::os::raw::c_void, *mut Io>(uarg),
            &mut *err,
        )
    };
    let slice = unsafe {
        std::slice::from_raw_parts(
            std::mem::transmute::<*const std::os::raw::c_void, *const u8>(buf),
            size as usize,
        )
    };
    match io.write(
        slice,
        <sandwich_rust_proto::State as protobuf::ProtobufEnum>::from_i32(tunnel_state as i32)
            .unwrap(),
    ) {
        Ok(n) => {
            *ioerr = sandwich_rust_proto::IOError::IOERROR_OK as u32;
            n as u64
        }
        Err(e) => {
            *ioerr = <errors::IOError as Into<u32>>::into(e);
            0u64
        }
    }
}

/// Bridge function between C and Rust for Close i/o.
extern "C" fn c_io_close<Io: IO>(uarg: *mut std::os::raw::c_void) {
    let io = unsafe { &mut *std::mem::transmute::<*mut std::os::raw::c_void, *mut Io>(uarg) };
    io.close()
}

/// Create a `struct SandwichCIOSettings` from a borrowed I/O trait.
fn create_c_settings<Io: IO>(io: &Io) -> sandwich_c::SandwichCIOSettings {
    sandwich_c::SandwichCIOSettings {
        read: Some(c_io_read::<Io>),
        write: Some(c_io_write::<Io>),
        close: Some(c_io_close::<Io>),
        uarg: unsafe { std::mem::transmute(io) },
    }
}

/// `struct SandwichCIO` wrapper.
type IOHandleC = pimpl::Pimpl<sandwich_c::SandwichCIO>;

/// Wrapper around struct SandwichCIO.
pub struct IOHandle(IOHandleC);

impl IOHandle {
    /// Creates an IOHandle from an IO interface.
    pub(crate) fn try_from<Io: IO>(io: &mut Io) -> Result<Self, errors::GlobalError> {
        let settings = create_c_settings(io);

        let mut handle = std::ptr::null_mut::<::sandwich_c::SandwichCIO>();

        let err = errors::GlobalError::from_c(unsafe {
            sandwich_c::sandwich_io_new(&settings, &mut handle)
        });
        if err.ok() {
            Ok(Self(IOHandleC::from_raw(
                handle,
                Some(|ptr| unsafe {
                    sandwich_c::sandwich_io_free(ptr);
                }),
            )))
        } else {
            Err(err)
        }
    }

    /// Borrows the C handle.
    #[allow(dead_code)]
    pub(crate) fn handle(&self) -> &IOHandleC {
        &self.0
    }

    /// Borrows the C handle.
    pub(crate) fn handle_mut(&mut self) -> &mut IOHandleC {
        &mut self.0
    }
}
