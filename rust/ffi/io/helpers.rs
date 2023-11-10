// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Helper functions that create commonly used IO objects.

use std::ffi::{c_int, c_void, CStr};
use std::fs::File;
use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};

use protobuf::Enum;

use pb::IOError;

use crate::ffi::support;
use crate::io::error::IntoIOError;

use super::IO;

/// A read function.
pub(crate) extern "C" fn sandwich_helper_io_read(
    uarg: *mut c_void,
    buf: *mut c_void,
    count: usize,
    tunnel_state: c_int,
    err: *mut c_int,
) -> usize {
    let mut boxed_helper_io: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(uarg.cast()) };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf.cast(), count) };
    let Some(tunnel_state) = pb::State::from_i32(support::to_i32(tunnel_state)) else {
        unsafe { *err = support::to_c_int(IOError::IOERROR_SYSTEM_ERROR.value()) };
        return 0;
    };
    let r = boxed_helper_io.read(slice, tunnel_state);
    Box::into_raw(boxed_helper_io);
    match r {
        Ok(size) => {
            unsafe { *err = support::to_c_int(IOError::IOERROR_OK.value()) };
            size
        }
        Err(e) => {
            unsafe { *err = support::to_c_int(e.into_io_error().value()) };
            0
        }
    }
}

/// A write function.
pub(crate) extern "C" fn sandwich_helper_io_write(
    uarg: *mut c_void,
    buf: *const c_void,
    count: usize,
    tunnel_state: c_int,
    err: *mut c_int,
) -> usize {
    let mut boxed_helper_io: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(uarg.cast()) };
    let slice = unsafe { std::slice::from_raw_parts(buf.cast(), count) };
    let Some(tunnel_state) = pb::State::from_i32(support::to_i32(tunnel_state)) else {
        unsafe { *err = support::to_c_int(IOError::IOERROR_SYSTEM_ERROR.value()) };
        return 0;
    };
    let r = boxed_helper_io.write(slice, tunnel_state);
    Box::into_raw(boxed_helper_io);
    match r {
        Ok(size) => {
            unsafe { *err = support::to_c_int(IOError::IOERROR_OK.value()) };
            size
        }
        Err(e) => {
            unsafe { *err = support::to_c_int(e.into_io_error().value()) };
            0
        }
    }
}

/// A read function.
pub(crate) extern "C" fn sandwich_helper_io_flush(uarg: *mut c_void) -> c_int {
    let mut io: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(uarg.cast()) };
    let r = io.flush();
    Box::into_raw(io);
    match r {
        Ok(_) => support::to_c_int(IOError::IOERROR_OK.value()),
        Err(e) => support::to_c_int(e.into_io_error().value()),
    }
}

/// Frees io created with sandwich_client_io_*_new() family of functions
/// Using this function with user created IO objects will cause undefined
/// behaviour.
#[no_mangle]
pub extern "C" fn sandwich_io_owned_free(owned_io: *mut OwnedIo) {
    let mut oio: Box<OwnedIo> = unsafe { Box::from_raw(owned_io.cast()) };
    if let Some(free) = oio.freeptr {
        (free)(oio.io);
        oio.freeptr = None;
    }
}

/// Frees an owned IO.
pub(crate) extern "C" fn sandwich_helper_owned_io_free(cio: *mut IO) {
    let boxed_cio: Box<IO> = unsafe { Box::from_raw(cio.cast()) };
    let _: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(boxed_cio.uarg.cast()) };
}

/// A free function.
pub type FreeFn = extern "C" fn(uarg: *mut IO);

/// An IO owned by a structure.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OwnedIo {
    pub(crate) io: *mut IO,
    pub(crate) freeptr: Option<FreeFn>,
}

/// Creates a new client TCP IO object.
#[no_mangle]
pub extern "C" fn sandwich_io_client_tcp_new(
    hostname: *const std::ffi::c_char,
    port: u16,
    is_blocking: bool,
    owned_io: *mut *mut OwnedIo,
) -> c_int {
    let Ok(hn) = unsafe { CStr::from_ptr(hostname.cast()) }.to_str() else {
        return support::to_c_int(pb::IOError::IOERROR_SYSTEM_ERROR.value());
    };
    let socket = match TcpStream::connect((hn, port)) {
        Ok(socket) => socket,
        Err(e) => return support::to_c_int(e.into_io_error().value()),
    };
    if let Err(e) = socket.set_nonblocking(!is_blocking) {
        return support::to_c_int(e.into_io_error().value());
    };
    setup_helper_io(Box::new(socket), owned_io)
}

/// Creates a new system socket IO object.
#[no_mangle]
pub extern "C" fn sandwich_io_socket_wrap_new(socket: RawFd, owned_io: *mut *mut OwnedIo) -> c_int {
    setup_helper_io(Box::new(unsafe { File::from_raw_fd(socket) }), owned_io)
}

fn setup_helper_io(io: Box<dyn crate::IO>, owned_io: *mut *mut OwnedIo) -> c_int {
    let boxed_io = Box::new(io);
    let io_ptr = Box::into_raw(boxed_io);
    let boxed_cio = Box::new(IO {
        readfn: sandwich_helper_io_read,
        writefn: sandwich_helper_io_write,
        flushfn: Some(sandwich_helper_io_flush),
        uarg: io_ptr.cast(),
    });
    if !owned_io.is_null() {
        let b = Box::new(OwnedIo {
            io: Box::into_raw(boxed_cio).cast(),
            freeptr: Some(sandwich_helper_owned_io_free),
        });
        unsafe { *owned_io = Box::into_raw(b) };
    }
    support::to_c_int(IOError::IOERROR_OK.value())
}
