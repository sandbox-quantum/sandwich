// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Helper functions that create commonly used IO objects.

use std::ffi::{c_void, CStr};

use pb::IOError;

use crate::io::helpers::{SystemSocketIo, TcpIo};

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HelperClientSettings {
    readfn: ReadFn,
    writefn: WriteFn,
    uarg: *mut c_void,
}

/// A read function.
extern "C" fn sandwich_helper_client_read(
    uarg: *mut c_void,
    buf: *mut c_void,
    count: usize,
    tunnel_state: i32,
    err: *mut i32,
) -> usize {
    use protobuf::Enum;
    let mut boxed_helper_client_io: Box<Box<dyn crate::IO>> =
        unsafe { Box::from_raw(uarg as *mut _) };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, count) };
    let r = boxed_helper_client_io.read(slice, pb::State::from_i32(tunnel_state).unwrap());
    Box::into_raw(boxed_helper_client_io);
    match r {
        Ok(size) => {
            unsafe { *err = IOError::IOERROR_OK.value() };
            size
        }
        Err(e) => {
            unsafe { *err = Into::<IOError>::into(crate::io::Error::from(e)).value() };
            0
        }
    }
}

/// A write function.
extern "C" fn sandwich_helper_client_write(
    uarg: *mut c_void,
    buf: *const c_void,
    count: usize,
    tunnel_state: i32,
    err: *mut i32,
) -> usize {
    use protobuf::Enum;
    let mut boxed_helper_client_io: Box<Box<dyn crate::IO>> =
        unsafe { Box::from_raw(uarg as *mut _) };
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, count) };
    let r = boxed_helper_client_io.write(slice, pb::State::from_i32(tunnel_state).unwrap());
    Box::into_raw(boxed_helper_client_io);
    match r {
        Ok(size) => {
            unsafe { *err = IOError::IOERROR_OK.value() };
            size
        }
        Err(e) => {
            unsafe { *err = Into::<IOError>::into(crate::io::Error::from(e)).value() };
            0
        }
    }
}

/// Frees io created with sandwich_client_io_*_new() family of functions
/// Using this function with user created IO objects will cause undefined
/// behaviour.
#[no_mangle]
pub extern "C" fn sandwich_io_owned_free(owned_io: *mut OwnedIo) {
    let mut oio: Box<OwnedIo> = unsafe { Box::from_raw(owned_io as *mut _) };
    if let Some(free) = oio.freeptr {
        (free)(oio.io);
        oio.freeptr = None;
    }
}

// Called when sandwich_io_owned_free is called.
extern "C" fn sandwich_helper_owned_io_free(cio: *mut super::io::Settings) {
    let boxed_cio: Box<HelperClientSettings> = unsafe { Box::from_raw(cio as *mut _) };
    let _: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(boxed_cio.uarg as *mut _) };
}

/// A free function.
pub type FreeFn = extern "C" fn(uarg: *mut super::io::Settings);

/// An IO owned by a structure.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OwnedIo {
    io: *mut super::io::Settings,
    freeptr: Option<FreeFn>,
}

/// Creates a new client TCP IO object.
#[no_mangle]
pub extern "C" fn sandwich_io_client_tcp_new(
    hostname: *const std::ffi::c_char,
    port: u16,
    is_blocking: bool,
    owned_io: *mut *mut OwnedIo,
) -> i32 {
    use protobuf::Enum;
    let hn = unsafe {
        CStr::from_ptr(hostname as *mut _)
            .to_str()
            .unwrap()
            .to_string()
    };
    let io: Box<dyn crate::IO> = match TcpIo::connect((hn, port), is_blocking) {
        Ok(io) => Box::new(io),
        Err(e) => return Into::<IOError>::into(crate::io::Error::from(e)).value(),
    };
    setup_helper_io(io, owned_io)
}

/// Creates a new system socket IO object.
#[no_mangle]
pub extern "C" fn sandwich_io_socket_wrap_new(
    socket: std::ffi::c_int,
    owned_io: *mut *mut OwnedIo,
) -> i32 {
    use protobuf::Enum;
    let io: Box<dyn crate::IO> = match SystemSocketIo::new(socket as std::os::fd::RawFd) {
        Ok(io) => Box::new(io),
        Err(e) => return Into::<IOError>::into(crate::io::Error::from(e)).value(),
    };
    setup_helper_io(io, owned_io)
}

fn setup_helper_io(io: Box<dyn crate::IO>, owned_io: *mut *mut OwnedIo) -> i32 {
    use protobuf::Enum;
    let boxed_io = Box::new(io);
    let io_ptr = Box::into_raw(boxed_io);
    let boxed_cio = Box::new(HelperClientSettings {
        readfn: sandwich_helper_client_read,
        writefn: sandwich_helper_client_write,
        uarg: io_ptr as *mut c_void,
    });
    if !owned_io.is_null() {
        let b = Box::new(OwnedIo {
            io: Box::into_raw(boxed_cio) as *mut super::io::Settings,
            freeptr: Some(sandwich_helper_owned_io_free),
        });
        unsafe { *owned_io = Box::into_raw(b) };
    }
    IOError::IOERROR_OK.value()
}
