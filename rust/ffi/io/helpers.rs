// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Helper functions that create commonly used IO objects.

use std::ffi::{c_int, CStr};
use std::fs::File;
use std::net::TcpStream;
use std::os::fd::{FromRawFd, RawFd};

use protobuf::Enum;

use pb::IOError;

use crate::ffi::support;
use crate::io::error::IntoIOError;

#[cfg(feature = "turbo")]
use crate::experimental::TurboClientIo;

use super::OwnedIo;

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
    unsafe {
        *owned_io = Box::into_raw(OwnedIo::from_std_io_boxed(socket));
    }
    support::to_c_int(IOError::IOERROR_OK.value())
}

/// Creates a new system socket IO object.
#[no_mangle]
pub extern "C" fn sandwich_io_socket_wrap_new(socket: RawFd, owned_io: *mut *mut OwnedIo) -> c_int {
    unsafe {
        *owned_io = Box::into_raw(OwnedIo::from_std_io_boxed(File::from_raw_fd(socket)));
    }
    support::to_c_int(IOError::IOERROR_OK.value())
}

/// Creates a new client Turbo IO object.
#[cfg(feature = "turbo")]
#[no_mangle]
pub extern "C" fn sandwich_io_client_turbo_new(
    udp_hostname: *const std::ffi::c_char,
    udp_port: u16,
    tcp_hostname: *const std::ffi::c_char,
    tcp_port: u16,
    is_blocking: bool,
    owned_io: *mut *mut OwnedIo,
) -> i32 {
    let Ok(uhn) = unsafe { CStr::from_ptr(udp_hostname.cast()) }.to_str() else {
        return support::to_c_int(pb::IOError::IOERROR_SYSTEM_ERROR.value());
    };
    let Ok(thn) = unsafe { CStr::from_ptr(tcp_hostname.cast()) }.to_str() else {
        return support::to_c_int(pb::IOError::IOERROR_SYSTEM_ERROR.value());
    };

    let turbo_client = match TurboClientIo::new((uhn, udp_port), (thn, tcp_port), is_blocking) {
        Ok(client) => OwnedIo::from_turbo_client_boxed(client),
        Err(e) => return support::to_c_int(e.into_io_error().value()),
    };
    unsafe {
        *owned_io = Box::into_raw(turbo_client);
    }
    support::to_c_int(IOError::IOERROR_OK.value())
}
