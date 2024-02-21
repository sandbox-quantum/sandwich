// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich Listener module for FFI.

use std::ffi::{c_int, c_void};
use std::ptr::{self, NonNull};

use protobuf::Enum;

use crate::ffi::support;
use crate::io::error::IntoIOError;
use crate::io::listener::Listener;

use super::OwnedIo;

/// Causes given listener to start listening for connections.
#[no_mangle]
pub extern "C" fn sandwich_listener_listen(listener: *mut c_void) -> c_int {
    let mut b: Box<Box<dyn Listener>> = unsafe { Box::from_raw(listener.cast()) };
    let r = b.listen();
    Box::into_raw(b);
    let ret = match r {
        Ok(_) => pb::IOError::IOERROR_OK.value(),
        Err(e) => e.into_io_error().value(),
    };

    support::to_c_int(ret)
}

/// Accept a new connection from a given listener.
#[no_mangle]
pub extern "C" fn sandwich_listener_accept(
    listener: *mut c_void,
    owned_io: *mut *mut OwnedIo,
) -> c_int {
    let owned_io = NonNull::new(owned_io);
    let mut b: Box<Box<dyn Listener>> = unsafe { Box::from_raw(listener.cast()) };
    let r = b.ffi_accept_owned();
    Box::into_raw(b);
    let ret = match r {
        Ok(boxed_owned_io) => {
            if let Some(owned_io) = owned_io {
                unsafe { *owned_io.as_ptr() = Box::into_raw(boxed_owned_io) };
            }
            pb::IOError::IOERROR_OK.value()
        }
        Err(e) => {
            if let Some(owned_io) = owned_io {
                unsafe { *owned_io.as_ptr() = ptr::null_mut() };
            }
            e.into_io_error().value()
        }
    };

    support::to_c_int(ret)
}

/// Closes the listener.
#[no_mangle]
pub extern "C" fn sandwich_listener_close(listener: *mut c_void) {
    let mut b: Box<Box<dyn Listener>> = unsafe { Box::from_raw(listener.cast()) };
    let _ = b.close();
    Box::into_raw(b);
}

/// Releases the listener.
#[no_mangle]
pub extern "C" fn sandwich_listener_free(listener: *mut c_void) {
    if !listener.is_null() {
        let mut b: Box<Box<dyn Listener>> = unsafe { Box::from_raw(listener.cast()) };
        let _ = b.destructor();
    }
}

/// Creates a new listener based on a ListenerConfiguration protobuf message.
///
/// See configuration options in `api/v1/listenerconfiguration.proto`.
#[no_mangle]
pub extern "C" fn sandwich_listener_new(
    src: *const c_void,
    n: usize,
    out: *mut *mut c_void,
) -> *mut crate::ffi::Error {
    if src.is_null() {
        return errors!{pb::ProtobufError::PROTOBUFERROR_NULLPTR => pb::APIError::APIERROR_CONFIGURATION}.into();
    }

    let slice = unsafe { std::slice::from_raw_parts(src.cast(), n) };
    let mut listener = pb_api::ListenerConfiguration::new();

    match <pb_api::ListenerConfiguration as protobuf::Message>::merge_from_bytes(&mut listener, slice) {
        Ok(_) => match crate::io::listener::try_from(&listener) {
            Ok(l) => {
                if !out.is_null() {
                    unsafe {
                        *out = Box::into_raw(Box::new(l)).cast();
                    }
                }
                std::ptr::null_mut()
            },
            Err(e) => e.into()
        },
        Err(_) => errors!{pb::ProtobufError::PROTOBUFERROR_PARSE_FAILED => pb::APIError::APIERROR_CONFIGURATION}.into()
    }
}
