// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich Listener module for FFI.

use std::ffi::{c_int, c_void};

use protobuf::Enum;

use crate::ffi::io::helpers;
use crate::ffi::support;
use crate::io::error::IntoIOError;
use crate::io::listener::Listener;

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

/// Settings for a helper I/O interface, using pointers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HelperIOSettings {
    /// The function that trampolines to the helper's read function.
    readfn: ReadFn,
    /// The function that trampolines to the helper's write function.
    writefn: WriteFn,
    /// A helper specific argument which will be passed to the trampoline
    /// read and written functions when called.
    uarg: *mut c_void,
}

/// Accept a new connection from a given listener.
#[no_mangle]
pub extern "C" fn sandwich_listener_accept(
    listener: *mut c_void,
    owned_io: *mut *mut helpers::OwnedIo,
) -> c_int {
    let mut b: Box<Box<dyn Listener>> = unsafe { Box::from_raw(listener.cast()) };
    let r = b.accept();
    Box::into_raw(b);
    let ret = match r {
        Ok(new_io) => {
            if !owned_io.is_null() {
                let io_ptr = Box::into_raw(Box::new(new_io));
                let settings = Box::new(HelperIOSettings {
                    readfn: helpers::sandwich_helper_io_read,
                    writefn: helpers::sandwich_helper_io_write,
                    uarg: io_ptr.cast(),
                });
                let oio = Box::new(helpers::OwnedIo {
                    io: Box::into_raw(settings).cast(),
                    freeptr: Some(helpers::sandwich_helper_owned_io_free),
                });
                unsafe {
                    *owned_io = Box::into_raw(oio);
                };
            }
            pb::IOError::IOERROR_OK.value()
        }
        Err(e) => {
            if !owned_io.is_null() {
                unsafe { *owned_io = std::ptr::null_mut() };
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
