// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich Listener module for FFI.

use std::ffi::c_void;

/// Causes given listener to start listening for connections.
#[no_mangle]
pub extern "C" fn sandwich_listener_listen(listener: *mut c_void) -> i32 {
    let mut b: Box<Box<dyn crate::io::listener::Listener>> =
        unsafe { Box::from_raw(listener as *mut _) };
    let r = b.listen();
    Box::into_raw(b);
    use protobuf::Enum;
    match r {
        Ok(_) => pb::IOError::IOERROR_OK.value(),
        Err(e) => Into::<pb::IOError>::into(Into::<crate::io::Error>::into(e)).value(),
    }
}

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
    owned_io: *mut *mut crate::ffi::io_helpers::OwnedIo,
) -> i32 {
    let mut b: Box<Box<dyn crate::io::listener::Listener>> =
        unsafe { Box::from_raw(listener as *mut _) };
    let r = b.accept();
    Box::into_raw(b);
    use protobuf::Enum;
    match r {
        Ok(new_io) => {
            if !owned_io.is_null() {
                let io_ptr = Box::into_raw(Box::new(new_io));
                let settings = Box::new(HelperIOSettings {
                    readfn: crate::ffi::io_helpers::sandwich_helper_io_read,
                    writefn: crate::ffi::io_helpers::sandwich_helper_io_write,
                    uarg: io_ptr as *mut c_void,
                });
                let oio = Box::new(crate::ffi::io_helpers::OwnedIo {
                    io: Box::into_raw(settings) as *mut crate::ffi::io::Settings,
                    freeptr: Some(crate::ffi::io_helpers::sandwich_helper_owned_io_free),
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
            Into::<pb::IOError>::into(Into::<crate::io::Error>::into(e)).value()
        }
    }
}

/// Closes the listener.
#[no_mangle]
pub extern "C" fn sandwich_listener_close(listener: *mut c_void) {
    let mut b: Box<Box<dyn crate::io::listener::Listener>> =
        unsafe { Box::from_raw(listener as *mut _) };
    let _ = b.close();
    Box::into_raw(b);
}

/// Releases the listener.
#[no_mangle]
pub extern "C" fn sandwich_listener_free(listener: *mut c_void) {
    if !listener.is_null() {
        let mut b: Box<Box<dyn crate::io::listener::Listener>> =
            unsafe { Box::from_raw(listener as *mut _) };
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

    let slice = unsafe { std::slice::from_raw_parts(src as *const u8, n) };
    let mut listener = pb_api::ListenerConfiguration::new();

    match <pb_api::ListenerConfiguration as protobuf::Message>::merge_from_bytes(&mut listener, slice) {
        Ok(_) => match crate::io::listener::try_from(&listener) {
            Ok(l) => {
                if !out.is_null() {
                    unsafe {
                        *out = Box::into_raw(Box::new(l)) as *mut c_void;
                    }
                }
                std::ptr::null_mut()
            },
            Err(e) => e.into()
        },
        Err(_) => errors!{pb::ProtobufError::PROTOBUFERROR_PARSE_FAILED => pb::APIError::APIERROR_CONFIGURATION}.into()
    }
}
