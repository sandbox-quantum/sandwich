// Copyright 2023 SandboxAQ
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

//! Helper functions that create commonly used IO objects

use crate::IO;

/// A read function.
pub type ReadFn = extern "C" fn(
    uarg: *mut std::ffi::c_void,
    buf: *mut std::ffi::c_void,
    count: usize,
    tunnel_state: i32,
    err: *mut i32,
) -> usize;

/// A write function.
pub type WriteFn = extern "C" fn(
    uarg: *mut std::ffi::c_void,
    buf: *const std::ffi::c_void,
    count: usize,
    tunnel_state: i32,
    err: *mut i32,
) -> usize;

/// A close function.
pub type CloseFn = extern "C" fn(uarg: *mut std::ffi::c_void);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HelperClientSettings {
    readfn: ReadFn,
    writefn: WriteFn,
    closefn: CloseFn,
    uarg: *mut std::ffi::c_void,
}

/// A read function.
extern "C" fn sandwich_helper_client_read(
    uarg: *mut std::ffi::c_void,
    buf: *mut std::ffi::c_void,
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
            unsafe { *err = pb::IOError::IOERROR_OK.value() };
            size
        }
        Err(e) => {
            unsafe { *err = Into::<pb::IOError>::into(e).value() };
            0
        }
    }
}

/// A write function.
extern "C" fn sandwich_helper_client_write(
    uarg: *mut std::ffi::c_void,
    buf: *const std::ffi::c_void,
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
            unsafe { *err = pb::IOError::IOERROR_OK.value() };
            size
        }
        Err(e) => {
            unsafe { *err = Into::<pb::IOError>::into(e).value() };
            0
        }
    }
}

/// A close function.
extern "C" fn sandwich_helper_client_close(uarg: *mut std::ffi::c_void) {
    let mut boxed_helper_client_io: Box<Box<dyn IO>> = unsafe { Box::from_raw(uarg as *mut _) };
    let _ = boxed_helper_client_io.close();
    Box::into_raw(boxed_helper_client_io);
}

/// Frees io created with sandwich_client_io_*_new() family of functions
/// Using this function with user created IO objects will cause undefined
/// behaviour.
#[no_mangle]
extern "C" fn sandwich_client_io_free(cio: *mut super::io::Settings) {
    let boxed_cio: Box<HelperClientSettings> = unsafe { Box::from_raw(cio as *mut _) };
    let _: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(boxed_cio.uarg as *mut _) };
}

/// Create a new client TCP IO object.
#[no_mangle]
pub extern "C" fn sandwich_client_io_tcp_new(
    hostname: *const std::ffi::c_char,
    port: u16,
    is_blocking: bool,
    cio: *mut *mut super::io::Settings,
) -> i32 {
    use protobuf::Enum;
    let hn = unsafe {
        std::ffi::CStr::from_ptr(hostname as *mut _)
            .to_str()
            .unwrap()
            .to_string()
    };
    let io: Box<dyn crate::IO> =
        match crate::io::helpers::tcp::TcpIo::new_client(&hn, &port, is_blocking) {
            Ok(io) => Box::new(io),
            Err(e) => return Into::<pb::IOError>::into(e).value(),
        };
    let boxed_io = Box::new(io);
    let io_ptr = Box::into_raw(boxed_io);
    let boxed_cio = Box::new(HelperClientSettings {
        readfn: sandwich_helper_client_read,
        writefn: sandwich_helper_client_write,
        closefn: sandwich_helper_client_close,
        uarg: io_ptr as *mut std::ffi::c_void,
    });
    if !cio.is_null() {
        let b = Box::into_raw(boxed_cio);
        unsafe { *cio = b as *mut super::io::Settings };
    }
    pb::IOError::IOERROR_OK.value()
}
