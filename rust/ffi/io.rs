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

//! Sandwich I/O module for FFI.
//!
//! Author: thb-sb

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

/// Settings for a generic I/O interface, using pointers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Settings {
    readfn: ReadFn,
    writefn: WriteFn,
    closefn: CloseFn,
    uarg: *mut std::ffi::c_void,
}

/// Implements [`crate::IO`] for [`Settings`].
impl crate::IO for Settings {
    fn read(&mut self, buf: &mut [u8], tunnel_state: pb::State) -> crate::io::Result<usize> {
        use protobuf::ProtobufEnum;

        let mut err = pb::IOError::IOERROR_UNKNOWN.value();
        let n = (self.readfn)(
            self.uarg,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len(),
            tunnel_state.value(),
            &mut err as *mut i32,
        );
        if err != pb::IOError::IOERROR_OK.value() {
            Err(pb::IOError::from_i32(err).unwrap().into())
        } else {
            Ok(n)
        }
    }
    fn write(&mut self, buf: &[u8], tunnel_state: pb::State) -> crate::io::Result<usize> {
        use protobuf::ProtobufEnum;

        let mut err = pb::IOError::IOERROR_UNKNOWN.value();
        let n = (self.writefn)(
            self.uarg,
            buf.as_ptr() as *const std::ffi::c_void,
            buf.len(),
            tunnel_state.value(),
            &mut err as *mut i32,
        );
        if err != pb::IOError::IOERROR_OK.value() {
            Err(pb::IOError::from_i32(err).unwrap().into())
        } else {
            Ok(n)
        }
    }
    fn close(&mut self) -> crate::io::Result<()> {
        (self.closefn)(self.uarg);
        Ok(())
    }
}

/// Instantiates an new I/O interface from a struct [`Settings`].
#[no_mangle]
pub extern "C" fn sandwich_io_new(
    set: *const Settings,
    io: *mut *mut std::ffi::c_void,
) -> *mut super::Error {
    let b = Box::new(unsafe { *set });
    unsafe {
        *io = Box::into_raw(b) as *mut std::ffi::c_void;
    }
    std::ptr::null_mut()
}

/// Releases an I/O interface.
#[no_mangle]
pub extern "C" fn sandwich_io_free(io: *mut std::ffi::c_void) {
    if !io.is_null() {
        let _ = unsafe { Box::from_raw(io as *mut Settings) };
    }
}
