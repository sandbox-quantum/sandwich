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

//! Sandwich error module for FFI.
//!
//! Author: thb-sb

/// An error, for FFI.
/// See module [`crate::error`] for more information.
#[repr(C)]
pub struct Error {
    pub(self) details: *mut Error,
    pub(self) kind: i32,
    pub(self) code: i32,
}

/// Instantiates an [`Error`] from a Rust error.
impl std::convert::From<crate::Error> for *mut Error {
    fn from(e: crate::Error) -> *mut Error {
        let mut root: *mut Error = std::ptr::null_mut();
        let mut cur: *mut Error = std::ptr::null_mut();

        for ec in e.iter().rev() {
            let (kind, code) = <_ as std::convert::Into<(i32, i32)>>::into(ec);
            let e_c = Box::<Error>::new(Error {
                details: std::ptr::null_mut(),
                kind,
                code,
            });
            if root.is_null() {
                root = Box::into_raw(e_c);
                cur = root;
            } else {
                unsafe {
                    (*cur).details = Box::into_raw(e_c);
                    cur = (*cur).details;
                }
            }
        }
        root
    }
}

/// Releases an [`Error`].
#[no_mangle]
pub extern "C" fn sandwich_error_free(mut ptr: *mut Error) {
    while !ptr.is_null() {
        let b = unsafe { Box::from_raw(ptr) };
        ptr = b.details;
    }
}
