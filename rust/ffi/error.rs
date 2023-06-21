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

/// An error, for FFI.
/// See module [`crate::error`] for more information.
#[repr(C)]
pub struct Error {
    pub(self) details: *mut Error,
    pub(self) msg: *mut i8,
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
            let msg = match ec.msg() {
                Some(s) => {
                    if let Ok(cstring) = std::ffi::CString::new(s) {
                        cstring.into_raw()
                    } else {
                        std::ptr::null_mut()
                    }
                }
                None => std::ptr::null_mut(),
            };
            let e_c = Box::<Error>::new(Error {
                details: std::ptr::null_mut(),
                msg,
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
        if !b.msg.is_null() {
            let _s = unsafe { std::ffi::CString::from_raw(b.msg) };
        }
        ptr = b.details;
    }
}

#[cfg(test)]
mod test {
    use super::Error;

    /// Tests conversion from [`crate::Error`] to [`super::Error`].
    #[test]
    fn test_error_ctor() {
        use protobuf::Enum;
        let err = errors! {
        pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID
            => pb::ConfigurationError::CONFIGURATIONERROR_INVALID
                => pb::APIError::APIERROR_CONFIGURATION};
        let ptr: *mut Error = err.into();
        assert!(!ptr.is_null());
        unsafe {
            assert_eq!((*ptr).kind, pb::ErrorKind::ERRORKIND_API.value());
            assert_eq!((*ptr).code, pb::APIError::APIERROR_CONFIGURATION.value());

            let ptr = (*ptr).details;
            assert!(!ptr.is_null());
            assert_eq!((*ptr).kind, pb::ErrorKind::ERRORKIND_CONFIGURATION.value());
            assert_eq!(
                (*ptr).code,
                pb::ConfigurationError::CONFIGURATIONERROR_INVALID.value()
            );

            let ptr = (*ptr).details;
            assert!(!ptr.is_null());
            assert_eq!(
                (*ptr).kind,
                pb::ErrorKind::ERRORKIND_TLS_CONFIGURATION.value()
            );
            assert_eq!(
                (*ptr).code,
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID.value()
            );

            let ptr = (*ptr).details;
            assert!(ptr.is_null());
        }
        super::sandwich_error_free(ptr);
    }

    /// Tests [`sandwich_error_free`] with a null pointer.
    #[test]
    fn test_error_free_null_ptr() {
        super::sandwich_error_free(std::ptr::null_mut());
    }
}
