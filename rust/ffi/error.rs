// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich error module for FFI.

use std::ffi::{CStr, CString};
use std::ptr::null_mut;

use crate::ErrorCode;

/// An error, for FFI.
/// See module [`crate::error`] for more information.
#[repr(C)]
pub struct Error {
    details: *mut Error,
    msg: *mut std::os::raw::c_char,
    kind: i32,
    code: i32,
}

/// Instantiates an [`Error`] from a Rust error.
impl From<crate::Error> for *mut Error {
    fn from(e: crate::Error) -> *mut Error {
        let mut root: *mut Error = null_mut();
        let mut cur: *mut Error = null_mut();
        for ec in e.iter().rev() {
            let (kind, code) = <_ as Into<(i32, i32)>>::into(ec);
            let msg = ec
                .msg()
                .and_then(|s| CString::new(s).ok())
                .map(CString::into_raw)
                .unwrap_or_else(null_mut);
            let e_c = Box::<Error>::new(Error {
                details: null_mut(),
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
            let _s = unsafe { CString::from_raw(b.msg) };
        }
        ptr = b.details;
    }
}

/// Returns a [`std::ffi::c_char`] from a [`sandwich::Error`] reference (AKA a SandwichError in C code).
/// The string will be in the format:
///     "Error Stack:
///      err:\[{str}\],code:\[{int},{int}\],msg:\[{str}\]"
///      "err" will be the error enumeration string.
///      "code" will be the pair of codes, (error kind, error code)
///      "msg" will be the extra error information from the underlying library.
///      There will be an error description line for every error linked in the Error collection.
/// Note: It is the caller's responsibility to free the returned string (using the corollary sandwich_error_stack_str_free function).
#[no_mangle]
pub extern "C" fn sandwich_error_stack_str_new(mut ptr: *mut Error) -> *const std::ffi::c_char {
    let mut err_msg_stack_str = String::from("Error Stack:\n");
    while !ptr.is_null() {
        let (err_kind, err_code) = unsafe { ((*ptr).kind, (*ptr).code) };
        let pbec = ErrorCode::try_from((err_kind, err_code))
            .unwrap_or_else(|_| pb::ProtobufError::PROTOBUFERROR_INVALID_ARGUMENT.into());
        let mut err_msg = String::new();
        unsafe {
            if !(*ptr).msg.is_null() {
                err_msg = cstr_to_safe_string((*ptr).msg);
            }
        }

        let err_msg_part = format!(
            "err:[{}],code:[{},{}],msg:[{}]]\n",
            pbec, err_kind, err_code, err_msg
        );
        err_msg_stack_str.push_str(&err_msg_part);
        ptr = unsafe { (*ptr).details };
    }
    CString::new(err_msg_stack_str)
        .unwrap_or_else(|_| CString::new("error converting Error Stack string!").unwrap())
        .into_raw()
}

/// Frees a [`CString`] generated from [`sandwich_error_stack_str_new`].
#[no_mangle]
pub unsafe extern "C" fn sandwich_error_stack_str_free(ptr: *const std::ffi::c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr as *mut _);
    }
}

/// Converts an [`std::ffi::c_char`] into a [`String`] that can be safely used.
fn cstr_to_safe_string(str_ptr: *const std::ffi::c_char) -> String {
    let cstr = unsafe { CStr::from_ptr(str_ptr) };
    String::from_utf8_lossy(cstr.to_bytes()).to_string()
}

#[cfg(test)]
mod test {
    use super::*;
    use protobuf::Enum;

    /// Tests conversion from [`crate::Error`] to [`super::Error`].
    #[test]
    fn test_error_ctor() {
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
        sandwich_error_free(ptr);
    }

    /// Tests [`sandwich_error_free`] with a null pointer.
    #[test]
    fn test_error_free_null_ptr() {
        sandwich_error_free(null_mut());
    }
    #[test]
    fn test_c_error_stack_str_null_error_and_free() {
        let err_str = sandwich_error_stack_str_new(null_mut());
        let safe_err_str = cstr_to_safe_string(err_str);
        let expect_str = "Error Stack:\n";
        unsafe {
            sandwich_error_stack_str_free(err_str);
        }
        assert_eq!(safe_err_str, expect_str);
    }

    #[test]
    fn test_c_error_stack_str_one_layer_error() {
        // Error message for Error Object
        let err_msg =
            CString::new("Tunnel failed to open successfully!").expect("CString::new failed");
        //Create the C Error
        let mut err: Error = Error {
            details: null_mut(),
            msg: err_msg.into_raw(),
            kind: pb::ErrorKind::ERRORKIND_API.value(),
            code: pb::APIError::APIERROR_TUNNEL.value(),
        };
        // Get pointer to C Error
        let p_err: *mut Error = &mut err;
        assert!(!p_err.is_null());
        // Get string from C Error pointer...
        let err_str = sandwich_error_stack_str_new(p_err);
        // Convert the C String to a rust String
        let safe_err_str = cstr_to_safe_string(err_str);
        let expect_str = "Error Stack:\nerr:[API errors.\n The following errors can occur during a call to the Context API.: Tunnel error.],code:[0,2],msg:[Tunnel failed to open successfully!]]\n";
        // Free the Error string (owned by the C code)
        unsafe {
            sandwich_error_stack_str_free(err_str);
        }
        assert_eq!(safe_err_str, expect_str);
        // cleanup
        unsafe {
            let _ = CString::from_raw(err.msg as *mut _);
        }
    }

    #[test]
    fn test_c_error_stack_str_invalid_error_code() {
        //Create the C Error
        let mut err: Error = Error {
            details: null_mut(),
            msg: null_mut(),
            kind: 99999,
            code: 91717,
        };
        // Get pointer to C Error
        let p_err: *mut Error = &mut err;
        assert!(!p_err.is_null());
        // Get string from C Error pointer...
        let err_str = sandwich_error_stack_str_new(p_err);
        let safe_err_str = cstr_to_safe_string(err_str);
        let expect_str =
            "Error Stack:\nerr:[Errors regarding protobuf.: / An invalid value was given.],code:[99999,91717],msg:[]]\n";
        // Free the Error string (owned by the C code)
        unsafe {
            sandwich_error_stack_str_free(err_str);
        }
        assert_eq!(safe_err_str, expect_str);
    }

    #[test]
    fn test_c_error_stack_str_multi_layer_error() {
        // Error message for Error Object
        let err_msg1 = CString::new("This is the root error message").expect("CString::new failed");
        let err_msg2 =
            CString::new("This is the middle error message").expect("CString::new failed");
        let err_msg3 =
            CString::new("This is the final error message").expect("CString::new failed");
        //Create the third C Error
        let mut err3: Error = Error {
            details: null_mut(),
            msg: err_msg3.into_raw(),
            kind: pb::ErrorKind::ERRORKIND_TUNNEL.value(),
            code: pb::TunnelError::TUNNELERROR_UNKNOWN.value(),
        };
        //Create the second C Error
        let mut err2: Error = Error {
            details: &mut err3,
            msg: err_msg2.into_raw(),
            kind: pb::ErrorKind::ERRORKIND_TLS_CONFIGURATION.value(),
            code: pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID.value(),
        };
        //Create the first C Error (Root)
        let mut err1: Error = Error{
            details: &mut err2,
            msg: err_msg1.into_raw(),
            kind: pb::ErrorKind::ERRORKIND_TLS_CONFIGURATION.value(),
            code: pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE.value(),
        };
        // Get pointer to C Error
        let p_err: *mut Error = &mut err1;
        assert!(!p_err.is_null());
        // Get string from C Error pointer...
        let err_str = sandwich_error_stack_str_new(p_err);
        // Convert the C String to a rust String
        let safe_err_str = cstr_to_safe_string(err_str);
        let expect_str = "Error Stack:\nerr:[Errors regarding TLS configurations.: Inconsistency between a private key and the corresponding certificate.],code:[2,4],msg:[This is the root error message]]\nerr:[Errors regarding TLS configurations.: Invalid configuration.],code:[2,5],msg:[This is the middle error message]]\nerr:[Tunnel error.: Unknown error.],code:[12,2],msg:[This is the final error message]]\n";
        // Free the Error string (owned by the C code)
        unsafe {
            sandwich_error_stack_str_free(err_str);
        }
        assert_eq!(safe_err_str, expect_str);
        // cleanup
        unsafe {
            let _ = CString::from_raw(err1.msg as *mut _);
            let _ = CString::from_raw(err2.msg as *mut _);
            let _ = CString::from_raw(err3.msg as *mut _);
        }
    }

    #[test]
    fn test_c_error_stack_str_multi_layer_error_invalid_middle_error() {
        // Error message for Error Object
        let err_msg1 = CString::new("This is the root error message").expect("CString::new failed");
        let err_msg2 =
            CString::new("This is the middle error message").expect("CString::new failed");
        let err_msg3 =
            CString::new("This is the final error message").expect("CString::new failed");
        //Create the third C Error
        let mut err3: Error = Error {
            details: null_mut(),
            msg: err_msg3.into_raw(),
            kind: pb::ErrorKind::ERRORKIND_TUNNEL.value(),
            code: pb::TunnelError::TUNNELERROR_UNKNOWN.value(),
        };
        //Create the second C Error
        let mut err2: Error = Error {
            details: &mut err3,
            msg: err_msg2.into_raw(),
            kind: 99911,
            code: 917881,
        };
        //Create the first C Error (Root)
        let mut err1: Error = Error{
            details: &mut err2,
            msg: err_msg1.into_raw(),
            kind: pb::ErrorKind::ERRORKIND_TLS_CONFIGURATION.value(),
            code: pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE.value(),
        };
        // Get pointer to C Error
        let p_err: *mut Error = &mut err1;
        assert!(!p_err.is_null());
        // Get string from C Error pointer...
        let err_str = sandwich_error_stack_str_new(p_err);
        // Convert the C String to a rust String
        let safe_err_str = cstr_to_safe_string(err_str);
        let expect_str = "Error Stack:\nerr:[Errors regarding TLS configurations.: Inconsistency between a private key and the corresponding certificate.],code:[2,4],msg:[This is the root error message]]\nerr:[Errors regarding protobuf.: / An invalid value was given.],code:[99911,917881],msg:[This is the middle error message]]\nerr:[Tunnel error.: Unknown error.],code:[12,2],msg:[This is the final error message]]\n";
        // Free the Error string (owned by the C code)
        unsafe {
            sandwich_error_stack_str_free(err_str);
        }
        assert_eq!(safe_err_str, expect_str);
        // cleanup
        unsafe {
            let _ = CString::from_raw(err1.msg as *mut _);
            let _ = CString::from_raw(err2.msg as *mut _);
            let _ = CString::from_raw(err3.msg as *mut _);
        }
    }
}
