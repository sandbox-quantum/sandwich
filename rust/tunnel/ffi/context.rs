// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich context module for FFI.

use std::ffi::c_void;

use crate::ffi::Error;

/// Instantiates a Sandwich context from a serialized configuration.
///
/// # Errors
///
/// See constructors of [`crate::tunnel::Context`].
#[no_mangle]
pub extern "C" fn sandwich_tunnel_context_new(
    src: *const c_void,
    n: usize,
    out: *mut *mut c_void,
) -> *mut Error {
    if src.is_null() {
        return errors!{pb::ProtobufError::PROTOBUFERROR_NULLPTR => pb::APIError::APIERROR_CONFIGURATION}.into();
    }

    let slice = unsafe { std::slice::from_raw_parts(src as *const u8, n) };
    let mut configuration = pb_api::Configuration::new();

    match <pb_api::Configuration as protobuf::Message>::merge_from_bytes(&mut configuration, slice) {
        Ok(_) => match crate::tunnel::Context::try_from(&configuration) {
            Ok(ctx) => {
                if !out.is_null() {
                    unsafe {
                        *out = Box::into_raw(Box::new(ctx)).cast();
                    }
                }
                std::ptr::null_mut()
            },
            Err(e) => e.into()
        },
        Err(_) => errors!{pb::ProtobufError::PROTOBUFERROR_PARSE_FAILED => pb::APIError::APIERROR_CONFIGURATION}.into()
    }
}

/// Releases a Sandwich context.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_context_free(ctx: *mut c_void) {
    if !ctx.is_null() {
        let _: Box<crate::tunnel::Context> = unsafe { Box::from_raw(ctx.cast()) };
    }
}

#[cfg(all(test, feature = "openssl1_1_1"))]
mod test {
    use super::*;
    use crate::tunnel::tls;

    /// Tests [`sandwich_tunnel_context_new`] and [`sandwich_tunnel_context_free`].
    #[test]
    fn test_context_ctor_dtor() {
        use protobuf::Message;

        let cert_path = crate::test::resolve_runfile(tls::test::CERT_PEM_PATH);
        let mut config = crate::tunnel::context::test::openssl1_1_1::create_configuration(
            crate::tunnel::Mode::Client,
            false,
        );
        config
            .mut_client()
            .mut_tls()
            .common_options
            .mut_or_insert_default()
            .mut_x509_verifier()
            .trusted_cas
            .push(crate::tunnel::context::test::openssl1_1_1::create_cert(
                &cert_path,
                Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            ));
        config
            .mut_client()
            .mut_tls()
            .common_options
            .mut_or_insert_default()
            .kem
            .push("kyber1024".to_string());

        let encoded = config.write_to_bytes().unwrap();
        drop(config);

        let mut ptr: *mut c_void = std::ptr::null_mut();
        sandwich_tunnel_context_new(
            encoded.as_ptr() as *const c_void,
            encoded.len(),
            &mut ptr as *mut *mut c_void,
        );
        assert!(!ptr.is_null());

        sandwich_tunnel_context_free(ptr);
    }

    /// Tests [`sandwich_tunnel_context_new`] with an error.
    #[test]
    fn test_context_ctor_error() {
        use protobuf::Message;

        let cert_path = crate::test::resolve_runfile(tls::test::CERT_PEM_PATH);
        let mut config = crate::tunnel::context::test::openssl1_1_1::create_configuration(
            crate::tunnel::Mode::Client,
            false,
        );
        config
            .mut_client()
            .mut_tls()
            .common_options
            .mut_or_insert_default()
            .mut_x509_verifier()
            .trusted_cas
            .push(crate::tunnel::context::test::openssl1_1_1::create_cert(
                &cert_path,
                Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            ));
        config
            .mut_client()
            .mut_tls()
            .common_options
            .mut_or_insert_default()
            .kem
            .push("kyber1023".to_string());

        let encoded = config.write_to_bytes().unwrap();

        let mut ptr: *mut c_void = std::ptr::null_mut();
        let err = sandwich_tunnel_context_new(
            encoded.as_ptr() as *const c_void,
            encoded.len(),
            &mut ptr as *mut *mut c_void,
        );
        assert_eq!(ptr, std::ptr::null_mut());
        sandwich_tunnel_context_free(ptr);
        crate::ffi::error::sandwich_error_free(err);
    }

    /// Tests [`sandwich_tunnel_context_new`] with a null pointer.
    #[test]
    fn test_context_ctor_nullptr() {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let err = sandwich_tunnel_context_new(std::ptr::null(), 0x41, &mut ptr as *mut *mut c_void);
        assert!(!err.is_null());
        assert!(ptr.is_null());

        crate::ffi::error::sandwich_error_free(err);
    }

    /// Tests [`sandwich_tunnel_context_new`] with an invalid protobuf message.
    #[test]
    fn test_context_ctor_invalid_msg() {
        let data = [0u8; 42];

        let mut ptr: *mut c_void = std::ptr::null_mut();
        let err = sandwich_tunnel_context_new(
            data.as_ptr() as *const c_void,
            data.len(),
            &mut ptr as *mut *mut c_void,
        );
        assert_eq!(ptr, std::ptr::null_mut());
        sandwich_tunnel_context_free(ptr);
        crate::ffi::error::sandwich_error_free(err);
    }
}
