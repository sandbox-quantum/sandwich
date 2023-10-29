// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich context module for FFI.

use std::ffi::c_void;

use crate::ffi::Error;
use crate::tunnel;

/// A serialized [`pb_api::Configuration`] for FFI.
#[repr(C)]
pub struct SandwichTunnelContextConfigurationSerialized {
    /// Buffer containing the serialized configuration message.
    src: *const c_void,

    /// Size of the buffer.
    n: usize,
}

/// Instantiates a Sandwich context from a serialized configuration.
///
/// # Errors
///
/// See constructors of [`tunnel::Context`].
#[no_mangle]
pub extern "C" fn sandwich_tunnel_context_new(
    sw: *const crate::Context,
    serialized_configuration: SandwichTunnelContextConfigurationSerialized,
    out: *mut *mut tunnel::Context,
) -> *mut Error {
    if serialized_configuration.src.is_null() {
        return errors!{pb::ProtobufError::PROTOBUFERROR_NULLPTR => pb::APIError::APIERROR_CONFIGURATION}.into();
    }
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            serialized_configuration.src.cast(),
            serialized_configuration.n,
        )
    };
    let mut configuration = pb_api::Configuration::new();

    match <pb_api::Configuration as protobuf::Message>::merge_from_bytes(&mut configuration, slice) {
        Ok(_) => match tunnel::Context::try_from(unsafe { &*sw }, &configuration) {
            Ok(ctx) => {
                if !out.is_null() {
                    unsafe {
                        *out = Box::into_raw(Box::new(ctx));
                    }
                }
                std::ptr::null_mut()
            },
            Err(e) => e.into(),
        },
        Err(_) => errors!{pb::ProtobufError::PROTOBUFERROR_PARSE_FAILED => pb::APIError::APIERROR_CONFIGURATION}.into()
    }
}

/// Releases a Sandwich context.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_context_free(ctx: *mut tunnel::Context) {
    if !ctx.is_null() {
        let _: Box<tunnel::Context> = unsafe { Box::from_raw(ctx) };
    }
}

#[cfg(all(test, feature = "openssl1_1_1"))]
mod test {
    use super::*;
    use crate::test::resolve_runfile;
    use crate::tunnel::tls;

    /// Tests [`sandwich_tunnel_context_new`] and [`sandwich_tunnel_context_free`].
    #[test]
    fn test_context_ctor_dtor() {
        use protobuf::Message;

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl : IMPL_OPENSSL1_1_1_OQS
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "kyber1024"
                        >
                        x509_verifier <
                            trusted_cas <
                                static <
                                    data <
                                        filename: "{}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                        >
                    >
                >
            >
            "#,
                resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let encoded = config.write_to_bytes().unwrap();
        drop(config);

        let mut ptr: *mut tunnel::Context = std::ptr::null_mut();
        let sw = crate::Context;
        sandwich_tunnel_context_new(
            &sw as *const _,
            SandwichTunnelContextConfigurationSerialized {
                src: encoded.as_ptr().cast(),
                n: encoded.len(),
            },
            &mut ptr as *mut *mut tunnel::Context,
        );
        assert!(!ptr.is_null());

        sandwich_tunnel_context_free(ptr);
    }

    /// Tests [`sandwich_tunnel_context_new`] with an error.
    #[test]
    fn test_context_ctor_error() {
        use protobuf::Message;

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl : IMPL_OPENSSL1_1_1_OQS
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "kyber1023"
                        >
                        x509_verifier <
                            trusted_cas <
                                static <
                                    data <
                                        filename: "{}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                        >
                    >
                >
            >
            "#,
                resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let encoded = config.write_to_bytes().unwrap();

        let mut ptr: *mut tunnel::Context = std::ptr::null_mut();
        let sw = crate::Context;
        let err = sandwich_tunnel_context_new(
            &sw as *const _,
            SandwichTunnelContextConfigurationSerialized {
                src: encoded.as_ptr().cast(),
                n: encoded.len(),
            },
            &mut ptr as *mut *mut tunnel::Context,
        );
        assert_eq!(ptr, std::ptr::null_mut());
        sandwich_tunnel_context_free(ptr);
        crate::ffi::error::sandwich_error_free(err);
    }

    /// Tests [`sandwich_tunnel_context_new`] with a null pointer.
    #[test]
    fn test_context_ctor_nullptr() {
        let mut ptr: *mut tunnel::Context = std::ptr::null_mut();
        let sw = crate::Context;
        let err = sandwich_tunnel_context_new(
            &sw as *const _,
            SandwichTunnelContextConfigurationSerialized {
                src: std::ptr::null(),
                n: 0x41,
            },
            &mut ptr as *mut *mut tunnel::Context,
        );
        assert!(!err.is_null());
        assert!(ptr.is_null());

        crate::ffi::error::sandwich_error_free(err);
    }

    /// Tests [`sandwich_tunnel_context_new`] with an invalid protobuf message.
    #[test]
    fn test_context_ctor_invalid_msg() {
        let data = [0u8; 42];

        let mut ptr: *mut tunnel::Context = std::ptr::null_mut();
        let sw = crate::Context;
        let err = sandwich_tunnel_context_new(
            &sw as *const _,
            SandwichTunnelContextConfigurationSerialized {
                src: data.as_ptr().cast(),
                n: data.len(),
            },
            &mut ptr as *mut *mut tunnel::Context,
        );
        assert_eq!(ptr, std::ptr::null_mut());
        sandwich_tunnel_context_free(ptr);
        crate::ffi::error::sandwich_error_free(err);
    }
}
