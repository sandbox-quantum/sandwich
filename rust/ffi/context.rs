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

//! Sandwich context module for FFI.

/// Instantiates a Sandwich context from a serialized configuration.
///
/// # Errors
///
/// See constructors of [`crate::Context`].
#[no_mangle]
pub extern "C" fn sandwich_context_new(
    src: *const std::ffi::c_void,
    n: usize,
    out: *mut *mut std::ffi::c_void,
) -> *mut super::Error {
    if src.is_null() {
        return errors!{pb::ProtobufError::PROTOBUFERROR_NULLPTR => pb::APIError::APIERROR_CONFIGURATION}.into();
    }

    let slice = unsafe { std::slice::from_raw_parts(src as *const u8, n) };
    let mut configuration = pb_api::Configuration::new();

    match <pb_api::Configuration as protobuf::Message>::merge_from_bytes(&mut configuration, slice) {
        Ok(_) => match crate::context::try_from(&configuration) {
            Ok(ctx) => {
                if !out.is_null() {
                    unsafe {
                        *out = Box::into_raw(Box::new(ctx)) as *mut std::ffi::c_void;
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
pub extern "C" fn sandwich_context_free(ctx: *mut std::ffi::c_void) {
    if !ctx.is_null() {
        let _: Box<Box<dyn crate::context::Context>> = unsafe { Box::from_raw(ctx as *mut _) };
    }
}

#[cfg(all(test, feature = "openssl"))]
mod test {
    /// Tests [`sandwich_context_new`] and [`sandwich_context_free`].
    #[test]
    fn test_context_ctor_dtor() {
        use protobuf::Message;

        let cert_path = crate::test::resolve_runfile(crate::tls::test::CERT_PEM_PATH);
        let mut config =
            crate::context::test::openssl::create_configuration(crate::Mode::Client, false);
        config
            .mut_client()
            .mut_tls()
            .common_options
            .mut_or_insert_default()
            .mut_x509_verifier()
            .trusted_cas
            .push(crate::context::test::openssl::create_cert(
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

        let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        super::sandwich_context_new(
            encoded.as_ptr() as *const std::ffi::c_void,
            encoded.len(),
            &mut ptr as *mut *mut std::ffi::c_void,
        );
        assert!(!ptr.is_null());

        super::sandwich_context_free(ptr);
    }

    /// Tests [`sandwich_context_new`] with an error.
    #[test]
    fn test_context_ctor_error() {
        use protobuf::Message;

        let cert_path = crate::test::resolve_runfile(crate::tls::test::CERT_PEM_PATH);
        let mut config =
            crate::context::test::openssl::create_configuration(crate::Mode::Client, false);
        config
            .mut_client()
            .mut_tls()
            .common_options
            .mut_or_insert_default()
            .mut_x509_verifier()
            .trusted_cas
            .push(crate::context::test::openssl::create_cert(
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

        let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let err = super::sandwich_context_new(
            encoded.as_ptr() as *const std::ffi::c_void,
            encoded.len(),
            &mut ptr as *mut *mut std::ffi::c_void,
        );
        assert_eq!(ptr, std::ptr::null_mut());
        super::sandwich_context_free(ptr);
        super::super::error::sandwich_error_free(err);
    }

    /// Tests [`sandwich_context_new`] with a null pointer.
    #[test]
    fn test_context_ctor_nullptr() {
        let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let err = super::sandwich_context_new(
            std::ptr::null(),
            0x41,
            &mut ptr as *mut *mut std::ffi::c_void,
        );
        assert!(!err.is_null());
        assert!(ptr.is_null());

        crate::ffi::error::sandwich_error_free(err);
    }

    /// Tests [`sandwich_context_new`] with an invalid protobuf message.
    #[test]
    fn test_context_ctor_invalid_msg() {
        let data = [0u8; 42];

        let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let err = super::sandwich_context_new(
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            &mut ptr as *mut *mut std::ffi::c_void,
        );
        assert_eq!(ptr, std::ptr::null_mut());
        super::sandwich_context_free(ptr);
        super::super::error::sandwich_error_free(err);
    }
}
