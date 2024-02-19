// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! OpenSSL 3 support module.

pub(crate) use openssl3::{
    BIO as NativeBio, EVP_PKEY as NativePrivateKey, SSL as NativeSsl, SSL_CTX as NativeSslCtx,
    X509 as NativeX509Certificate, X509_STORE_CTX as NativeX509StoreCtx,
    X509_VERIFY_PARAM as NativeX509VerifyParam,
};

use std::ffi::{c_int, c_ulong, CStr, CString};
use std::ptr::{self, NonNull};

use crate::support::Pimpl;
use crate::Result;

use super::LibCtx;

/// Returns the last error.
pub(crate) fn peek_last_error() -> c_ulong {
    unsafe { openssl3::ERR_peek_last_error() }
}

/// Returns the library where a given error occurred.
///
/// This function reproduces the `ERR_GET_LIB` method from OpenSSL, which
/// is a static function in header (thus not understandable by bindgen).
pub(crate) fn err_get_lib(err: c_ulong) -> c_int {
    ((err >> openssl3::ERR_LIB_OFFSET) & (openssl3::ERR_LIB_MASK as c_ulong)) as c_int
}

/// Returns the reason of why a given error occurred.
///
/// This function reproduces the `ERR_GET_REASON` method from OpenSSL, which
/// is a static function in header (thus not understandable by bindgen).
pub(crate) fn err_get_reason(err: c_ulong) -> c_int {
    (err & (openssl3::ERR_REASON_MASK as c_ulong)) as c_int
}

/// Returns a string containing the error strings for all errors that
/// OpenSSL 3 has recorded.
/// This function clears the error queue.
pub(crate) fn errstr() -> String {
    const DEFAULT_BUFFER_LEN: usize = 256;

    let Some(bio) = (unsafe {
        Pimpl::new(openssl3::BIO_new(openssl3::BIO_s_mem()), |x| {
            openssl3::BIO_free_all(x)
        })
    }) else {
        return "unknown error (BIO unavailable)".into();
    };

    unsafe {
        openssl3::ERR_print_errors(bio.as_nonnull().as_ptr());
    }

    let mut buffer = vec![0u8; DEFAULT_BUFFER_LEN];

    let mut buffer_ptr = buffer.as_mut_ptr();
    let mut size = 0;
    loop {
        let mut readbytes = 0usize;
        let ret = unsafe {
            openssl3::BIO_read_ex(
                bio.as_nonnull().as_ptr(),
                buffer_ptr.cast(),
                DEFAULT_BUFFER_LEN,
                &mut readbytes as *mut _,
            )
        };
        if ret == 0 {
            break;
        }
        if readbytes == 0 {
            break;
        }
        size += readbytes;
        if readbytes < DEFAULT_BUFFER_LEN {
            break;
        }
        let current_position = buffer.len();
        let Some(new_size) = current_position.checked_add(DEFAULT_BUFFER_LEN) else {
            break;
        };
        buffer.resize(new_size, 0u8);
        buffer_ptr = unsafe { buffer.as_mut_ptr().add(current_position) };
    }
    buffer.resize(size, 0u8);

    if let Some(first_null_byte) = buffer.iter().position(|x| *x == 0u8) {
        if first_null_byte == 0 {
            return "no additional information".to_string();
        }
        buffer.resize(first_null_byte, 0u8);
    } else if buffer.is_empty() {
        return "no additional information".to_string();
    }

    String::from_utf8(buffer).unwrap_or_else(|_| "unknown error (not UTF-8)".into())
}

/// Creates a new `BIO` object with a specific method.
#[allow(non_snake_case)]
pub(crate) fn new_BIO(
    bio_meth: NonNull<openssl3::BIO_METHOD>,
) -> Result<Pimpl<'static, NativeBio>> {
    unsafe {
        Pimpl::new(openssl3::BIO_new(bio_meth.as_ptr()), |bio| {
            openssl3::BIO_free_all(bio)
        })
    }
    .ok_or_else(|| {
        (
            pb::SystemError::SYSTEMERROR_MEMORY,
            "failed to create a new BIO object",
        )
            .into()
    })
}

/// Creates a `BIO` object from a immutable buffer.
#[allow(non_snake_case)]
pub(crate) fn BIO_from_buffer<'a>(buffer: impl AsRef<[u8]> + 'a) -> Result<Pimpl<'a, NativeBio>> {
    let buffer = buffer.as_ref();
    let size: i32 = buffer.len().try_into().map_err(|e| {
        (
            pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW,
            format!("cannot create a BIO object: {e}"),
        )
    })?;
    unsafe {
        Pimpl::new(
            openssl3::BIO_new_mem_buf(buffer.as_ptr().cast(), size),
            |x| openssl3::BIO_free_all(x),
        )
    }
    .ok_or_else(|| {
        (
            pb::SystemError::SYSTEMERROR_MEMORY,
            "cannot allocate a new BIO object",
        )
            .into()
    })
}

/// Reads a certificate (`X509` object) from a `BIO` object.
#[allow(non_snake_case)]
pub(crate) fn X509_from_BIO<'a, 'b>(
    lib_ctx: &'_ LibCtx<'a>,
    bio: NonNull<NativeBio>,
    format: pb_api::ASN1EncodingFormat,
) -> Result<Pimpl<'b, openssl3::X509>>
where
    'a: 'b,
{
    let x509 =
        NonNull::new(unsafe { openssl3::X509_new_ex(lib_ctx.as_nonnull().as_ptr(), ptr::null()) })
            .ok_or((
                pb::SystemError::SYSTEMERROR_MEMORY,
                "failed to allocate a new `X509` object",
            ))?;

    let mut inplace_ptr = x509.as_ptr();
    let ptr = match format {
        pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => {
            NonNull::new(unsafe {
                openssl3::PEM_read_bio_X509(bio.as_ptr(), &mut inplace_ptr, None, ptr::null_mut())
            })
            .ok_or_else(|| {
                unsafe { openssl3::X509_free(inplace_ptr) };
                (
                    pb::CertificateError::CERTIFICATEERROR_MALFORMED,
                    format!("failed to read the certificate: {}", errstr()),
                )
            })?;
            inplace_ptr
        }
        pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => {
            NonNull::new(unsafe { openssl3::d2i_X509_bio(bio.as_ptr(), &mut inplace_ptr) })
                .ok_or_else(|| {
                    unsafe { openssl3::X509_free(inplace_ptr) };
                    (
                        pb::CertificateError::CERTIFICATEERROR_MALFORMED,
                        format!("failed to read the certificate: {}", errstr()),
                    )
                })?;
            inplace_ptr
        }
    };
    Ok(unsafe { Pimpl::new_unchecked(ptr, |x| openssl3::X509_free(x)) })
}

/// Reads a private key (`EVP_PKEY` object) from a `BIO` object.
#[allow(non_snake_case)]
pub(crate) fn EVP_PKEY_from_BIO<'a, 'b>(
    lib_ctx: &'_ LibCtx<'a>,
    bio: NonNull<NativeBio>,
    format: pb_api::ASN1EncodingFormat,
) -> Result<Pimpl<'b, openssl3::EVP_PKEY>>
where
    'a: 'b,
{
    unsafe {
        Pimpl::new(
            match format {
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => {
                    openssl3::PEM_read_bio_PrivateKey_ex(
                        bio.as_ptr(),
                        ptr::null_mut(),
                        None,
                        ptr::null_mut(),
                        lib_ctx.as_nonnull().as_ptr(),
                        ptr::null(),
                    )
                }
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => openssl3::d2i_PrivateKey_ex_bio(
                    bio.as_ptr(),
                    ptr::null_mut(),
                    lib_ctx.as_nonnull().as_ptr(),
                    ptr::null(),
                ),
            },
            |x| openssl3::EVP_PKEY_free(x),
        )
    }
    .ok_or_else(|| {
        (
            pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED,
            format!("failed to read the private key: {}", errstr()),
        )
            .into()
    })
}

/// Tells if a BIO has reached EOF.
#[allow(non_snake_case)]
pub(crate) fn is_BIO_eof(bio: NonNull<NativeBio>) -> bool {
    // `BIO_eof` is a C macro.
    (unsafe {
        openssl3::BIO_ctrl(
            bio.as_ptr(),
            openssl3::BIO_CTRL_EOF as c_int,
            0,
            ptr::null_mut(),
        )
    }) == 1
}

/// Returns the cipher name in the OpenSSL format.
pub(crate) fn cipher_name(name: impl AsRef<str>) -> Option<&'static str> {
    let cstr = CString::new(name.as_ref().to_string()).ok()?;
    NonNull::new(unsafe { openssl3::OPENSSL_cipher_name(cstr.as_ptr()) }.cast_mut())
        .and_then(|nn| unsafe { CStr::from_ptr(nn.as_ptr()) }.to_str().ok())
}

#[cfg(test)]
pub(crate) mod test {
    use std::ffi::{c_int, CString};

    use super::*;

    /// Flushes the current error stack.
    fn openssl_flush_error_stack() {
        let mut i = 20;
        while i != 0 {
            if unsafe { openssl3::ERR_get_error() } == 0 {
                break;
            }
            i -= 1;
        }
        assert_ne!(i, 0);
    }

    /// Creates a new OpenSSL error.
    fn openssl_new_error(lib: impl Into<c_int>, reason: impl Into<c_int>, msg: impl Into<String>) {
        let lib: c_int = lib.into();
        let reason: c_int = reason.into();
        let msg = CString::new(msg.into()).unwrap();

        unsafe {
            openssl3::ERR_new();
            openssl3::ERR_set_error(lib, reason, msg.as_ptr());
        }
    }

    /// Returns a certificate ([`NativeX509Certificate`]) that has been read
    /// from a file in the testdata directory.
    pub(crate) fn get_certificate_from_testdata_file<'a>(
        lib_ctx: &LibCtx<'a>,
        path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> Result<Pimpl<'a, NativeX509Certificate>> {
        let path = crate::test::resolve_runfile(path.as_ref());
        let content = std::fs::read(path).unwrap();
        let bio = BIO_from_buffer(&content).unwrap();
        X509_from_BIO(lib_ctx, bio.as_nonnull(), format)
    }

    /// Returns a private key ([`NativePrivateKey`]) that has been read
    /// from a file in the testdata directory.
    pub(crate) fn get_private_key_from_testdata_file<'a>(
        lib_ctx: &LibCtx<'a>,
        path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> Result<Pimpl<'a, NativePrivateKey>> {
        let path = crate::test::resolve_runfile(path.as_ref());
        let content = std::fs::read(path).unwrap();
        let bio = BIO_from_buffer(&content).unwrap();
        EVP_PKEY_from_BIO(lib_ctx, bio.as_nonnull(), format)
    }

    /// Tests [`errstr`].
    #[test]
    fn test_errstr() {
        openssl_flush_error_stack();
        openssl_new_error(1, 2, "this is an error");
        let result = errstr();

        assert!(
            result.contains("this is an error"),
            "error string from OpenSSL does not seem to match the pattern defined"
        );
    }

    /// Tests [`errstr`] with a string that matches the `DEFAULT_BUFFER_LEN`.
    #[test]
    fn test_errstr_default_len() {
        let _lib_ctx = LibCtx::try_new().unwrap();
        openssl_flush_error_stack();
        let msg = "A".to_string().repeat(201);
        openssl_new_error(1, 2, msg.clone());
        let result = errstr();

        assert!(
            result.contains(&format!("error:00800002:lib(1)::reason(2)::-1:{msg}")),
            "error string from OpenSSL does not seem to match the pattern defined"
        );
    }

    /// Tests [`BIO_from_buffer`].
    #[test]
    #[allow(non_snake_case)]
    fn test_BIO_from_buffer() {
        let buf_in = vec![42u8; 42];
        let bio = BIO_from_buffer(&buf_in).unwrap();
        let mut buf_out = vec![42u8; 42];
        let mut readbytes = 0usize;

        let result = unsafe {
            openssl3::BIO_read_ex(
                bio.as_nonnull().as_ptr(),
                buf_out.as_mut_ptr().cast(),
                buf_out.len(),
                &mut readbytes as *mut _,
            )
        };

        assert_eq!(
            (result, readbytes, &buf_in),
            (1, 42, &buf_out),
            "`BIO_read_ex` did not return the expected result"
        );
    }

    /// Tests [`BIO_from_buffer`] with empty BIO.
    #[test]
    #[allow(non_snake_case)]
    fn test_BIO_from_buffer_empty() {
        let buf_in = vec![0u8; 0];
        let bio = BIO_from_buffer(&buf_in).unwrap();
        let mut buf_out = vec![0u8; 42];
        let mut readbytes = 0usize;

        let ret = unsafe {
            openssl3::BIO_read_ex(
                bio.as_nonnull().as_ptr(),
                buf_out.as_mut_ptr().cast(),
                buf_out.len(),
                &mut readbytes as *mut _,
            )
        };

        assert_eq!(
            (ret, readbytes),
            (0, 0),
            "`BIO_read_ex` did not return 0 for an empty buffer"
        );
    }

    /// Tests [`X509_from_BIO`] with a PEM-encoded certificate.
    #[test]
    #[allow(non_snake_case)]
    fn test_X509_from_BIO_PEM() {
        let cert_path =
            crate::test::resolve_runfile("testdata/falcon1024.cert.pem");
        let data = std::fs::read(cert_path).unwrap();
        let bio = BIO_from_buffer(&data).unwrap();
        let lib_ctx = LibCtx::try_new().unwrap();

        let result = X509_from_BIO(
            &lib_ctx,
            bio.as_nonnull(),
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        );

        result.unwrap();
    }

    /// Tests [`X509_from_BIO`] with a DER-encoded certificate.
    #[test]
    #[allow(non_snake_case)]
    fn test_X509_from_BIO_DER() {
        let cert_path =
            crate::test::resolve_runfile("testdata/dilithium5.cert.der");
        let data = std::fs::read(cert_path).unwrap();
        let bio = BIO_from_buffer(&data).unwrap();
        let lib_ctx = LibCtx::try_new().unwrap();

        X509_from_BIO(
            &lib_ctx,
            bio.as_nonnull(),
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER,
        )
        .unwrap();
    }

    /// Tests [`X509_from_BIO`] with an invalid DER-encoded certificate.
    #[test]
    #[allow(non_snake_case)]
    fn test_X509_from_BIO_DER_invalid() {
        let cert_path =
            crate::test::resolve_runfile("testdata/cert_unknown_sig_alg.der");
        let data = std::fs::read(cert_path).unwrap();
        let bio = BIO_from_buffer(&data).unwrap();
        let lib_ctx = LibCtx::try_new().unwrap();

        let err = X509_from_BIO(
            &lib_ctx,
            bio.as_nonnull(),
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        );

        let err = err.unwrap_err();
        assert!(err.is(&errors! {pb::CertificateError::CERTIFICATEERROR_MALFORMED}));
    }

    /// Tests [`EVP_PKEY_from_BIO`] with a PEM-encoded private key.
    #[test]
    #[allow(non_snake_case)]
    fn test_EVP_PKEY_from_BIO_PEM() {
        let private_key_path =
            crate::test::resolve_runfile("testdata/dilithium5.key.pem");
        let data = std::fs::read(private_key_path).unwrap();
        let bio = BIO_from_buffer(&data).unwrap();
        let lib_ctx = LibCtx::try_new().unwrap();

        EVP_PKEY_from_BIO(
            &lib_ctx,
            bio.as_nonnull(),
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
        .unwrap();
    }

    /// Tests [`EVP_PKEY_from_BIO`] with a DER-encoded private key.
    #[test]
    #[allow(non_snake_case)]
    fn test_EVP_PKEY_from_BIO_DER() {
        let private_key_path =
            crate::test::resolve_runfile("testdata/dilithium5.key.der");
        let data = std::fs::read(private_key_path).unwrap();
        let bio = BIO_from_buffer(&data).unwrap();
        let lib_ctx = LibCtx::try_new().unwrap();

        EVP_PKEY_from_BIO(
            &lib_ctx,
            bio.as_nonnull(),
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER,
        )
        .unwrap();
    }

    /// Tests [`is_BIO_eof`].
    #[test]
    #[allow(non_snake_case)]
    fn test_is_BIO_eof() {
        let data = vec![42u8; 42];
        let bio = BIO_from_buffer(&data).unwrap();
        let mut buf_out = vec![42u8; 42];
        let mut readbytes = 0usize;
        let ret = unsafe {
            openssl3::BIO_read_ex(
                bio.as_nonnull().as_ptr(),
                buf_out.as_mut_ptr().cast(),
                buf_out.len(),
                &mut readbytes as *mut _,
            )
        };

        let result = is_BIO_eof(bio.as_nonnull());

        assert_eq!((ret, readbytes, result), (1, buf_out.len(), true));
    }

    /// Tests [`is_BIO_eof`] with a non-empty BIO.
    #[test]
    #[allow(non_snake_case)]
    fn test_is_BIO_eof_non_empty() {
        let data = vec![42u8; 42];
        let bio = BIO_from_buffer(&data).unwrap();
        let mut buf_out = vec![0u8; 42];
        let mut readbytes = 0usize;
        let ret = unsafe {
            openssl3::BIO_read_ex(
                bio.as_nonnull().as_ptr(),
                buf_out.as_mut_ptr().cast(),
                buf_out.len() - 1,
                &mut readbytes as *mut _,
            )
        };

        let result = is_BIO_eof(bio.as_nonnull());

        assert_eq!((ret, readbytes, result), (1, buf_out.len() - 1, false));
    }

    /// Tests [`is_BIO_eof`] with a non-empty BIO full of zeros.
    #[test]
    #[allow(non_snake_case)]
    fn test_is_BIO_eof_non_empty_zeros() {
        let data = vec![0u8; 42];
        let bio = BIO_from_buffer(&data).unwrap();
        let mut buf_out = vec![42u8; 42];
        let mut readbytes = 0usize;
        let ret = unsafe {
            openssl3::BIO_read_ex(
                bio.as_nonnull().as_ptr(),
                buf_out.as_mut_ptr().cast(),
                buf_out.len() - 1,
                &mut readbytes as *mut _,
            )
        };

        let result = is_BIO_eof(bio.as_nonnull());

        assert_eq!((ret, readbytes, result), (1, buf_out.len() - 1, false));
    }
}
