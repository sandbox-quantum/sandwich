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

//! Defines [`OpenSSLOssl`] structure that implements [`crate::ossl::Ossl`].
//!
//! Author: thb-sb

extern crate openssl;

pub(crate) struct Ossl {}

/// Convert an OpenSSL error to a [`crate::tunnel::RecordError`].
fn openssl_error_to_record_error(e: i32, errno: std::io::Error) -> crate::tunnel::RecordError {
    match e as u32 {
        openssl::SSL_ERROR_WANT_READ => pb::RecordError::RECORDERROR_WANT_READ,
        openssl::SSL_ERROR_WANT_WRITE => pb::RecordError::RECORDERROR_WANT_WRITE,
        openssl::SSL_ERROR_ZERO_RETURN => pb::RecordError::RECORDERROR_CLOSED,
        openssl::SSL_ERROR_SYSCALL => match errno.raw_os_error() {
            // EPIPE
            Some(32) => pb::RecordError::RECORDERROR_CLOSED,
            Some(_) | None => pb::RecordError::RECORDERROR_UNKNOWN,
        },
        _ => pb::RecordError::RECORDERROR_UNKNOWN,
    }
    .into()
}

/// Creates a BIO object from a buffer.
fn buffer_to_bio<'data: 'pimpl, 'pimpl>(
    buf: &'data impl std::convert::AsRef<[u8]>,
) -> crate::Result<crate::Pimpl<'pimpl, openssl::BIO>> {
    let obj = buf.as_ref();
    let ptr = if obj.len() <= (std::i32::MAX as usize) {
        unsafe {
            Ok::<*mut openssl::bio_st, _>(openssl::BIO_new_mem_buf(
                obj.as_ptr() as *const std::ffi::c_void,
                obj.len() as i32,
            ))
        }
    } else {
        Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)
    }?;
    if !ptr.is_null() {
        Ok(crate::Pimpl::from_raw(
            ptr,
            Some(|p| unsafe {
                openssl::BIO_free_all(p);
            }),
        ))
    } else {
        Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
    }
}

/// Implements [`crate::ossl::Ossl`] for [`Ossl`].
impl crate::ossl::Ossl for Ossl {
    type NativeCertificate = openssl::x509_st;
    type NativePrivateKey = openssl::evp_pkey_st;
    type NativeSslCtx = openssl::SSL_CTX;
    type NativeSsl = openssl::SSL;
    type NativeBio = openssl::BIO;

    fn new_ssl_context<'pimpl>(
        mode: crate::Mode,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeSslCtx>> {
        let ctx = unsafe {
            openssl::SSL_CTX_new(match mode {
                crate::Mode::Client => openssl::TLS_client_method(),
                crate::Mode::Server => openssl::TLS_server_method(),
            })
        };
        if ctx.is_null() {
            Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
        } else {
            unsafe {
                openssl::SSL_CTX_set_options(
                    ctx,
                    (openssl::SSL_OP_NO_SSLv3
                        | openssl::SSL_OP_NO_TLSv1
                        | openssl::SSL_OP_NO_TLSv1_1
                        | openssl::SSL_OP_NO_TLSv1_2
                        | openssl::SSL_OP_NO_DTLSv1
                        | openssl::SSL_OP_NO_DTLSv1_2)
                        .into(),
                );
                openssl::SSL_CTX_set_quiet_shutdown(ctx, 0);
                openssl::SSL_CTX_ctrl(
                    ctx,
                    openssl::SSL_CTRL_SET_SESS_CACHE_MODE as i32,
                    openssl::SSL_SESS_CACHE_OFF.into(),
                    std::ptr::null_mut(),
                );
                openssl::SSL_CTX_ctrl(
                    ctx,
                    openssl::SSL_CTRL_SET_GROUPS as i32,
                    0,
                    std::ptr::null_mut(),
                );
            }
            let mut pimpl = crate::Pimpl::<openssl::SSL_CTX>::from_raw(
                ctx,
                Some(|x| unsafe {
                    openssl::SSL_CTX_free(x);
                }),
            );
            if mode == crate::Mode::Client {
                unsafe {
                    openssl::SSL_CTX_set_verify(
                        pimpl.as_mut_ptr(),
                        openssl::SSL_VERIFY_PEER as i32,
                        None,
                    )
                };
                let ptr = unsafe { openssl::X509_STORE_new() };
                if ptr.is_null() {
                    return Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
                }
                unsafe {
                    openssl::SSL_CTX_set_cert_store(pimpl.as_mut_ptr(), ptr);
                    openssl::X509_STORE_set_trust(ptr, 1);
                }
            }
            match unsafe { openssl::SSL_CTX_ctrl(pimpl.as_mut_ptr(), openssl::SSL_CTRL_SET_MIN_PROTO_VERSION as i32, openssl::TLS1_3_VERSION.into(), std::ptr::null_mut()) } {
                1 => Ok(pimpl),
                _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION.into())
            }
        }
    }

    fn ssl_context_set_verify_mode(pimpl: &mut crate::Pimpl<'_, Self::NativeSslCtx>, flags: u32) {
        unsafe {
            openssl::SSL_CTX_set_verify(
                pimpl.as_mut_ptr(),
                if ((flags as i32)
                    & <pb_api::TLSFlags as protobuf::Enum>::value(
                        &pb_api::TLSFlags::TLSFLAGS_SKIP_VERIFY,
                    ))
                    != 0
                {
                    openssl::SSL_VERIFY_NONE
                } else {
                    openssl::SSL_VERIFY_PEER
                } as i32,
                None,
            );
        }
    }

    fn ssl_context_set_kems(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        kems: std::slice::Iter<'_, std::string::String>,
    ) -> crate::Result<()> {
        let mut nids = std::vec::Vec::<i32>::new();
        for k in kems {
            let nid = match std::ffi::CString::new(k.as_bytes()) {
                Ok(cstr) => Ok(unsafe { openssl::OBJ_txt2nid(cstr.as_c_str().as_ptr()) }),
                Err(_) => Err(
                    errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::KEMError::KEMERROR_INVALID},
                ),
            }?;
            if nid == (openssl::NID_undef as i32) {
                return Err(pb::KEMError::KEMERROR_INVALID.into());
            }
            nids.push(nid);
            if nids.len() > (std::i32::MAX as usize) {
                return Err(pb::KEMError::KEMERROR_TOO_MANY.into());
            }
        }
        if !nids.is_empty() {
            match unsafe {
                openssl::SSL_CTX_ctrl(
                    ssl_ctx.as_mut_ptr(),
                    openssl::SSL_CTRL_SET_GROUPS as i32,
                    nids.len() as i64,
                    nids.as_ptr() as *mut std::ffi::c_void,
                )
            } {
                1 => Ok(()),
                _ => Err(pb::KEMError::KEMERROR_INVALID.into()),
            }
        } else {
            Ok(())
        }
    }

    fn ssl_context_append_certificate_to_trust_store(
        ssl_ctx: &crate::Pimpl<'_, Self::NativeSslCtx>,
        mut cert: crate::Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()> {
        let store = unsafe { openssl::SSL_CTX_get_cert_store(ssl_ctx.as_ptr()) };
        if store.is_null() {
            Err(
                errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::CertificateError::CERTIFICATEERROR_UNKNOWN},
            )
        } else {
            unsafe {
                openssl::X509_STORE_add_cert(store, cert.as_mut_ptr());
            };
            Ok(())
        }
    }

    fn ssl_context_set_certificate(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        mut cert: crate::Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()> {
        match unsafe { openssl::SSL_CTX_use_certificate(ssl_ctx.as_mut_ptr(), cert.as_mut_ptr()) } {
            1 => Ok(()),
            _ => Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into()),
        }
    }

    fn ssl_context_set_private_key(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        mut pkey: crate::Pimpl<'_, Self::NativePrivateKey>,
    ) -> crate::Result<()> {
        match unsafe { openssl::SSL_CTX_use_PrivateKey(ssl_ctx.as_mut_ptr(), pkey.as_mut_ptr()) } {
            1 => Ok(()),
            _ => Err(pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into()),
        }
    }

    fn certificate_from_pem<'pimpl>(
        cert: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeCertificate>> {
        if cert.as_ref().len() > (std::i32::MAX as usize) {
            return Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW.into());
        }
        let mut bio = unwrap_or!(
            buffer_to_bio(&cert),
            pb::CertificateError::CERTIFICATEERROR_UNKNOWN
        );
        let cert = unsafe {
            openssl::PEM_read_bio_X509(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut Self::NativeCertificate,
                None,
                std::ptr::null_mut(),
            )
        };
        if cert.is_null() {
            Err(match (unsafe { openssl::ERR_get_error() } as u32) >> 24 {
                openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
                }
                _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                cert,
                Some(|x| unsafe {
                    openssl::X509_free(x);
                }),
            ))
        }
    }

    fn certificate_from_der<'pimpl>(
        cert: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeCertificate>> {
        if cert.as_ref().len() > (std::i32::MAX as usize) {
            return Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW.into());
        }
        let mut bio = unwrap_or!(
            buffer_to_bio(&cert),
            pb::CertificateError::CERTIFICATEERROR_UNKNOWN
        );
        let cert = unsafe {
            openssl::d2i_X509_bio(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut Self::NativeCertificate,
            )
        };
        if cert.is_null() {
            Err(match (unsafe { openssl::ERR_get_error() } as u32) >> 24 {
                openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
                }
                _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                cert,
                Some(|x| unsafe {
                    openssl::X509_free(x);
                }),
            ))
        }
    }

    fn private_key_from_pem<'pimpl>(
        pkey: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativePrivateKey>> {
        if pkey.as_ref().len() > (std::i32::MAX as usize) {
            return Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW.into());
        }
        let mut bio = unwrap_or!(
            buffer_to_bio(&pkey),
            pb::PrivateKeyError::PRIVATEKEYERROR_UNKNOWN
        );
        let pkey = unsafe {
            openssl::PEM_read_bio_PrivateKey(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut Self::NativePrivateKey,
                None,
                std::ptr::null_mut(),
            )
        };
        if pkey.is_null() {
            Err(match (unsafe { openssl::ERR_get_error() } as u32) >> 24 {
                openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}
                }
                _ => pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                pkey,
                Some(|x| unsafe {
                    openssl::EVP_PKEY_free(x);
                }),
            ))
        }
    }

    fn private_key_from_der<'pimpl>(
        pkey: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativePrivateKey>> {
        if pkey.as_ref().len() > (std::i32::MAX as usize) {
            return Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW.into());
        }
        let mut bio = unwrap_or!(
            buffer_to_bio(&pkey),
            pb::PrivateKeyError::PRIVATEKEYERROR_UNKNOWN
        );
        let pkey = unsafe {
            openssl::d2i_PrivateKey_bio(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut openssl::evp_pkey_st,
            )
        };
        if pkey.is_null() {
            Err(match (unsafe { openssl::ERR_get_error() } as u32) >> 24 {
                openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}
                }
                _ => pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                pkey,
                Some(|x| unsafe {
                    openssl::EVP_PKEY_free(x);
                }),
            ))
        }
    }

    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &mut crate::Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<crate::Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl,
    {
        let ptr = unsafe { openssl::SSL_new(ssl_context.as_mut_ptr()) };
        if ptr.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY.into());
        }
        Ok(crate::Pimpl::from_raw(
            ptr,
            Some(|x| unsafe {
                openssl::SSL_free(x);
            }),
        ))
    }

    fn new_ssl_bio<'pimpl>() -> crate::Result<crate::Pimpl<'pimpl, Self::NativeBio>> {
        let bio = unsafe { openssl::BIO_new(&super::BIO_METH as *const openssl::bio_method_st) };
        if bio.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY.into());
        }
        Ok(crate::Pimpl::from_raw(
            bio,
            Some(|x| unsafe {
                openssl::BIO_free_all(x);
            }),
        ))
    }

    fn ssl_set_bio<'pimpl>(
        bio: *mut Self::NativeBio,
        ssl: *mut Self::NativeSsl,
        data: *mut std::ffi::c_void,
    ) -> crate::Result<()> {
        unsafe {
            openssl::BIO_set_data(bio, data);
            openssl::BIO_set_init(bio, 1);
            openssl::SSL_set_bio(ssl, bio, bio);
        }
        Ok(())
    }

    fn ssl_handshake(
        ssl: *mut Self::NativeSsl,
        mode: crate::Mode,
    ) -> (pb::tunnel::HandshakeState, Option<pb::State>) {
        let err = match mode {
            crate::Mode::Client => unsafe { openssl::SSL_connect(ssl) },
            crate::Mode::Server => unsafe { openssl::SSL_accept(ssl) },
        } as u32;
        if err == 1 {
            (
                pb::HandshakeState::HANDSHAKESTATE_DONE,
                Some(pb::State::STATE_HANDSHAKE_DONE),
            )
        } else {
            match unsafe { openssl::SSL_get_error(ssl, err as i32) } as u32 {
                openssl::SSL_ERROR_WANT_READ => (
                    pb::HandshakeState::HANDSHAKESTATE_WANT_READ,
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                openssl::SSL_ERROR_WANT_WRITE => (
                    pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE,
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                openssl::SSL_ERROR_ZERO_RETURN => (
                    pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS,
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                openssl::SSL_ERROR_WANT_ACCEPT | openssl::SSL_ERROR_WANT_CONNECT => (
                    pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS,
                    Some(pb::State::STATE_NOT_CONNECTED),
                ),
                _ => (
                    pb::HandshakeState::HANDSHAKESTATE_ERROR,
                    Some(pb::State::STATE_ERROR),
                ),
            }
        }
    }

    fn ssl_read(ssl: *mut Self::NativeSsl, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let err = unsafe {
            openssl::SSL_read(
                ssl,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as i32,
            )
        };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { openssl::SSL_get_error(ssl, err) };
        if (serr == (openssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(pb::RecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn ssl_write(ssl: *mut Self::NativeSsl, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let err = unsafe {
            openssl::SSL_write(
                ssl,
                buf.as_ptr() as *const std::ffi::c_void,
                buf.len() as i32,
            )
        };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { openssl::SSL_get_error(ssl, err) };
        if (serr == (openssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(pb::RecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn ssl_close(ssl: *mut Self::NativeSsl) -> crate::tunnel::RecordResult<()> {
        unsafe {
            openssl::SSL_shutdown(ssl);
        };
        Ok(())
    }

    fn ssl_get_shutdown_state(ssl: *const Self::NativeSsl) -> Option<pb::State> {
        let err = unsafe { openssl::SSL_get_shutdown(ssl) } as u32;
        if (err & openssl::SSL_SENT_SHUTDOWN) != 0 {
            // According to the OpenSSL documentation:
            // > SSL_SENT_SHUTDOWN:
            // > […] the connection is being considered closed and the session is
            //       closed and correct.
            //
            // It means that if the flag `SSL_SENT_SHUTDOWN` is set, then the record
            // plane can be considered as closed (and not in the process of being
            // closed)
            Some(pb::State::STATE_DISCONNECTED)
        } else {
            None
        }
    }

    fn ssl_get_handshake_state(ssl: *const Self::NativeSsl) -> pb::HandshakeState {
        let s = unsafe { openssl::SSL_get_state(ssl) };
        if s == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK {
            pb::HandshakeState::HANDSHAKESTATE_DONE
        } else {
            pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS
        }
    }
}

/// Instantiates a [`Context`] from a protobuf configuration message.
pub(crate) fn try_from<'ctx>(
    configuration: &pb_api::Configuration,
) -> crate::Result<Box<dyn crate::Context<'ctx> + 'ctx>> {
    crate::openssl::assert_compliance(configuration)?;
    Ok(Box::new(crate::ossl::OsslContext::<Ossl>::try_from(
        configuration,
    )?))
}

#[cfg(test)]
mod test {
    use super::Ossl;

    /// Certificate related tests.
    mod certificates {
        use super::Ossl;
        use crate::ossl::Ossl as OsslTrait;

        /// Tests [`Ossl::certificate_from_pem`] using a PEM certificate.
        #[test]
        fn test_certificate_from_pem_valid() {
            let cert = std::fs::read(crate::openssl::test::CERT_PEM_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_pem(cert);
            let cert = cert.unwrap();
            assert!(!cert.as_ptr().is_null());
        }

        /// Tests [`Ossl::certificate_from_pem`] using a PEM certificate that is too large.
        #[test]
        fn test_certificate_from_pem_too_large() {
            let cert = vec![0u8; (std::i32::MAX as usize) + 1];
            let cert = Ossl::certificate_from_pem(cert);
            let err = cert.unwrap_err();
            assert!(err.is(&errors! {pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW}));
        }

        /// Tests [`Ossl::certificate_from_pem`] using a DER certificate.
        #[test]
        fn test_certificate_from_pem_with_der() {
            let cert = std::fs::read(crate::openssl::test::CERT_DER_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_pem(cert);
            let err = cert.unwrap_err();
            assert!(err.is(&errors!{pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}));
        }

        /// Tests [`Ossl::certificate_from_der`] using a DER certificate.
        #[test]
        fn test_certificate_from_der_valid() {
            let cert = std::fs::read(crate::openssl::test::CERT_DER_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_der(cert);
            let cert = cert.unwrap();
            assert!(!cert.as_ptr().is_null());
        }

        /// Tests [`Ossl::certificate_from_der`] using a DER certificate that is too large.
        #[test]
        fn test_certificate_from_der_too_large() {
            let cert = vec![0u8; (std::i32::MAX as usize) + 1];
            let cert = Ossl::certificate_from_der(cert);
            let err = cert.unwrap_err();
            assert!(err.is(&errors! {pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW}));
        }

        /// Tests [`Ossl::certificate_from_der`] using a DER certificate that contains an invalid sig alg (invalid OID).
        #[test]
        fn test_certificate_from_der_with_invalid_der() {
            let cert = std::fs::read(crate::openssl::test::CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_der(cert);
            let err = cert.unwrap_err();
            assert!(err.is(&errors!{pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}));
        }
    }

    /// Private keys related tests.
    mod private_keys {
        use super::Ossl;
        use crate::ossl::Ossl as OsslTrait;

        /// Tests [`Ossl::private_key_from_pem`] using a PEM private key.
        #[test]
        fn test_private_key_from_pem_valid() {
            let skey = std::fs::read(crate::openssl::test::SK_PATH)
                .expect("failed to read the private key");
            let skey = Ossl::private_key_from_pem(skey);
            let skey = skey.unwrap();
            assert!(!skey.as_ptr().is_null());
        }

        /// Tests [`Ossl::private_key_from_pem`] using a PEM private key that is too large.
        #[test]
        fn test_private_key_from_pem_too_large() {
            let skey = vec![0u8; (std::i32::MAX as usize) + 1];
            let skey = Ossl::private_key_from_pem(skey);
            let err = skey.unwrap_err();
            assert!(err.is(&errors! {pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW}));
        }

        /// Tests [`Ossl::private_key_from_pem`] using a DER private key.
        #[test]
        fn test_private_key_from_pem_with_der() {
            let skey = std::fs::read(crate::openssl::test::SK_DER_PATH)
                .expect("failed to read the private key");
            let skey = Ossl::private_key_from_pem(skey);
            let err = skey.unwrap_err();
            assert!(err.is(&errors!{pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}));
        }

        /// Tests [`Ossl::private_key_from_der`] using a DER private key.
        #[test]
        fn test_private_key_from_der_valid() {
            let skey = std::fs::read(crate::openssl::test::SK_DER_PATH)
                .expect("failed to read the private key");
            let skey = Ossl::private_key_from_der(skey);
            let skey = skey.unwrap();
            assert!(!skey.as_ptr().is_null());
        }

        /// Tests [`Ossl::private_key_from_der`] using a DER private key that is too large.
        #[test]
        fn test_private_key_from_der_too_large() {
            let skey = vec![0u8; (std::i32::MAX as usize) + 1];
            let skey = Ossl::private_key_from_der(skey);
            let err = skey.unwrap_err();
            assert!(err.is(&errors! {pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW}));
        }
    }

    /// SSL context related tests.
    mod ssl_ctx {
        use super::Ossl;
        use crate::ossl::Ossl as OsslTrait;

        /// Tests instantiates a [`SSL_CTX`] for a client.
        #[test]
        fn test_ssl_ctx_client() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());
        }

        /// Tests instantiates a [`SSL_CTX`] for a server.
        #[test]
        fn test_ssl_ctx_server() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Server);
            let ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());
        }

        /// Tests [`Ossl::ssl_context_set_verify_mode`].
        #[test]
        fn test_ssl_ctx_set_verify_mode() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
            assert_eq!(mode, openssl::SSL_VERIFY_PEER as i32);

            Ossl::ssl_context_set_verify_mode(&mut ssl, 0);

            let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
            assert_eq!(mode, openssl::SSL_VERIFY_PEER as i32);

            Ossl::ssl_context_set_verify_mode(
                &mut ssl,
                <pb_api::TLSFlags as protobuf::Enum>::value(&pb_api::TLSFlags::TLSFLAGS_SKIP_VERIFY)
                    as u32,
            );

            let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
            assert_eq!(mode, openssl::SSL_VERIFY_NONE as i32);
        }

        /// Tests [`Ossl::ssl_context_set_kems`] with two valid KEMs.
        #[test]
        fn test_ssl_ctx_set_kems_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let kems = vec!["kyber512".into(), "X25519".into()];
            Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap();

            let ssl = Ossl::new_ssl_context(crate::Mode::Server);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap();
        }

        /// Tests [`Ossl::ssl_context_set_kems`] with one valid KEM and one invalid KEM.
        #[test]
        fn test_ssl_ctx_set_kems_invalid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let kems = vec!["kyber512".into(), "X1337".into()];
            let err = Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap_err();
            assert!(err.is(&errors! {pb::KEMError::KEMERROR_INVALID}));
        }

        /// Tests [`Ossl::ssl_context_set_kems`] with no KEMs.
        #[test]
        fn test_ssl_ctx_set_kems_no_kems() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let kems = std::vec::Vec::<std::string::String>::new();
            Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap();
        }

        /// Tests [`Ossl::ssl_context_set_certificate`] with a valid PEM certificate.
        #[test]
        fn test_ssl_ctx_set_certificate_pem_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Server);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let cert = std::fs::read(crate::openssl::test::CERT_PEM_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_pem(cert);
            let cert = cert.unwrap();
            assert!(!cert.as_ptr().is_null());

            Ossl::ssl_context_set_certificate(&mut ssl, cert).unwrap();
        }

        /// Tests [`Ossl::ssl_context_set_certificate`] with a valid DER certificate.
        #[test]
        fn test_ssl_ctx_set_certificate_der_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Server);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let cert = std::fs::read(crate::openssl::test::CERT_DER_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_der(cert);
            let cert = cert.unwrap();
            assert!(!cert.as_ptr().is_null());

            Ossl::ssl_context_set_certificate(&mut ssl, cert).unwrap();
        }

        /// Tests [`Ossl::ssl_context_set_private_key`] with a valid PEM private key.
        #[test]
        fn test_ssl_ctx_set_private_key_pem_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Server);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let skey = std::fs::read(crate::openssl::test::SK_PATH)
                .expect("failed to read the private key");
            let skey = Ossl::private_key_from_pem(skey);
            let skey = skey.unwrap();
            assert!(!skey.as_ptr().is_null());

            Ossl::ssl_context_set_private_key(&mut ssl, skey).unwrap();
        }

        /// Tests [`Ossl::ssl_context_set_private_key`] with a valid DER private key.
        #[test]
        fn test_ssl_ctx_set_private_key_der_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Server);
            let mut ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let skey = std::fs::read(crate::openssl::test::SK_DER_PATH)
                .expect("failed to read the private key");
            let skey = Ossl::private_key_from_der(skey);
            let skey = skey.unwrap();
            assert!(!skey.as_ptr().is_null());

            Ossl::ssl_context_set_private_key(&mut ssl, skey).unwrap();
        }

        /// Tests [`Ossl::ssl_context_append_certificate_to_trust_store`] with a valid PEM certificate.
        #[test]
        fn test_ssl_ctx_append_certificate_to_trust_store_pem_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let cert = std::fs::read(crate::openssl::test::CERT_PEM_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_pem(cert);
            let cert = cert.unwrap();
            assert!(!cert.as_ptr().is_null());

            Ossl::ssl_context_append_certificate_to_trust_store(&ssl, cert).unwrap();
        }

        /// Tests [`Ossl::ssl_context_append_certificate_to_trust_store`] with a valid DER certificate.
        #[test]
        fn test_ssl_ctx_append_certificate_to_trust_store_der_valid() {
            let ssl = Ossl::new_ssl_context(crate::Mode::Client);
            let ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let cert = std::fs::read(crate::openssl::test::CERT_DER_PATH)
                .expect("failed to read the certificate");
            let cert = Ossl::certificate_from_der(cert);
            let cert = cert.unwrap();
            assert!(!cert.as_ptr().is_null());

            Ossl::ssl_context_append_certificate_to_trust_store(&ssl, cert).unwrap();
        }
    }

    /// SSL handle related tests.
    mod ssl_handle {
        use super::Ossl;
        use crate::ossl::Ossl as OsslTrait;

        /// Tests creation of SSL handles.
        #[test]
        fn test_ssl_creation() {
            let ctx = Ossl::new_ssl_context(crate::Mode::Client);
            let mut ctx = ctx.unwrap();
            assert!(!ctx.as_ptr().is_null());

            let ssl = Ossl::new_ssl_handle(&mut ctx);
            let ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let ptr = unsafe { openssl::SSL_get_SSL_CTX(ssl.as_ptr()) };
            assert_eq!(ptr as *const _, ctx.as_ptr());

            let ctx = Ossl::new_ssl_context(crate::Mode::Server);
            let mut ctx = ctx.unwrap();
            assert!(!ctx.as_ptr().is_null());

            let ssl = Ossl::new_ssl_handle(&mut ctx);
            let ssl = ssl.unwrap();
            assert!(!ssl.as_ptr().is_null());

            let ptr = unsafe { openssl::SSL_get_SSL_CTX(ssl.as_ptr()) };
            assert_eq!(ptr as *const _, ctx.as_ptr());
        }
    }

    /// BIO related tests.
    mod ssl_bio {
        use super::Ossl;
        use crate::ossl::Ossl as OsslTrait;

        /// Tests creation of SSL BIO.
        #[test]
        fn test_bio_creation() {
            let bio = Ossl::new_ssl_bio();
            let bio = bio.unwrap();
            assert!(!bio.as_ptr().is_null());
        }
    }
}
