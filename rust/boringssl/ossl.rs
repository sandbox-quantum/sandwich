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

//! Defines [`Ossl`] structure that implements [`crate::ossl::Ossl`].

extern crate boringssl;

pub(crate) struct Ossl {}

/// Default supported signing algorithms.
/// This is needed for BoringSSL, because it doesn't support ED25519 by default.
/// See <https://github.com/grpc/grpc/issues/24252#issuecomment-1305773355>
const DEFAULT_SIGNATURE_ALGORITHMS: [u16; 17] = [
    boringssl::SSL_SIGN_RSA_PKCS1_SHA1 as u16,
    boringssl::SSL_SIGN_RSA_PKCS1_SHA256 as u16,
    boringssl::SSL_SIGN_RSA_PKCS1_SHA384 as u16,
    boringssl::SSL_SIGN_RSA_PKCS1_SHA512 as u16,
    boringssl::SSL_SIGN_ECDSA_SHA1 as u16,
    boringssl::SSL_SIGN_ECDSA_SECP256R1_SHA256 as u16,
    boringssl::SSL_SIGN_ECDSA_SECP384R1_SHA384 as u16,
    boringssl::SSL_SIGN_ECDSA_SECP521R1_SHA512 as u16,
    boringssl::SSL_SIGN_RSA_PSS_RSAE_SHA256 as u16,
    boringssl::SSL_SIGN_RSA_PSS_RSAE_SHA384 as u16,
    boringssl::SSL_SIGN_RSA_PSS_RSAE_SHA512 as u16,
    boringssl::SSL_SIGN_ED25519 as u16,
    boringssl::SSL_SIGN_DILITHIUM2 as u16,
    boringssl::SSL_SIGN_DILITHIUM3 as u16,
    boringssl::SSL_SIGN_DILITHIUM5 as u16,
    boringssl::SSL_SIGN_FALCON512 as u16,
    boringssl::SSL_SIGN_FALCON1024 as u16,
];

/// Convert a BoringSSL error to a [`crate::tunnel::RecordError`].
fn openssl_error_to_record_error(e: i32, errno: std::io::Error) -> crate::tunnel::RecordError {
    match e as u32 {
        boringssl::SSL_ERROR_WANT_READ => pb::RecordError::RECORDERROR_WANT_READ,
        boringssl::SSL_ERROR_WANT_WRITE => pb::RecordError::RECORDERROR_WANT_WRITE,
        boringssl::SSL_ERROR_ZERO_RETURN => pb::RecordError::RECORDERROR_CLOSED,
        boringssl::SSL_ERROR_SYSCALL => match errno.raw_os_error() {
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
) -> crate::Result<crate::Pimpl<'pimpl, boringssl::BIO>> {
    let obj = buf.as_ref();
    let ptr = if obj.len() <= (std::isize::MAX as usize) {
        unsafe {
            Ok::<*mut boringssl::bio_st, _>(boringssl::BIO_new_mem_buf(
                obj.as_ptr() as *const std::ffi::c_void,
                obj.len() as isize,
            ))
        }
    } else {
        Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)
    }?;
    if !ptr.is_null() {
        Ok(crate::Pimpl::from_raw(
            ptr,
            Some(|p| unsafe {
                boringssl::BIO_free_all(p);
            }),
        ))
    } else {
        Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
    }
}

/// Implements [`crate::ossl::Ossl`] for [`Ossl`].
impl crate::ossl::Ossl for Ossl {
    type NativeCertificate = boringssl::x509_st;
    type NativePrivateKey = boringssl::evp_pkey_st;
    type NativeSslCtx = boringssl::SSL_CTX;
    type NativeSsl = boringssl::SSL;
    type NativeX509StoreCtx = boringssl::X509_STORE_CTX;
    type NativeX509VerifyParams = boringssl::X509_VERIFY_PARAM;
    type NativeBio = boringssl::BIO;

    fn new_ssl_context<'pimpl>(
        mode: crate::Mode,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeSslCtx>> {
        let ctx = unsafe {
            boringssl::SSL_CTX_new(match mode {
                crate::Mode::Client => boringssl::TLS_client_method(),
                crate::Mode::Server => boringssl::TLS_server_method(),
            })
        };
        if ctx.is_null() {
            Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
        } else {
            unsafe {
                boringssl::SSL_CTX_set_options(
                    ctx,
                    boringssl::SSL_OP_NO_SSLv3
                        | boringssl::SSL_OP_NO_TLSv1
                        | boringssl::SSL_OP_NO_TLSv1_1
                        | boringssl::SSL_OP_NO_TLSv1_2
                        | boringssl::SSL_OP_NO_DTLSv1
                        | boringssl::SSL_OP_NO_DTLSv1_2,
                );
                boringssl::SSL_CTX_set_quiet_shutdown(ctx, 0);
                boringssl::SSL_CTX_set_session_cache_mode(
                    ctx,
                    boringssl::SSL_SESS_CACHE_OFF as i32,
                );
                boringssl::SSL_CTX_set1_groups(ctx, std::ptr::null_mut(), 0);
                boringssl::SSL_CTX_set_signing_algorithm_prefs(
                    ctx,
                    DEFAULT_SIGNATURE_ALGORITHMS.as_ptr(),
                    DEFAULT_SIGNATURE_ALGORITHMS.len(),
                );
                boringssl::SSL_CTX_set_verify_algorithm_prefs(
                    ctx,
                    DEFAULT_SIGNATURE_ALGORITHMS.as_ptr(),
                    DEFAULT_SIGNATURE_ALGORITHMS.len(),
                );
            }
            let mut pimpl = crate::Pimpl::<boringssl::SSL_CTX>::from_raw(
                ctx,
                Some(|x| unsafe {
                    boringssl::SSL_CTX_free(x);
                }),
            );
            if mode == crate::Mode::Client {
                unsafe {
                    boringssl::SSL_CTX_set_verify(
                        pimpl.as_mut_ptr(),
                        boringssl::SSL_VERIFY_PEER as i32,
                        Some(Self::verify_callback),
                    )
                };
                let ptr = unsafe { boringssl::X509_STORE_new() };
                if ptr.is_null() {
                    return Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
                }
                unsafe {
                    boringssl::SSL_CTX_set_cert_store(pimpl.as_mut_ptr(), ptr);
                    boringssl::X509_STORE_set_trust(ptr, 1);
                }
            }

            match unsafe { boringssl::SSL_CTX_set_min_proto_version(pimpl.as_mut_ptr(), boringssl::TLS1_3_VERSION as u16) } {
                1 => Ok(pimpl),
                _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION.into())
            }
        }
    }

    fn ssl_context_set_verify_mode(
        pimpl: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        mode: crate::ossl::VerifyMode,
    ) {
        let flag = match mode {
            crate::ossl::VerifyMode::None => boringssl::SSL_VERIFY_NONE,
            crate::ossl::VerifyMode::Peer => boringssl::SSL_VERIFY_PEER,
            crate::ossl::VerifyMode::Mutual => {
                boringssl::SSL_VERIFY_PEER | boringssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            }
        } as i32;
        unsafe {
            boringssl::SSL_CTX_set_verify(pimpl.as_mut_ptr(), flag, Some(Self::verify_callback));
        }
    }

    fn ssl_context_set_verify_depth(pimpl: &mut crate::Pimpl<'_, Self::NativeSslCtx>, depth: u32) {
        unsafe {
            boringssl::SSL_CTX_set_verify_depth(pimpl.as_mut_ptr(), depth as i32);
        }
    }

    fn ssl_context_set_kems(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        kems: std::slice::Iter<'_, std::string::String>,
    ) -> crate::Result<()> {
        let mut nids = std::vec::Vec::<i32>::new();
        for k in kems {
            let nid = match std::ffi::CString::new(k.as_bytes()) {
                Ok(cstr) => Ok(unsafe { boringssl::OBJ_txt2nid(cstr.as_c_str().as_ptr()) }),
                Err(_) => Err(
                    errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::KEMError::KEMERROR_INVALID},
                ),
            }?;
            if nid == (boringssl::NID_undef as i32) {
                return Err(pb::KEMError::KEMERROR_INVALID.into());
            }
            nids.push(nid);
            if nids.len() > (std::i32::MAX as usize) {
                return Err(pb::KEMError::KEMERROR_TOO_MANY.into());
            }
        }
        if !nids.is_empty() {
            match unsafe {
                boringssl::SSL_CTX_set1_groups(ssl_ctx.as_mut_ptr(), nids.as_ptr(), nids.len())
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
        let store = unsafe { boringssl::SSL_CTX_get_cert_store(ssl_ctx.as_ptr()) };
        if store.is_null() {
            Err(
                errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::CertificateError::CERTIFICATEERROR_UNKNOWN},
            )
        } else {
            unsafe {
                boringssl::X509_STORE_add_cert(store, cert.as_mut_ptr());
            };
            Ok(())
        }
    }

    fn ssl_context_set_certificate(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        mut cert: crate::Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()> {
        match unsafe { boringssl::SSL_CTX_use_certificate(ssl_ctx.as_mut_ptr(), cert.as_mut_ptr()) }
        {
            1 => Ok(()),
            _ => Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into()),
        }
    }

    fn ssl_context_set_private_key(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        mut pkey: crate::Pimpl<'_, Self::NativePrivateKey>,
    ) -> crate::Result<()> {
        match unsafe { boringssl::SSL_CTX_use_PrivateKey(ssl_ctx.as_mut_ptr(), pkey.as_mut_ptr()) }
        {
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
            boringssl::PEM_read_bio_X509(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut Self::NativeCertificate,
                None,
                std::ptr::null_mut(),
            )
        };
        if cert.is_null() {
            Err(match unsafe { boringssl::ERR_get_error() } >> 24 {
                boringssl::ERR_LIB_PEM | boringssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
                }
                _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                cert,
                Some(|x| unsafe {
                    boringssl::X509_free(x);
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
            boringssl::d2i_X509_bio(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut Self::NativeCertificate,
            )
        };
        if cert.is_null() {
            Err(match unsafe { boringssl::ERR_get_error() } >> 24 {
                boringssl::ERR_LIB_PEM | boringssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
                }
                _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                cert,
                Some(|x| unsafe {
                    boringssl::X509_free(x);
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
            boringssl::PEM_read_bio_PrivateKey(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut Self::NativePrivateKey,
                None,
                std::ptr::null_mut(),
            )
        };
        if pkey.is_null() {
            Err(match unsafe { boringssl::ERR_get_error() } >> 24 {
                boringssl::ERR_LIB_PEM | boringssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}
                }
                _ => pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                pkey,
                Some(|x| unsafe {
                    boringssl::EVP_PKEY_free(x);
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
            boringssl::d2i_PrivateKey_bio(
                bio.as_mut_ptr(),
                std::ptr::null_mut() as *mut *mut boringssl::evp_pkey_st,
            )
        };
        if pkey.is_null() {
            Err(match unsafe { boringssl::ERR_get_error() } >> 24 {
                boringssl::ERR_LIB_PEM | boringssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}
                }
                _ => pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into(),
            })
        } else {
            Ok(crate::Pimpl::from_raw(
                pkey,
                Some(|x| unsafe {
                    boringssl::EVP_PKEY_free(x);
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
        let ptr = unsafe { boringssl::SSL_new(ssl_context.as_mut_ptr()) };
        if ptr.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY.into());
        }
        Ok(crate::Pimpl::from_raw(
            ptr,
            Some(|x| unsafe {
                boringssl::SSL_free(x);
            }),
        ))
    }

    fn new_ssl_bio<'pimpl>() -> crate::Result<crate::Pimpl<'pimpl, Self::NativeBio>> {
        let bio =
            unsafe { boringssl::BIO_new(&super::BIO_METH as *const boringssl::bio_method_st) };
        if bio.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY.into());
        }
        Ok(crate::Pimpl::from_raw(
            bio,
            Some(|x| unsafe {
                boringssl::BIO_free_all(x);
            }),
        ))
    }

    fn ssl_set_bio<'pimpl>(
        bio: *mut Self::NativeBio,
        ssl: *mut Self::NativeSsl,
        data: *mut std::ffi::c_void,
    ) -> crate::Result<()> {
        unsafe {
            boringssl::BIO_set_data(bio, data);
            boringssl::BIO_set_init(bio, 1);
            boringssl::SSL_set_bio(ssl, bio, bio);
        }
        Ok(())
    }

    fn ssl_set_extra_data_for_verify<T>(
        ssl: *mut Self::NativeSsl,
        extra_data: *mut T,
    ) -> Result<(), pb::SystemError> {
        if unsafe {
            boringssl::SSL_set_ex_data(ssl, crate::ossl::VERIFY_TUNNEL_INDEX, extra_data.cast())
        } as u64
            == 0
        {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY);
        }
        Ok(())
    }

    fn ssl_handshake(
        ssl: *mut Self::NativeSsl,
        mode: crate::Mode,
        tun: &crate::ossl::OsslTunnel<Ossl>,
    ) -> (crate::Result<pb::tunnel::HandshakeState>, Option<pb::State>) {
        let err = match mode {
            crate::Mode::Client => unsafe { boringssl::SSL_connect(ssl) },
            crate::Mode::Server => unsafe { boringssl::SSL_accept(ssl) },
        } as u32;
        if err == 1 {
            (
                Ok(pb::HandshakeState::HANDSHAKESTATE_DONE),
                Some(pb::State::STATE_HANDSHAKE_DONE),
            )
        } else {
            match unsafe { boringssl::SSL_get_error(ssl, err as i32) } as u32 {
                boringssl::SSL_ERROR_WANT_READ => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_WANT_READ),
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                boringssl::SSL_ERROR_WANT_WRITE => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE),
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                boringssl::SSL_ERROR_ZERO_RETURN => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS),
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                boringssl::SSL_ERROR_WANT_ACCEPT | boringssl::SSL_ERROR_WANT_CONNECT => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS),
                    Some(pb::State::STATE_NOT_CONNECTED),
                ),
                _ => {
                    let err = unsafe { boringssl::ERR_get_error() };
                    let errlib = (err >> 24) & 0xFF;
                    let e_r = unsafe { boringssl::ERR_error_string(err, std::ptr::null_mut()) };
                    let err_cstring = unsafe { std::ffi::CStr::from_ptr(e_r) };
                    let mut err_string: String = "BoringSSL error: ".into();
                    if let Ok(s) = err_cstring.to_str() {
                        err_string.push_str(s);
                    } else {
                        return (
                            Err(pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR.into()),
                            Some(pb::State::STATE_ERROR),
                        );
                    }
                    if errlib != boringssl::ERR_LIB_SSL {
                        let x_e_s = unsafe {
                            boringssl::X509_verify_cert_error_string(tun.verify_error as i64)
                        } as *mut i8;
                        let x509_error_cstr = unsafe { std::ffi::CStr::from_ptr(x_e_s) };
                        let mut x509_error_str = err_string + "; ";
                        if let Ok(s) = x509_error_cstr.to_str() {
                            x509_error_str.push_str(s);
                        } else {
                            return (
                                Err(crate::Error::from((
                                    pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                    x509_error_str,
                                ))),
                                Some(pb::State::STATE_ERROR),
                            );
                        }
                        return match tun.verify_error as u32 {
                            boringssl::X509_V_OK => {
                                let mut buf = [0u8; 1000];
                                unsafe { boringssl::ERR_error_string_n(err, buf.as_mut_ptr() as *mut i8, buf.len()) };
                                let err_string = std::ffi::CStr::from_bytes_with_nul(&buf).unwrap().to_str().unwrap();
                                (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR, err_string))),
                                    Some(pb::State::STATE_ERROR),
                                )
                            },
                            boringssl::X509_V_ERR_CERT_HAS_EXPIRED => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            boringssl::X509_V_ERR_CERT_REVOKED => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_REVOKED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            boringssl::X509_V_ERR_CERT_SIGNATURE_FAILURE => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            boringssl::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
                            | boringssl::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
                            | boringssl::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
                            | boringssl::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
                            | boringssl::X509_V_ERR_CERT_CHAIN_TOO_LONG
                            | boringssl::X509_V_ERR_INVALID_PURPOSE
                            | boringssl::X509_V_ERR_CERT_UNTRUSTED
                            | boringssl::X509_V_ERR_CERT_REJECTED => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_INVALID_CERTIFICATE, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            _ => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                                )
                        };
                    }
                    match err & 0xFFF {
                        boringssl::SSL_R_CERTIFICATE_VERIFY_FAILED => {
                            let x_e_s = unsafe {
                                boringssl::X509_verify_cert_error_string(tun.verify_error as i64)
                            } as *mut i8;
                            let x509_error_cstr = unsafe { std::ffi::CStr::from_ptr(x_e_s) };
                            let mut x509_error_str = err_string + "; ";
                            if let Ok(s) = x509_error_cstr.to_str() {
                                x509_error_str.push_str(s);
                            } else {
                                return (
                                    Err(crate::Error::from((
                                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                        x509_error_str,
                                    ))),
                                    Some(pb::State::STATE_ERROR),
                                );
                            }
                            match tun.verify_error as u32 {
                                boringssl::X509_V_ERR_CERT_HAS_EXPIRED => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                boringssl::X509_V_ERR_CERT_REVOKED => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_REVOKED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                boringssl::X509_V_ERR_CERT_SIGNATURE_FAILURE => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                boringssl::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
                                | boringssl::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
                                | boringssl::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
                                | boringssl::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
                                | boringssl::X509_V_ERR_CERT_CHAIN_TOO_LONG
                                | boringssl::X509_V_ERR_INVALID_PURPOSE
                                | boringssl::X509_V_ERR_CERT_UNTRUSTED
                                | boringssl::X509_V_ERR_CERT_REJECTED => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_INVALID_CERTIFICATE, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                _ => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                    ),

                            }
                        }
                        _ => (
                            Err(pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR.into()),
                            Some(pb::State::STATE_ERROR),
                        ),
                    }
                }
            }
        }
    }

    fn ssl_read(ssl: *mut Self::NativeSsl, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let err = unsafe {
            boringssl::SSL_read(
                ssl,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as i32,
            )
        };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { boringssl::SSL_get_error(ssl, err) };
        if (serr == (boringssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(pb::RecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn ssl_write(ssl: *mut Self::NativeSsl, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let err = unsafe {
            boringssl::SSL_write(
                ssl,
                buf.as_ptr() as *const std::ffi::c_void,
                buf.len() as i32,
            )
        };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { boringssl::SSL_get_error(ssl, err) };
        if (serr == (boringssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(pb::RecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn ssl_close(ssl: *mut Self::NativeSsl) -> crate::tunnel::RecordResult<()> {
        unsafe {
            boringssl::SSL_shutdown(ssl);
        };
        Ok(())
    }

    fn ssl_get_shutdown_state(ssl: *const Self::NativeSsl) -> Option<pb::State> {
        let err = unsafe { boringssl::SSL_get_shutdown(ssl) } as u32;
        if (err & boringssl::SSL_SENT_SHUTDOWN) != 0 {
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
        let s = unsafe { boringssl::SSL_state(ssl) } as u32;
        if s == boringssl::SSL_ST_OK {
            pb::HandshakeState::HANDSHAKESTATE_DONE
        } else {
            pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS
        }
    }

    fn x509_store_context_get_ssl(
        store_ctx: *mut Self::NativeX509StoreCtx,
    ) -> Option<*const Self::NativeSsl> {
        let ssl_idx = unsafe { boringssl::SSL_get_ex_data_X509_STORE_CTX_idx() };
        if ssl_idx < 0 {
            return None;
        }
        let ssl = unsafe { boringssl::X509_STORE_CTX_get_ex_data(store_ctx, ssl_idx) }
            as *const Self::NativeSsl;
        if ssl.is_null() {
            None
        } else {
            Some(ssl)
        }
    }

    fn x509_store_context_get_error(store_ctx: *mut Self::NativeX509StoreCtx) -> i32 {
        unsafe { boringssl::X509_STORE_CTX_get_error(store_ctx) }
    }

    fn x509_store_context_set_error(store_ctx: *mut Self::NativeX509StoreCtx, error: i32) {
        unsafe {
            boringssl::X509_STORE_CTX_set_error(store_ctx, error);
        }
    }

    fn x509_store_error_code_valid() -> i32 {
        boringssl::X509_V_OK as i32
    }

    fn x509_error_code_is_certificate_expired(error: i32) -> bool {
        error == boringssl::X509_V_ERR_CERT_HAS_EXPIRED as i32
    }

    fn ssl_get_tunnel<'a>(
        ssl: *const Self::NativeSsl,
    ) -> Option<&'a mut crate::ossl::OsslTunnel<'a, 'a, Self>> {
        unsafe {
            boringssl::SSL_get_ex_data(ssl, crate::ossl::VERIFY_TUNNEL_INDEX)
                .cast::<crate::ossl::OsslTunnel<Self>>()
                .as_mut::<'a>()
        }
    }

    fn ssl_get_x509_verify_parameters(
        ssl: *mut Self::NativeSsl,
    ) -> Option<*mut Self::NativeX509VerifyParams> {
        let params = unsafe { boringssl::SSL_get0_param(ssl) };
        if !params.is_null() {
            Some(params)
        } else {
            None
        }
    }

    fn x509_verify_parameters_add_san_dns(
        verify_params: *mut Self::NativeX509VerifyParams,
        dns: &str,
    ) -> crate::Result<()> {
        let cstring = std::ffi::CString::new(dns.as_bytes()).map_err(|e| {
            (
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("dns '{dns}' is invalid: {e}"),
            )
        })?;
        let cstr = cstring.as_c_str();
        let err = unsafe {
            boringssl::X509_VERIFY_PARAM_add1_host(verify_params, cstr.as_ptr(), dns.len())
        };
        if err == 1 {
            Ok(())
        } else {
            Err((
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("cannot add SAN entry of type dns '{dns}'"),
            )
                .into())
        }
    }

    fn x509_verify_parameters_set_san_email(
        verify_params: *mut Self::NativeX509VerifyParams,
        email: &str,
    ) -> crate::Result<()> {
        let cstring = std::ffi::CString::new(email.as_bytes()).map_err(|e| {
            (
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("email '{email}' is invalid: {e}"),
            )
        })?;
        let cstr = cstring.as_c_str();
        let err = unsafe {
            boringssl::X509_VERIFY_PARAM_set1_email(verify_params, cstr.as_ptr(), email.len())
        };
        if err == 1 {
            Ok(())
        } else {
            Err((
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("cannot set SAN of type email '{email}'"),
            )
                .into())
        }
    }

    fn x509_verify_parameters_set_san_ip_address(
        verify_params: *mut Self::NativeX509VerifyParams,
        ip_addr: &str,
    ) -> crate::Result<()> {
        let cstring = std::ffi::CString::new(ip_addr.as_bytes()).map_err(|e| {
            (
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("ip address '{ip_addr}' is invalid: {e}"),
            )
        })?;
        let cstr = cstring.as_c_str();
        let err = unsafe { boringssl::X509_VERIFY_PARAM_set1_ip_asc(verify_params, cstr.as_ptr()) };
        if err == 1 {
            Ok(())
        } else {
            Err((
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("cannot set SAN of type ip address '{ip_addr}'"),
            )
                .into())
        }
    }
}

/// Instantiates a [`crate::Context`] from a protobuf configuration message.
pub(crate) fn try_from<'ctx>(
    configuration: &pb_api::Configuration,
) -> crate::Result<Box<dyn crate::Context<'ctx> + 'ctx>> {
    crate::tls::assert_compliance(configuration)?;
    Ok(Box::new(crate::ossl::OsslContext::<Ossl>::try_from(
        configuration,
    )?))
}

GenOsslUnitTests!(
    use crate::boringssl::ossl::Ossl;
);

#[cfg(test)]
mod additional_tests {
    use super::Ossl;
    use crate::ossl::Ossl as OsslTrait;

    /// Tests [`Ossl::ssl_context_set_verify_mode`].
    #[test]
    fn test_ssl_ctx_set_verify_mode() {
        let ssl = Ossl::new_ssl_context(crate::Mode::Client);
        let mut ssl = ssl.unwrap();
        assert!(!ssl.as_ptr().is_null());

        let mode = unsafe { boringssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
        assert_eq!(mode, boringssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(&mut ssl, crate::ossl::VerifyMode::Peer);

        let mode = unsafe { boringssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
        assert_eq!(mode, boringssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(&mut ssl, crate::ossl::VerifyMode::None);

        let mode = unsafe { boringssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
        assert_eq!(mode, boringssl::SSL_VERIFY_NONE as i32);
    }
}
