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

//! Sandwich OpenSSL implementation module.
//! Defines [`Ossl`] structure that implements [`crate::implementation::ossl::Ossl`].

extern crate openssl1_1_1;

mod io;

use crate::support;
use crate::tunnel::tls;

use openssl1_1_1 as openssl;

use super::super::ossl;

struct Ossl {}

/// Converts an OpenSSL error to a [`crate::tunnel::RecordError`].
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
) -> crate::Result<support::Pimpl<'pimpl, openssl::BIO>> {
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
        Ok(support::Pimpl::from_raw(
            ptr,
            Some(|p| unsafe {
                openssl::BIO_free_all(p);
            }),
        ))
    } else {
        Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
    }
}

/// Implements [`super::Ossl`] for [`Ossl`].
impl super::Ossl for Ossl {
    type NativeCertificate = openssl::x509_st;
    type NativePrivateKey = openssl::evp_pkey_st;
    type NativeSslCtx = openssl::SSL_CTX;
    type NativeSsl = openssl::SSL;
    type NativeX509StoreCtx = openssl::X509_STORE_CTX;
    type NativeX509VerifyParams = openssl::X509_VERIFY_PARAM;
    type NativeBio = openssl::BIO;

    fn new_ssl_context<'pimpl>(
        mode: crate::Mode,
    ) -> crate::Result<support::Pimpl<'pimpl, Self::NativeSslCtx>> {
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
            let mut pimpl = support::Pimpl::<openssl::SSL_CTX>::from_raw(
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
                        Some(Self::verify_callback),
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
            match unsafe {
                openssl::SSL_CTX_ctrl(
                    pimpl.as_mut_ptr(),
                    openssl::SSL_CTRL_SET_MIN_PROTO_VERSION as i32,
                    openssl::TLS1_3_VERSION.into(),
                    std::ptr::null_mut(),
                )
            } {
                1 => Ok(pimpl),
                _ => Err(
                    pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION
                        .into(),
                ),
            }
        }
    }

    fn ssl_context_set_verify_mode(
        pimpl: &mut support::Pimpl<'_, Self::NativeSslCtx>,
        mode: ossl::VerifyMode,
    ) {
        let flag = match mode {
            ossl::VerifyMode::None => openssl::SSL_VERIFY_NONE,
            ossl::VerifyMode::Peer => openssl::SSL_VERIFY_PEER,
            ossl::VerifyMode::Mutual => {
                openssl::SSL_VERIFY_PEER | openssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            }
        } as i32;
        unsafe {
            openssl::SSL_CTX_set_verify(pimpl.as_mut_ptr(), flag, Some(Self::verify_callback));
        }
    }

    fn ssl_context_set_verify_depth(
        pimpl: &mut support::Pimpl<'_, Self::NativeSslCtx>,
        depth: u32,
    ) {
        unsafe {
            openssl::SSL_CTX_set_verify_depth(pimpl.as_mut_ptr(), depth as i32);
        }
    }

    fn ssl_context_set_kems(
        ssl_ctx: &mut support::Pimpl<'_, Self::NativeSslCtx>,
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
        ssl_ctx: &support::Pimpl<'_, Self::NativeSslCtx>,
        mut cert: support::Pimpl<'_, Self::NativeCertificate>,
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
        ssl_ctx: &mut support::Pimpl<'_, Self::NativeSslCtx>,
        mut cert: support::Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()> {
        match unsafe { openssl::SSL_CTX_use_certificate(ssl_ctx.as_mut_ptr(), cert.as_mut_ptr()) } {
            1 => Ok(()),
            _ => Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into()),
        }
    }

    fn ssl_context_set_private_key(
        ssl_ctx: &mut support::Pimpl<'_, Self::NativeSslCtx>,
        mut pkey: support::Pimpl<'_, Self::NativePrivateKey>,
    ) -> crate::Result<()> {
        match unsafe { openssl::SSL_CTX_use_PrivateKey(ssl_ctx.as_mut_ptr(), pkey.as_mut_ptr()) } {
            1 => Ok(()),
            _ => Err(pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into()),
        }
    }

    fn ssl_context_check_private_key(
        ssl_ctx: &support::Pimpl<'_, Self::NativeSslCtx>,
    ) -> crate::Result<()> {
        if unsafe { openssl::SSL_CTX_check_private_key(ssl_ctx.as_ptr()) } != 1 {
            Err(pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE.into())
        } else {
            Ok(())
        }
    }

    fn certificate_from_pem<'pimpl>(
        cert: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<support::Pimpl<'pimpl, Self::NativeCertificate>> {
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
            Ok(support::Pimpl::from_raw(
                cert,
                Some(|x| unsafe {
                    openssl::X509_free(x);
                }),
            ))
        }
    }

    fn certificate_from_der<'pimpl>(
        cert: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<support::Pimpl<'pimpl, Self::NativeCertificate>> {
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
            Ok(support::Pimpl::from_raw(
                cert,
                Some(|x| unsafe {
                    openssl::X509_free(x);
                }),
            ))
        }
    }

    fn private_key_from_pem<'pimpl>(
        pkey: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<support::Pimpl<'pimpl, Self::NativePrivateKey>> {
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
            Ok(support::Pimpl::from_raw(
                pkey,
                Some(|x| unsafe {
                    openssl::EVP_PKEY_free(x);
                }),
            ))
        }
    }

    fn private_key_from_der<'pimpl>(
        pkey: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<support::Pimpl<'pimpl, Self::NativePrivateKey>> {
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
            Ok(support::Pimpl::from_raw(
                pkey,
                Some(|x| unsafe {
                    openssl::EVP_PKEY_free(x);
                }),
            ))
        }
    }

    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &mut support::Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<support::Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl,
    {
        let ptr = unsafe { openssl::SSL_new(ssl_context.as_mut_ptr()) };
        if ptr.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY.into());
        }
        Ok(support::Pimpl::from_raw(
            ptr,
            Some(|x| unsafe {
                openssl::SSL_free(x);
            }),
        ))
    }

    fn new_ssl_bio<'pimpl>() -> crate::Result<support::Pimpl<'pimpl, Self::NativeBio>> {
        let bio = unsafe { openssl::BIO_new(&io::BIO_METH as *const openssl::bio_method_st) };
        if bio.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY.into());
        }
        Ok(support::Pimpl::from_raw(
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

    fn ssl_set_extra_data_for_verify<T>(
        ssl: *mut Self::NativeSsl,
        extra_data: *mut T,
    ) -> Result<(), pb::SystemError> {
        if unsafe { openssl::SSL_set_ex_data(ssl, ossl::VERIFY_TUNNEL_INDEX, extra_data.cast()) }
            as u64
            == 0
        {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY);
        }
        Ok(())
    }

    fn ssl_handshake(
        ssl: *mut Self::NativeSsl,
        mode: crate::Mode,
        tun: &super::OsslTunnel<Ossl>,
    ) -> (crate::Result<pb::tunnel::HandshakeState>, Option<pb::State>) {
        let err = match mode {
            crate::Mode::Client => unsafe { openssl::SSL_connect(ssl) },
            crate::Mode::Server => unsafe { openssl::SSL_accept(ssl) },
        } as u32;
        if err == 1 {
            (
                Ok(pb::HandshakeState::HANDSHAKESTATE_DONE),
                Some(pb::State::STATE_HANDSHAKE_DONE),
            )
        } else {
            let e = unsafe { openssl::SSL_get_error(ssl, err as i32) } as u32;
            match e {
                openssl::SSL_ERROR_WANT_READ => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_WANT_READ),
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                openssl::SSL_ERROR_WANT_WRITE => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE),
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                openssl::SSL_ERROR_ZERO_RETURN => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS),
                    Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
                ),
                openssl::SSL_ERROR_WANT_ACCEPT | openssl::SSL_ERROR_WANT_CONNECT => (
                    Ok(pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS),
                    Some(pb::State::STATE_NOT_CONNECTED),
                ),
                openssl::SSL_ERROR_WANT_X509_LOOKUP => (
                        Err(crate::Error::from((
                                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                        "OpenSSL error: application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.".to_string()
                                    ))
                        ),
                        Some(pb::State::STATE_ERROR),
                ),
                openssl::SSL_ERROR_WANT_ASYNC => (
                        Err(crate::Error::from((
                                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                        "OpenSSL error: asynchronous engine is still processing data.".to_string()
                                    ))
                        ),
                        Some(pb::State::STATE_ERROR),
                ),
                openssl::SSL_ERROR_WANT_ASYNC_JOB => (
                        Err(crate::Error::from((
                                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                        "OpenSSL error: no async jobs are available in the pool.".to_string()
                                    ))
                        ),
                        Some(pb::State::STATE_ERROR),
                ),
                openssl::SSL_ERROR_WANT_CLIENT_HELLO_CB => (
                        Err(crate::Error::from((
                                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                        "OpenSSL error: application callback set by SSL_CTX_set_client_hello_cb() has asked to be called again.".to_string()
                                    ))
                        ),
                        Some(pb::State::STATE_ERROR),
                ),
                openssl::SSL_ERROR_SYSCALL | openssl::SSL_ERROR_SSL => {
                    let err = unsafe { openssl::ERR_get_error() } as u32;
                    if err == 0 && tun.verify_error == 0 {
                        return (
                            Err(crate::Error::from((
                                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                        match e {
                                          openssl::SSL_ERROR_SYSCALL => "OpenSSL error: Returned SSL_ERROR_SYSCALL with no additional info.",
                                          openssl::SSL_ERROR_SSL => "OpenSSL error: Returned SSL_ERROR_SSL with no additional info.",
                                          _ => "OpenSSL error: Reached an unreachable point.",
                                        }.to_string()
                                ))
                            ),
                            Some(pb::State::STATE_ERROR),
                        );
                    }
                    let errlib = (err >> 24) & 0xFF;
                    let e_r =
                        unsafe { openssl::ERR_error_string(err as u64, std::ptr::null_mut()) };
                    let err_cstring = unsafe { std::ffi::CStr::from_ptr(e_r) };
                    let mut err_string: String = "OpenSSL error: ".into();
                    if let Ok(s) = err_cstring.to_str() {
                        err_string.push_str(s);
                    } else {
                        return (
                            Err(pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR.into()),
                            Some(pb::State::STATE_ERROR),
                        );
                    }
                    if errlib != openssl::ERR_LIB_SSL {
                        let x_e_s = unsafe {
                            openssl::X509_verify_cert_error_string(tun.verify_error as i64)
                        } as *mut std::os::raw::c_char;
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
                            openssl::X509_V_OK => {
                                (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                )
                            }
                            openssl::X509_V_ERR_CERT_HAS_EXPIRED => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            openssl::X509_V_ERR_CERT_REVOKED => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_REVOKED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            openssl::X509_V_ERR_CERT_SIGNATURE_FAILURE => (
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED, x509_error_str))),
                                Some(pb::State::STATE_ERROR),
                            ),
                            openssl::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
                            | openssl::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
                            | openssl::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
                            | openssl::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
                            | openssl::X509_V_ERR_CERT_CHAIN_TOO_LONG
                            | openssl::X509_V_ERR_INVALID_PURPOSE
                            | openssl::X509_V_ERR_CERT_UNTRUSTED
                            | openssl::X509_V_ERR_CERT_REJECTED => (
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
                        openssl::SSL_R_CERTIFICATE_VERIFY_FAILED => {
                            let x_e_s = unsafe {
                                openssl::X509_verify_cert_error_string(tun.verify_error as i64)
                            } as *mut std::os::raw::c_char;
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
                                openssl::X509_V_ERR_CERT_HAS_EXPIRED => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                openssl::X509_V_ERR_CERT_REVOKED => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_REVOKED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                openssl::X509_V_ERR_CERT_SIGNATURE_FAILURE => (
                                    Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED, x509_error_str))),
                                    Some(pb::State::STATE_ERROR),
                                ),
                                openssl::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
                                | openssl::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
                                | openssl::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
                                | openssl::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
                                | openssl::X509_V_ERR_CERT_CHAIN_TOO_LONG
                                | openssl::X509_V_ERR_INVALID_PURPOSE
                                | openssl::X509_V_ERR_CERT_UNTRUSTED
                                | openssl::X509_V_ERR_CERT_REJECTED => (
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
                _ => (
                    Err(pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR.into()),
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

    fn x509_store_context_get_ssl(
        store_ctx: *mut Self::NativeX509StoreCtx,
    ) -> Option<*const Self::NativeSsl> {
        let ssl_idx = unsafe { openssl::SSL_get_ex_data_X509_STORE_CTX_idx() };
        if ssl_idx < 0 {
            return None;
        }
        let ssl = unsafe { openssl::X509_STORE_CTX_get_ex_data(store_ctx, ssl_idx) }
            as *const Self::NativeSsl;
        if ssl.is_null() {
            None
        } else {
            Some(ssl)
        }
    }

    fn x509_store_context_get_error(store_ctx: *mut Self::NativeX509StoreCtx) -> i32 {
        unsafe { openssl::X509_STORE_CTX_get_error(store_ctx) }
    }

    fn x509_store_context_set_error(store_ctx: *mut Self::NativeX509StoreCtx, error: i32) {
        unsafe {
            openssl::X509_STORE_CTX_set_error(store_ctx, error);
        }
    }

    fn x509_store_error_code_valid() -> i32 {
        openssl::X509_V_OK as i32
    }

    fn x509_error_code_is_certificate_expired(error: i32) -> bool {
        error == openssl::X509_V_ERR_CERT_HAS_EXPIRED as i32
    }

    fn ssl_get_tunnel<'a>(
        ssl: *const Self::NativeSsl,
    ) -> Option<&'a mut super::OsslTunnel<'a, 'a, Self>> {
        unsafe {
            openssl::SSL_get_ex_data(ssl, ossl::VERIFY_TUNNEL_INDEX)
                .cast::<super::OsslTunnel<Self>>()
                .as_mut::<'a>()
        }
    }

    fn ssl_get_x509_verify_parameters(
        ssl: *mut Self::NativeSsl,
    ) -> Option<*mut Self::NativeX509VerifyParams> {
        let params = unsafe { openssl::SSL_get0_param(ssl) };
        if !params.is_null() {
            unsafe {
                openssl::X509_VERIFY_PARAM_set_hostflags(
                    params,
                    openssl::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
                );
            }
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
            openssl::X509_VERIFY_PARAM_add1_host(verify_params, cstr.as_ptr(), dns.len())
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
            openssl::X509_VERIFY_PARAM_set1_email(verify_params, cstr.as_ptr(), email.len())
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
        let err = unsafe { openssl::X509_VERIFY_PARAM_set1_ip_asc(verify_params, cstr.as_ptr()) };
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
    tls::assert_compliance(configuration)?;
    Ok(Box::new(super::OsslContext::<Ossl>::try_from(
        configuration,
    )?))
}

GenOsslUnitTests!(
    use crate::implementation::ossl::openssl1_1_1::Ossl;
);

#[cfg(test)]
mod additional_tests {
    use super::super::Ossl as OsslTrait;
    use super::Ossl;
    use openssl1_1_1 as openssl;

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

    /// Tests [`Ossl::ssl_context_set_verify_mode`].
    #[test]
    fn test_ssl_ctx_set_verify_mode() {
        let ssl = Ossl::new_ssl_context(crate::Mode::Client);
        let mut ssl = ssl.unwrap();
        assert!(!ssl.as_ptr().is_null());

        let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
        assert_eq!(mode, openssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(&mut ssl, super::ossl::VerifyMode::Peer);

        let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
        assert_eq!(mode, openssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(&mut ssl, super::ossl::VerifyMode::None);

        let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_ptr()) };
        assert_eq!(mode, openssl::SSL_VERIFY_NONE as i32);
    }
}

#[cfg(test)]
pub(crate) mod additional_test {
    use super::tls;

    /// A simple I/O interface.
    struct IOBuffer {
        pub(self) read: std::vec::Vec<u8>,
        pub(self) write: std::vec::Vec<u8>,
    }

    /// Implements [`crate::IO`] for [`IOBuffer`].
    impl crate::IO for IOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> crate::io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.read.len());
            if n == 0 {
                Err(pb::IOError::IOERROR_WOULD_BLOCK.into())
            } else {
                buf.copy_from_slice(&self.read[0..n]);
                self.read.drain(0..n);
                Ok(n)
            }
        }

        fn write(&mut self, buf: &[u8], _state: pb::State) -> crate::io::Result<usize> {
            self.write.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn close(&mut self) -> crate::io::Result<()> {
            self.read.clear();
            self.write.clear();
            Ok(())
        }
    }

    /// Implements [`IOBuffer`].
    impl IOBuffer {
        /// Constructs a new [`IOBuffer`].
        fn new() -> Self {
            Self {
                read: std::vec::Vec::new(),
                write: std::vec::Vec::new(),
            }
        }
    }

    /// A double I/O interface.
    struct LinkedIOBuffer {
        pub(self) buf: std::vec::Vec<u8>,
        pub(self) recv: std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        pub(self) send: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
    }

    /// Implements [`crate::IO`] for [`LinkedIOBuffer`].
    impl crate::IO for LinkedIOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> crate::io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.buf.len());
            if n > 0 {
                buf[0..n].copy_from_slice(&self.buf[0..n]);
                self.buf.drain(0..n);
            }
            if n == buf.len() {
                return Ok(n);
            }

            let r = buf.len() - n;
            match self.recv.try_recv() {
                Ok(mut v) => {
                    self.buf.append(&mut v);
                    Ok(())
                }
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => Err(pb::IOError::IOERROR_WOULD_BLOCK),
                    _ => Err(pb::IOError::IOERROR_CLOSED),
                },
            }?;

            let result = n;
            let n = std::cmp::min(r, self.buf.len());
            buf[result..result + n].copy_from_slice(&self.buf[0..n]);
            self.buf.drain(0..n);
            Ok(result + n)
        }

        fn write(&mut self, buf: &[u8], _state: pb::State) -> crate::io::Result<usize> {
            self.send
                .send(std::vec::Vec::from(buf))
                .map(|_| buf.len())
                .map_err(|_| pb::IOError::IOERROR_CLOSED.into())
        }

        fn close(&mut self) -> crate::io::Result<()> {
            self.buf.clear();
            Ok(())
        }
    }

    /// Implements [`LinkedIOBuffer`].
    impl LinkedIOBuffer {
        /// Constructs a new [`LinkedIOBuffer`].
        fn new(
            send: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
            recv: std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        ) -> Self {
            Self {
                buf: std::vec::Vec::new(),
                recv,
                send,
            }
        }
    }

    /// Test tunnel constructor for client.
    #[test]
    fn test_client() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();
        let tun = ctx.new_tunnel(Box::new(io), verifier);
        assert!(tun.is_ok());
        let mut tun = tun.unwrap();
        let rec = tun.handshake().unwrap();
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_READ);
        assert_eq!(tun.state(), pb::State::STATE_HANDSHAKE_IN_PROGRESS);
        let _ = tun.close();
    }

    /// Test tunnel constructor for server.
    #[test]
    fn test_server() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
                crate::test::resolve_runfile(tls::test::SK_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();
        let tun = ctx.new_tunnel(Box::new(io), verifier);
        assert!(tun.is_ok());
        let mut tun = tun.unwrap();
        let rec = tun.handshake().unwrap();
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_READ);
        let _ = tun.close();
    }

    /// Test tunnel between client and server.
    #[test]
    fn test_all() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
                crate::test::resolve_runfile(tls::test::SK_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), verifier.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Test tunnel between client and server with an expired certificate.
    #[test]
    fn test_expired() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
                crate::test::resolve_runfile(tls::test::CERT_EXPIRED_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), verifier.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );

        // test that upon an error it always returns the same error
        for _ in 0..10 {
            match client.handshake() {
                Err(e) => {
                    assert_eq!(
                        *(e.iter().next().unwrap().code()),
                        crate::error::ProtoBasedErrorCode::from(
                            pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED
                        )
                    );
                }
                Ok(v) => panic!("Should have errored, but got: {} instead", v),
            }
        }
    }

    /// Test mTLS.
    #[test]
    #[allow(non_snake_case)]
    fn test_mTLS() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let server_certificate =
            crate::test::resolve_runfile("testdata/dilithium5.cert.pem");
        let server_private_key =
            crate::test::resolve_runfile("testdata/dilithium5.key.pem");

        let client_certificate =
            crate::test::resolve_runfile("testdata/falcon1024.cert.pem");
        let client_private_key =
            crate::test::resolve_runfile("testdata/falcon1024.key.pem");

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{client_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
                      static <
                        data <
                          filename: "{client_private_key}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{client_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
                      static <
                        data <
                          filename: "{server_private_key}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), verifier.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Test mTLS, but the client doesn't send its identity.
    #[test]
    #[allow(non_snake_case)]
    fn test_mTLS_no_client_cert() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let server_certificate =
            crate::test::resolve_runfile("testdata/dilithium5.cert.pem");
        let server_private_key =
            crate::test::resolve_runfile("testdata/dilithium5.key.pem");

        let client_certificate =
            crate::test::resolve_runfile("testdata/falcon1024.cert.pem");

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{client_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
                      static <
                        data <
                          filename: "{server_private_key}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), verifier.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );

        server.handshake().unwrap_err();
    }

    /// Test tunnel between client and server with an expired certificate,
    /// and `allow_expired_certificate` to true.
    #[test]
    fn test_expired_allow_expired_certificate() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    allow_expired_certificate: true
                  >
                >
              >
            >
            "#,
                crate::test::resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
                crate::test::resolve_runfile(tls::test::CERT_EXPIRED_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), verifier.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Tests the constructor of a tunnel with a empty message for the tunnel verifier.
    #[test]
    fn test_tunnel_no_verifier() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();

        let verifier = pb_api::TunnelVerifier::new();
        ctx.new_tunnel(Box::new(io), verifier).expect_err(
            "constructing a tunnel with an empty message for the tunnel verifier must fail",
        );
    }

    /// Tests the constructor of a tunnel with a valid SAN verifier.
    #[test]
    fn test_tunnel_san_verifier_valid() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                >
            "#,
        )
        .unwrap();
        ctx.new_tunnel(Box::new(io), verifier)
            .expect("constructing a tunnel with a valid SANVerifier must succeed");
    }

    /// Tests the constructor of a tunnel with an empty SAN verifier.
    #[test]
    fn test_tunnel_empty_san_verifier() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                >
            "#,
        )
        .unwrap();
        ctx.new_tunnel(Box::new(io), verifier)
            .expect_err("constructing a tunnel with an empty SANVerifier must fail");
    }

    /// Tests the constructor of a tunnel with an invalid SAN verifier.
    #[test]
    fn test_tunnel_san_verifier_invalid() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();

        let verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "zadig@example.com"
                    >
                    alt_names <
                        email: "user@example.com"
                    >
                >
            "#,
        )
        .unwrap();
        ctx.new_tunnel(Box::new(io), verifier)
            .expect_err("constructing a tunnel with an invalid SANVerifier must fail");
    }

    /// Tests the SAN verifier with a simple dns hostname `example.com` that
    /// matches the SANs in the certificate presented by the server.
    #[test]
    fn test_san_dns_match() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Tests the SAN verifier with a simple dns hostname `example2.com` that
    /// doesn't match the SANs in the certificate presented by the server.
    #[test]
    fn test_san_dns_mismatch() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example2.com"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );

        client
            .handshake()
            .expect_err("handshake must fail because hostnames mistmatch");

        server.handshake().unwrap_err();
    }

    /// Tests the SAN verifier with a simple email address `user@example.com` that
    /// matches the SANs in the certificate presented by the server.
    #[test]
    fn test_san_email_match() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "user@example.com"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Tests the SAN verifier with a simple email address `root@example.com` that
    /// doesn't match the SANs in the certificate presented by the server.
    #[test]
    fn test_san_email_mismatch() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "root@example.com"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );

        client
            .handshake()
            .expect_err("handshake must fail because email mistmatch");

        server.handshake().unwrap_err();
    }

    /// Tests the SAN verifier with a simple IP address `127.0.0.1` that
    /// matches the SANs in the certificate presented by the server.
    #[test]
    fn test_san_ip_address_match() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        ip_address: "127.0.0.1"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Tests the SAN verifier with a simple IP address `127.0.0.2` that
    /// doesn't match the SANs in the certificate presented by the server.
    #[test]
    fn test_san_ip_address_mismatch() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        ip_address: "127.0.0.2"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );

        client
            .handshake()
            .expect_err("handshake must fail because email mistmatch");

        server.handshake().unwrap_err();
    }

    /// Tests the SAN verifier with an email and a certificate being signed
    /// for that email and also a wildcard DNS name.
    #[test]
    fn test_san_email_certificate_email_wildcard_match() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "zadig@example.com"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Tests the SAN verifier with a DNS name and a certificate being signed
    /// for an email and also a wildcard DNS name that covers the DNS name.
    #[test]
    fn test_san_dns_wildcard_match() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
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
                crate::test::resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
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
                crate::test::resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
                crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "subdomain.example.com"
                    >
                >
            "#,
        )
        .unwrap();

        let server_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_verifier)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_verifier)
            .unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }
}
