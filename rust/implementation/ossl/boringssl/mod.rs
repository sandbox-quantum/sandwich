// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich BoringSSL implementation module.

//! Defines [`Ossl`] structure that implements [`ossl::Ossl`].

extern crate boringssl;

use std::ffi::c_ulong;
use std::pin::Pin;
use std::ptr::{self, NonNull};

use pb::RecordError as PbRecordError;

use super::super::ossl::{self, VerifyMode};
use super::Ossl as OsslTrait;
use crate::support::Pimpl;
use crate::tunnel::{tls, Mode, RecordError};

mod io;

/// Offset in error codes where the code library is stored.
const ERR_LIB_OFFSET: u32 = 24;

/// Mask to extract the code library from an error code.
const ERR_LIB_MASK: u32 = 0xff;

/// Mask to extract the reason from an error code.
const ERR_REASON_MASK: u32 = 0xfff;

/// Context backed by BOringSSL 1.1.1.
#[derive(Debug)]
pub struct Context<'a>(pub(crate) ossl::OsslContext<'a, Ossl>);

impl<'a> TryFrom<&pb_api::Configuration> for Context<'a> {
    type Error = crate::Error;

    fn try_from(cfg: &pb_api::Configuration) -> Result<Self, Self::Error> {
        Ok(Self(ossl::OsslContext::<Ossl>::try_from(cfg)?))
    }
}

/// Tunnel backed by BoringSSL.
#[derive(Debug)]
pub struct Tunnel<'a>(pub(crate) Pin<Box<ossl::OsslTunnel<'a, Ossl>>>);

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

/// Convert a BoringSSL error to a [`RecordError`].
fn boringssl_error_to_record_error(e: i32, errno: std::io::Error) -> RecordError {
    match e as u32 {
        boringssl::SSL_ERROR_WANT_READ => PbRecordError::RECORDERROR_WANT_READ,
        boringssl::SSL_ERROR_WANT_WRITE => PbRecordError::RECORDERROR_WANT_WRITE,
        boringssl::SSL_ERROR_ZERO_RETURN => PbRecordError::RECORDERROR_CLOSED,
        boringssl::SSL_ERROR_SYSCALL => match errno.raw_os_error() {
            // EPIPE
            Some(32) => PbRecordError::RECORDERROR_CLOSED,
            Some(_) | None => PbRecordError::RECORDERROR_UNKNOWN,
        },
        _ => PbRecordError::RECORDERROR_UNKNOWN,
    }
    .into()
}

/// Reads the last BoringSSL error that occurred while parsing a certificate.
fn read_certificate_asn1_error() -> crate::Error {
    match err_get_lib(unsafe { boringssl::ERR_get_error() }) {
        boringssl::ERR_LIB_PEM | boringssl::ERR_LIB_ASN1 => {
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
        }
        _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
    }
}

/// Reads the last BoringSSL error that occurred while parsing a private key.
fn read_private_key_asn1_error() -> crate::Error {
    match err_get_lib(unsafe { boringssl::ERR_get_error() }) {
        boringssl::ERR_LIB_PEM | boringssl::ERR_LIB_ASN1 => {
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}
        }
        _ => pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into(),
    }
}

/// Returns the code of the library where a given error occurred.
///
/// This function replicates the behavior of `ERR_GET_LIB`. Unfortunately,
/// `ERR_GET_LIB` cannot be used since it's a static function defined in
/// the header file `openssl/err.h` (bindgen is unable to compile static
/// functions).
///
/// WARNING: this function differs from OpenSSL 3's.
fn err_get_lib(errcode: u32) -> u32 {
    (errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK
}

/// Returns the reason of why an error occurred.
///
/// This function replicates the behavior of `ERR_GET_REASON`. For more information,
/// see `err_get_lib`.
///
/// WARNING: this function differs from OpenSSL 3's.
fn err_get_reason(errcode: u32) -> u32 {
    errcode & ERR_REASON_MASK
}

pub(crate) struct Ossl {}

/// Implements [`ossl::Ossl`] for [`Ossl`].
impl OsslTrait for Ossl {
    type NativeCertificate = boringssl::x509_st;
    type NativePrivateKey = boringssl::evp_pkey_st;
    type NativeSslCtx = boringssl::SSL_CTX;
    type NativeSsl = boringssl::SSL;
    type NativeX509StoreCtx = boringssl::X509_STORE_CTX;
    type NativeX509VerifyParams = boringssl::X509_VERIFY_PARAM;
    type NativeBio = boringssl::BIO;

    fn new_ssl_context(mode: Mode) -> crate::Result<Pimpl<'static, Self::NativeSslCtx>> {
        let ctx = unsafe {
            Pimpl::new(
                boringssl::SSL_CTX_new(match mode {
                    Mode::Client => boringssl::TLS_client_method(),
                    Mode::Server => boringssl::TLS_server_method(),
                }),
                |x| boringssl::SSL_CTX_free(x),
            )
        }
        .ok_or(pb::SystemError::SYSTEMERROR_MEMORY)?;

        unsafe {
            boringssl::SSL_CTX_set_quiet_shutdown(ctx.as_nonnull().as_ptr(), 0);
            boringssl::SSL_CTX_set_session_cache_mode(
                ctx.as_nonnull().as_ptr(),
                boringssl::SSL_SESS_CACHE_OFF as i32,
            );
            boringssl::SSL_CTX_set1_groups(ctx.as_nonnull().as_ptr(), ptr::null_mut(), 0);
            boringssl::SSL_CTX_set_signing_algorithm_prefs(
                ctx.as_nonnull().as_ptr(),
                DEFAULT_SIGNATURE_ALGORITHMS.as_ptr(),
                DEFAULT_SIGNATURE_ALGORITHMS.len(),
            );
            boringssl::SSL_CTX_set_verify_algorithm_prefs(
                ctx.as_nonnull().as_ptr(),
                DEFAULT_SIGNATURE_ALGORITHMS.as_ptr(),
                DEFAULT_SIGNATURE_ALGORITHMS.len(),
            );
        }
        if mode == Mode::Client {
            Self::ssl_context_set_verify_mode(ctx.as_nonnull(), VerifyMode::Peer);
            let ptr = unsafe { boringssl::X509_STORE_new() };
            if ptr.is_null() {
                return Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
            }
            unsafe {
                boringssl::SSL_CTX_set_cert_store(ctx.as_nonnull().as_ptr(), ptr);
                boringssl::X509_STORE_set_trust(ptr, 1);
            }
        }

        if unsafe {
            boringssl::SSL_CTX_set_min_proto_version(
                ctx.as_nonnull().as_ptr(),
                boringssl::TLS1_3_VERSION as u16,
            )
        } == 1
        {
            Ok(ctx)
        } else {
            Err(
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION
                    .into(),
            )
        }
    }

    fn ssl_context_set_verify_mode(ssl_ctx: NonNull<Self::NativeSslCtx>, mode: VerifyMode) {
        let flag = match mode {
            VerifyMode::None => boringssl::SSL_VERIFY_NONE,
            VerifyMode::Peer => boringssl::SSL_VERIFY_PEER,
            VerifyMode::Mutual => {
                boringssl::SSL_VERIFY_PEER | boringssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            }
        } as i32;
        unsafe {
            boringssl::SSL_CTX_set_verify(ssl_ctx.as_ptr(), flag, Some(Self::verify_callback));
        }
    }

    fn ssl_context_initialize_x509_verify_parameters(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
    ) -> crate::Result<()> {
        let x509_verify_param =
            NonNull::new(unsafe { boringssl::SSL_CTX_get0_param(ssl_ctx.as_ptr()) }).ok_or((
                pb::SystemError::SYSTEMERROR_MEMORY,
                "BoringSSL failed to initialize the X509_VERIFY_PARAM structure",
            ))?;

        fn enable_flag(
            x509_verify_param: NonNull<boringssl::X509_VERIFY_PARAM>,
            flag: impl Into<c_ulong>,
        ) -> crate::Result<()> {
            let flag = flag.into();
            if unsafe { boringssl::X509_VERIFY_PARAM_set_flags(x509_verify_param.as_ptr(), flag) }
                == 1
            {
                Ok(())
            } else {
                Err((
                    pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID,
                    format!("failed to set flag '{flag}'"),
                )
                    .into())
            }
        }

        enable_flag(x509_verify_param, boringssl::X509_V_FLAG_X509_STRICT)?;
        enable_flag(x509_verify_param, boringssl::X509_V_FLAG_TRUSTED_FIRST)?;
        enable_flag(x509_verify_param, boringssl::X509_V_FLAG_PARTIAL_CHAIN)
    }

    fn ssl_context_set_verify_depth(ssl_ctx: NonNull<Self::NativeSslCtx>, depth: u32) {
        unsafe {
            boringssl::SSL_CTX_set_verify_depth(ssl_ctx.as_ptr(), depth as i32);
        }
    }

    fn ssl_context_set_kems(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        kems: std::slice::Iter<'_, String>,
    ) -> crate::Result<()> {
        let mut nids = Vec::<i32>::new();
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
            if nids.len() > (i32::MAX as usize) {
                return Err(pb::KEMError::KEMERROR_TOO_MANY.into());
            }
        }
        if !nids.is_empty()
            || unsafe {
                boringssl::SSL_CTX_set1_groups(ssl_ctx.as_ptr(), nids.as_ptr(), nids.len())
            } == 1
        {
            Ok(())
        } else {
            Err(pb::KEMError::KEMERROR_INVALID.into())
        }
    }

    fn bio_from_buffer<'a>(
        buf: impl AsRef<[u8]> + 'a,
    ) -> crate::Result<Pimpl<'a, Self::NativeBio>> {
        let obj = buf.as_ref();
        let ptr = if obj.len() <= (std::isize::MAX as usize) {
            unsafe {
                Ok::<*mut Self::NativeBio, _>(boringssl::BIO_new_mem_buf(
                    obj.as_ptr().cast(),
                    obj.len() as isize,
                ))
            }
        } else {
            Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)
        }?;
        unsafe { Pimpl::new(ptr, |p| boringssl::BIO_free_all(p)) }
            .ok_or_else(|| pb::SystemError::SYSTEMERROR_MEMORY.into())
    }

    fn bio_eof(bio: NonNull<Self::NativeBio>) -> bool {
        unsafe { boringssl::BIO_eof(bio.as_ptr()) == 1 }
    }

    fn ssl_context_append_certificate_to_trust_store(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: NonNull<Self::NativeCertificate>,
    ) -> crate::Result<()> {
        let store = NonNull::new( unsafe { boringssl::SSL_CTX_get_cert_store(ssl_ctx.as_ptr()) } )
            .ok_or_else(|| errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::CertificateError::CERTIFICATEERROR_UNKNOWN})?;
        if unsafe { boringssl::X509_STORE_add_cert(store.as_ptr(), cert.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
        }
    }

    fn ssl_context_set_certificate(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: NonNull<Self::NativeCertificate>,
    ) -> crate::Result<()> {
        if unsafe { boringssl::SSL_CTX_use_certificate(ssl_ctx.as_ptr(), cert.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into())
        }
    }

    fn ssl_context_add_extra_chain_cert(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: Pimpl<'static, Self::NativeCertificate>,
    ) -> crate::Result<()> {
        if unsafe {
            boringssl::SSL_CTX_add_extra_chain_cert(ssl_ctx.as_ptr(), cert.as_nonnull().as_ptr())
        } == 1
        {
            // `SSL_CTX_add_extra_chain_cert` takes ownership of the cert object, so we release the object from the `Pimpl` object.
            cert.into_raw();
            Ok(())
        } else {
            Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into())
        }
    }

    fn ssl_context_set_private_key(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        pkey: NonNull<Self::NativePrivateKey>,
    ) -> crate::Result<()> {
        if unsafe { boringssl::SSL_CTX_use_PrivateKey(ssl_ctx.as_ptr(), pkey.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into())
        }
    }

    fn ssl_context_check_private_key(ssl_ctx: NonNull<Self::NativeSslCtx>) -> crate::Result<()> {
        if unsafe { boringssl::SSL_CTX_check_private_key(ssl_ctx.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE.into())
        }
    }

    fn ssl_context_set_alpn_protos(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        alpn_protocols: std::slice::Iter<'_, String>,
    ) -> crate::Result<()> {
        let mut protos: String = String::new();
        for proto in alpn_protocols {
            let x = proto.len();
            if 0 < x && x < 256 {
                if proto.contains('\0') {
                    return Err(pb::ALPNError::ALPNERROR_INVALID_STRING.into());
                }

                protos.push((x as u8) as char);
                protos.push_str(proto);
            } else {
                return Err(pb::ALPNError::ALPNERROR_LENGTH_ERROR.into());
            }
        }

        let len = protos.len();
        let cstr = std::ffi::CString::new(protos.as_bytes()).unwrap();

        if unsafe {
            boringssl::SSL_CTX_set_alpn_protos(ssl_ctx.as_ptr(), cstr.as_ptr().cast(), len)
        } == 0
        {
            Ok(())
        } else {
            Err(pb::ALPNError::ALPNERROR_INVALID_STRING.into())
        }
    }

    fn certificate_from_bio(
        bio: NonNull<Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativeCertificate>> {
        #[allow(unreachable_patterns)]
        let cert = match format {
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => unsafe {
                boringssl::PEM_read_bio_X509(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativeCertificate>(),
                    None,
                    ptr::null_mut(),
                )
            },
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => unsafe {
                boringssl::d2i_X509_bio(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativeCertificate>(),
                )
            },
            _ => unreachable!(),
        };
        unsafe { Pimpl::new(cert, |x| boringssl::X509_free(x)) }
            .ok_or_else(read_certificate_asn1_error)
    }

    fn private_key_from_bio(
        bio: NonNull<Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativePrivateKey>> {
        #[allow(unreachable_patterns)]
        let private_key = match format {
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => unsafe {
                boringssl::PEM_read_bio_PrivateKey(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativePrivateKey>(),
                    None,
                    ptr::null_mut(),
                )
            },
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => unsafe {
                boringssl::d2i_PrivateKey_bio(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativePrivateKey>(),
                )
            },
            _ => unreachable!(),
        };
        unsafe { Pimpl::new(private_key, |x| boringssl::EVP_PKEY_free(x)) }
            .ok_or_else(read_private_key_asn1_error)
    }

    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl,
    {
        unsafe {
            Pimpl::new(boringssl::SSL_new(ssl_context.as_nonnull().as_ptr()), |x| {
                boringssl::SSL_free(x)
            })
        }
        .ok_or_else(|| pb::SystemError::SYSTEMERROR_MEMORY.into())
    }

    fn new_ssl_bio() -> crate::Result<Pimpl<'static, Self::NativeBio>> {
        unsafe {
            Pimpl::new(
                boringssl::BIO_new(&io::BIO_METH as *const boringssl::bio_method_st),
                |x| boringssl::BIO_free_all(x),
            )
        }
        .ok_or_else(|| pb::SystemError::SYSTEMERROR_MEMORY.into())
    }

    fn bio_set_data(bio: NonNull<Self::NativeBio>, data: *mut std::ffi::c_void) {
        unsafe {
            boringssl::BIO_set_data(bio.as_ptr(), data);
        }
    }

    fn ssl_set_bio(
        ssl: NonNull<Self::NativeSsl>,
        bio: NonNull<Self::NativeBio>,
    ) -> crate::Result<()> {
        unsafe {
            boringssl::BIO_set_init(bio.as_ptr(), 1);
            boringssl::SSL_set_bio(ssl.as_ptr(), bio.as_ptr(), bio.as_ptr());
        }
        Ok(())
    }

    fn ssl_set_extra_data_for_verify<T>(
        ssl: NonNull<Self::NativeSsl>,
        extra_data: *mut T,
    ) -> Result<(), pb::SystemError> {
        if unsafe {
            boringssl::SSL_set_ex_data(
                ssl.as_ptr(),
                ossl::VERIFY_TUNNEL_SECURITY_REQUIREMENTS_INDEX,
                extra_data.cast(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err(pb::SystemError::SYSTEMERROR_MEMORY)
        }
    }

    fn ssl_set_server_name_indication(
        ssl: NonNull<Self::NativeSsl>,
        hostname: impl Into<String>,
    ) -> crate::Result<()> {
        let cstr = std::ffi::CString::new(hostname.into())
            .map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;
        if unsafe {
            boringssl::SSL_set_tlsext_host_name(ssl.as_ptr(), cstr.as_c_str().as_ptr().cast())
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::SystemError::SYSTEMERROR_MEMORY,
                "BoringSSL failed to set the SNI",
            )
                .into())
        }
    }

    fn ssl_handshake(
        ssl: NonNull<Self::NativeSsl>,
        mode: Mode,
    ) -> (crate::Result<pb::tunnel::HandshakeState>, Option<pb::State>) {
        let err = match mode {
            Mode::Client => unsafe { boringssl::SSL_connect(ssl.as_ptr()) },
            Mode::Server => unsafe { boringssl::SSL_accept(ssl.as_ptr()) },
        } as u32;
        if err == 1 {
            return (
                Ok(pb::HandshakeState::HANDSHAKESTATE_DONE),
                Some(pb::State::STATE_HANDSHAKE_DONE),
            );
        }
        let e = unsafe { boringssl::SSL_get_error(ssl.as_ptr(), err as i32) } as u32;
        let last_verify_error = Ossl::ssl_get_last_verify_error(ssl);
        match e {
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
            boringssl::SSL_ERROR_WANT_X509_LOOKUP => (
                    Err(crate::Error::from((
                                    pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                    "BoringSSL error: application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.".to_string()
                                ))
                    ),
                    Some(pb::State::STATE_ERROR),
            ),
            boringssl::SSL_ERROR_SYSCALL | boringssl::SSL_ERROR_SSL => {
                let err = unsafe { boringssl::ERR_get_error() };
                if err == 0 && last_verify_error == 0 {
                    return (
                        Err(crate::Error::from((
                                    pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                                    match e {
                                      boringssl::SSL_ERROR_SYSCALL => "BoringSSL error: Returned SSL_ERROR_SYSCALL with no additional info.",
                                      boringssl::SSL_ERROR_SSL => "BoringSSL error: Returned SSL_ERROR_SSL with no additional info.",
                                      _ => "BoringSSL error: Reached an unreachable point.",
                                    }.to_string()
                            ))
                        ),
                        Some(pb::State::STATE_ERROR),
                    );
                }
                let errlib = err_get_lib(err);
                let e_r = unsafe { boringssl::ERR_error_string(err, ptr::null_mut()) };
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
                        boringssl::X509_verify_cert_error_string(last_verify_error as i64)
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
                    return match last_verify_error as u32 {
                        boringssl::X509_V_OK => {
                            let mut buf = vec![0u8; 1024];
                            unsafe { boringssl::ERR_error_string_n(err, buf.as_mut_ptr() as *mut std::os::raw::c_char, buf.len()) };
                            let err_string = String::from_utf8(buf)
                            .unwrap_or("Unable to get error string from boringssl".into());
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
                match err_get_reason(err) {
                    boringssl::SSL_R_CERTIFICATE_VERIFY_FAILED => {
                        let x_e_s = unsafe {
                            boringssl::X509_verify_cert_error_string(last_verify_error as i64)
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
                        match last_verify_error as u32 {
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
                        Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR, err_string))),
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

    fn ssl_read(
        ssl: NonNull<Self::NativeSsl>,
        buf: &mut [u8],
    ) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(PbRecordError::RECORDERROR_TOO_BIG.into());
        }

        let err =
            unsafe { boringssl::SSL_read(ssl.as_ptr(), buf.as_mut_ptr().cast(), buf.len() as i32) };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { boringssl::SSL_get_error(ssl.as_ptr(), err) };
        if (serr == (boringssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(PbRecordError::RECORDERROR_CLOSED.into());
        }
        Err(boringssl_error_to_record_error(serr, os_error))
    }

    fn ssl_write(ssl: NonNull<Self::NativeSsl>, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(PbRecordError::RECORDERROR_TOO_BIG.into());
        }

        let err =
            unsafe { boringssl::SSL_write(ssl.as_ptr(), buf.as_ptr().cast(), buf.len() as i32) };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { boringssl::SSL_get_error(ssl.as_ptr(), err) };
        if (serr == (boringssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(PbRecordError::RECORDERROR_CLOSED.into());
        }
        Err(boringssl_error_to_record_error(serr, os_error))
    }

    fn ssl_close(ssl: NonNull<Self::NativeSsl>) -> crate::tunnel::RecordResult<()> {
        unsafe {
            boringssl::SSL_shutdown(ssl.as_ptr());
        }
        Ok(())
    }

    fn ssl_get_shutdown_state(ssl: NonNull<Self::NativeSsl>) -> Option<pb::State> {
        let err = unsafe { boringssl::SSL_get_shutdown(ssl.as_ptr()) } as u32;
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

    fn ssl_get_handshake_state(ssl: NonNull<Self::NativeSsl>) -> pb::HandshakeState {
        let s = unsafe { boringssl::SSL_state(ssl.as_ptr()) } as u32;
        if s == boringssl::SSL_ST_OK {
            pb::HandshakeState::HANDSHAKESTATE_DONE
        } else {
            pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS
        }
    }

    fn x509_store_context_get_ssl(
        store_ctx: NonNull<Self::NativeX509StoreCtx>,
    ) -> Option<NonNull<Self::NativeSsl>> {
        let ssl_idx = unsafe { boringssl::SSL_get_ex_data_X509_STORE_CTX_idx() };
        if ssl_idx < 0 {
            return None;
        }
        NonNull::new(
            unsafe { boringssl::X509_STORE_CTX_get_ex_data(store_ctx.as_ptr(), ssl_idx) }
                .cast::<Self::NativeSsl>(),
        )
    }

    fn x509_store_context_get_error(store_ctx: NonNull<Self::NativeX509StoreCtx>) -> i32 {
        unsafe { boringssl::X509_STORE_CTX_get_error(store_ctx.as_ptr()) }
    }

    fn x509_store_context_set_error(store_ctx: NonNull<Self::NativeX509StoreCtx>, error: i32) {
        unsafe {
            boringssl::X509_STORE_CTX_set_error(store_ctx.as_ptr(), error);
        }
    }

    fn x509_store_error_code_valid() -> i32 {
        boringssl::X509_V_OK as i32
    }

    fn x509_error_code_is_certificate_expired(error: i32) -> bool {
        error == boringssl::X509_V_ERR_CERT_HAS_EXPIRED as i32
    }

    fn ssl_get_tunnel_security_requirements<'a>(
        ssl: NonNull<Self::NativeSsl>,
    ) -> Option<&'a tls::TunnelSecurityRequirements> {
        unsafe {
            boringssl::SSL_get_ex_data(
                ssl.as_ptr(),
                ossl::VERIFY_TUNNEL_SECURITY_REQUIREMENTS_INDEX,
            )
            .cast::<tls::TunnelSecurityRequirements>()
            .as_ref::<'a>()
        }
    }

    fn ssl_set_last_verify_error(ssl: NonNull<Self::NativeSsl>, err: i32) {
        unsafe {
            boringssl::SSL_set_ex_data(
                ssl.as_ptr(),
                ossl::VERIFY_TUNNEL_LAST_VERIFY_ERROR_INDEX,
                err as _,
            );
        }
    }

    fn ssl_get_last_verify_error(ssl: NonNull<Self::NativeSsl>) -> i32 {
        unsafe {
            boringssl::SSL_get_ex_data(ssl.as_ptr(), ossl::VERIFY_TUNNEL_LAST_VERIFY_ERROR_INDEX)
                as i32
        }
    }

    fn ssl_get_x509_verify_parameters(
        ssl: NonNull<Self::NativeSsl>,
    ) -> Option<NonNull<Self::NativeX509VerifyParams>> {
        NonNull::new(unsafe { boringssl::SSL_get0_param(ssl.as_ptr()) })
    }

    fn x509_verify_parameters_add_san_dns(
        verify_params: NonNull<Self::NativeX509VerifyParams>,
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
            boringssl::X509_VERIFY_PARAM_add1_host(verify_params.as_ptr(), cstr.as_ptr(), dns.len())
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
        verify_params: NonNull<Self::NativeX509VerifyParams>,
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
            boringssl::X509_VERIFY_PARAM_set1_email(
                verify_params.as_ptr(),
                cstr.as_ptr(),
                email.len(),
            )
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
        verify_params: NonNull<Self::NativeX509VerifyParams>,
        ip_addr: &str,
    ) -> crate::Result<()> {
        let cstring = std::ffi::CString::new(ip_addr.as_bytes()).map_err(|e| {
            (
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("ip address '{ip_addr}' is invalid: {e}"),
            )
        })?;
        let cstr = cstring.as_c_str();
        let err = unsafe {
            boringssl::X509_VERIFY_PARAM_set1_ip_asc(verify_params.as_ptr(), cstr.as_ptr())
        };
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

GenOsslUnitTests!(
    use crate::implementation::ossl::boringssl::Ossl;
);

#[cfg(test)]
mod additional_tests {
    use super::*;

    /// Tests [`Ossl::ssl_context_set_verify_mode`].
    #[test]
    fn test_ssl_ctx_set_verify_mode() {
        let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

        let mode = unsafe { boringssl::SSL_CTX_get_verify_mode(ssl.as_nonnull().as_ptr()) };
        assert_eq!(mode, boringssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(ssl.as_nonnull(), super::VerifyMode::Peer);

        let mode = unsafe { boringssl::SSL_CTX_get_verify_mode(ssl.as_nonnull().as_ptr()) };
        assert_eq!(mode, boringssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(ssl.as_nonnull(), super::VerifyMode::None);

        let mode = unsafe { boringssl::SSL_CTX_get_verify_mode(ssl.as_nonnull().as_ptr()) };
        assert_eq!(mode, boringssl::SSL_VERIFY_NONE as i32);
    }
}

#[cfg(test)]
pub(crate) mod additional_test {
    use crate::test::resolve_runfile;
    use crate::tunnel::tls;
    use crate::tunnel::Context;

    /// A simple I/O interface.
    struct IOBuffer {
        pub(self) read: Vec<u8>,
        pub(self) write: Vec<u8>,
    }

    /// Implements [`crate::IO`] for [`IOBuffer`].
    impl crate::IO for IOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> Result<usize, std::io::Error> {
            let n = std::cmp::min(buf.len(), self.read.len());
            if n == 0 {
                Err(std::io::ErrorKind::WouldBlock.into())
            } else {
                buf.copy_from_slice(&self.read[0..n]);
                self.read.drain(0..n);
                Ok(n)
            }
        }

        fn write(&mut self, buf: &[u8], _state: pb::State) -> Result<usize, std::io::Error> {
            self.write.extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    /// Implements [`IOBuffer`].
    impl IOBuffer {
        /// Constructs a new [`IOBuffer`].
        fn new() -> Self {
            Self {
                read: Vec::new(),
                write: Vec::new(),
            }
        }
    }

    /// A double I/O interface.
    struct LinkedIOBuffer {
        pub(self) buf: Vec<u8>,
        pub(self) recv: std::sync::mpsc::Receiver<Vec<u8>>,
        pub(self) send: std::sync::mpsc::Sender<Vec<u8>>,
    }

    /// Implements [`crate::IO`] for [`LinkedIOBuffer`].
    impl crate::IO for LinkedIOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> Result<usize, std::io::Error> {
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
                    Ok::<(), std::io::Error>(())
                }
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => {
                        Err(std::io::ErrorKind::WouldBlock.into())
                    }
                    _ => Err(std::io::ErrorKind::BrokenPipe.into()),
                },
            }?;

            let result = n;
            let n = std::cmp::min(r, self.buf.len());
            buf[result..result + n].copy_from_slice(&self.buf[0..n]);
            self.buf.drain(0..n);
            Ok(result + n)
        }

        fn write(&mut self, buf: &[u8], _state: pb::State) -> Result<usize, std::io::Error> {
            self.send
                .send(Vec::from(buf))
                .map(|_| buf.len())
                .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
        }
    }

    /// Implements [`LinkedIOBuffer`].
    impl LinkedIOBuffer {
        /// Constructs a new [`LinkedIOBuffer`].
        fn new(
            send: std::sync::mpsc::Sender<Vec<u8>>,
            recv: std::sync::mpsc::Receiver<Vec<u8>>,
        ) -> Self {
            Self {
                buf: Vec::new(),
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
                resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = IOBuffer::new();

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();

        let tun = ctx.new_tunnel(Box::new(io), tunnel_configuration);
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
                  empty_verifier<>
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
                resolve_runfile(tls::test::CERT_PEM_PATH),
                resolve_runfile(tls::test::SK_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = IOBuffer::new();

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();
        let tun = ctx.new_tunnel(Box::new(io), tunnel_configuration);
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
                resolve_runfile(tls::test::CERT_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier<>
                  identity<
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
                resolve_runfile(tls::test::CERT_PEM_PATH),
                resolve_runfile(tls::test::SK_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();
        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), tunnel_configuration.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), tunnel_configuration)
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
                resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier<>
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
                resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
                resolve_runfile(tls::test::CERT_EXPIRED_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), tunnel_configuration.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), tunnel_configuration)
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
                resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();
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
                resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
                resolve_runfile(tls::test::CERT_EXPIRED_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), tunnel_configuration.clone())
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), tunnel_configuration)
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
                resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();
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
                resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            dns: "example.com"
                        >
                    >
                >
            "#,
            )
            .unwrap();

        let server_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_tunnel_configuration)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_tunnel_configuration)
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
                resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();
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
                resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_BORINGSSL_OQS.into();
        let sw_ctx = crate::Context;
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            dns: "example2.com"
                        >
                    >
                >
            "#,
            )
            .unwrap();

        let server_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier<empty_verifier<>>
            "#,
            )
            .unwrap();

        let mut client = client_ctx
            .new_tunnel(Box::new(client_io), client_tunnel_configuration)
            .unwrap();
        let mut server = server_ctx
            .new_tunnel(Box::new(server_io), server_tunnel_configuration)
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
}
