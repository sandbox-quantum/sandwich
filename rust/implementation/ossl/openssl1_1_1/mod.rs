// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich OpenSSL implementation module.
//! Defines [`Ossl`] structure that implements [`crate::implementation::ossl::Ossl`].

extern crate openssl1_1_1;

use std::ffi::{c_int, c_ulong, c_void};
use std::pin::Pin;
use std::ptr::{self, NonNull};

use openssl1_1_1 as openssl;
use pb::RecordError as PbRecordError;

use super::super::ossl;
use super::Ossl as OsslTrait;
use crate::support::Pimpl;
use crate::tunnel::{tls, Mode, RecordError};
use tls::{TlsVersion, VerifyMode};

mod io;

/// Offset in error codes where the code library is stored.
const ERR_LIB_OFFSET: u32 = 24;

/// Mask to extract the code library from an error code.
const ERR_LIB_MASK: c_ulong = 0xff;

/// Mask to extract the reason from an error code.
const ERR_REASON_MASK: c_ulong = 0xfff;

/// Context backed by OpenSSL 1.1.1.
#[derive(Debug)]
pub struct Context<'a>(pub(crate) ossl::OsslContext<'a, Ossl>);

impl<'a> TryFrom<&pb_api::Configuration> for Context<'a> {
    type Error = crate::Error;

    fn try_from(cfg: &pb_api::Configuration) -> Result<Self, Self::Error> {
        Ok(Self(ossl::OsslContext::<Ossl>::try_from(cfg)?))
    }
}

/// Tunnel backed by OpenSSL 1.1.1.
#[derive(Debug)]
pub struct Tunnel<'a>(pub(crate) Pin<Box<ossl::OsslTunnel<'a, Ossl>>>);

pub struct Ossl {}

/// Converts an OpenSSL error to a [`RecordError`].
fn openssl_error_to_record_error(e: i32, errno: std::io::Error) -> RecordError {
    match e as u32 {
        openssl::SSL_ERROR_WANT_READ => PbRecordError::RECORDERROR_WANT_READ,
        openssl::SSL_ERROR_WANT_WRITE => PbRecordError::RECORDERROR_WANT_WRITE,
        openssl::SSL_ERROR_ZERO_RETURN => PbRecordError::RECORDERROR_CLOSED,
        openssl::SSL_ERROR_SYSCALL => match errno.raw_os_error() {
            // EPIPE
            Some(32) => PbRecordError::RECORDERROR_CLOSED,
            Some(_) | None => PbRecordError::RECORDERROR_UNKNOWN,
        },
        _ => PbRecordError::RECORDERROR_UNKNOWN,
    }
    .into()
}

/// Reads the last OpenSSL error that occurred while parsing a certificate.
fn read_certificate_asn1_error() -> crate::Error {
    match err_get_lib(unsafe { openssl::ERR_get_error() }) {
        openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
        }
        _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
    }
}

/// Reads the last OpenSSL error that occurred while parsing a private key.
fn read_private_key_asn1_error() -> crate::Error {
    match err_get_lib(unsafe { openssl::ERR_get_error() }) {
        openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
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
fn err_get_lib(errcode: c_ulong) -> u32 {
    ((errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK) as u32
}

/// Returns the reason of why an error occurred.
///
/// This function replicates the behavior of `ERR_GET_REASON`. For more information,
/// see `err_get_lib`.
///
/// WARNING: this function differs from OpenSSL 3's.
fn err_get_reason(errcode: c_ulong) -> u32 {
    (errcode & ERR_REASON_MASK) as u32
}

/// Translates ciphersuite from IANA standard name to OpenSSL name.
fn get_openssl_name(iana_name: &str) -> crate::Result<&'static str> {
    let cstr =
        std::ffi::CString::new(iana_name).map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;
    let openssl_name_ptr = unsafe { openssl::OPENSSL_cipher_name(cstr.as_ptr()) };
    let openssl_name = unsafe { std::ffi::CStr::from_ptr(openssl_name_ptr) }
        .to_str()
        .map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;

    if openssl_name == "(NONE)" {
        Err(pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE.into())
    } else {
        Ok(openssl_name)
    }
}

/// Implements [`super::Ossl`] for [`Ossl`].
impl OsslTrait for Ossl {
    type NativeCertificate = openssl::x509_st;
    type NativePrivateKey = openssl::evp_pkey_st;
    type NativeSslCtx = openssl::SSL_CTX;
    type NativeSsl = openssl::SSL;
    type NativeX509StoreCtx = openssl::X509_STORE_CTX;
    type NativeX509VerifyParams = openssl::X509_VERIFY_PARAM;
    type NativeBio = openssl::BIO;

    fn new_ssl_context(mode: Mode) -> crate::Result<Pimpl<'static, Self::NativeSslCtx>> {
        let ctx = unsafe {
            Pimpl::new(
                openssl::SSL_CTX_new(match mode {
                    Mode::Client => openssl::TLS_client_method(),
                    Mode::Server => openssl::TLS_server_method(),
                }),
                |x| openssl::SSL_CTX_free(x),
            )
        }
        .ok_or(pb::SystemError::SYSTEMERROR_MEMORY)?;

        Self::ssl_context_set_tls12_ciphersuites(
            ctx.as_nonnull(),
            crate::tunnel::tls::DEFAULT_TLS12_CIPHERSUITES.iter(),
        )?;
        Self::ssl_context_set_tls13_ciphersuites(
            ctx.as_nonnull(),
            crate::tunnel::tls::DEFAULT_TLS13_CIPHERSUITES.iter(),
        )?;

        unsafe {
            // When we no longer need a read buffer or a write buffer for a given SSL, then release the memory
            // we were using to hold it. Using this flag can save around 34k per idle SSL connection.
            // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
            // openssl::SSL_CTX_set_mode(ctx.as_nonnull(), openssl::SSL_MODE_RELEASE_BUFFERS);
            openssl::SSL_CTX_ctrl(
                ctx.as_nonnull().as_ptr(),
                openssl::SSL_CTRL_MODE as i32,
                openssl::SSL_MODE_RELEASE_BUFFERS.into(),
                ptr::null_mut(),
            );

            openssl::SSL_CTX_set_quiet_shutdown(ctx.as_nonnull().as_ptr(), 0);
            // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
            // SSL_CTX_set_session_cache_mode(ctx.as_nonull().as_ptr(), openssl::SSL_SESS_CACHE_OFF).

            openssl::SSL_CTX_ctrl(
                ctx.as_nonnull().as_ptr(),
                openssl::SSL_CTRL_SET_SESS_CACHE_MODE as i32,
                openssl::SSL_SESS_CACHE_OFF.into(),
                ptr::null_mut(),
            );

            // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
            // SSL_CTX_set1_groups(ctx.as_nonull().as_ptr(), NULL, 0);
            openssl::SSL_CTX_ctrl(
                ctx.as_nonnull().as_ptr(),
                openssl::SSL_CTRL_SET_GROUPS as i32,
                0,
                ptr::null_mut(),
            );
        }
        if mode == Mode::Client {
            Self::ssl_context_set_verify_mode(ctx.as_nonnull(), VerifyMode::Peer);
            let ptr = unsafe { openssl::X509_STORE_new() };
            if ptr.is_null() {
                return Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
            }
            unsafe {
                openssl::SSL_CTX_set_cert_store(ctx.as_nonnull().as_ptr(), ptr);
            }
        }

        if unsafe {
            openssl::SSL_CTX_set_trust(
                ctx.as_nonnull().as_ptr(),
                match mode {
                    Mode::Client => openssl::X509_TRUST_SSL_CLIENT,
                    Mode::Server => openssl::X509_TRUST_SSL_SERVER,
                } as c_int,
            )
        } != 1
        {
            return Err((
                pb::SystemError::SYSTEMERROR_BACKEND,
                "failed to set the trust parameter",
            )
                .into());
        }

        Ok(ctx)
    }

    fn ssl_context_set_min_protocol_version(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        min_tls_version: TlsVersion,
    ) -> crate::Result<()> {
        let min_proto = match min_tls_version {
            TlsVersion::Tls12 => openssl::TLS1_2_VERSION,
            TlsVersion::Tls13 => openssl::TLS1_3_VERSION,
        };

        // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
        // SSL_CTX_set_min_proto_version(ssl_ctx.as_ptr(), min_proto.into());
        if unsafe {
            openssl::SSL_CTX_ctrl(
                ssl_ctx.as_ptr(),
                openssl::SSL_CTRL_SET_MIN_PROTO_VERSION as i32,
                min_proto.into(),
                ptr::null_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err(
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION
                    .into(),
            )
        }
    }

    fn ssl_context_set_max_protocol_version(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        max_tls_version: TlsVersion,
    ) -> crate::Result<()> {
        let max_proto = match max_tls_version {
            TlsVersion::Tls12 => openssl::TLS1_2_VERSION,
            TlsVersion::Tls13 => openssl::TLS1_3_VERSION,
        };

        // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
        // SSL_CTX_set_max_proto_version(ssl_ctx.as_ptr(), max_proto.into());
        if unsafe {
            openssl::SSL_CTX_ctrl(
                ssl_ctx.as_ptr(),
                openssl::SSL_CTRL_SET_MAX_PROTO_VERSION as i32,
                max_proto.into(),
                ptr::null_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err(
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION
                    .into(),
            )
        }
    }

    fn ssl_context_set_tls12_ciphersuites(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        ciphersuites: std::slice::Iter<'_, impl AsRef<str>>,
    ) -> crate::Result<()> {
        if ciphersuites.len() == 0 {
            return Ok(());
        }
        let mut openssl_names: Vec<String> = Vec::new();
        for std_name in ciphersuites {
            let openssl_name = get_openssl_name(std_name.as_ref())?;
            openssl_names.push(openssl_name.to_string())
        }
        let cipher = tls::support::build_ciphersuites_list(openssl_names.iter(), "!+@")?;
        let cstr =
            std::ffi::CString::new(cipher).map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;
        if unsafe { openssl::SSL_CTX_set_cipher_list(ssl_ctx.as_ptr(), cstr.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE.into())
        }
    }

    fn ssl_context_set_tls13_ciphersuites(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        ciphersuites: std::slice::Iter<'_, impl AsRef<str>>,
    ) -> crate::Result<()> {
        if ciphersuites.len() == 0 {
            return Ok(());
        }

        let cipher = tls::support::build_ciphersuites_list(ciphersuites, "!+-@")?;
        let cstr =
            std::ffi::CString::new(cipher).map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;
        if unsafe { openssl::SSL_CTX_set_ciphersuites(ssl_ctx.as_ptr(), cstr.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE.into())
        }
    }

    fn fill_certificate_trust_store_with_default_cas(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
    ) -> crate::Result<()> {
        if unsafe { openssl::SSL_CTX_set_default_verify_paths(ssl_ctx.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::CertificateError::CERTIFICATEERROR_UNKNOWN.into())
        }
    }

    fn ssl_context_set_verify_mode(ssl_ctx: NonNull<Self::NativeSslCtx>, mode: VerifyMode) {
        let flag = match mode {
            VerifyMode::None => openssl::SSL_VERIFY_NONE,
            VerifyMode::Peer => openssl::SSL_VERIFY_PEER,
            VerifyMode::Mutual => {
                openssl::SSL_VERIFY_PEER | openssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            }
        } as i32;
        unsafe {
            openssl::SSL_CTX_set_verify(ssl_ctx.as_ptr(), flag, Some(Self::verify_callback));
        }
    }

    fn ssl_context_initialize_x509_verify_parameters(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
    ) -> crate::Result<()> {
        let x509_verify_param =
            NonNull::new(unsafe { openssl::SSL_CTX_get0_param(ssl_ctx.as_ptr()) }).ok_or((
                pb::SystemError::SYSTEMERROR_MEMORY,
                "OpenSSL 1.1.1 failed to initialize the X509_VERIFY_PARAM structure",
            ))?;

        fn enable_flag(
            x509_verify_param: NonNull<openssl::X509_VERIFY_PARAM>,
            flag: impl Into<c_ulong>,
        ) -> crate::Result<()> {
            let flag = flag.into();
            if unsafe { openssl::X509_VERIFY_PARAM_set_flags(x509_verify_param.as_ptr(), flag) }
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

        enable_flag(x509_verify_param, openssl::X509_V_FLAG_X509_STRICT)?;
        enable_flag(x509_verify_param, openssl::X509_V_FLAG_TRUSTED_FIRST)?;
        enable_flag(x509_verify_param, openssl::X509_V_FLAG_PARTIAL_CHAIN)
    }

    fn ssl_context_set_verify_depth(ssl_ctx: NonNull<Self::NativeSslCtx>, depth: u32) {
        unsafe {
            openssl::SSL_CTX_set_verify_depth(ssl_ctx.as_ptr(), depth as i32);
        }
    }

    fn ssl_context_set_kes(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        kes: std::slice::Iter<'_, impl AsRef<str>>,
    ) -> crate::Result<()> {
        if kes.len() > u32::MAX as usize {
            return Err(pb::KEMError::KEMERROR_TOO_MANY.into());
        }

        if kes.len() == 0 {
            return Ok(());
        }

        let ke_list = crate::support::join_strings_with_delimiter(kes, ':');
        let cstr =
            std::ffi::CString::new(ke_list).map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;
        // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
        // SSL_CTX_set1_groups_list(ssl_ctx.as_ptr(), cstr.as_ptr());
        if unsafe {
            openssl::SSL_CTX_ctrl(
                ssl_ctx.as_ptr(),
                openssl::SSL_CTRL_SET_GROUPS_LIST as i32,
                0.into(),
                cstr.as_ptr() as *mut c_void,
            )
        } == 1
        {
            Ok(())
        } else {
            Err(pb::KEMError::KEMERROR_INVALID.into())
        }
    }

    fn bio_from_buffer<'a>(
        buffer: impl AsRef<[u8]> + 'a,
    ) -> crate::Result<Pimpl<'a, Self::NativeBio>> {
        let obj = buffer.as_ref();
        let ptr = if obj.len() <= (i32::MAX as usize) {
            unsafe {
                Ok::<*mut Self::NativeBio, _>(openssl::BIO_new_mem_buf(
                    obj.as_ptr().cast(),
                    obj.len() as i32,
                ))
            }
        } else {
            Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)
        }?;
        unsafe { Pimpl::new(ptr, |p| openssl::BIO_free_all(p)) }
            .ok_or_else(|| pb::SystemError::SYSTEMERROR_MEMORY.into())
    }

    fn bio_eof(bio: NonNull<Self::NativeBio>) -> bool {
        // BIO_eof(bio)
        unsafe {
            openssl::BIO_ctrl(
                bio.as_ptr(),
                openssl::BIO_CTRL_EOF as c_int,
                0,
                ptr::null_mut(),
            ) == 1
        }
    }

    fn ssl_context_append_certificate_to_trust_store(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: NonNull<Self::NativeCertificate>,
    ) -> crate::Result<()> {
        let store = NonNull::new( unsafe { openssl::SSL_CTX_get_cert_store(ssl_ctx.as_ptr()) } )
            .ok_or_else(|| errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::CertificateError::CERTIFICATEERROR_UNKNOWN})?;
        if unsafe { openssl::X509_STORE_add_cert(store.as_ptr(), cert.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::SystemError::SYSTEMERROR_MEMORY.into())
        }
    }

    fn ssl_context_set_certificate(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: NonNull<Self::NativeCertificate>,
    ) -> crate::Result<()> {
        if unsafe { openssl::SSL_CTX_use_certificate(ssl_ctx.as_ptr(), cert.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into())
        }
    }

    fn ssl_context_add_extra_chain_cert(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: Pimpl<'static, Self::NativeCertificate>,
    ) -> crate::Result<()> {
        // Bindgen can't parse function macros, so we use OpenSSL's internal API instead of the public API.
        // SSL_CTX_add_extra_chain_cert(ssl_ctx.as_mut_ptr(), cert.as_mut_ptr());
        if unsafe {
            openssl::SSL_CTX_ctrl(
                ssl_ctx.as_ptr(),
                openssl::SSL_CTRL_EXTRA_CHAIN_CERT as c_int,
                0,
                cert.as_nonnull().as_ptr().cast(),
            )
        } == 1
        {
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
        if unsafe { openssl::SSL_CTX_use_PrivateKey(ssl_ctx.as_ptr(), pkey.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err(pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into())
        }
    }

    fn ssl_context_check_private_key(ssl_ctx: NonNull<Self::NativeSslCtx>) -> crate::Result<()> {
        if unsafe { openssl::SSL_CTX_check_private_key(ssl_ctx.as_ptr()) } == 1 {
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
            openssl::SSL_CTX_set_alpn_protos(ssl_ctx.as_ptr(), cstr.as_ptr().cast(), len as u32)
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
                openssl::PEM_read_bio_X509(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativeCertificate>(),
                    None,
                    ptr::null_mut(),
                )
            },
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => unsafe {
                openssl::d2i_X509_bio(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativeCertificate>(),
                )
            },
            _ => unreachable!(),
        };
        unsafe { Pimpl::new(cert, |x| openssl::X509_free(x)) }
            .ok_or_else(read_certificate_asn1_error)
    }

    fn private_key_from_bio(
        bio: NonNull<Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativePrivateKey>> {
        #[allow(unreachable_patterns)]
        let private_key = match format {
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => unsafe {
                openssl::PEM_read_bio_PrivateKey(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativePrivateKey>(),
                    None,
                    ptr::null_mut(),
                )
            },
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => unsafe {
                openssl::d2i_PrivateKey_bio(
                    bio.as_ptr(),
                    ptr::null_mut::<*mut Self::NativePrivateKey>(),
                )
            },
            _ => unreachable!(),
        };
        unsafe { Pimpl::new(private_key, |x| openssl::EVP_PKEY_free(x)) }
            .ok_or_else(read_private_key_asn1_error)
    }

    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl,
    {
        unsafe {
            Pimpl::new(openssl::SSL_new(ssl_context.as_nonnull().as_ptr()), |x| {
                openssl::SSL_free(x)
            })
        }
        .ok_or_else(|| pb::SystemError::SYSTEMERROR_MEMORY.into())
    }

    fn new_ssl_bio() -> crate::Result<Pimpl<'static, Self::NativeBio>> {
        unsafe {
            Pimpl::new(
                openssl::BIO_new(&io::BIO_METH as *const openssl::bio_method_st),
                |x| openssl::BIO_free_all(x),
            )
        }
        .ok_or_else(|| pb::SystemError::SYSTEMERROR_MEMORY.into())
    }

    fn bio_set_data(bio: NonNull<Self::NativeBio>, data: *mut c_void) {
        unsafe {
            openssl::BIO_set_data(bio.as_ptr(), data);
        }
    }

    fn ssl_set_bio(
        ssl: NonNull<Self::NativeSsl>,
        bio: NonNull<Self::NativeBio>,
    ) -> crate::Result<()> {
        unsafe {
            openssl::BIO_set_init(bio.as_ptr(), 1);
            openssl::SSL_set_bio(ssl.as_ptr(), bio.as_ptr(), bio.as_ptr());
        }
        Ok(())
    }

    fn ssl_set_extra_data_for_verify<T>(
        ssl: NonNull<Self::NativeSsl>,
        extra_data: *mut T,
    ) -> Result<(), pb::SystemError> {
        if unsafe {
            openssl::SSL_set_ex_data(
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
        use std::ffi::CString;
        let cstr =
            CString::new(hostname.into()).map_err(|_| pb::SystemError::SYSTEMERROR_MEMORY)?;
        if unsafe {
            openssl::SSL_ctrl(
                ssl.as_ptr(),
                openssl::SSL_CTRL_SET_TLSEXT_HOSTNAME as c_int,
                openssl::TLSEXT_NAMETYPE_host_name as i64,
                cstr.as_c_str().as_ptr().cast::<c_void>().cast_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::SystemError::SYSTEMERROR_MEMORY,
                "OpenSSL failed to set the SNI",
            )
                .into())
        }
    }

    fn ssl_handshake(
        ssl: NonNull<Self::NativeSsl>,
        mode: Mode,
    ) -> (crate::Result<pb::tunnel::HandshakeState>, Option<pb::State>) {
        let err = match mode {
            Mode::Client => unsafe { openssl::SSL_connect(ssl.as_ptr()) },
            Mode::Server => unsafe { openssl::SSL_accept(ssl.as_ptr()) },
        } as u32;
        if err == 1 {
            return (
                Ok(pb::HandshakeState::HANDSHAKESTATE_DONE),
                Some(pb::State::STATE_HANDSHAKE_DONE),
            );
        }
        let e = unsafe { openssl::SSL_get_error(ssl.as_ptr(), err as i32) } as u32;
        let last_verify_error = Ossl::ssl_get_last_verify_error(ssl);
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
                let err = unsafe { openssl::ERR_get_error() };
                if err == 0 && last_verify_error == 0 {
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
                let errlib = err_get_lib(err);
                let e_r =
                    unsafe { openssl::ERR_error_string(err, ptr::null_mut()) };
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
                        openssl::X509_verify_cert_error_string(last_verify_error as i64)
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
                match err_get_reason(err) {
                    openssl::SSL_R_CERTIFICATE_VERIFY_FAILED => {
                        let x_e_s = unsafe {
                            openssl::X509_verify_cert_error_string(last_verify_error as i64)
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
                                Err(crate::Error::from((pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR, x509_error_str))),
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
            unsafe { openssl::SSL_read(ssl.as_ptr(), buf.as_mut_ptr().cast(), buf.len() as i32) };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { openssl::SSL_get_error(ssl.as_ptr(), err) };
        if (serr == (openssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(PbRecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn ssl_write(ssl: NonNull<Self::NativeSsl>, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(PbRecordError::RECORDERROR_TOO_BIG.into());
        }

        let err =
            unsafe { openssl::SSL_write(ssl.as_ptr(), buf.as_ptr().cast(), buf.len() as i32) };
        let os_error = std::io::Error::last_os_error();

        if err > 0 {
            return Ok(err as usize);
        }

        let serr = unsafe { openssl::SSL_get_error(ssl.as_ptr(), err) };
        if (serr == (openssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            return Err(PbRecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn ssl_close(ssl: NonNull<Self::NativeSsl>) -> crate::tunnel::RecordResult<()> {
        unsafe {
            openssl::SSL_shutdown(ssl.as_ptr());
        }
        Ok(())
    }

    fn ssl_get_shutdown_state(ssl: NonNull<Self::NativeSsl>) -> Option<pb::State> {
        let err = unsafe { openssl::SSL_get_shutdown(ssl.as_ptr()) } as u32;
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

    fn ssl_get_handshake_state(ssl: NonNull<Self::NativeSsl>) -> pb::HandshakeState {
        if unsafe { openssl::SSL_get_state(ssl.as_ptr()) }
            == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK
        {
            pb::HandshakeState::HANDSHAKESTATE_DONE
        } else {
            pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS
        }
    }

    fn x509_store_context_get_ssl(
        store_ctx: NonNull<Self::NativeX509StoreCtx>,
    ) -> Option<NonNull<Self::NativeSsl>> {
        let ssl_idx = unsafe { openssl::SSL_get_ex_data_X509_STORE_CTX_idx() };
        if ssl_idx < 0 {
            return None;
        }
        NonNull::new(
            unsafe { openssl::X509_STORE_CTX_get_ex_data(store_ctx.as_ptr(), ssl_idx) }
                .cast::<Self::NativeSsl>(),
        )
    }

    fn x509_store_context_get_error(store_ctx: NonNull<Self::NativeX509StoreCtx>) -> i32 {
        unsafe { openssl::X509_STORE_CTX_get_error(store_ctx.as_ptr()) }
    }

    fn x509_store_context_set_error(store_ctx: NonNull<Self::NativeX509StoreCtx>, error: i32) {
        unsafe {
            openssl::X509_STORE_CTX_set_error(store_ctx.as_ptr(), error);
        }
    }

    fn x509_store_error_code_valid() -> i32 {
        openssl::X509_V_OK as i32
    }

    fn x509_error_code_is_certificate_expired(error: i32) -> bool {
        error == openssl::X509_V_ERR_CERT_HAS_EXPIRED as i32
    }

    fn ssl_get_tunnel_security_requirements<'a>(
        ssl: NonNull<Self::NativeSsl>,
    ) -> Option<&'a tls::TunnelSecurityRequirements> {
        unsafe {
            openssl::SSL_get_ex_data(
                ssl.as_ptr(),
                ossl::VERIFY_TUNNEL_SECURITY_REQUIREMENTS_INDEX,
            )
            .cast::<tls::TunnelSecurityRequirements>()
            .as_ref::<'a>()
        }
    }

    fn ssl_set_last_verify_error(ssl: NonNull<Self::NativeSsl>, err: i32) {
        unsafe {
            openssl::SSL_set_ex_data(
                ssl.as_ptr(),
                ossl::VERIFY_TUNNEL_LAST_VERIFY_ERROR_INDEX,
                err as _,
            );
        }
    }

    fn ssl_get_last_verify_error(ssl: NonNull<Self::NativeSsl>) -> i32 {
        unsafe {
            openssl::SSL_get_ex_data(ssl.as_ptr(), ossl::VERIFY_TUNNEL_LAST_VERIFY_ERROR_INDEX)
                as i32
        }
    }

    fn ssl_get_x509_verify_parameters(
        ssl: NonNull<Self::NativeSsl>,
    ) -> Option<NonNull<Self::NativeX509VerifyParams>> {
        let Some(params) = NonNull::new(unsafe { openssl::SSL_get0_param(ssl.as_ptr()) }) else {
            return None;
        };
        unsafe {
            openssl::X509_VERIFY_PARAM_set_hostflags(
                params.as_ptr(),
                openssl::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
            );
        }
        Some(params)
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
            openssl::X509_VERIFY_PARAM_add1_host(verify_params.as_ptr(), cstr.as_ptr(), dns.len())
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
            openssl::X509_VERIFY_PARAM_set1_email(
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
            openssl::X509_VERIFY_PARAM_set1_ip_asc(verify_params.as_ptr(), cstr.as_ptr())
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

    #[cfg(feature = "tracer")]
    fn ssl_set_msg_callback(
        ssl: NonNull<Self::NativeSsl>,
        cb: Option<
            unsafe extern "C" fn(
                write_p: c_int,
                version: c_int,
                content_type: c_int,
                buf: *const c_void,
                len: usize,
                ssl: *mut Self::NativeSsl,
                arg: *mut c_void,
            ),
        >,
    ) {
        unsafe { openssl::SSL_set_msg_callback(ssl.as_ptr(), cb) };
    }

    #[cfg(feature = "tracer")]
    fn ssl_set_message_callback_arg(
        ssl: NonNull<Self::NativeSsl>,
        tracer: *mut crate::support::tracing::SandwichTracer,
    ) {
        // This is supposed to be a call to "set_msg_callback_arg", but since this is a macro it's not
        // supported by rust-bindgen, so we manually resolve it.
        unsafe {
            openssl::SSL_ctrl(
                ssl.as_ptr(),
                openssl::SSL_CTRL_SET_MSG_CALLBACK_ARG as c_int,
                0,
                tracer.cast(),
            )
        };
    }
}

GenOsslUnitTests!(
    use crate::implementation::ossl::openssl1_1_1::Ossl;
);

#[cfg(test)]
mod additional_tests {
    use super::*;

    /// Tests creation of SSL handles.
    #[test]
    fn test_ssl_creation() {
        let ctx = Ossl::new_ssl_context(Mode::Client).unwrap();

        let ssl = Ossl::new_ssl_handle(&ctx).unwrap();

        let ptr = unsafe { openssl::SSL_get_SSL_CTX(ssl.as_nonnull().as_ptr()) };
        assert_eq!(ptr as *const _, ctx.as_nonnull().as_ptr());

        let ctx = Ossl::new_ssl_context(Mode::Server).unwrap();

        let ssl = Ossl::new_ssl_handle(&ctx).unwrap();

        let ptr = unsafe { openssl::SSL_get_SSL_CTX(ssl.as_nonnull().as_ptr()) };
        assert_eq!(ptr as *const _, ctx.as_nonnull().as_ptr());
    }

    /// Tests [`Ossl::ssl_context_set_verify_mode`].
    #[test]
    fn test_ssl_ctx_set_verify_mode() {
        let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

        let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_nonnull().as_ptr()) };
        assert_eq!(mode, openssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(ssl.as_nonnull(), VerifyMode::Peer);

        let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_nonnull().as_ptr()) };
        assert_eq!(mode, openssl::SSL_VERIFY_PEER as i32);

        Ossl::ssl_context_set_verify_mode(ssl.as_nonnull(), VerifyMode::None);

        let mode = unsafe { openssl::SSL_CTX_get_verify_mode(ssl.as_nonnull().as_ptr()) };
        assert_eq!(mode, openssl::SSL_VERIFY_NONE as i32);
    }
}

#[cfg(test)]
pub(crate) mod additional_test {
    use crate::io::test::MpscIO;
    use crate::test::resolve_runfile;
    use crate::tunnel::{tls, Context};

    use super::get_openssl_name;

    #[test]
    fn test_client() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                    ciphersuite: "TLS_AES_256_GCM_SHA384"
                  >
                  tls12 <
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
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

        let sw_ctx = crate::Context::new();
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = MpscIO::default();

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
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE);
        assert_eq!(tun.state(), pb::State::STATE_HANDSHAKE_IN_PROGRESS);
        let _ = tun.close();
    }

    /// Test tunnel constructor for server.
    #[test]
    fn test_server() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                    ciphersuite: "TLS_AES_256_GCM_SHA384"
                  >
                  tls12 <
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                  >
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
                resolve_runfile(tls::test::CERT_PEM_PATH),
                resolve_runfile(tls::test::SK_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = MpscIO::new();

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
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                    ciphersuite: "TLS_AES_256_GCM_SHA384"
                  >
                  tls12 <
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
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

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                    ciphersuite: "TLS_AES_256_GCM_SHA384"
                  >
                  tls12 <
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                  >
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
                resolve_runfile(tls::test::CERT_PEM_PATH),
                resolve_runfile(tls::test::SK_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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

    /// Tests TLS 1.2 tunnel between client and server.
    #[test]
    fn test_tls12_all() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls12 <
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                    ciphersuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                    ciphersuite: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                    ciphersuite: "TLS_RSA_WITH_AES_256_GCM_SHA384"
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                    ciphersuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    ciphersuite: "TLS_RSA_WITH_AES_128_GCM_SHA256"
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
                resolve_runfile(tls::test::CERT_RSA_PEM_PATH)
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  empty_verifier <>
                  tls12 <
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                    ciphersuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                    ciphersuite: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                    ciphersuite: "TLS_RSA_WITH_AES_256_GCM_SHA384"
                    ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                    ciphersuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    ciphersuite: "TLS_RSA_WITH_AES_128_GCM_SHA256"
                  >
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
                resolve_runfile(tls::test::CERT_RSA_PEM_PATH),
                resolve_runfile(tls::test::RSA_SK_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Tests invalid ciphersuite in TLS 1.2.
    #[test]
    fn test_tls12_ciphersuites_control_chars_invalid() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls12 <
                    ciphersuite: "-TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                  >
                >
              >
            >
            "#,
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        Context::try_from(&sw_ctx, &config).unwrap_err();
    }

    /// Tests invalid ciphersuite in TLS 1.3.
    #[test]
    fn test_tls13_ciphersuites_control_chars_invalid() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                    ciphersuite: "!TLS_AES_256_GCM_SHA384"
                  >
                >
              >
            >
            "#,
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        Context::try_from(&sw_ctx, &config).unwrap_err();
    }

    /// Test tunnel between client and server with an expired certificate.
    #[test]
    fn test_expired() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::CERT_EXPIRED_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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

    /// Test mTLS.
    #[test]
    #[allow(non_snake_case)]
    fn test_mTLS() {
        let server_certificate = resolve_runfile("testdata/dilithium5.cert.pem");
        let server_private_key = resolve_runfile("testdata/dilithium5.key.pem");

        let client_certificate = resolve_runfile("testdata/falcon1024.cert.pem");
        let client_private_key = resolve_runfile("testdata/falcon1024.key.pem");

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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

    /// Test mTLS, but the client doesn't send its identity.
    #[test]
    #[allow(non_snake_case)]
    fn test_mTLS_no_client_cert() {
        let server_certificate = resolve_runfile("testdata/dilithium5.cert.pem");
        let server_private_key = resolve_runfile("testdata/dilithium5.key.pem");

        let client_certificate = resolve_runfile("testdata/falcon1024.cert.pem");

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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

        server.handshake().unwrap_err();
    }

    /// Test tunnel between client and server with an expired certificate,
    /// and `allow_expired_certificate` to true.
    #[test]
    fn test_expired_allow_expired_certificate() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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

    /// Tests the constructor of a tunnel with a empty message for the tunnel verifier.
    #[test]
    fn test_tunnel_no_verifier() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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

        let sw_ctx = crate::Context::new();
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = MpscIO::default();

        let tunnel_configuration = pb_api::TunnelConfiguration::new();
        ctx.new_tunnel(Box::new(io), tunnel_configuration)
            .expect_err(
            "constructing a tunnel with an empty verifier in the tunnel configuration must fail",
        );
    }

    /// Tests the constructor of a tunnel with a valid SAN verifier.
    #[test]
    fn test_tunnel_san_verifier_valid() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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

        let sw_ctx = crate::Context::new();
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = MpscIO::default();

        let tunnel_configuration =
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
        ctx.new_tunnel(Box::new(io), tunnel_configuration)
            .expect("constructing a tunnel with a valid SANVerifier must succeed");
    }

    /// Tests the constructor of a tunnel with an empty SAN verifier.
    #[test]
    fn test_tunnel_empty_san_verifier() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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

        let sw_ctx = crate::Context::new();
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = MpscIO::default();

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <>
                >
            "#,
            )
            .unwrap();
        ctx.new_tunnel(Box::new(io), tunnel_configuration)
            .expect_err("constructing a tunnel with an empty SANVerifier must fail");
    }

    /// Tests the constructor of a tunnel with an invalid SAN verifier.
    #[test]
    fn test_tunnel_san_verifier_invalid() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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

        let sw_ctx = crate::Context::new();
        let ctx = Context::try_from(&sw_ctx, &config).unwrap();
        let io = MpscIO::default();

        let tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            email: "zadig@example.com"
                        >
                        alt_names <
                            email: "user@example.com"
                        >
                    >
                >
            "#,
            )
            .unwrap();
        ctx.new_tunnel(Box::new(io), tunnel_configuration)
            .expect_err("constructing a tunnel with an invalid SANVerifier must fail");
    }

    /// Tests the SAN verifier with a simple dns hostname `example.com` that
    /// matches the SANs in the certificate presented by the server.
    #[test]
    fn test_san_dns_match() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

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

    /// Tests the SAN verifier with a simple email address `user@example.com` that
    /// matches the SANs in the certificate presented by the server.
    #[test]
    fn test_san_email_match() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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
                resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            email: "user@example.com"
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

    /// Tests the SAN verifier with a simple email address `root@example.com` that
    /// doesn't match the SANs in the certificate presented by the server.
    #[test]
    fn test_san_email_mismatch() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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
                resolve_runfile(tls::test::USER_AT_EXAMPLE_COM_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            email: "root@example.com"
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
            .expect_err("handshake must fail because email mistmatch");

        server.handshake().unwrap_err();
    }

    /// Tests the SAN verifier with a simple IP address `127.0.0.1` that
    /// matches the SANs in the certificate presented by the server.
    #[test]
    fn test_san_ip_address_match() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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
                resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            ip_address: "127.0.0.1"
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

    /// Tests the SAN verifier with a simple IP address `127.0.0.2` that
    /// doesn't match the SANs in the certificate presented by the server.
    #[test]
    fn test_san_ip_address_mismatch() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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
                resolve_runfile(tls::test::IP_127_0_0_1_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            ip_address: "127.0.0.2"
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
            .expect_err("handshake must fail because email mistmatch");

        server.handshake().unwrap_err();
    }

    /// Tests the SAN verifier with an email and a certificate being signed
    /// for that email and also a wildcard DNS name.
    #[test]
    fn test_san_email_certificate_email_wildcard_match() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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
                resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            email: "zadig@example.com"
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

    /// Tests the SAN verifier with a DNS name and a certificate being signed
    /// for an email and also a wildcard DNS name that covers the DNS name.
    #[test]
    fn test_san_dns_wildcard_match() {
        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            client <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
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
                resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let client_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            impl: IMPL_OPENSSL1_1_1_OQS
            server <
              tls <
                common_options <
                  tls13 <
                    ke: "kyber512"
                  >
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
                resolve_runfile(tls::test::EMAIL_AND_DNS_WILDCARD_CERT_PATH),
                resolve_runfile(tls::test::PQ_PRIVATE_KEY_PEM_PATH),
            )
            .as_str(),
        )
        .unwrap();

        let sw_ctx = crate::Context::new();
        let server_ctx = Context::try_from(&sw_ctx, &config).unwrap();

        let (client_io, server_io) = MpscIO::new_pair();

        let client_tunnel_configuration =
            protobuf::text_format::parse_from_str::<pb_api::TunnelConfiguration>(
                r#"
                verifier <
                    san_verifier <
                        alt_names <
                            dns: "subdomain.example.com"
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
    /// Tests valid translation from IANA names to OpenSSL names.
    #[test]
    fn test_get_openssl_name_valid() {
        let iana_names = [
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_PSK_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_PSK_WITH_AES_256_CBC_SHA",
        ];

        let openssl_names = [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-PSK-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-PSK-AES128-CBC-SHA",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-PSK-AES256-CBC-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "PSK-AES128-CBC-SHA",
            "AES256-SHA",
            "PSK-AES256-CBC-SHA",
        ];

        let openssl_names_from_iana_names: Vec<&str> = iana_names
            .iter()
            .filter_map(|n| get_openssl_name(n).ok())
            .collect();

        assert_eq!(openssl_names_from_iana_names, openssl_names);
    }

    /// Tests translation from invalid IANA names to OpenSSL names.
    #[test]
    fn test_get_openssl_name_invalid_name() {
        let iana_names = ["AES256-SHA256"];

        let openssl_names: [&str; 0] = [];

        let openssl_names_from_iana_names: Vec<&str> = iana_names
            .iter()
            .filter_map(|n| get_openssl_name(n).ok())
            .collect();

        assert_eq!(openssl_names_from_iana_names, openssl_names);
    }

    /// Tests invalid translation from IANA names with control characters to OpenSSL names.
    #[test]
    fn test_get_openssl_name_invalid_control_chars() {
        let iana_names = ["!AES256-SHA", "@AES256-SHA", "-AES256-SHA", "+AES256-SHA"];

        let openssl_names: [&str; 0] = [];

        let openssl_names_from_iana_names: Vec<&str> = iana_names
            .iter()
            .filter_map(|n| get_openssl_name(n).ok())
            .collect();

        assert_eq!(openssl_names_from_iana_names, openssl_names);
    }
}
