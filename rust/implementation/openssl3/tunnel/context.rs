// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel implementation usiong OpenSSL 3 and oqs-provider.

use std::borrow::Borrow;
use std::ffi::{c_int, CString};
use std::pin::Pin;
use std::ptr::{self, NonNull};

use crate::ossl3::{support, LibCtx};
use crate::support::Pimpl;
use crate::tunnel::tls::{TlsVersion, VerifyMode};
use crate::tunnel::{tls, Mode};
use crate::Result;

use support::{NativePrivateKey, NativeSsl, NativeSslCtx, NativeX509Certificate};

use super::{verify_callback, Tunnel, TunnelBuilder, X509VerifyParam};

/// Tunnel context.
pub struct Context<'a> {
    /// Library context parent.
    _lib_ctx: &'a LibCtx<'a>,

    /// `SSL_CTX` object.
    ssl_ctx: Pimpl<'a, NativeSslCtx>,

    /// Security requirements from the verifiers.
    security_requirements: tls::TunnelSecurityRequirements,

    /// Execution mode.
    mode: Mode,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL3Context(mode={mode:?})", mode = self.mode)
    }
}

impl Borrow<tls::TunnelSecurityRequirements> for Context<'_> {
    fn borrow(&self) -> &tls::TunnelSecurityRequirements {
        &self.security_requirements
    }
}

/// Instantiates a new SSL context (`SSL_CTX`).
fn new_ssl_context<'a, 'b>(ctx: &'a crate::Context, mode: Mode) -> Result<Pimpl<'b, NativeSslCtx>>
where
    'a: 'b,
{
    unsafe {
        Pimpl::new(
            openssl3::SSL_CTX_new_ex(
                ctx.get_openssl3_lib_ctx().as_nonnull().as_ptr(),
                ptr::null(),
                match mode {
                    Mode::Client => openssl3::TLS_client_method(),
                    Mode::Server => openssl3::TLS_server_method(),
                },
            ),
            |ptr| openssl3::SSL_CTX_free(ptr),
        )
    }
    .ok_or_else(|| {
        (
            pb::SystemError::SYSTEMERROR_MEMORY,
            "failed to instantiate a new `SSL_CTX`",
        )
            .into()
    })
}

/// Converts a [`TlsVersion`] into the corresponding OpenSSL symbol.
impl From<TlsVersion> for i64 {
    fn from(tls_version: TlsVersion) -> Self {
        match tls_version {
            TlsVersion::Tls12 => openssl3::TLS1_2_VERSION,
            TlsVersion::Tls13 => openssl3::TLS1_3_VERSION,
        }
        .into()
    }
}

/// Convenient wrapper around a `SSL_CTX`.
struct SslContext(NonNull<NativeSslCtx>);

impl std::fmt::Debug for SslContext {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SslContext({:p})", self.0.as_ptr())
    }
}

impl SslContext {
    /// Disables session caching on a SSL context.
    fn disable_session_cache_mode(&self) {
        // `SSL_CTX_set_session_cache_mode` is a C macro.
        unsafe {
            openssl3::SSL_CTX_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_SET_SESS_CACHE_MODE as i32,
                openssl3::SSL_SESS_CACHE_OFF.into(),
                ptr::null_mut(),
            )
        };
    }

    /// Defines the minimum TLS version to use.
    fn set_minimum_tls_version(&self, version: TlsVersion) -> Result<()> {
        // `SSL_CTX_set_min_proto_version` is a C macro.
        if unsafe {
            openssl3::SSL_CTX_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_SET_MIN_PROTO_VERSION as i32,
                version.into(),
                ptr::null_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION,
                format!(
                    "failed to set the minimum TLS version: {}",
                    support::errstr()
                ),
            )
                .into())
        }
    }

    /// Defines the maximum TLS version to use.
    fn set_maximum_tls_version(&self, version: TlsVersion) -> Result<()> {
        // `SSL_CTX_set_max_proto_version` is a C macro.
        if unsafe {
            openssl3::SSL_CTX_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_SET_MAX_PROTO_VERSION as i32,
                version.into(),
                ptr::null_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION,
                format!(
                    "failed to set the maximum TLS version: {}",
                    support::errstr()
                ),
            )
                .into())
        }
    }

    /// Sets the minimum and the maximum TLS versions to use.
    fn set_min_and_max_tls_version(&self, tls_options: &pb_api::TLSOptions) -> Result<()> {
        let (min_version, max_version) =
            tls::support::tls_options_get_min_max_tls_version(tls_options);
        self.set_minimum_tls_version(min_version)?;
        self.set_maximum_tls_version(max_version)
    }

    /// Initializes the trusted certificate store.
    fn initialize_trusted_cert_store(&self) -> Result<()> {
        let x509_store = NonNull::new(unsafe { openssl3::X509_STORE_new() }).ok_or((
            pb::SystemError::SYSTEMERROR_MEMORY,
            "failed to instantiate an X509_STORE",
        ))?;

        unsafe {
            openssl3::SSL_CTX_set_cert_store(self.0.as_ptr(), x509_store.as_ptr());
            openssl3::X509_STORE_set_trust(
                x509_store.as_ptr(),
                openssl3::X509_VP_FLAG_DEFAULT as i32,
            );
        }

        Ok(())
    }

    /// Sets the `SSL_MODE_RELEASE_BUFFERS` option.
    ///
    /// See <https://www.openssl.org/docs/man3.2/man3/SSL_CTX_set_mode.html#SSL_MODE_RELEASE_BUFFERS>
    /// for more information.
    fn set_mode_release_buffers(&self) {
        // `SSL_CTX_set_mode` is a C macro.
        unsafe {
            openssl3::SSL_CTX_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_MODE as c_int,
                openssl3::SSL_MODE_RELEASE_BUFFERS.into(),
                ptr::null_mut(),
            )
        };
    }

    /// Sets the default parameters for a SSL context.
    fn set_default_parameters(&self) -> Result<()> {
        const ENABLED: i32 = 1;

        unsafe {
            openssl3::SSL_CTX_set_quiet_shutdown(self.0.as_ptr(), ENABLED);
        }

        self.disable_session_cache_mode();
        self.set_mode_release_buffers();
        self.initialize_trusted_cert_store()
    }

    /// Sets the list of available ciphers.
    /// This function is only used for TLS 1.2.
    /// Names will be converted to OpenSSL names using `OPENSSL_cipher_name`.
    fn set_cipher_list<S>(&self, ciphers: impl IntoIterator<Item = S>) -> Result<()>
    where
        S: AsRef<str>,
    {
        let ciphersuites = tls::support::build_ciphersuites_list(
            ciphers.into_iter().filter_map(support::cipher_name),
            "!+@-",
        )?;
        let cstr = CString::new(ciphersuites).map_err(|e| {
            (
                pb::SystemError::SYSTEMERROR_MEMORY,
                format!("failed to build a `CString`: {e}"),
            )
        })?;
        if unsafe { openssl3::SSL_CTX_set_cipher_list(self.0.as_ptr(), cstr.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err((
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE,
                format!("failed to set the cipher list: {}", support::errstr()),
            )
                .into())
        }
    }

    /// Sets the list of available ciphers using the default list provided
    /// by OpenSSL.
    /// This function is only useful for TLS 1.2.
    fn set_default_cipher_list(&self) -> Result<()> {
        let cstr =
            NonNull::new(unsafe { openssl3::OSSL_default_cipher_list() }.cast_mut()).ok_or((
                pb::SystemError::SYSTEMERROR_BACKEND,
                "`OSSL_default_cipher_list` returned NULL",
            ))?;
        if unsafe { openssl3::SSL_CTX_set_cipher_list(self.0.as_ptr(), cstr.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err((
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE,
                format!("failed to set the cipher list: {}", support::errstr()),
            )
                .into())
        }
    }

    /// Sets the list of available ciphersuites for TLS 1.3.
    fn set_ciphersuites<S>(&self, ciphers: impl IntoIterator<Item = S>) -> Result<()>
    where
        S: AsRef<str>,
    {
        let control_string = tls::support::build_ciphersuites_list(ciphers, "!+@-")?;

        let cstr = CString::new(control_string).map_err(|e| {
            (
                pb::SystemError::SYSTEMERROR_MEMORY,
                format!("failed to build a `CString`: {e}"),
            )
        })?;
        if unsafe { openssl3::SSL_CTX_set_ciphersuites(self.0.as_ptr(), cstr.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err((
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE,
                format!("failed to set the ciphersuites: {}", support::errstr()),
            )
                .into())
        }
    }

    /// Sets the list of available ciphersuites using the default list provided
    /// by OpenSSL.
    /// This function is only useful for TLS 1.3.
    fn set_default_ciphersuites(&self) -> Result<()> {
        let cstr = NonNull::new(unsafe { openssl3::OSSL_default_ciphersuites() }.cast_mut())
            .ok_or((
                pb::SystemError::SYSTEMERROR_BACKEND,
                "`OSSL_default_ciphersuites` returned NULL",
            ))?;
        if unsafe { openssl3::SSL_CTX_set_ciphersuites(self.0.as_ptr(), cstr.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err((
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CIPHERSUITE,
                format!("failed to set the ciphersuites: {}", support::errstr()),
            )
                .into())
        }
    }

    /// Configures TLS 1.2.
    fn configure_tls12(&self, tls12_config: Option<&pb_api::TLSv12Config>) -> Result<()> {
        let Some(config) = tls12_config else {
            return Ok(());
        };
        if config.ciphersuite.is_empty() {
            self.set_default_cipher_list()?;
        } else {
            self.set_cipher_list(&config.ciphersuite)?;
        }

        Ok(())
    }

    /// Configures TLS 1.3.
    fn configure_tls13(&self, tls13_config: Option<&pb_api::TLSv13Config>) -> Result<()> {
        let Some(config) = tls13_config else {
            return Ok(());
        };

        self.set_kes(&config.ke)?;

        if config.ciphersuite.is_empty() {
            self.set_default_ciphersuites()?;
        } else {
            self.set_ciphersuites(&config.ciphersuite)?;
        }

        Ok(())
    }

    /// Sets the KEs to an SSL context.
    fn set_kes(&self, kes: &[impl AsRef<str>]) -> Result<()> {
        if kes.is_empty() {
            return Err((pb::KEMError::KEMERROR_INVALID, "no KE specified").into());
        }

        let list = CString::new(kes.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(":"))
            .map_err(|e| {
                (
                    pb::SystemError::SYSTEMERROR_MEMORY,
                    format!("failed to create the string list of KEs: {e}"),
                )
            })?;

        // `SSL_CTX_set1_groups_list` is a C macro.
        if unsafe {
            openssl3::SSL_CTX_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_SET_GROUPS_LIST as i32,
                0,
                list.as_ptr().cast_mut().cast(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err((pb::KEMError::KEMERROR_INVALID, support::errstr()).into())
        }
    }

    /// Sets supported application protocols (ALPN).
    fn set_alpn_protocols<S>(&self, protocols: impl IntoIterator<Item = S>) -> Result<()>
    where
        S: AsRef<str>,
    {
        let mut protos = String::new();
        for proto in protocols.into_iter() {
            let proto = proto.as_ref();
            let x: u8 = proto.len().try_into().map_err(|_| {
                (
                    pb::ALPNError::ALPNERROR_LENGTH_ERROR,
                    "ALPN length overflow",
                )
            })?;
            if x == 0 {
                return Err((
                    pb::ALPNError::ALPNERROR_LENGTH_ERROR,
                    "ALPN length erro: empty",
                )
                    .into());
            }
            if proto.contains('\0') {
                return Err((
                    pb::ALPNError::ALPNERROR_INVALID_STRING,
                    "string cannot contain null bytes",
                )
                    .into());
            }
            protos.push(x as char);
            protos.push_str(proto);
        }

        let len: u32 = protos.len().try_into().map_err(|_| {
            (
                pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW,
                "protos string is too large",
            )
        })?;
        let cstr = CString::new(protos.as_bytes()).map_err(|e| {
            (
                pb::SystemError::SYSTEMERROR_MEMORY,
                format!("failed to create a CString: {e}"),
            )
        })?;
        if unsafe { openssl3::SSL_CTX_set_alpn_protos(self.0.as_ptr(), cstr.as_ptr().cast(), len) }
            == 0
        {
            Ok(())
        } else {
            Err(pb::ALPNError::ALPNERROR_INVALID_STRING.into())
        }
    }

    /// Sets the certificate to use when the remote peer requests an authentication.
    /// This is used in server mode and in client mode when mTLS is enabled.
    fn set_certificate(&self, certificate: NonNull<NativeX509Certificate>) -> Result<()> {
        if unsafe { openssl3::SSL_CTX_use_certificate(self.0.as_ptr(), certificate.as_ptr()) } == 1
        {
            Ok(())
        } else {
            Err((
                pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED,
                format!(
                    "failed to use certificate for authentication: {}",
                    support::errstr()
                ),
            )
                .into())
        }
    }

    /// Sets the private key to use when the remote peer is requesting an authentication.
    /// This is used in server mode and in clinet mode when mTLS is enabled.
    ///
    /// This method also checks the consistency between the provided certificate
    /// and the private key.
    /// The certificate is provided using [`SslContext::set_certificate`].
    fn set_private_key(&self, private_key: NonNull<NativePrivateKey>) -> Result<()> {
        if unsafe { openssl3::SSL_CTX_use_PrivateKey(self.0.as_ptr(), private_key.as_ptr()) } != 1 {
            return Err((
                pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED,
                format!(
                    "failed to use private key for authentication: {}",
                    support::errstr()
                ),
            )
                .into());
        };

        if unsafe { openssl3::SSL_CTX_check_private_key(self.0.as_ptr()) } == 1 {
            Ok(())
        } else {
            Err((pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE,
                format!("private key does not match certificate: {}", support::errstr())).into())
        }
    }

    /// Appends a certificate to the certificate chain the peer is going to expose
    /// to remote.
    ///
    /// This function takes a [`Pimpl`] as input since [`SSL_CTX_add_extra_chain_cert`]
    /// takes the ownership of the `X509` object.
    fn add_extra_chain_cert<'a, 'b>(
        &self,
        extra_certificate: Pimpl<'b, NativeX509Certificate>,
    ) -> Result<()>
    where
        'a: 'b,
    {
        // `SSL_CTX_add_extra_chain_cert` is a C macro.
        if unsafe {
            openssl3::SSL_CTX_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_EXTRA_CHAIN_CERT as c_int,
                0,
                extra_certificate.as_nonnull().as_ptr().cast(),
            )
        } == 1
        {
            // [`SSL_CTX_add_extra_chain_cert`] takes the ownership of the given
            // `X509` object.
            extra_certificate.into_raw();
            Ok(())
        } else {
            Err((
                pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED,
                format!(
                    "failed to add an extra certificate to the certificate chain: {}",
                    support::errstr()
                ),
            )
                .into())
        }
    }

    /// Sets the X.509 identity to use.
    /// If the client sets an X.509 identity, then it will expect a client
    /// certificate request from the server, in order to establish a mutual
    /// TLS tunnel (mTLS).
    fn set_identity(
        &self,
        lib_ctx: &LibCtx<'_>,
        identity: Option<&pb_api::X509Identity>,
    ) -> Result<()> {
        let Some(identity) = identity else {
            return Ok(());
        };
        let (certificate_chain_format, data_source) = identity
            .certificate
            .as_ref()
            .ok_or(pb::CertificateError::CERTIFICATEERROR_MALFORMED.into())
            .and_then(tls::support::configuration_read_certificate)
            .map_err(|e| e >> pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;
        let cert_chain_bio = support::BIO_from_buffer(&data_source)?;
        let leaf_certificate = support::X509_from_BIO(
            lib_ctx,
            cert_chain_bio.as_nonnull(),
            certificate_chain_format,
        )?;
        self.set_certificate(leaf_certificate.as_nonnull())?;

        let (format, data_source) = identity
            .private_key
            .as_ref()
            .ok_or(pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED.into())
            .and_then(tls::support::configuration_read_private_key)
            .map_err(|e| e >> pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;
        let bio = support::BIO_from_buffer(&data_source)?;
        let private_key = support::EVP_PKEY_from_BIO(lib_ctx, bio.as_nonnull(), format)?;
        self.set_private_key(private_key.as_nonnull())?;

        while !support::is_BIO_eof(cert_chain_bio.as_nonnull()) {
            let certificate_in_chain = support::X509_from_BIO(
                lib_ctx,
                cert_chain_bio.as_nonnull(),
                certificate_chain_format,
            )?;
            self.add_extra_chain_cert(certificate_in_chain)?;
        }

        Ok(())
    }

    /// Imports the trusted certificates from the protobuf configuration to the
    /// OpenSSL SSL context.
    fn fill_certificate_trust_store(
        &self,
        lib_ctx: &LibCtx<'_>,
        x509_verifier: Option<&pb_api::X509Verifier>,
    ) -> Result<()> {
        let Some(x509_verifier) = x509_verifier else {
            return Ok(());
        };

        let store = NonNull::new(unsafe { openssl3::SSL_CTX_get_cert_store(self.0.as_ptr()) })
            .ok_or((
                pb::SystemError::SYSTEMERROR_MEMORY,
                "SSL_CTX does not have a certificate store",
            ))?;

        for certificate in x509_verifier.trusted_cas.iter() {
            let (format, data_source) = tls::support::configuration_read_certificate(certificate)?;
            let bio = support::BIO_from_buffer(&data_source)?;

            while !support::is_BIO_eof(bio.as_nonnull()) {
                let x509 = support::X509_from_BIO(lib_ctx, bio.as_nonnull(), format)?;
                unsafe {
                    openssl3::X509_STORE_add_cert(store.as_ptr(), x509.as_nonnull().as_ptr())
                };
            }
        }

        Ok(())
    }

    /// Sets the verification mode.
    ///
    /// If a `X509Verifier` structure is present in the protobuf configuration,
    /// then `SSL_VERIFY_PEER` is used in client mode, and `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`
    /// is used in server mode.
    fn set_verify_mode(&self, verify_mode: VerifyMode) {
        let flag = match verify_mode {
            VerifyMode::None => openssl3::SSL_VERIFY_NONE,
            VerifyMode::Peer => openssl3::SSL_VERIFY_PEER,
            VerifyMode::Mutual => {
                openssl3::SSL_VERIFY_PEER | openssl3::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            }
        };
        unsafe {
            openssl3::SSL_CTX_set_verify(self.0.as_ptr(), flag as i32, Some(verify_callback));
        }
    }
}

/// Instantiates a new SSL object from an SSL context.
///
/// `Pimpl` is passed here instead of the regular `NonNull` to enforce the lifetime
/// of the resulting SSL object.
fn ssl_context_new_ssl<'a, 'b>(
    ssl_context: &Pimpl<'a, NativeSslCtx>,
) -> Result<Pimpl<'b, NativeSsl>>
where
    'a: 'b,
{
    unsafe {
        Pimpl::new(openssl3::SSL_new(ssl_context.as_nonnull().as_ptr()), |x| {
            openssl3::SSL_free(x)
        })
    }
    .ok_or_else(|| {
        (
            pb::SystemError::SYSTEMERROR_MEMORY,
            format!("failed to instantiate a new SSL: {}", support::errstr()),
        )
            .into()
    })
}

/// Determines the verify mode depending on the mode and the existence of a
/// X509Verifier structure in the protobuf configuration.
fn get_verify_mode_from_mode_and_x509_verifier(
    mode: Mode,
    x509_verifier: Option<&pb_api::X509Verifier>,
) -> VerifyMode {
    if x509_verifier.is_none() {
        VerifyMode::None
    } else if mode == Mode::Client {
        VerifyMode::Peer
    } else {
        VerifyMode::Mutual
    }
}

/// A boxed and pinned tunnel.
pub(crate) type PinnedTunnel<'a> = Pin<Box<Tunnel<'a>>>;

impl<'a> Context<'a> {
    /// Instantiates a new [`Context`] from a [protobuf configuration](`pb_api::Configuration`)
    /// and a top-level context.
    pub(crate) fn try_from<'b>(
        ctx: &'a crate::Context,
        configuration: &pb_api::Configuration,
    ) -> Result<Self>
    where
        'b: 'a,
    {
        let lib_ctx = ctx.borrow();
        let (mode, tls_options) = tls::support::configuration_get_mode_and_options(configuration)?;
        let ssl_ctx = new_ssl_context(ctx, mode)?;
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        ssl_ctx_wrapped.set_default_parameters()?;
        ssl_ctx_wrapped.set_min_and_max_tls_version(tls_options)?;
        ssl_ctx_wrapped.configure_tls12(tls_options.tls12.as_ref())?;
        ssl_ctx_wrapped.configure_tls13(tls_options.tls13.as_ref())?;
        ssl_ctx_wrapped.set_alpn_protocols(tls_options.alpn_protocols.iter())?;

        let x509_verify_param = X509VerifyParam::try_from(&ssl_ctx)?;
        x509_verify_param.set_default_parameters()?;

        let x509_verifier = tls::support::tls_options_get_x509_verifier(tls_options)
            .and_then(tls::support::x509_verifier_verify_emptiness)?;
        x509_verify_param
            .update_certificate_chain_validation_depth_from_x509_verifier(x509_verifier);

        ssl_ctx_wrapped.set_identity(lib_ctx, tls_options.identity.as_ref())?;
        ssl_ctx_wrapped.fill_certificate_trust_store(lib_ctx, x509_verifier)?;

        let verify_mode = get_verify_mode_from_mode_and_x509_verifier(mode, x509_verifier);
        ssl_ctx_wrapped.set_verify_mode(verify_mode);

        let security_requirements = x509_verifier
            .map(tls::TunnelSecurityRequirements::from)
            .unwrap_or_default();

        Ok(Self {
            _lib_ctx: lib_ctx,
            mode,
            security_requirements,
            ssl_ctx,
        })
    }

    /// Instantiates a new SSL object.
    pub(crate) fn new_ssl<'b>(&self) -> Result<Pimpl<'b, NativeSsl>>
    where
        'a: 'b,
    {
        let ssl = ssl_context_new_ssl(&self.ssl_ctx)?;
        match self.mode {
            Mode::Client => unsafe { openssl3::SSL_set_connect_state(ssl.as_nonnull().as_ptr()) },
            Mode::Server => unsafe { openssl3::SSL_set_accept_state(ssl.as_nonnull().as_ptr()) },
        };
        Ok(ssl)
    }

    /// Returns the security requirements of the context.
    pub(crate) fn security_requirements(&self) -> &tls::TunnelSecurityRequirements {
        self.borrow()
    }

    /// Creates a new tunnel.
    pub(crate) fn new_tunnel(
        &self,
        io: Box<dyn crate::IO>,
        configuration: pb_api::TunnelConfiguration,
    ) -> std::result::Result<PinnedTunnel<'_>, (crate::Error, Box<dyn crate::IO>)> {
        TunnelBuilder {
            ssl_ctx: self,
            io,
            configuration,
        }
        .build()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Returns the maximum depth for certificate chain validation.
    fn ssl_context_get_verify_depth(ssl_ctx: NonNull<NativeSslCtx>) -> i32 {
        unsafe { openssl3::SSL_CTX_get_verify_depth(ssl_ctx.as_ptr()) }
    }

    /// Tests [`new_ssl_context`] in client mode.
    #[test]
    fn test_new_ssl_context_client() {
        let ctx = crate::Context::default();

        new_ssl_context(&ctx, Mode::Client).unwrap();
    }

    /// Tests [`new_ssl_context`] in server mode.
    #[test]
    fn test_new_ssl_context_server() {
        let ctx = crate::Context::default();

        new_ssl_context(&ctx, Mode::Server).unwrap();
    }

    /// Tests [`SslContext::disable_session_cache_mode`].
    #[test]
    fn test_ssl_context_disable_session_cache_mode() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        ssl_ctx_wrapped.disable_session_cache_mode();

        let result = unsafe {
            // `SSL_CTX_get_session_cache_mode` is a C macro.
            openssl3::SSL_CTX_ctrl(
                ssl_ctx.as_nonnull().as_ptr(),
                openssl3::SSL_CTRL_GET_SESS_CACHE_MODE as i32,
                0,
                ptr::null_mut(),
            )
        };

        assert_eq!(result, openssl3::SSL_SESS_CACHE_OFF.into());
    }

    /// Tests [`SslContext::set_minimum_version`].
    #[test]
    fn test_ssl_context_set_minimum_version() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let result = ssl_ctx_wrapped.set_minimum_tls_version(TlsVersion::Tls13);

        let min_proto = unsafe {
            // `SSL_CTX_get_min_proto_version` is a C macro.
            openssl3::SSL_CTX_ctrl(
                ssl_ctx.as_nonnull().as_ptr(),
                openssl3::SSL_CTRL_GET_MIN_PROTO_VERSION as i32,
                0,
                ptr::null_mut(),
            )
        };

        result.expect("fail to set minimum version for TLS protocol");
        assert_eq!(min_proto, openssl3::TLS1_3_VERSION.into());
    }

    /// Tests [`SslContext::initialize_trusted_cert_store`].
    #[test]
    fn test_ssl_context_initialize_trusted_cert_store() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let result_init = ssl_ctx_wrapped.initialize_trusted_cert_store();

        let result = NonNull::new(unsafe {
            openssl3::SSL_CTX_get_cert_store(ssl_ctx.as_nonnull().as_ptr())
        });

        result_init.expect("`SslContext::initialize_trusted_cert_store` failed");
        result.expect("certificate store is NULL");
    }

    /// Tests [`SslContext::set_default_parameters`].
    #[test]
    fn test_ssl_context_set_default_parameters() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.set_default_parameters();

        result.expect("`SslContext::set_default_parameters` failed");
    }

    /// Tests [`SslContext::set_ciphersuites`].

    /// Tests [`SslContext::set_kes`].
    #[test]
    #[allow(non_snake_case)]
    fn test_ssl_context_set_KEs() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.set_kes(&["X25519", "kyber768"]);

        result.expect("`SslContext::set_kes` failed");
    }

    /// Tests [`SslContext::set_kes`] with invalid KE.
    #[test]
    #[allow(non_snake_case)]
    fn test_ssl_context_set_KEs_invalid() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.set_kes(&["X25519", "kyber1337"]);

        let err = result.expect_err("`SslContext::set_kes` succeed");
        let e = err.iter().next().unwrap();
        let msg = e.msg().unwrap();
        assert!(msg.contains("group 'kyber1337' cannot be set"));
    }

    /// Tests [`SslContext::set_kes`] with no KE.
    #[test]
    #[allow(non_snake_case)]
    fn test_ssl_context_set_KEs_empty() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let empty: [&str; 0] = [];
        let result = ssl_ctx_wrapped.set_kes(&empty);

        let err = result.expect_err("`SslContext::set_kes` succeed");
        let e = err.iter().next().unwrap();
        let msg = e.msg().unwrap();
        assert!(msg.contains("no KE specified"));
    }

    /// Tests [`SslContext::set_alpn_protocols`].
    #[test]
    fn test_ssl_context_set_alpn_protocols() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.set_alpn_protocols(["http/1.1", "h2", "h3", "h2c"]);

        result.expect("`SslContext::set_alpn_protocols` failed");
    }

    /// Tests [`SslContext::set_alpn_protocols`] with a protocol containing a null byte.
    #[test]
    fn test_ssl_context_set_alpn_protocols_invalid_null_byte() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.set_alpn_protocols(["http/1.1", "h\x002"]);

        let err = result.expect_err("`SslContext::set_alpn_protocols` succeed");
        let e = err.iter().next().unwrap();
        let msg = e.msg().unwrap();
        assert!(msg.contains("string cannot contain null bytes"));
    }

    /// Tests [`SslContext::set_alpn_protocols`] with a protocol name of length > 255.
    #[test]
    fn test_ssl_context_set_alpn_protocols_invalid_too_long() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.set_alpn_protocols(["a".repeat(256)]);

        let err = result.expect_err("`SslContext::set_alpn_protocols` succeed");
        let e = err.iter().next().unwrap();
        let msg = e.msg().unwrap();
        assert!(msg.contains("ALPN length overflow"));
    }

    /// Tests [`SslContext::set_certificate`].
    #[test]
    fn test_ssl_context_set_certificate() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let cert = support::test::get_certificate_from_testdata_file(
            ctx.borrow(),
            "testdata/falcon1024.cert.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
        .unwrap();

        let result = ssl_ctx_wrapped.set_certificate(cert.as_nonnull());

        result.expect("`SslContext::set_certificate` failed");
    }

    /// Tests [`SslContext::set_private_key`].
    #[test]
    fn test_ssl_context_set_private_key() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let cert = support::test::get_certificate_from_testdata_file(
            ctx.borrow(),
            "testdata/falcon1024.cert.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
        .unwrap();
        ssl_ctx_wrapped.set_certificate(cert.as_nonnull()).unwrap();
        let private_key = support::test::get_private_key_from_testdata_file(
            ctx.borrow(),
            "testdata/falcon1024.key.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
        .unwrap();

        let result = ssl_ctx_wrapped.set_private_key(private_key.as_nonnull());

        result.expect("`SslContext::set_private_key` failed");
    }

    /// Tests [`SslContext::set_private_key`] with inconsistent (certificate, private_key).
    #[test]
    fn test_ssl_context_set_private_key_inconsistent() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let cert = support::test::get_certificate_from_testdata_file(
            ctx.borrow(),
            "testdata/falcon1024.cert.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
        .unwrap();
        ssl_ctx_wrapped.set_certificate(cert.as_nonnull()).unwrap();
        let private_key = support::test::get_private_key_from_testdata_file(
            ctx.borrow(),
            "testdata/dilithium5.key.der",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER,
        )
        .unwrap();

        let result = ssl_ctx_wrapped.set_private_key(private_key.as_nonnull());

        let err = result.expect_err("`SslContext::set_private_key` succeed");
        assert!(err.is(&errors!{pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE}));
    }

    /// Tests [`SslContext::add_extra_chain_cert`].
    #[test]
    fn test_ssl_context_add_extra_chain_cert() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let cert = support::test::get_certificate_from_testdata_file(
            ctx.borrow(),
            "testdata/falcon1024.cert.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
        .unwrap();
        ssl_ctx_wrapped.set_certificate(cert.as_nonnull()).unwrap();

        let result = ssl_ctx_wrapped.add_extra_chain_cert(cert);

        result.expect("`SslContext::add_extra_chain_cert` failed");
    }

    /// Tests [`SslContext::set_identity`].
    #[test]
    fn test_ssl_context_set_identity() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let identity = tls::support::test::create_x509_identity(
            "testdata/falcon1024.cert.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            "testdata/falcon1024.key.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        );

        let result = ssl_ctx_wrapped.set_identity(ctx.borrow(), Some(&identity));

        result.expect("`SslContext::set_identity` failed");
    }

    /// Tests [`SslContext::set_identity`] with inconsistent certificate/key.
    #[test]
    fn test_ssl_context_set_identity_inconsistent() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let identity = tls::support::test::create_x509_identity(
            "testdata/falcon1024.cert.pem",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            "testdata/dilithium5.key.der",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER,
        );

        let result = ssl_ctx_wrapped.set_identity(ctx.borrow(), Some(&identity));

        let err = result.expect_err("`SslContext::set_identity` succeed");
        assert!(err.is(&errors!{pb::TLSConfigurationError::TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE}));
    }

    /// Tests [`SslContext::fill_certificate_trust_store`].
    #[test]
    fn test_ssl_context_fill_certificate_trust_store() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let x509_verifier = tls::support::test::create_x509_verifier(
            [(
                "testdata/etc_ssl_cert.pem",
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            )],
            false,
            4u32,
        );

        let result =
            ssl_ctx_wrapped.fill_certificate_trust_store(ctx.borrow(), Some(&x509_verifier));

        result.expect("`SslContext::fill_certificate_trust_store` failed");
    }

    /// Tests [`SslContext::fill_certificate_trust_store`] with no X509Verifier.
    #[test]
    fn test_ssl_context_fill_certificate_trust_store_no_x509_verifier() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());

        let result = ssl_ctx_wrapped.fill_certificate_trust_store(ctx.borrow(), None);

        result.expect("`SslContext::fill_certificate_trust_store` failed");
    }

    /// Tests [`SslContext::fill_certificate_trust_store`] with an invalid
    /// certificate in the middle of the list.
    #[test]
    fn test_ssl_context_fill_certificate_trust_store_invalid() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();
        let ssl_ctx_wrapped = SslContext(ssl_ctx.as_nonnull());
        let x509_verifier = tls::support::test::create_x509_verifier(
            [(
                "testdata/etc_ssl_cert_invalid.pem",
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            )],
            false,
            4u32,
        );

        let result =
            ssl_ctx_wrapped.fill_certificate_trust_store(ctx.borrow(), Some(&x509_verifier));

        let err = result.expect_err("`SslContext::fill_certificate_trust_store` succeed");
        assert!(err.is(&errors! {pb::CertificateError::CERTIFICATEERROR_MALFORMED}));
    }

    /// Tests [`get_verify_mode_from_mode_and_x509_verifier`] in client mode
    /// with an X509 verifier.
    #[test]
    fn test_get_verify_mode_from_mode_and_x509_verifier_client() {
        let x509_verifier = tls::support::test::create_x509_verifier(
            [(
                "testdata/etc_ssl_cert.pem",
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            )],
            false,
            4u32,
        );

        let result =
            get_verify_mode_from_mode_and_x509_verifier(Mode::Client, Some(&x509_verifier));

        assert_eq!(result, VerifyMode::Peer);
    }

    /// Tests [`get_verify_mode_from_mode_and_x509_verifier`] in client mode
    /// with an no X509 verifier.
    #[test]
    fn test_get_verify_mode_from_mode_and_x509_verifier_client_no_verifier() {
        let result = get_verify_mode_from_mode_and_x509_verifier(Mode::Client, None);

        assert_eq!(result, VerifyMode::None);
    }

    /// Tests [`get_verify_mode_from_mode_and_x509_verifier`] in server mode
    /// with no X509 verifier.
    #[test]
    fn test_get_verify_mode_from_mode_and_x509_verifier_server_no_verifier() {
        let result = get_verify_mode_from_mode_and_x509_verifier(Mode::Server, None);

        assert_eq!(result, VerifyMode::None);
    }

    /// Tests [`get_verify_mode_from_mode_and_x509_verifier`] in server mode
    /// with an X509 verifier (mTLS).
    #[allow(non_snake_case)]
    #[test]
    fn test_get_verify_mode_from_mode_and_x509_verifier_server_mTLS() {
        let x509_verifier = tls::support::test::create_x509_verifier(
            [(
                "testdata/etc_ssl_cert.pem",
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            )],
            false,
            4u32,
        );

        let result =
            get_verify_mode_from_mode_and_x509_verifier(Mode::Server, Some(&x509_verifier));

        assert_eq!(result, VerifyMode::Mutual);
    }

    /// Tests [`ssl_context_new_ssl`].
    #[test]
    fn test_ssl_context_new_ssl() {
        let ctx = crate::Context::default();
        let ssl_ctx = new_ssl_context(&ctx, Mode::Client).unwrap();

        let result = ssl_context_new_ssl(&ssl_ctx);

        result.expect("`ssl_context_new_ssl` failed");
    }

    /// Tests [`TryFrom`] for [`Context`].
    #[test]
    fn test_context_try_from() {
        let ctx = crate::Context::default();
        let configuration =
            protobuf::text_format::parse_from_str::<pb_api::Configuration>(&format!(
                r#"
                impl: IMPL_OPENSSL3_OQS_PROVIDER
                client <
                    tls <
                        common_options <
                            tls13 <
                                ke: "X25519"
                                ke: "kyber768"
                            >
                            x509_verifier <
                                trusted_cas <
                                    static <
                                        data <
                                            filename: "{etc_ssl_cert_pem}"
                                        >
                                        format: ENCODING_FORMAT_PEM
                                    >
                                >
                                max_verify_depth: 42
                            >
                            identity <
                                certificate <
                                    static <
                                        data <
                                            filename: "{certificate_file}"
                                        >
                                        format: ENCODING_FORMAT_PEM
                                    >
                                >
                                private_key <
                                    static <
                                        data <
                                            filename: "{private_key_file}"
                                        >
                                        format: ENCODING_FORMAT_PEM
                                    >
                                >
                            >
                            alpn_protocols: "http/1.1"
                        >
                    >
                >
            "#,
                etc_ssl_cert_pem =
                    crate::test::resolve_runfile("testdata/etc_ssl_cert.pem"),
                certificate_file =
                    crate::test::resolve_runfile("testdata/falcon1024.cert.pem"),
                private_key_file =
                    crate::test::resolve_runfile("testdata/falcon1024.key.pem"),
            ))
            .unwrap();

        let result = Context::try_from(&ctx, &configuration);

        let context = result.expect("`try_from` failed");
        assert_eq!(
            ssl_context_get_verify_depth(context.ssl_ctx.as_nonnull()),
            42
        );
    }
}
