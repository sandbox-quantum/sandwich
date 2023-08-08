// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Ossl`] trait, the OpenSSL trait, to support multiple OpenSSL-like implementation.
//!
//! This trait aims to ease the support of multiple OpenSSL-like implementations,
//! such as BoringSSL, LibreSSL and OpenSSL.

use std::borrow::{Borrow, BorrowMut};

use pb::{CertificateError, DataSourceError, PrivateKeyError, RecordError, TLSConfigurationError};

use crate::support::{DataSource, Pimpl};
use crate::tunnel::{tls, Mode};

/// Default maximum depth for the certificate chain verification.
const DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH: u32 = 100;

/// User-data index of the tunnel in the SSL handle.
/// For more information, see <https://www.openssl.org/docs/man1.1.1/man3/SSL_get_ex_data.html>.
const VERIFY_TUNNEL_INDEX: i32 = 0;

/// Verify mode.
pub(crate) enum VerifyMode {
    /// Do not verify anything.
    ///
    ///  - Server mode TLS: the server will not send a client certificate
    ///    request.
    ///  - Server mode mTLS: undefined behavior.
    ///  - Client mode TLS/mTLS: The client will discard the verification result.
    None,

    /// Verify peer.
    ///
    ///  - Server mode: undefined behavior.
    ///  - Client mode: the handshake will immediately fail if the verification
    ///    of the certificate chain is unsuccessful.
    Peer,

    /// Mutual TLS.
    ///
    ///  - Server mode: enable mTLS
    ///  - Client mode: undefined behavior.
    Mutual,
}

/// Trait that supports various OpenSSL-like implementations.
pub(crate) trait Ossl {
    /// The C type for a certificate.
    type NativeCertificate: 'static;

    /// The C type for a private key.
    type NativePrivateKey: 'static;

    /// The C type for a SSL context (SSL_CTX).
    type NativeSslCtx: 'static;

    /// The C type for a SSL handle (SSL).
    type NativeSsl;

    /// The C type for a X.509 trusted store context.
    type NativeX509StoreCtx;

    /// The C type for some verification parameters (X509_VERIFY_PARAM).
    type NativeX509VerifyParams;

    /// The C type for a BIO object.
    type NativeBio;

    /// Creates a new SSL context.
    fn new_ssl_context(mode: Mode) -> crate::Result<Pimpl<'static, Self::NativeSslCtx>>;

    /// Sets the verify mode to a SSL context.
    fn ssl_context_set_verify_mode(pimpl: &mut Pimpl<'_, Self::NativeSslCtx>, mode: VerifyMode);

    /// Sets the maximum depth for the certificate chain verification.
    fn ssl_context_set_verify_depth(pimpl: &mut Pimpl<'_, Self::NativeSslCtx>, depth: u32);

    /// Sets the KEM to a SSL context.
    fn ssl_context_set_kems(
        ssl_ctx: &mut Pimpl<'_, Self::NativeSslCtx>,
        kems: std::slice::Iter<'_, String>,
    ) -> crate::Result<()>;

    /// Creates a BIO object from a buffer.
    fn bio_from_buffer<'a>(
        buffer: impl AsRef<[u8]> + 'a,
    ) -> crate::Result<Pimpl<'a, Self::NativeBio>>;

    /// Tells if a BIO has reached EOF.
    fn bio_eof(bio: &mut Pimpl<'_, Self::NativeBio>) -> bool;

    /// Appends a certificate to the certificate trust store.
    /// This is used in client mode.
    fn ssl_context_append_certificate_to_trust_store(
        ssl_ctx: &Pimpl<'_, Self::NativeSslCtx>,
        cert: Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Sets the certificate to use.
    /// This is used in server mode.
    fn ssl_context_set_certificate(
        ssl_ctx: &mut Pimpl<'_, Self::NativeSslCtx>,
        cert: Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Adds a certificate to the extra chain certificates.
    fn ssl_context_add_extra_chain_cert(
        ssl_ctx: &mut Pimpl<'_, Self::NativeSslCtx>,
        cert: Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Sets the private key to use.
    /// This is used in server mode.
    fn ssl_context_set_private_key(
        ssl_ctx: &mut Pimpl<'_, Self::NativeSslCtx>,
        pkey: Pimpl<'_, Self::NativePrivateKey>,
    ) -> crate::Result<()>;

    /// Checks the consistency of a private key with the corresponding
    /// certificate loaded.
    /// The private key is the one loaded using [`Ossl::ssl_context_set_private_key`]
    /// and the certificate is the one loaded using [`Ossl::ssl_context_set_certificate`].
    fn ssl_context_check_private_key(ssl_ctx: &Pimpl<'_, Self::NativeSslCtx>) -> crate::Result<()>;

    /// Sets ALPN protocols.
    fn ssl_context_set_alpn_protos(
        ssl: &mut Pimpl<'_, Self::NativeSslCtx>,
        alpn_protocols: std::slice::Iter<'_, String>,
    ) -> crate::Result<()>;

    /// Instantiates a certificate from a BIO object.
    fn certificate_from_bio(
        bio: &mut Pimpl<'_, Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativeCertificate>>;

    /// Instantiates a private key from a BIO object.
    fn private_key_from_bio(
        bio: &mut Pimpl<'_, Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativePrivateKey>>;

    /// Instantiates a SSL handle from a SSL context.
    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &mut Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl;

    /// Instantiates a BIO object for the SSL handle.
    fn new_ssl_bio<'pimpl>() -> crate::Result<Pimpl<'pimpl, Self::NativeBio>>;

    /// Attaches a BIO to a SSL handle, and sets its forwarded data.
    fn ssl_set_bio(
        bio: *mut Self::NativeBio,
        ssl: *mut Self::NativeSsl,
        data: *mut std::ffi::c_void,
    ) -> crate::Result<()>;

    /// Sets the verify_error location for an SSL context
    fn ssl_set_extra_data_for_verify<T>(
        ssl: *mut Self::NativeSsl,
        extra_data: *mut T,
    ) -> Result<(), pb::SystemError>;

    /// Sets the server name indication (SNI) extension.
    /// This method adds the SNI extension record to the ClientHello.
    fn ssl_set_server_name_indication(
        ssl: *mut Self::NativeSsl,
        hostname: impl Into<String>,
    ) -> crate::Result<()>;

    /// Performs the handshake.
    fn ssl_handshake(
        ssl: *mut Self::NativeSsl,
        mode: Mode,
        tun: &OsslTunnel<'_, '_, Self>,
    ) -> (crate::Result<pb::tunnel::HandshakeState>, Option<pb::State>);

    /// Reads from a SSL handle.
    fn ssl_read(ssl: *mut Self::NativeSsl, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize>;

    /// Writes to a SSL handle.
    fn ssl_write(ssl: *mut Self::NativeSsl, buf: &[u8]) -> crate::tunnel::RecordResult<usize>;

    /// Closes the SSL handle.
    fn ssl_close(ssl: *mut Self::NativeSsl) -> crate::tunnel::RecordResult<()>;

    /// Returns the state of the SSL handle shutdowniness, or nothing if the tunnel
    /// is not in shutdown mode.
    fn ssl_get_shutdown_state(ssl: *const Self::NativeSsl) -> Option<pb::State>;

    /// Returns the state of the SSL handshake.
    fn ssl_get_handshake_state(ssl: *const Self::NativeSsl) -> pb::HandshakeState;

    /// Returns the SSL handle (`SSL*`) from a X.509 trusted store (`X509_STORE_CTX*`).
    fn x509_store_context_get_ssl(
        store_ctx: *mut Self::NativeX509StoreCtx,
    ) -> Option<*const Self::NativeSsl>;

    /// Returns the error stored in a X.509 trusted store.
    fn x509_store_context_get_error(store_ctx: *mut Self::NativeX509StoreCtx) -> i32;

    /// Sets the error stored in a X.509 trusted store.
    fn x509_store_context_set_error(store_ctx: *mut Self::NativeX509StoreCtx, error: i32);

    /// Returns the no-error code for a X.509 trusted store.
    fn x509_store_error_code_valid() -> i32;

    /// Returns true if the given error corresponds to the 'certificate has expired' error.
    fn x509_error_code_is_certificate_expired(error: i32) -> bool;

    /// Returns the tunnel ([`OsslTunnel`]) attached to a SSL handle.
    fn ssl_get_tunnel<'a>(ssl: *const Self::NativeSsl) -> Option<&'a mut OsslTunnel<'a, 'a, Self>>;

    /// The verify callback.
    /// This callback is passed to `SSL_set_verify`.
    extern "C" fn verify_callback(
        mut verify_code: std::ffi::c_int,
        store_ctx: *mut Self::NativeX509StoreCtx,
    ) -> std::ffi::c_int {
        if verify_code == 1 {
            return verify_code;
        }

        let ssl = if let Some(ssl) = Self::x509_store_context_get_ssl(store_ctx) {
            ssl
        } else {
            return verify_code;
        };

        let tun = if let Some(tun) = Self::ssl_get_tunnel(ssl) {
            tun
        } else {
            return verify_code;
        };

        let error = Self::x509_store_context_get_error(store_ctx);

        if tun
            .security_requirements
            .assess_x509_store_error::<Self>(error)
        {
            verify_code = 1;
            Self::x509_store_context_set_error(store_ctx, Self::x509_store_error_code_valid());
        }

        tun.verify_error = error;
        verify_code
    }

    /// Returns the X.509 verification parameters from a SSL handle.
    fn ssl_get_x509_verify_parameters(
        ssl: *mut Self::NativeSsl,
    ) -> Option<*mut Self::NativeX509VerifyParams>;

    /// Appends a DNS as SAN to the X.509 verification parameters.
    fn x509_verify_parameters_add_san_dns(
        verify_params: *mut Self::NativeX509VerifyParams,
        dns: &str,
    ) -> crate::Result<()>;

    /// Set an email address as SAN to the X.509 verification parameters.
    fn x509_verify_parameters_set_san_email(
        verify_params: *mut Self::NativeX509VerifyParams,
        email: &str,
    ) -> crate::Result<()>;

    /// Set an IP address as SAN to the X.509 verification parameters.
    /// IPv4 address or IPv6 address are allowed.
    /// Ranges and masks are disallowed.
    fn x509_verify_parameters_set_san_ip_address(
        verify_params: *mut Self::NativeX509VerifyParams,
        ip_addr: &str,
    ) -> crate::Result<()>;
}

/// A generic context that uses an OpenSSL-like backend.
pub(crate) struct OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// Execution mode.
    mode: Mode,

    /// SSL context.
    ssl_ctx: Pimpl<'ctx, OsslInterface::NativeSslCtx>,

    /// Security requirements from the verifiers.
    security_requirements: tls::TunnelSecurityRequirements,
}

/// Implements [`std::fmt::Debug`] for [`Ossl`].
impl<OsslInterface> std::fmt::Debug for OsslContext<'_, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OsslContext")
    }
}

/// Implements [`crate::tunnel::Context`] for [`OsslContext`].
impl<'ctx, OsslInterface> crate::tunnel::Context<'ctx> for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl + 'static,
{
    fn new_tunnel<'io, 'tun>(
        &mut self,
        io: Box<dyn crate::IO + 'io>,
        configuration: pb_api::TunnelConfiguration,
    ) -> crate::tunnel::TunnelResult<'io, 'tun>
    where
        'io: 'tun,
        'ctx: 'tun,
    {
        OsslTunnel::<'io, 'tun, OsslInterface>::new_with_io(TunnelBuilder {
            ctx: self,
            io,
            configuration,
        })
    }
}

/// Returns the execution mode (Client or Server) and the tls options (`TLSOptions`).
fn configuration_get_mode_and_tls_options(
    configuration: &pb_api::Configuration,
) -> crate::Result<(Mode, &pb_api::TLSOptions)> {
    configuration
        .opts
        .as_ref()
        .and_then(|opts| match opts {
            pb_api::configuration::configuration::Opts::Client(opt) => opt
                .opts
                .as_ref()
                .and_then(|proto| match proto {
                    pb_api::configuration::client_options::Opts::Tls(tls) => Some(tls),
                    _ => None,
                })
                .and_then(|opts| opts.common_options.as_ref())
                .map(|tls| (Mode::Client, tls)),
            pb_api::configuration::configuration::Opts::Server(opt) => opt
                .opts
                .as_ref()
                .and_then(|proto| match proto {
                    pb_api::configuration::server_options::Opts::Tls(tls) => Some(tls),
                    _ => None,
                })
                .and_then(|opts| opts.common_options.as_ref())
                .map(|tls| (Mode::Server, tls)),
            _ => unreachable!(),
        })
        .ok_or(TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY.into())
}

/// Returns the X.509 verifier if exists.
/// If no X.509 verifier is found, and `EmptyVerifier` isn't specified, then
/// it's an error.
fn tls_options_get_x509_verifier(
    tls_options: &pb_api::TLSOptions,
) -> crate::Result<Option<&pb_api::X509Verifier>> {
    tls_options
        .peer_verifier
        .as_ref()
        .ok_or(
            (
                TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY,
                "no verifier specified",
            )
                .into(),
        )
        .and_then(|v| match v {
            pb_api::tlsoptions::Peer_verifier::X509Verifier(x509) => Ok(Some(x509)),
            pb_api::tlsoptions::Peer_verifier::EmptyVerifier(_) => Ok(None),
            _ => unreachable!(),
        })
}

/// Verifies that a X.509 verifier isn't empty.
fn x509_verifier_verify_emptiness(
    x509_verifier: Option<&pb_api::X509Verifier>,
) -> crate::Result<Option<&pb_api::X509Verifier>> {
    if let Some(x509) = x509_verifier {
        if !x509.trusted_cas.is_empty() {
            Ok(x509_verifier)
        } else {
            Err((
                TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY,
                "X.509 verifier empty",
            )
                .into())
        }
    } else {
        Ok(x509_verifier)
    }
}

/// Sets the X.509 identity to use.
/// If the client sets an X.509 identity, then it will expect a client
/// certificate request from the server, in order to establish a mutual
/// TLS tunnel (mTLS).
fn ssl_context_set_identity<OsslInterface>(
    ssl_ctx: &mut Pimpl<'_, OsslInterface::NativeSslCtx>,
    identity: &pb_api::X509Identity,
) -> crate::Result<()>
where
    OsslInterface: Ossl,
{
    let (format, data_source) = identity
        .certificate
        .as_ref()
        .ok_or(CertificateError::CERTIFICATEERROR_MALFORMED.into())
        .and_then(read_certificate)
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    let mut bio = OsslInterface::bio_from_buffer(&data_source)
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    OsslInterface::certificate_from_bio(&mut bio, format)
        .and_then(|cert| OsslInterface::ssl_context_set_certificate(ssl_ctx, cert))
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    while !OsslInterface::bio_eof(&mut bio) {
        OsslInterface::certificate_from_bio(&mut bio, format)
            .and_then(|cert| OsslInterface::ssl_context_add_extra_chain_cert(ssl_ctx, cert))
            .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;
    }

    let (format, data_source) = identity
        .private_key
        .as_ref()
        .ok_or(PrivateKeyError::PRIVATEKEYERROR_MALFORMED.into())
        .and_then(read_private_key)
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    OsslInterface::bio_from_buffer(&data_source)
        .and_then(|mut bio| OsslInterface::private_key_from_bio(&mut bio, format))
        .and_then(|private_key| OsslInterface::ssl_context_set_private_key(ssl_ctx, private_key))
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    OsslInterface::ssl_context_check_private_key(ssl_ctx)
}

/// Pushes the trusted certificate authority certificates to the trust store.
fn ssl_fill_trust_store<OsslInterface>(
    ssl_ctx: &mut Pimpl<'_, OsslInterface::NativeSslCtx>,
    x509_verifier: &pb_api::X509Verifier,
) -> crate::Result<usize>
where
    OsslInterface: Ossl,
{
    for cert in x509_verifier.trusted_cas.iter() {
        let (format, data_source) = read_certificate(cert)?;
        let mut bio = OsslInterface::bio_from_buffer(&data_source)?;

        while !OsslInterface::bio_eof(&mut bio) {
            OsslInterface::certificate_from_bio(&mut bio, format).and_then(|cert| {
                OsslInterface::ssl_context_append_certificate_to_trust_store(ssl_ctx, cert)
            })?;
        }
    }
    Ok(x509_verifier.trusted_cas.len())
}

/// Instantiates an OsslContext from a protobuf configuration.
impl<'ctx, OsslInterface> TryFrom<&pb_api::Configuration> for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    type Error = crate::Error;

    fn try_from(configuration: &pb_api::Configuration) -> crate::Result<Self> {
        let (mode, tls_options) = configuration_get_mode_and_tls_options(configuration)?;

        let mut ssl_ctx = OsslInterface::new_ssl_context(mode)
            .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

        OsslInterface::ssl_context_set_kems(&mut ssl_ctx, tls_options.kem.iter())
            .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

        OsslInterface::ssl_context_set_alpn_protos(&mut ssl_ctx, tls_options.alpn_protocols.iter())
            .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

        let x509_verifier =
            tls_options_get_x509_verifier(tls_options).and_then(x509_verifier_verify_emptiness)?;

        OsslInterface::ssl_context_set_verify_depth(
            &mut ssl_ctx,
            x509_verifier
                .and_then(|v| {
                    if v.max_verify_depth == 0 {
                        None
                    } else {
                        Some(v.max_verify_depth)
                    }
                })
                .unwrap_or(DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH),
        );

        if let Some(identity) = tls_options.identity.as_ref() {
            ssl_context_set_identity::<OsslInterface>(&mut ssl_ctx, identity)?;
            true
        } else {
            false
        };

        if let Some(v) = x509_verifier {
            ssl_fill_trust_store::<OsslInterface>(&mut ssl_ctx, v)
                .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?
        } else {
            0
        };

        if x509_verifier.is_none() {
            OsslInterface::ssl_context_set_verify_mode(&mut ssl_ctx, VerifyMode::None);
        } else {
            OsslInterface::ssl_context_set_verify_mode(
                &mut ssl_ctx,
                match mode {
                    Mode::Client => VerifyMode::Peer,
                    Mode::Server => VerifyMode::Mutual,
                },
            );
        }

        let security_requirements = x509_verifier
            .map(tls::TunnelSecurityRequirements::from)
            .unwrap_or_default();

        Ok(Self {
            mode,
            ssl_ctx,
            security_requirements,
        })
    }
}

/// Borrows the SSL context from [`OsslContext`].
impl<'ctx, OsslInterface> Borrow<Pimpl<'ctx, OsslInterface::NativeSslCtx>>
    for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow(&self) -> &Pimpl<'ctx, OsslInterface::NativeSslCtx> {
        &self.ssl_ctx
    }
}

/// Borrows as mutable the SSL context from [`OsslContext`].
impl<'ctx, OsslInterface> BorrowMut<Pimpl<'ctx, OsslInterface::NativeSslCtx>>
    for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow_mut(&mut self) -> &mut Pimpl<'ctx, OsslInterface::NativeSslCtx> {
        &mut self.ssl_ctx
    }
}

/// Reads the content of a certificate as described in a protobuf message.
fn read_certificate(
    cert: &pb_api::Certificate,
) -> crate::Result<(pb_api::ASN1EncodingFormat, DataSource<'_>)> {
    use pb_api::certificate::certificate;
    cert.source
        .as_ref()
        .ok_or_else(|| DataSourceError::DATASOURCEERROR_EMPTY.into())
        .and_then(|oneof| match oneof {
            certificate::Source::Static(ref asn1ds) => asn1ds
                .data
                .as_ref()
                .ok_or_else(|| DataSourceError::DATASOURCEERROR_EMPTY.into())
                .and_then(DataSource::try_from)
                .and_then(|ds| {
                    asn1ds
                        .format
                        .enum_value()
                        .map_err(|_| pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into())
                        .map(|f| (f, ds))
                }),
            _ => Err(DataSourceError::DATASOURCEERROR_EMPTY.into()),
        })
}

/// Reads the content of a private key as described in a protobuf message.
fn read_private_key(
    private_key: &pb_api::PrivateKey,
) -> crate::Result<(pb_api::ASN1EncodingFormat, DataSource<'_>)> {
    use pb_api::private_key::private_key;
    private_key
        .source
        .as_ref()
        .ok_or_else(|| DataSourceError::DATASOURCEERROR_EMPTY.into())
        .and_then(|oneof| match oneof {
            private_key::Source::Static(ref asn1ds) => asn1ds
                .data
                .as_ref()
                .ok_or_else(|| DataSourceError::DATASOURCEERROR_EMPTY.into())
                .and_then(DataSource::try_from)
                .and_then(|ds| {
                    asn1ds
                        .format
                        .enum_value()
                        .map_err(|_| pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into())
                        .map(|f| (f, ds))
                }),
            _ => Err(DataSourceError::DATASOURCEERROR_EMPTY.into()),
        })
}

/// Implements [`OsslContext`].
impl<'ctx, OsslInterface> OsslContext<'ctx, OsslInterface> where OsslInterface: Ossl {}

/// A generic tunnel that uses an OpenSSL-like backend.
pub(crate) struct OsslTunnel<'io, 'tun, OsslInterface>
where
    OsslInterface: Ossl + ?Sized,
{
    /// The current mode.
    pub(crate) mode: Mode,

    /// The SSL handle.
    pub(crate) ssl: Pimpl<'tun, OsslInterface::NativeSsl>,

    /// The BIO handle.
    pub(crate) bio: Pimpl<'tun, OsslInterface::NativeBio>,

    /// The IO.
    pub(crate) io: Box<dyn crate::IO + 'io>,

    /// The security at tunnel time.
    pub(crate) security_requirements: tls::TunnelSecurityRequirements,

    /// Verification Errors.
    pub(crate) verify_error: std::ffi::c_int,

    /// The state of the tunnel.
    pub(crate) state: pb::State,
}

/// Implements [`std::fmt::Debug`] for [`OsslTunnel`].
impl<OsslInterface> std::fmt::Debug for OsslTunnel<'_, '_, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Ossl tunnel")
    }
}

/// Tunnel builder.
/// This is a convenient aggregate of useful values to build a tunnel.
pub(crate) struct TunnelBuilder<'ctx, 'io, 'a, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// The context.
    pub(crate) ctx: &'a mut OsslContext<'ctx, OsslInterface>,

    /// The IO interface.
    pub(crate) io: Box<dyn crate::IO + 'io>,

    /// The tunnel-time configuration.
    pub(crate) configuration: pb_api::TunnelConfiguration,
}

/// Applies security requirements regarding the Subject Alternative Names.
fn apply_san_verifier_to_ssl<OsslInterface>(
    ssl: *mut OsslInterface::NativeSsl,
    san_verifier: &pb_api::SANVerifier,
) -> crate::Result<()>
where
    OsslInterface: Ossl,
{
    use pb_api::verifiers::sanmatcher::San;
    if san_verifier.alt_names.is_empty() {
        unreachable!();
    }

    let params = OsslInterface::ssl_get_x509_verify_parameters(ssl).ok_or((
        pb::TunnelError::TUNNELERROR_UNKNOWN,
        "failed to get the X.509 verify parameters from the SSL handle",
    ))?;

    for san in san_verifier.alt_names.iter() {
        match san.san.as_ref() {
            Some(San::Dns(dns)) => OsslInterface::x509_verify_parameters_add_san_dns(params, dns),
            Some(San::Email(email)) => {
                OsslInterface::x509_verify_parameters_set_san_email(params, email)
            }
            Some(San::IpAddress(ip_addr)) => {
                OsslInterface::x509_verify_parameters_set_san_ip_address(params, ip_addr)
            }
            _ => unreachable!(),
        }?;
    }

    Ok(())
}

/// Instantiates a [`OsslTunnel`] from a [`OsslContext`] and an IO interface.
impl<'ctx, 'io, 'tun, OsslInterface> TryFrom<TunnelBuilder<'ctx, 'io, '_, OsslInterface>>
    for OsslTunnel<'io, 'tun, OsslInterface>
where
    'io: 'tun,
    'ctx: 'tun,
    OsslInterface: Ossl,
{
    type Error = (crate::Error, Box<dyn crate::IO + 'io>);

    fn try_from(
        builder: TunnelBuilder<'ctx, 'io, '_, OsslInterface>,
    ) -> Result<OsslTunnel<'io, 'tun, OsslInterface>, Self::Error> {
        use tls::VerifierSanitizer;

        let tunnel_verifier = if let Some(v) = builder.configuration.verifier.as_ref() {
            v
        } else {
            return Err((
                (pb::TunnelError::TUNNELERROR_VERIFIER, "empty verifier").into(),
                builder.io,
            ));
        };

        let security_requirements = builder.ctx.security_requirements.clone();
        if let Err(e) = security_requirements.run_sanitizer_checks(tunnel_verifier) {
            return Err((e, builder.io));
        }

        let ssl = OsslInterface::new_ssl_handle(builder.ctx.borrow_mut());
        let mut ssl = if let Err(e) = ssl {
            return Err((e, builder.io));
        } else {
            ssl.unwrap()
        };

        if let Some(pb_api::verifiers::tunnel_verifier::Verifier::SanVerifier(ref san_verifier)) =
            tunnel_verifier.verifier
        {
            if let Err(e) =
                apply_san_verifier_to_ssl::<OsslInterface>(ssl.as_mut_ptr(), san_verifier)
            {
                return Err((e, builder.io));
            }
        }

        if !builder.configuration.server_name_indication.is_empty() {
            if let Err(e) = OsslInterface::ssl_set_server_name_indication(
                ssl.as_mut_ptr(),
                builder.configuration.server_name_indication.clone(),
            ) {
                return Err((e, builder.io));
            }
        }

        let bio = OsslInterface::new_ssl_bio();
        let bio = if let Err(e) = bio {
            return Err((e, builder.io));
        } else {
            bio.unwrap()
        };
        let bio = Pimpl::from_raw(bio.into_raw(), None);

        Ok(Self {
            mode: builder.ctx.mode,
            ssl,
            bio,
            io: builder.io,
            security_requirements: builder.ctx.security_requirements.clone(),
            verify_error: 0,
            state: pb::State::STATE_NOT_CONNECTED,
        })
    }
}

/// Implements [`crate::tunnel::Tunnel`] for [`OsslTunnel`].
impl<'io: 'tun, 'tun, OsslInterface> crate::tunnel::Tunnel<'io, 'tun>
    for OsslTunnel<'io, 'tun, OsslInterface>
where
    OsslInterface: Ossl + 'static,
{
    fn state(&self) -> crate::tunnel::State {
        self.state.into()
    }

    fn handshake(&mut self) -> crate::Result<crate::tunnel::HandshakeState> {
        if self.state == pb::State::STATE_HANDSHAKE_DONE {
            return Ok(pb::HandshakeState::HANDSHAKESTATE_DONE.into());
        }

        let state = OsslInterface::ssl_get_handshake_state(self.ssl.as_ptr());
        if state == pb::HandshakeState::HANDSHAKESTATE_DONE {
            self.state = pb::State::STATE_HANDSHAKE_DONE;
            return Ok(state.into());
        }

        let (handshake_state, tunnel_state) =
            OsslInterface::ssl_handshake(self.ssl.as_mut_ptr(), self.mode, self);
        if let Some(tunnel_state) = tunnel_state {
            self.state = tunnel_state;
        }
        match handshake_state {
            Ok(state) => Ok(state.into()),
            Err(state) => Err(state),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(RecordError::RECORDERROR_TOO_BIG.into());
        }

        let res = OsslInterface::ssl_read(self.ssl.as_mut_ptr(), buf);

        let new_state = self.check_shutdown();
        if res.is_ok() {
            return res;
        }

        match new_state {
            pb::State::STATE_BEING_SHUTDOWN => Err(RecordError::RECORDERROR_BEING_SHUTDOWN.into()),
            pb::State::STATE_DISCONNECTED => Err(RecordError::RECORDERROR_CLOSED.into()),
            _ => res,
        }
    }

    fn write(&mut self, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(RecordError::RECORDERROR_TOO_BIG.into());
        }

        let res = OsslInterface::ssl_write(self.ssl.as_mut_ptr(), buf);

        let new_state = self.check_shutdown();
        if res.is_ok() {
            return res;
        }

        match new_state {
            pb::State::STATE_BEING_SHUTDOWN => Err(RecordError::RECORDERROR_BEING_SHUTDOWN.into()),
            pb::State::STATE_DISCONNECTED => Err(RecordError::RECORDERROR_CLOSED.into()),
            _ => res,
        }
    }

    fn close(&mut self) -> crate::tunnel::RecordResult<()> {
        OsslInterface::ssl_close(self.ssl.as_mut_ptr())
    }
}

/// Implements [`OsslTunnel`].
impl<'io, 'tun, OsslInterface> OsslTunnel<'io, 'tun, OsslInterface>
where
    OsslInterface: Ossl + 'static,
    'io: 'tun,
{
    /// Instantiates a new [`OsslTunnel`] from a [`OsslContext`] and an IO interface.
    fn new_with_io<'ctx>(
        builder: TunnelBuilder<'ctx, 'io, '_, OsslInterface>,
    ) -> crate::tunnel::TunnelResult<'io, 'tun>
    where
        'ctx: 'tun,
    {
        let mut tun: Box<OsslTunnel<'io, 'tun, OsslInterface>> = Box::new(Self::try_from(builder)?);
        if let Err(e) = OsslInterface::ssl_set_bio(
            tun.bio.as_mut_ptr(),
            tun.ssl.as_mut_ptr(),
            (&mut *tun as *mut Self) as *mut std::ffi::c_void,
        ) {
            return Err((e, tun.io));
        }

        let tun_ptr: *mut OsslTunnel<OsslInterface> = &mut *tun;
        if let Err(e) = OsslInterface::ssl_set_extra_data_for_verify(tun.ssl.as_mut_ptr(), tun_ptr)
        {
            return Err((e.into(), tun.io));
        }
        Ok(tun)
    }

    /// Check the state of SSL, regarding the shutdown phase, and update
    /// the tunnel state if necessary.
    fn check_shutdown(&mut self) -> pb::State {
        let state = OsslInterface::ssl_get_shutdown_state(self.ssl.as_ptr());
        if let Some(state) = state {
            self.state = state;
        }
        state.unwrap_or(self.state)
    }
}

/// Generates generic unit tests for an OpenSSL interface ([`Ossl`]).
macro_rules! GenOsslUnitTests {
    ($ossl:item) => {
        #[cfg(test)]
        mod test {
            use pb::CertificateError;

            use super::tls;
            use crate::tunnel::{Mode};
            use crate::implementation::ossl::Ossl as OsslTrait;
            $ossl

            /// Certificate related tests.
            mod certificates {
                use super::*;

                /// Tests [`Ossl::certificate_from_bio`] using a PEM certificate.
                #[test]
                fn test_certificate_from_bio_pem_valid() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());
                }

                /// Tests [`Ossl::certificate_from_bio`] using /etc/ssl/cert.pem.
                #[test]
                fn test_certificate_from_bio_etc_ssl_cert() {
                    let cert = std::fs::read(crate::test::resolve_runfile("testdata/etc_ssl_cert.pem"))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    while !Ossl::bio_eof(&mut bio) {
                        let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM);
                        let cert = cert.unwrap();
                        assert!(!cert.as_ptr().is_null());
                    }
                }

                /// Tests [`Ossl::certificate_from_bio`] using a DER certificate.
                #[test]
                fn test_certificate_from_bio_with_der() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());
                }

                /// Tests [`Ossl::certificate_from_bio`] using a DER certificate.
                #[test]
                fn test_certificate_from_bio_der_valid() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());
                }

                /// Tests [`Ossl::certificate_from_bio`] using a DER certificate that contains an invalid sig alg (invalid OID).
                #[test]
                fn test_certificate_from_bio_der_with_invalid_der() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let err = cert.unwrap_err();
                    assert!(err.is(&errors!{pb::ASN1Error::ASN1ERROR_MALFORMED => CertificateError::CERTIFICATEERROR_MALFORMED}));
                }
            }

            /// Private keys related tests.
            mod private_keys {
                use super::*;

                /// Tests [`Ossl::private_key_from_bio`] using a PEM private key.
                #[test]
                fn test_private_key_from_bio_pem_valid() {
                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&skey)
                        .expect("failed to create a bio from a buffer");
                    let skey = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM);
                    let skey = skey.unwrap();
                    assert!(!skey.as_ptr().is_null());
                }

                /// Tests [`Ossl::private_key_from_bio`] using a DER private key.
                #[test]
                fn test_private_key_from_bio_der_with_der() {
                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_DER_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&skey)
                        .expect("failed to create a bio from a buffer");
                    let skey = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let skey = skey.unwrap();
                    assert!(!skey.as_ptr().is_null());
                }

                /// Tests [`Ossl::private_key_from_bio`] using a DER private key.
                #[test]
                fn test_private_key_from_bio_der_valid() {
                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_DER_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&skey)
                        .expect("failed to create a bio from a buffer");
                    let skey = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let skey = skey.unwrap();
                    assert!(!skey.as_ptr().is_null());
                }
            }

            /// SSL context related tests.
            mod ssl_ctx {
                use super::*;

                /// Tests instantiates a [`SSL_CTX`] for a client.
                #[test]
                fn test_ssl_ctx_client() {
                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());
                }

                /// Tests instantiates a [`SSL_CTX`] for a server.
                #[test]
                fn test_ssl_ctx_server() {
                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());
                }

                /// Tests [`Ossl::ssl_context_set_kems`] with two valid KEMs.
                #[test]
                fn test_ssl_ctx_set_kems_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let kems = vec!["kyber512".into(), "X25519".into()];
                    Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap();

                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_kems`] with one valid KEM and one invalid KEM.
                #[test]
                fn test_ssl_ctx_set_kems_invalid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let kems = vec!["kyber512".into(), "X1337".into()];
                    let err = Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::KEMError::KEMERROR_INVALID}));
                }

                /// Tests [`Ossl::ssl_context_set_kems`] with no KEMs.
                #[test]
                fn test_ssl_ctx_set_kems_no_kems() {
                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let kems = Vec::<String>::new();
                    Ossl::ssl_context_set_kems(&mut ssl, kems.iter()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_certificate`] with a valid PEM certificate.
                #[test]
                fn test_ssl_ctx_set_certificate_pem_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());

                    Ossl::ssl_context_set_certificate(&mut ssl, cert).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_certificate`] with a valid DER certificate.
                #[test]
                fn test_ssl_ctx_set_certificate_der_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());

                    Ossl::ssl_context_set_certificate(&mut ssl, cert).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_private_key`] with a valid PEM private key.
                #[test]
                fn test_ssl_ctx_set_private_key_pem_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&skey).unwrap();
                    let skey = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM);
                    let skey = skey.unwrap();
                    assert!(!skey.as_ptr().is_null());

                    Ossl::ssl_context_set_private_key(&mut ssl, skey).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_private_key`] with a valid DER private key.
                #[test]
                fn test_ssl_ctx_set_private_key_der_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_DER_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&skey).unwrap();
                    let skey = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let skey = skey.unwrap();
                    assert!(!skey.as_ptr().is_null());

                    Ossl::ssl_context_set_private_key(&mut ssl, skey).unwrap();
                }

                /// Tests [`Ossl::ssl_context_append_certificate_to_trust_store`] with a valid PEM certificate.
                #[test]
                fn test_ssl_ctx_append_certificate_to_trust_store_pem_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());

                    Ossl::ssl_context_append_certificate_to_trust_store(&ssl, cert).unwrap();
                }

                /// Tests [`Ossl::ssl_context_append_certificate_to_trust_store`] with a valid DER certificate.
                #[test]
                fn test_ssl_ctx_append_certificate_to_trust_store_der_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());

                    Ossl::ssl_context_append_certificate_to_trust_store(&ssl, cert).unwrap();
                }

                /// Tests [`Ossl::ssl_context_check_private_key`] with a valid pair certificate/private key,
                /// and then an inconsistency pair certificate/private key.
                #[test]
                fn test_ssl_ctx_check_private_key() {
                    let mut ssl_ctx = Ossl::new_ssl_context(Mode::Server).unwrap();
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM)
                        .expect("failed to parse the certificate");
                    Ossl::ssl_context_set_certificate(&mut ssl_ctx, cert)
                        .expect("failed to set the certificate");

                    let private_key = std::fs::read(crate::test::resolve_runfile(tls::test::SK_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&private_key).unwrap();
                    let private_key = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM)
                        .expect("failed to parse the private key");
                    Ossl::ssl_context_set_private_key(&mut ssl_ctx, private_key)
                        .expect("failed to set the private key");

                    Ossl::ssl_context_check_private_key(&ssl_ctx)
                        .expect("private key and certificate should be seen as consistent");

                    let mut ssl_ctx = Ossl::new_ssl_context(Mode::Server).unwrap();
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let mut bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM)
                        .expect("failed to parse the certificate");
                    Ossl::ssl_context_set_certificate(&mut ssl_ctx, cert)
                        .expect("failed to set the certificate");

                    let private_key = std::fs::read(crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_DER_PATH))
                        .expect("failed to read the private key");
                    let mut bio = Ossl::bio_from_buffer(&private_key).unwrap();
                    let private_key = Ossl::private_key_from_bio(&mut bio, pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER)
                        .expect("failed to parse the certificate");

                    // BoringSSL performs the consistency check when `SSL_CTX_use_PrivateKey` is called.
                    // See https://github.com/google/boringssl/blob/e9f816b12b3e68de575d21e2a9b7d76e4e5c58ac/ssl/ssl_privkey.cc#L86-L91.
                    let mut has_err = false;
                    if Ossl::ssl_context_set_private_key(&mut ssl_ctx, private_key).is_err() {
                        has_err = true;
                    }

                    if Ossl::ssl_context_check_private_key(&ssl_ctx).is_err() {
                        has_err = true;
                    }

                    if !has_err {
                        panic!("private key and certificate must be seen has inconsistent between each other");
                    }
                }

                /// Tests [`Ossl::ssl_context_set_alpn_protos`] with ALPN HTTPs.
                #[test]
                fn test_ssl_ctx_set_alpn_protos_valid() {
                    let protos = vec!["http/1.1".into(), "h2".into(), "h3".into(), "h2c".into()];

                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    Ossl::ssl_context_set_alpn_protos(&mut ssl, protos.iter()).unwrap();

                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    Ossl::ssl_context_set_alpn_protos(&mut ssl, protos.iter()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_alpn_protos`] with ALPN has NULL bytes in the middle.
                #[test]
                fn test_ssl_ctx_set_alpn_protos_nullbytes() {
                    let protos = vec!["http\x00/1.1".into()];

                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let err = Ossl::ssl_context_set_alpn_protos(&mut ssl, protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_INVALID_STRING}));

                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let err = Ossl::ssl_context_set_alpn_protos(&mut ssl, protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_INVALID_STRING}));
                }

                /// Tests [`Ossl::ssl_context_set_alpn_protos`] with ALPN has length longer than 255.
                #[test]
                fn test_ssl_ctx_set_alpn_protos_invalid_length() {
                    let protos = vec!["http/1.1".repeat(100).into()];

                    let ssl = Ossl::new_ssl_context(Mode::Client);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let err = Ossl::ssl_context_set_alpn_protos(&mut ssl, protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_LENGTH_ERROR}));

                    let ssl = Ossl::new_ssl_context(Mode::Server);
                    let mut ssl = ssl.unwrap();
                    assert!(!ssl.as_ptr().is_null());

                    let err = Ossl::ssl_context_set_alpn_protos(&mut ssl, protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_LENGTH_ERROR}));
                }
            }

            /// BIO related tests.
            mod ssl_bio {
                use super::*;

                /// Tests creation of SSL BIO.
                #[test]
                fn test_bio_creation() {
                    let bio = Ossl::new_ssl_bio();
                    let bio = bio.unwrap();
                    assert!(!bio.as_ptr().is_null());
                }
            }

            /// X509 verify params related tests.
            mod x509_verify_params {
                use super::*;

                /// Tests the getter of SSL for X509 verify params.
                #[test]
                fn test_getter_x509_verify_params() {
                    let mut ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let mut ssl = Ossl::new_ssl_handle(&mut ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_mut_ptr()).unwrap();
                    assert!(!params.is_null());
                }

                /// Tests adding a DNS entry to the X509 verify params.
                #[test]
                fn test_add_dns() {
                    let mut ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let mut ssl = Ossl::new_ssl_handle(&mut ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_mut_ptr()).unwrap();
                    assert!(!params.is_null());

                    Ossl::x509_verify_parameters_add_san_dns(params, "example.com").expect("adding a valid DNS must be valid");
                }

                /// Tests setting an email entry to the X509 verify params.
                #[test]
                fn test_set_email() {
                    let mut ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let mut ssl = Ossl::new_ssl_handle(&mut ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_mut_ptr()).unwrap();
                    assert!(!params.is_null());

                    Ossl::x509_verify_parameters_set_san_email(params, "zadig@example.com").expect("setting a valid email address must be valid");
                }

                /// Tests setting an IP address to the X509 verify params.
                #[test]
                fn test_set_ip_address() {
                    let mut ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let mut ssl = Ossl::new_ssl_handle(&mut ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_mut_ptr()).unwrap();
                    assert!(!params.is_null());

                    Ossl::x509_verify_parameters_set_san_ip_address(params, "127.0.0.1").expect("setting a valid IP address must be valid");
                }
            }
        }
    };
}

#[cfg(feature = "boringssl")]
pub(crate) mod boringssl;

#[cfg(feature = "openssl1_1_1")]
pub(crate) mod openssl1_1_1;
