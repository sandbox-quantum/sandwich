// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Ossl`] trait, the OpenSSL trait, to support multiple OpenSSL-like implementation.
//!
//! This trait aims to ease the support of multiple OpenSSL-like implementations,
//! such as BoringSSL, LibreSSL and OpenSSL.

use std::borrow::{Borrow, BorrowMut};
use std::pin::Pin;
use std::ptr::NonNull;

use pb::{CertificateError, DataSourceError, PrivateKeyError, RecordError, TLSConfigurationError};

use crate::support::{DataSource, Pimpl};
use crate::tunnel::{tls, Mode};

/// Default maximum depth for the certificate chain verification.
const DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH: u32 = 100;

/// User-data index of the tunnel security requirements in the SSL handle.
/// For more information, see <https://www.openssl.org/docs/man1.1.1/man3/SSL_get_ex_data.html>.
const VERIFY_TUNNEL_SECURITY_REQUIREMENTS_INDEX: i32 = 0;

/// User-data index storing the last verify error.
const VERIFY_TUNNEL_LAST_VERIFY_ERROR_INDEX: i32 = 1;

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
    fn ssl_context_set_verify_mode(ssl_ctx: NonNull<Self::NativeSslCtx>, mode: VerifyMode);

    /// Sets the maximum depth for the certificate chain verification.
    fn ssl_context_set_verify_depth(ssl_ctx: NonNull<Self::NativeSslCtx>, depth: u32);

    /// Sets the KEM to a SSL context.
    fn ssl_context_set_kems(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        kems: std::slice::Iter<'_, String>,
    ) -> crate::Result<()>;

    /// Creates a BIO object from a buffer.
    fn bio_from_buffer<'a>(
        buffer: impl AsRef<[u8]> + 'a,
    ) -> crate::Result<Pimpl<'a, Self::NativeBio>>;

    /// Tells if a BIO has reached EOF.
    fn bio_eof(bio: NonNull<Self::NativeBio>) -> bool;

    /// Appends a certificate to the certificate trust store.
    /// This is used in client mode.
    fn ssl_context_append_certificate_to_trust_store(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: NonNull<Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Sets the certificate to use.
    /// This is used in server mode.
    fn ssl_context_set_certificate(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: NonNull<Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Adds a certificate to the extra chain certificates.
    fn ssl_context_add_extra_chain_cert(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        cert: Pimpl<'static, Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Sets the private key to use.
    /// This is used in server mode.
    fn ssl_context_set_private_key(
        ssl_ctx: NonNull<Self::NativeSslCtx>,
        pkey: NonNull<Self::NativePrivateKey>,
    ) -> crate::Result<()>;

    /// Checks the consistency of a private key with the corresponding
    /// certificate loaded.
    /// The private key is the one loaded using [`Ossl::ssl_context_set_private_key`]
    /// and the certificate is the one loaded using [`Ossl::ssl_context_set_certificate`].
    fn ssl_context_check_private_key(ssl_ctx: NonNull<Self::NativeSslCtx>) -> crate::Result<()>;

    /// Sets ALPN protocols.
    fn ssl_context_set_alpn_protos(
        ssl: NonNull<Self::NativeSslCtx>,
        alpn_protocols: std::slice::Iter<'_, String>,
    ) -> crate::Result<()>;

    /// Instantiates a certificate from a BIO object.
    fn certificate_from_bio(
        bio: NonNull<Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativeCertificate>>;

    /// Instantiates a private key from a BIO object.
    fn private_key_from_bio(
        bio: NonNull<Self::NativeBio>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<Pimpl<'static, Self::NativePrivateKey>>;

    /// Instantiates a SSL handle from a SSL context.
    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl;

    /// Instantiates a BIO object for the SSL handle.
    fn new_ssl_bio() -> crate::Result<Pimpl<'static, Self::NativeBio>>;

    /// Sets the data to be forwarded to a bio handle.
    fn bio_set_data(bio: NonNull<Self::NativeBio>, data: *mut std::ffi::c_void);

    /// Attaches a BIO to a SSL handle.
    fn ssl_set_bio(
        ssl: NonNull<Self::NativeSsl>,
        bio: NonNull<Self::NativeBio>,
    ) -> crate::Result<()>;

    /// Sets the verify_error location for an SSL context
    fn ssl_set_extra_data_for_verify<T>(
        ssl: NonNull<Self::NativeSsl>,
        extra_data: *mut T,
    ) -> Result<(), pb::SystemError>;

    /// Sets the server name indication (SNI) extension.
    /// This method adds the SNI extension record to the ClientHello.
    fn ssl_set_server_name_indication(
        ssl: NonNull<Self::NativeSsl>,
        hostname: impl Into<String>,
    ) -> crate::Result<()>;

    /// Performs the handshake.
    fn ssl_handshake(
        ssl: NonNull<Self::NativeSsl>,
        mode: Mode,
    ) -> (crate::Result<pb::tunnel::HandshakeState>, Option<pb::State>);

    /// Reads from a SSL handle.
    fn ssl_read(
        ssl: NonNull<Self::NativeSsl>,
        buf: &mut [u8],
    ) -> crate::tunnel::RecordResult<usize>;

    /// Writes to a SSL handle.
    fn ssl_write(ssl: NonNull<Self::NativeSsl>, buf: &[u8]) -> crate::tunnel::RecordResult<usize>;

    /// Closes the SSL handle.
    fn ssl_close(ssl: NonNull<Self::NativeSsl>) -> crate::tunnel::RecordResult<()>;

    /// Returns the state of the SSL handle shutdowniness, or nothing if the tunnel
    /// is not in shutdown mode.
    fn ssl_get_shutdown_state(ssl: NonNull<Self::NativeSsl>) -> Option<pb::State>;

    /// Returns the state of the SSL handshake.
    fn ssl_get_handshake_state(ssl: NonNull<Self::NativeSsl>) -> pb::HandshakeState;

    /// Returns the SSL handle (`SSL*`) from a X.509 trusted store (`X509_STORE_CTX*`).
    fn x509_store_context_get_ssl(
        store_ctx: NonNull<Self::NativeX509StoreCtx>,
    ) -> Option<NonNull<Self::NativeSsl>>;

    /// Returns the error stored in a X.509 trusted store.
    fn x509_store_context_get_error(store_ctx: NonNull<Self::NativeX509StoreCtx>) -> i32;

    /// Sets the error stored in a X.509 trusted store.
    fn x509_store_context_set_error(store_ctx: NonNull<Self::NativeX509StoreCtx>, error: i32);

    /// Returns the no-error code for a X.509 trusted store.
    fn x509_store_error_code_valid() -> i32;

    /// Returns true if the given error corresponds to the 'certificate has expired' error.
    fn x509_error_code_is_certificate_expired(error: i32) -> bool;

    /// Returns the [`tls::TunnelSecurityRequirements`] attached to a tunnel using the SSL handle.
    fn ssl_get_tunnel_security_requirements<'a>(
        ssl: NonNull<Self::NativeSsl>,
    ) -> Option<&'a tls::TunnelSecurityRequirements>;
    /// Sets the last verify error returned by [`Self::verify_callback`].
    fn ssl_set_last_verify_error(ssl: NonNull<Self::NativeSsl>, err: i32);

    /// Returns the last verify error returned by [`Self::verify_callback`].
    fn ssl_get_last_verify_error(ssl: NonNull<Self::NativeSsl>) -> i32;

    /// The verify callback.
    /// This callback is passed to `SSL_set_verify`.
    extern "C" fn verify_callback(
        mut verify_code: std::ffi::c_int,
        store_ctx: *mut Self::NativeX509StoreCtx,
    ) -> std::ffi::c_int {
        let store_ctx = unsafe { NonNull::new_unchecked(store_ctx) };
        if verify_code == 1 {
            return verify_code;
        }

        let Some(ssl) = Self::x509_store_context_get_ssl(store_ctx) else {
            return verify_code;
        };

        let Some(sec_req) = Self::ssl_get_tunnel_security_requirements(ssl) else {
            return verify_code;
        };

        let error = Self::x509_store_context_get_error(store_ctx);

        if sec_req.assess_x509_store_error::<Self>(error) {
            verify_code = 1;
            Self::x509_store_context_set_error(store_ctx, Self::x509_store_error_code_valid());
        }

        Self::ssl_set_last_verify_error(ssl, error);
        verify_code
    }

    /// Returns the X.509 verification parameters from a SSL handle.
    fn ssl_get_x509_verify_parameters(
        ssl: NonNull<Self::NativeSsl>,
    ) -> Option<NonNull<Self::NativeX509VerifyParams>>;

    /// Appends a DNS as SAN to the X.509 verification parameters.
    fn x509_verify_parameters_add_san_dns(
        verify_params: NonNull<Self::NativeX509VerifyParams>,
        dns: &str,
    ) -> crate::Result<()>;

    /// Set an email address as SAN to the X.509 verification parameters.
    fn x509_verify_parameters_set_san_email(
        verify_params: NonNull<Self::NativeX509VerifyParams>,
        email: &str,
    ) -> crate::Result<()>;

    /// Set an IP address as SAN to the X.509 verification parameters.
    /// IPv4 address or IPv6 address are allowed.
    /// Ranges and masks are disallowed.
    fn x509_verify_parameters_set_san_ip_address(
        verify_params: NonNull<Self::NativeX509VerifyParams>,
        ip_addr: &str,
    ) -> crate::Result<()>;
}

/// A generic context that uses an OpenSSL-like backend.
pub(crate) struct OsslContext<'a, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// Execution mode.
    mode: Mode,

    /// SSL context.
    ssl_ctx: Pimpl<'a, OsslInterface::NativeSslCtx>,

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

pub(crate) type PinnelOsslTunnel<'tun, OsslInterface> = Pin<Box<OsslTunnel<'tun, OsslInterface>>>;

impl<'a, OsslInterface> OsslContext<'a, OsslInterface>
where
    OsslInterface: Ossl + 'static,
{
    pub(crate) fn new_tunnel(
        &self,
        io: Box<dyn crate::IO>,
        configuration: pb_api::TunnelConfiguration,
    ) -> Result<PinnelOsslTunnel<'_, OsslInterface>, (crate::Error, Box<dyn crate::IO>)> {
        OsslTunnel::<OsslInterface>::try_from(TunnelBuilder {
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
    let Some(x509) = x509_verifier else {
        return Ok(x509_verifier);
    };
    if !x509.trusted_cas.is_empty() {
        Ok(x509_verifier)
    } else {
        Err((
            TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY,
            "X.509 verifier empty",
        )
            .into())
    }
}

/// Sets the X.509 identity to use.
/// If the client sets an X.509 identity, then it will expect a client
/// certificate request from the server, in order to establish a mutual
/// TLS tunnel (mTLS).
fn ssl_context_set_identity<OsslInterface>(
    ssl_ctx: NonNull<OsslInterface::NativeSslCtx>,
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

    let bio = OsslInterface::bio_from_buffer(&data_source)
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    OsslInterface::certificate_from_bio(bio.as_nonnull(), format)
        .and_then(|cert| OsslInterface::ssl_context_set_certificate(ssl_ctx, cert.as_nonnull()))
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    while !OsslInterface::bio_eof(bio.as_nonnull()) {
        OsslInterface::certificate_from_bio(bio.as_nonnull(), format)
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
        .and_then(|bio| OsslInterface::private_key_from_bio(bio.as_nonnull(), format))
        .and_then(|private_key| {
            OsslInterface::ssl_context_set_private_key(ssl_ctx, private_key.as_nonnull())
        })
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

    OsslInterface::ssl_context_check_private_key(ssl_ctx)
}

/// Pushes the trusted certificate authority certificates to the trust store.
fn ssl_fill_trust_store<OsslInterface>(
    ssl_ctx: NonNull<OsslInterface::NativeSslCtx>,
    x509_verifier: &pb_api::X509Verifier,
) -> crate::Result<usize>
where
    OsslInterface: Ossl,
{
    for cert in x509_verifier.trusted_cas.iter() {
        let (format, data_source) = read_certificate(cert)?;
        let bio = OsslInterface::bio_from_buffer(&data_source)?;

        while !OsslInterface::bio_eof(bio.as_nonnull()) {
            OsslInterface::certificate_from_bio(bio.as_nonnull(), format).and_then(|cert| {
                OsslInterface::ssl_context_append_certificate_to_trust_store(
                    ssl_ctx,
                    cert.as_nonnull(),
                )
            })?;
        }
    }
    Ok(x509_verifier.trusted_cas.len())
}

/// Instantiates an OsslContext from a protobuf configuration.
impl<'a, OsslInterface> TryFrom<&pb_api::Configuration> for OsslContext<'a, OsslInterface>
where
    OsslInterface: Ossl,
{
    type Error = crate::Error;

    fn try_from(configuration: &pb_api::Configuration) -> crate::Result<Self> {
        let (mode, tls_options) = configuration_get_mode_and_tls_options(configuration)?;

        let ssl_ctx = OsslInterface::new_ssl_context(mode)
            .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

        OsslInterface::ssl_context_set_kems(ssl_ctx.as_nonnull(), tls_options.kem.iter())
            .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

        OsslInterface::ssl_context_set_alpn_protos(
            ssl_ctx.as_nonnull(),
            tls_options.alpn_protocols.iter(),
        )
        .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;

        let x509_verifier =
            tls_options_get_x509_verifier(tls_options).and_then(x509_verifier_verify_emptiness)?;

        OsslInterface::ssl_context_set_verify_depth(
            ssl_ctx.as_nonnull(),
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
            ssl_context_set_identity::<OsslInterface>(ssl_ctx.as_nonnull(), identity)?;
        }

        if let Some(v) = x509_verifier {
            ssl_fill_trust_store::<OsslInterface>(ssl_ctx.as_nonnull(), v)
                .map_err(|e| e >> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID)?;
        }

        if x509_verifier.is_none() {
            OsslInterface::ssl_context_set_verify_mode(ssl_ctx.as_nonnull(), VerifyMode::None);
        } else {
            OsslInterface::ssl_context_set_verify_mode(
                ssl_ctx.as_nonnull(),
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
impl<'a, OsslInterface> Borrow<Pimpl<'a, OsslInterface::NativeSslCtx>>
    for OsslContext<'a, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow(&self) -> &Pimpl<'a, OsslInterface::NativeSslCtx> {
        &self.ssl_ctx
    }
}

/// Borrows as mutable the SSL context from [`OsslContext`].
impl<'a, OsslInterface> BorrowMut<Pimpl<'a, OsslInterface::NativeSslCtx>>
    for OsslContext<'a, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow_mut(&mut self) -> &mut Pimpl<'a, OsslInterface::NativeSslCtx> {
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
impl<'a, OsslInterface> OsslContext<'a, OsslInterface> where OsslInterface: Ossl {}

/// A generic tunnel that uses an OpenSSL-like backend.
pub(crate) struct OsslTunnel<'a, OsslInterface>
where
    OsslInterface: Ossl + ?Sized,
{
    /// The current mode.
    pub(crate) mode: Mode,

    /// The SSL handle.
    pub(crate) ssl: Pimpl<'a, OsslInterface::NativeSsl>,

    /// The BIO handle.
    pub(crate) bio: NonNull<OsslInterface::NativeBio>,

    /// The IO.
    pub(crate) io: Box<dyn crate::IO>,

    /// The security at tunnel time.
    pub(crate) security_requirements: tls::TunnelSecurityRequirements,

    /// The state of the tunnel.
    pub(crate) state: pb::State,
}

/// Implements [`std::fmt::Debug`] for [`OsslTunnel`].
impl<OsslInterface> std::fmt::Debug for OsslTunnel<'_, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Ossl tunnel")
    }
}

/// Tunnel builder.
/// This is a convenient aggregate of useful values to build a tunnel.
pub(crate) struct TunnelBuilder<'a, 'b, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// The context.
    pub(crate) ctx: &'b OsslContext<'a, OsslInterface>,

    /// The IO interface.
    pub(crate) io: Box<dyn crate::IO>,

    /// The tunnel-time configuration.
    pub(crate) configuration: pb_api::TunnelConfiguration,
}

/// Applies security requirements regarding the Subject Alternative Names.
fn apply_san_verifier_to_ssl<OsslInterface>(
    ssl: NonNull<OsslInterface::NativeSsl>,
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

/// Implements [`crate::tunnel::Tunnel`] for [`OsslTunnel`].
impl<'a, OsslInterface> OsslTunnel<'a, OsslInterface>
where
    OsslInterface: Ossl + 'static,
{
    fn try_from<'b>(
        builder: TunnelBuilder<'b, '_, OsslInterface>,
    ) -> Result<PinnelOsslTunnel<'a, OsslInterface>, (crate::Error, Box<dyn crate::IO>)>
    where
        'b: 'a,
    {
        use tls::VerifierSanitizer;

        let Some(tunnel_verifier) = builder.configuration.verifier.as_ref() else {
            return Err((
                (pb::TunnelError::TUNNELERROR_VERIFIER, "empty verifier").into(),
                builder.io,
            ));
        };

        let security_requirements = builder.ctx.security_requirements.clone();
        if let Err(e) = security_requirements.run_sanitizer_checks(tunnel_verifier) {
            return Err((e, builder.io));
        }

        let ssl = OsslInterface::new_ssl_handle(builder.ctx.borrow());
        let ssl = if let Err(e) = ssl {
            return Err((e, builder.io));
        } else {
            ssl.unwrap()
        };

        OsslInterface::ssl_set_last_verify_error(ssl.as_nonnull(), 0);

        if let Some(pb_api::verifiers::tunnel_verifier::Verifier::SanVerifier(ref san_verifier)) =
            tunnel_verifier.verifier
        {
            if let Err(e) =
                apply_san_verifier_to_ssl::<OsslInterface>(ssl.as_nonnull(), san_verifier)
            {
                return Err((e, builder.io));
            }
        }

        if !builder.configuration.server_name_indication.is_empty() {
            if let Err(e) = OsslInterface::ssl_set_server_name_indication(
                ssl.as_nonnull(),
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
        if let Err(e) = OsslInterface::ssl_set_bio(ssl.as_nonnull(), bio.as_nonnull()) {
            return Err((e, builder.io));
        }
        let bio = unsafe {
            // We are sure that `bio` is non-null since it was previously wrapped
            // by `Pimpl`.
            NonNull::new_unchecked(bio.into_raw())
        };

        let mut tun = Box::new(Self {
            mode: builder.ctx.mode,
            ssl,
            bio,
            io: builder.io,
            security_requirements: builder.ctx.security_requirements.clone(),
            state: pb::State::STATE_NOT_CONNECTED,
        });

        OsslInterface::bio_set_data(tun.bio, (&mut *tun as *mut Self).cast());
        let _ = OsslInterface::ssl_set_extra_data_for_verify(
            tun.ssl.as_nonnull(),
            &mut tun.security_requirements as *mut _,
        );
        Ok(Box::into_pin(tun))
    }

    pub(crate) fn state(&self) -> crate::tunnel::State {
        self.state.into()
    }

    pub(crate) fn handshake(&mut self) -> crate::Result<crate::tunnel::HandshakeState> {
        if self.state == pb::State::STATE_HANDSHAKE_DONE {
            return Ok(pb::HandshakeState::HANDSHAKESTATE_DONE.into());
        }

        let state = OsslInterface::ssl_get_handshake_state(self.ssl.as_nonnull());
        if state == pb::HandshakeState::HANDSHAKESTATE_DONE {
            self.state = pb::State::STATE_HANDSHAKE_DONE;
            return Ok(state.into());
        }

        let (handshake_state, tunnel_state) =
            OsslInterface::ssl_handshake(self.ssl.as_nonnull(), self.mode);
        if let Some(tunnel_state) = tunnel_state {
            self.state = tunnel_state;
        }
        match handshake_state {
            Ok(state) => Ok(state.into()),
            Err(state) => Err(state),
        }
    }

    pub(crate) fn read(&mut self, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(RecordError::RECORDERROR_TOO_BIG.into());
        }

        let res = OsslInterface::ssl_read(self.ssl.as_nonnull(), buf);

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

    pub(crate) fn write(&mut self, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (i32::MAX as usize) {
            return Err(RecordError::RECORDERROR_TOO_BIG.into());
        }

        let res = OsslInterface::ssl_write(self.ssl.as_nonnull(), buf);

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

    pub(crate) fn close(&mut self) -> crate::tunnel::RecordResult<()> {
        OsslInterface::ssl_close(self.ssl.as_nonnull())
    }

    /// Check the state of SSL, regarding the shutdown phase, and update
    /// the tunnel state if necessary.
    fn check_shutdown(&mut self) -> pb::State {
        let state = OsslInterface::ssl_get_shutdown_state(self.ssl.as_nonnull());
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

            use crate::tunnel::tls;
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
                    let bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM).unwrap();
                }

                /// Tests [`Ossl::certificate_from_bio`] using /etc/ssl/cert.pem.
                #[test]
                fn test_certificate_from_bio_etc_ssl_cert() {
                    let cert = std::fs::read(crate::test::resolve_runfile("testdata/etc_ssl_cert.pem"))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    while !Ossl::bio_eof(bio.as_nonnull()) {
                        Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM).unwrap();
                    }
                }

                /// Tests [`Ossl::certificate_from_bio`] using a DER certificate.
                #[test]
                fn test_certificate_from_bio_with_der() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                }

                /// Tests [`Ossl::certificate_from_bio`] using a DER certificate.
                #[test]
                fn test_certificate_from_bio_der_valid() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                }

                /// Tests [`Ossl::certificate_from_bio`] using a DER certificate that contains an invalid sig alg (invalid OID).
                #[test]
                fn test_certificate_from_bio_der_with_invalid_der() {
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert)
                        .expect("failed to create a bio from a buffer");
                    let err = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap_err();
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
                    let bio = Ossl::bio_from_buffer(&skey)
                        .expect("failed to create a bio from a buffer");
                    Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM).unwrap();
                }

                /// Tests [`Ossl::private_key_from_bio`] using a DER private key.
                #[test]
                fn test_private_key_from_bio_der_with_der() {
                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_DER_PATH))
                        .expect("failed to read the private key");
                    let bio = Ossl::bio_from_buffer(&skey)
                        .expect("failed to create a bio from a buffer");
                    Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                }

                /// Tests [`Ossl::private_key_from_bio`] using a DER private key.
                #[test]
                fn test_private_key_from_bio_der_valid() {
                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_DER_PATH))
                        .expect("failed to read the private key");
                    let bio = Ossl::bio_from_buffer(&skey)
                        .expect("failed to create a bio from a buffer");
                    Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                }
            }

            /// SSL context related tests.
            mod ssl_ctx {
                use super::*;

                /// Tests instantiates a [`SSL_CTX`] for a client.
                #[test]
                fn test_ssl_ctx_client() {
                    Ossl::new_ssl_context(Mode::Client).unwrap();
                }

                /// Tests instantiates a [`SSL_CTX`] for a server.
                #[test]
                fn test_ssl_ctx_server() {
                    Ossl::new_ssl_context(Mode::Server).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_kems`] with two valid KEMs.
                #[test]
                fn test_ssl_ctx_set_kems_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let kems = vec!["kyber512".into(), "X25519".into()];
                    Ossl::ssl_context_set_kems(ssl.as_nonnull(), kems.iter()).unwrap();

                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    Ossl::ssl_context_set_kems(ssl.as_nonnull(), kems.iter()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_kems`] with one valid KEM and one invalid KEM.
                #[test]
                fn test_ssl_ctx_set_kems_invalid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let kems = vec!["kyber512".into(), "X1337".into()];
                    let err = Ossl::ssl_context_set_kems(ssl.as_nonnull(), kems.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::KEMError::KEMERROR_INVALID}));
                }

                /// Tests [`Ossl::ssl_context_set_kems`] with no KEMs.
                #[test]
                fn test_ssl_ctx_set_kems_no_kems() {
                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let kems = Vec::<String>::new();
                    Ossl::ssl_context_set_kems(ssl.as_nonnull(), kems.iter()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_certificate`] with a valid PEM certificate.
                #[test]
                fn test_ssl_ctx_set_certificate_pem_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM).unwrap();
                    Ossl::ssl_context_set_certificate(ssl.as_nonnull(), cert.as_nonnull()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_certificate`] with a valid DER certificate.
                #[test]
                fn test_ssl_ctx_set_certificate_der_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                    Ossl::ssl_context_set_certificate(ssl.as_nonnull(), cert.as_nonnull()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_private_key`] with a valid PEM private key.
                #[test]
                fn test_ssl_ctx_set_private_key_pem_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_PATH))
                        .expect("failed to read the private key");
                    let bio = Ossl::bio_from_buffer(&skey).unwrap();
                    let skey = Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM).unwrap();
                    Ossl::ssl_context_set_private_key(ssl.as_nonnull(), skey.as_nonnull()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_private_key`] with a valid DER private key.
                #[test]
                fn test_ssl_ctx_set_private_key_der_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    let skey = std::fs::read(crate::test::resolve_runfile(tls::test::SK_DER_PATH))
                        .expect("failed to read the private key");
                    let bio = Ossl::bio_from_buffer(&skey).unwrap();
                    let skey = Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                    Ossl::ssl_context_set_private_key(ssl.as_nonnull(), skey.as_nonnull()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_append_certificate_to_trust_store`] with a valid PEM certificate.
                #[test]
                fn test_ssl_ctx_append_certificate_to_trust_store_pem_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM).unwrap();

                    Ossl::ssl_context_append_certificate_to_trust_store(ssl.as_nonnull(), cert.as_nonnull()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_append_certificate_to_trust_store`] with a valid DER certificate.
                #[test]
                fn test_ssl_ctx_append_certificate_to_trust_store_der_valid() {
                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_DER_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER).unwrap();
                    Ossl::ssl_context_append_certificate_to_trust_store(ssl.as_nonnull(), cert.as_nonnull()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_check_private_key`] with a valid pair certificate/private key,
                /// and then an inconsistency pair certificate/private key.
                #[test]
                fn test_ssl_ctx_check_private_key() {
                    let ssl_ctx = Ossl::new_ssl_context(Mode::Server).unwrap();
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM)
                        .expect("failed to parse the certificate");
                    Ossl::ssl_context_set_certificate(ssl_ctx.as_nonnull(), cert.as_nonnull())
                        .expect("failed to set the certificate");

                    let private_key = std::fs::read(crate::test::resolve_runfile(tls::test::SK_PATH))
                        .expect("failed to read the private key");
                    let bio = Ossl::bio_from_buffer(&private_key).unwrap();
                    let private_key = Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM)
                        .expect("failed to parse the private key");
                    Ossl::ssl_context_set_private_key(ssl_ctx.as_nonnull(), private_key.as_nonnull())
                        .expect("failed to set the private key");

                    Ossl::ssl_context_check_private_key(ssl_ctx.as_nonnull())
                        .expect("private key and certificate should be seen as consistent");

                    let ssl_ctx = Ossl::new_ssl_context(Mode::Server).unwrap();
                    let cert = std::fs::read(crate::test::resolve_runfile(tls::test::CERT_PEM_PATH))
                        .expect("failed to read the certificate");
                    let bio = Ossl::bio_from_buffer(&cert).unwrap();
                    let cert = Ossl::certificate_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM)
                        .expect("failed to parse the certificate");
                    Ossl::ssl_context_set_certificate(ssl_ctx.as_nonnull(), cert.as_nonnull())
                        .expect("failed to set the certificate");

                    let private_key = std::fs::read(crate::test::resolve_runfile(tls::test::PQ_PRIVATE_KEY_DER_PATH))
                        .expect("failed to read the private key");
                    let bio = Ossl::bio_from_buffer(&private_key).unwrap();
                    let private_key = Ossl::private_key_from_bio(bio.as_nonnull(), pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER)
                        .expect("failed to parse the certificate");

                    // BoringSSL performs the consistency check when `SSL_CTX_use_PrivateKey` is called.
                    // See https://github.com/google/boringssl/blob/e9f816b12b3e68de575d21e2a9b7d76e4e5c58ac/ssl/ssl_privkey.cc#L86-L91.
                    let mut has_err = false;
                    if Ossl::ssl_context_set_private_key(ssl_ctx.as_nonnull(), private_key.as_nonnull()).is_err() {
                        has_err = true;
                    }

                    if Ossl::ssl_context_check_private_key(ssl_ctx.as_nonnull()).is_err() {
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

                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    Ossl::ssl_context_set_alpn_protos(ssl.as_nonnull(), protos.iter()).unwrap();

                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    Ossl::ssl_context_set_alpn_protos(ssl.as_nonnull(), protos.iter()).unwrap();
                }

                /// Tests [`Ossl::ssl_context_set_alpn_protos`] with ALPN has NULL bytes in the middle.
                #[test]
                fn test_ssl_ctx_set_alpn_protos_nullbytes() {
                    let protos = vec!["http\x00/1.1".into()];

                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let err = Ossl::ssl_context_set_alpn_protos(ssl.as_nonnull(), protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_INVALID_STRING}));

                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();

                    let err = Ossl::ssl_context_set_alpn_protos(ssl.as_nonnull(), protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_INVALID_STRING}));
                }

                /// Tests [`Ossl::ssl_context_set_alpn_protos`] with ALPN has length longer than 255.
                #[test]
                fn test_ssl_ctx_set_alpn_protos_invalid_length() {
                    let protos = vec!["http/1.1".repeat(100).into()];

                    let ssl = Ossl::new_ssl_context(Mode::Client).unwrap();

                    let err = Ossl::ssl_context_set_alpn_protos(ssl.as_nonnull(), protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_LENGTH_ERROR}));

                    let ssl = Ossl::new_ssl_context(Mode::Server).unwrap();
                    let err = Ossl::ssl_context_set_alpn_protos(ssl.as_nonnull(), protos.iter()).unwrap_err();
                    assert!(err.is(&errors! {pb::ALPNError::ALPNERROR_LENGTH_ERROR}));
                }
            }

            /// BIO related tests.
            mod ssl_bio {
                use super::*;

                /// Tests creation of SSL BIO.
                #[test]
                fn test_bio_creation() {
                    Ossl::new_ssl_bio().unwrap();
                }
            }

            /// X509 verify params related tests.
            mod x509_verify_params {
                use super::*;

                /// Tests the getter of SSL for X509 verify params.
                #[test]
                fn test_getter_x509_verify_params() {
                    let ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let ssl = Ossl::new_ssl_handle(&ctx).unwrap();
                    Ossl::ssl_get_x509_verify_parameters(ssl.as_nonnull()).unwrap();
                }

                /// Tests adding a DNS entry to the X509 verify params.
                #[test]
                fn test_add_dns() {
                    let ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let ssl = Ossl::new_ssl_handle(&ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_nonnull()).unwrap();
                    Ossl::x509_verify_parameters_add_san_dns(params, "example.com").expect("adding a valid DNS must be valid");
                }

                /// Tests setting an email entry to the X509 verify params.
                #[test]
                fn test_set_email() {
                    let ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let ssl = Ossl::new_ssl_handle(&ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_nonnull()).unwrap();
                    Ossl::x509_verify_parameters_set_san_email(params, "zadig@example.com").expect("setting a valid email address must be valid");
                }

                /// Tests setting an IP address to the X509 verify params.
                #[test]
                fn test_set_ip_address() {
                    let ctx = Ossl::new_ssl_context(Mode::Client).unwrap();
                    let ssl = Ossl::new_ssl_handle(&ctx).unwrap();
                    let params = Ossl::ssl_get_x509_verify_parameters(ssl.as_nonnull()).unwrap();
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
