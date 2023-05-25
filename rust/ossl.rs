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

//! Defines [`Ossl`] trait, the OpenSSL trait, to support multiple OpenSSL-like implementation.
//!
//! This trait aims to ease the support of multiple OpenSSL-like implementations,
//! such as BoringSSL, LibreSSL and OpenSSL.

/// Default maximum depth for the certificate chain verification.
pub(crate) const DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH: u32 = 100;

/// Trait that supports various OpenSSL-like implementations.
pub(crate) trait Ossl {
    /// The C type for a certificate.
    type NativeCertificate;

    /// The C type for a private key.
    type NativePrivateKey;

    /// The C type for a SSL context (SSL_CTX).
    type NativeSslCtx;

    /// The C type for a SSL handle (SSL).
    type NativeSsl;

    /// The C type for a BIO object.
    type NativeBio;

    /// Creates a new SSL context.
    fn new_ssl_context<'pimpl>(
        mode: crate::Mode,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeSslCtx>>;

    /// Sets the verify mode to a SSL context.
    fn ssl_context_set_verify_mode(pimpl: &mut crate::Pimpl<'_, Self::NativeSslCtx>, flags: u32);

    /// Sets the maximum depth for the certificate chain verification.
    fn ssl_context_set_verify_depth(pimpl: &mut crate::Pimpl<'_, Self::NativeSslCtx>, depth: u32);

    /// Sets the KEM to a SSL context.
    fn ssl_context_set_kems(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        kems: std::slice::Iter<'_, std::string::String>,
    ) -> crate::Result<()>;

    /// Appends a certificate to the certificate trust store.
    /// This is used in client mode.
    fn ssl_context_append_certificate_to_trust_store(
        ssl_ctx: &crate::Pimpl<'_, Self::NativeSslCtx>,
        cert: crate::Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Sets the certificate to use.
    /// This is used in server mode.
    fn ssl_context_set_certificate(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        cert: crate::Pimpl<'_, Self::NativeCertificate>,
    ) -> crate::Result<()>;

    /// Sets the private key to use.
    /// This is used in server mode.
    fn ssl_context_set_private_key(
        ssl_ctx: &mut crate::Pimpl<'_, Self::NativeSslCtx>,
        pkey: crate::Pimpl<'_, Self::NativePrivateKey>,
    ) -> crate::Result<()>;

    /// Instantiates a certificate using a buffer that contains a PEM-encoded certificate.
    fn certificate_from_pem<'pimpl>(
        cert: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeCertificate>>;

    /// Instantiates a certificate using a buffer that contains a DER-encoded certificate.
    fn certificate_from_der<'pimpl>(
        cert: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativeCertificate>>;

    /// Instantiates a private key using a buffer that contains a PEM-encoded private key.
    fn private_key_from_pem<'pimpl>(
        pkey: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativePrivateKey>>;

    /// Instantiates a private key using a buffer that contains a DER-encoded private key.
    fn private_key_from_der<'pimpl>(
        pkey: impl std::convert::AsRef<[u8]>,
    ) -> crate::Result<crate::Pimpl<'pimpl, Self::NativePrivateKey>>;

    /// Instantiates a SSL handle from a SSL context.
    fn new_ssl_handle<'ctx, 'ssl>(
        ssl_context: &mut crate::Pimpl<'ctx, Self::NativeSslCtx>,
    ) -> crate::Result<crate::Pimpl<'ssl, Self::NativeSsl>>
    where
        'ctx: 'ssl;

    /// Instantiates a BIO object for the SSL handle.
    fn new_ssl_bio<'pimpl>() -> crate::Result<crate::Pimpl<'pimpl, Self::NativeBio>>;

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

    /// Performs the handshake.
    fn ssl_handshake(
        ssl: *mut Self::NativeSsl,
        mode: crate::Mode,
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
}

/// A generic context that uses an OpenSSL-like backend.
pub(crate) struct OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// Execution mode.
    mode: crate::Mode,

    /// SSL context.
    ssl_ctx: crate::Pimpl<'ctx, OsslInterface::NativeSslCtx>,
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

/// Implements [`crate::Context`] for [`OsslContext`].
impl<'ctx, OsslInterface> crate::Context<'ctx> for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl + 'static,
{
    fn new_tunnel<'io, 'tun>(
        &mut self,
        io: Box<dyn crate::IO + 'io>,
    ) -> crate::TunnelResult<'io, 'tun>
    where
        'io: 'tun,
        'ctx: 'tun,
    {
        OsslTunnel::<'io, 'tun, OsslInterface>::new_with_io(self, io)
    }
}

/// Instantiates an OsslContext from a protobuf configuration.
impl<'ctx, OsslInterface> std::convert::TryFrom<&pb_api::Configuration>
    for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    type Error = crate::Error;

    fn try_from(configuration: &pb_api::Configuration) -> crate::Result<Self> {
        use pb_api::configuration::client_options as pb_client_options;
        use pb_api::configuration::configuration as pb_configuration;
        use pb_api::configuration::server_options as pb_server_options;
        let mut mode = crate::Mode::Client;
        let (mut ssl_ctx, common_options) = configuration.opts.as_ref()
            .ok_or(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY.into())
            .and_then(|m| match m {
                pb_configuration::Opts::Client(cli) => {
                    mode = crate::Mode::Client;
                    cli.opts.as_ref()
                        .ok_or(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY.into())
                        .and_then(|proto| match proto {
                            pb_client_options::Opts::Tls(tls) => Ok(
                                tls.common_options.as_ref()
                            ),
                            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY.into())
                        })
                },
                pb_configuration::Opts::Server(serv) => {
                    mode = crate::Mode::Server;
                    serv.opts.as_ref()
                        .ok_or(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY.into())
                        .and_then(|proto| match proto {
                            pb_server_options::Opts::Tls(tls) => Ok(
                                tls.common_options.as_ref()
                            ),
                            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY.into())
                        })
                },
                _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY.into()),
            })
            .and_then(|common_options| OsslInterface::new_ssl_context(mode).map(|ssl_ctx| (ssl_ctx, common_options)))
            .and_then(|(mut ssl_ctx, common_options)| if let Some(co) = common_options {
                    OsslInterface::ssl_context_set_kems(&mut ssl_ctx, co.kem.iter()).map(|_|(ssl_ctx, common_options))
                } else {
                    Ok((ssl_ctx, common_options))
                })
            .map_err(|e| e >> match mode {
                    crate::Mode::Client => crate::ErrorCode::from(pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_SSL_CTX_FAILED),
                    crate::Mode::Server => crate::ErrorCode::from(pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_SSL_CTX_FAILED),
            })?;

        let depth = common_options
            .as_ref()
            .and_then(|co| co.x509_verifier.as_ref())
            .map(|verifier| verifier.max_verify_depth)
            .unwrap_or(DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH);
        OsslInterface::ssl_context_set_verify_depth(&mut ssl_ctx, depth);

        let flags = common_options.map(|co| co.flags).unwrap_or(0);
        if mode == crate::Mode::Client {
            OsslInterface::ssl_context_set_verify_mode(&mut ssl_ctx, flags as u32);
        }
        let mut ctx = Self { mode, ssl_ctx };

        unwrap_or!(
            ctx.set_certificates(configuration),
            pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
        );
        unwrap_or!(
            ctx.set_private_key(configuration),
            pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
        );
        Ok(ctx)
    }
}

/// Borrows the SSL context from [`OsslContext`].
impl<'ctx, OsslInterface> std::borrow::Borrow<crate::Pimpl<'ctx, OsslInterface::NativeSslCtx>>
    for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow(&self) -> &crate::Pimpl<'ctx, OsslInterface::NativeSslCtx> {
        &self.ssl_ctx
    }
}

/// Borrows as mutable the SSL context from [`OsslContext`].
impl<'ctx, OsslInterface> std::borrow::BorrowMut<crate::Pimpl<'ctx, OsslInterface::NativeSslCtx>>
    for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow_mut(&mut self) -> &mut crate::Pimpl<'ctx, OsslInterface::NativeSslCtx> {
        &mut self.ssl_ctx
    }
}

/// Reads the content of a certificate as described in a protobuf message.
fn read_certificate(
    cert: &pb_api::Certificate,
) -> crate::Result<(pb_api::ASN1EncodingFormat, crate::DataSource<'_>)> {
    use pb_api::certificate::certificate;
    cert.source
        .as_ref()
        .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
        .and_then(|oneof| match oneof {
            certificate::Source::Static(ref asn1ds) => asn1ds
                .data
                .as_ref()
                .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
                .and_then(crate::DataSource::try_from)
                .and_then(|ds| {
                    asn1ds
                        .format
                        .enum_value()
                        .map_err(|_| pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into())
                        .map(|f| (f, ds))
                }),
            _ => Err(pb::DataSourceError::DATASOURCEERROR_EMPTY.into()),
        })
}

/// Reads the content of a private key as described in a protobuf message.
fn read_private_key(
    private_key: &pb_api::PrivateKey,
) -> crate::Result<(pb_api::ASN1EncodingFormat, crate::DataSource<'_>)> {
    use pb_api::private_key::private_key;
    private_key
        .source
        .as_ref()
        .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
        .and_then(|oneof| match oneof {
            private_key::Source::Static(ref asn1ds) => asn1ds
                .data
                .as_ref()
                .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
                .and_then(crate::DataSource::try_from)
                .and_then(|ds| {
                    asn1ds
                        .format
                        .enum_value()
                        .map_err(|_| pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into())
                        .map(|f| (f, ds))
                }),
            _ => Err(pb::DataSourceError::DATASOURCEERROR_EMPTY.into()),
        })
}

/// Implements [`OsslContext`].
impl<'ctx, OsslInterface> OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// Sets the certificates.
    /// If client mode, then it appends the supplied certificates to the trust store.
    /// If server mode, then it sets the certificate to use.
    fn set_certificates(&mut self, configuration: &pb_api::Configuration) -> crate::Result<()> {
        match self.mode {
            crate::Mode::Client => {
                if let Some(x509_verifier) = configuration
                    .client()
                    .tls()
                    .common_options
                    .as_ref()
                    .and_then(|co| co.x509_verifier.as_ref())
                {
                    for cert in x509_verifier.trusted_cas.iter() {
                        read_certificate(cert)
                        .and_then(|(format, cert)| match format {
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => OsslInterface::certificate_from_pem(cert),
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => OsslInterface::certificate_from_der(cert),
                        })
                        .and_then(|cert| OsslInterface::ssl_context_append_certificate_to_trust_store(&self.ssl_ctx, cert))
                        .map_err(|e| e >> pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE)?;
                    }
                }
                Ok(())
            }
            crate::Mode::Server => {
                if let Some(cert) = configuration.server().tls().certificate.as_ref() {
                    read_certificate(cert)
                        .and_then(|(format, cert)| match format {
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => OsslInterface::certificate_from_pem(cert),
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => OsslInterface::certificate_from_der(cert),
                        })
                        .and_then(|cert| OsslInterface::ssl_context_set_certificate(&mut self.ssl_ctx, cert))
                        .map_err(|e| e >> pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Sets the private key.
    fn set_private_key(&mut self, configuration: &pb_api::Configuration) -> crate::Result<()> {
        if self.mode == crate::Mode::Server {
            if let Some(private_key) = configuration.server().tls().private_key.as_ref() {
                read_private_key(private_key)
                    .and_then(|(format, private_key)| match format {
                        pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => OsslInterface::private_key_from_pem(private_key),
                        pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => OsslInterface::private_key_from_der(private_key),
                    })
                    .and_then(|private_key| OsslInterface::ssl_context_set_private_key(&mut self.ssl_ctx, private_key))
                    .map_err(|e| e >> pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

/// A generic tunnel that uses an OpenSSL-like backend.
pub(crate) struct OsslTunnel<'io, 'tun, OsslInterface>
where
    OsslInterface: Ossl + ?Sized,
{
    /// The current mode.
    pub(crate) mode: crate::Mode,

    /// The SSL handle.
    pub(crate) ssl: crate::Pimpl<'tun, OsslInterface::NativeSsl>,

    /// The BIO handle.
    pub(crate) bio: crate::Pimpl<'tun, OsslInterface::NativeBio>,

    /// The IO.
    pub(crate) io: Box<dyn crate::IO + 'io>,

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

/// Instantiates a [`OsslTunnel`] from a [`OsslContext`] and an IO interface.
impl<'ctx, 'io, 'tun, OsslInterface>
    std::convert::TryFrom<(
        &mut OsslContext<'ctx, OsslInterface>,
        Box<dyn crate::IO + 'io>,
    )> for OsslTunnel<'io, 'tun, OsslInterface>
where
    'io: 'tun,
    'ctx: 'tun,
    OsslInterface: Ossl,
{
    type Error = (crate::Error, Box<dyn crate::IO + 'io>);

    fn try_from(
        (ctx, io): (
            &mut OsslContext<'ctx, OsslInterface>,
            Box<dyn crate::IO + 'io>,
        ),
    ) -> std::result::Result<OsslTunnel<'io, 'tun, OsslInterface>, Self::Error> {
        use std::borrow::BorrowMut;

        let ssl = OsslInterface::new_ssl_handle(ctx.borrow_mut());
        let ssl = if let Err(e) = ssl {
            return Err((e, io));
        } else {
            ssl.unwrap()
        };

        let bio = OsslInterface::new_ssl_bio();
        let bio = if let Err(e) = bio {
            return Err((e, io));
        } else {
            bio.unwrap()
        };
        let bio = crate::Pimpl::from_raw(bio.into_raw(), None);

        Ok(Self {
            mode: ctx.mode,
            ssl,
            bio,
            io,
            verify_error: 0,
            state: pb::State::STATE_NOT_CONNECTED,
        })
    }
}

/// Implements [`crate::Tunnel`] for [`OsslTunnel`].
impl<'io: 'tun, 'tun, OsslInterface> crate::Tunnel<'io, 'tun>
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
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let res = OsslInterface::ssl_read(self.ssl.as_mut_ptr(), buf);

        let new_state = self.check_shutdown();
        if res.is_ok() {
            return res;
        }

        match new_state {
            pb::State::STATE_BEING_SHUTDOWN => {
                Err(pb::RecordError::RECORDERROR_BEING_SHUTDOWN.into())
            }
            pb::State::STATE_DISCONNECTED => Err(pb::RecordError::RECORDERROR_CLOSED.into()),
            _ => res,
        }
    }

    fn write(&mut self, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let res = OsslInterface::ssl_write(self.ssl.as_mut_ptr(), buf);

        let new_state = self.check_shutdown();
        if res.is_ok() {
            return res;
        }

        match new_state {
            pb::State::STATE_BEING_SHUTDOWN => {
                Err(pb::RecordError::RECORDERROR_BEING_SHUTDOWN.into())
            }
            pb::State::STATE_DISCONNECTED => Err(pb::RecordError::RECORDERROR_CLOSED.into()),
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
        ctx: &mut OsslContext<'ctx, OsslInterface>,
        io: Box<dyn crate::IO + 'io>,
    ) -> crate::TunnelResult<'io, 'tun>
    where
        'ctx: 'tun,
    {
        let mut tun: Box<OsslTunnel<'io, 'tun, OsslInterface>> =
            Box::new(Self::try_from((ctx, io))?);
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
            $ossl
            /// Certificate related tests.
            mod certificates {
                use super::Ossl;
                use crate::ossl::Ossl as OsslTrait;

                /// Tests [`Ossl::certificate_from_pem`] using a PEM certificate.
                #[test]
                fn test_certificate_from_pem_valid() {
                    let cert = std::fs::read(crate::tls::test::CERT_PEM_PATH)
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
                    let cert = std::fs::read(crate::tls::test::CERT_DER_PATH)
                        .expect("failed to read the certificate");
                    let cert = Ossl::certificate_from_pem(cert);
                    let err = cert.unwrap_err();
                    assert!(err.is(&errors!{pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}));
                }

                /// Tests [`Ossl::certificate_from_der`] using a DER certificate.
                #[test]
                fn test_certificate_from_der_valid() {
                    let cert = std::fs::read(crate::tls::test::CERT_DER_PATH)
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
                    let cert = std::fs::read(crate::tls::test::CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH)
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
                    let skey = std::fs::read(crate::tls::test::SK_PATH)
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
                    let skey = std::fs::read(crate::tls::test::SK_DER_PATH)
                        .expect("failed to read the private key");
                    let skey = Ossl::private_key_from_pem(skey);
                    let err = skey.unwrap_err();
                    assert!(err.is(&errors!{pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}));
                }

                /// Tests [`Ossl::private_key_from_der`] using a DER private key.
                #[test]
                fn test_private_key_from_der_valid() {
                    let skey = std::fs::read(crate::tls::test::SK_DER_PATH)
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

                    let cert = std::fs::read(crate::tls::test::CERT_PEM_PATH)
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

                    let cert = std::fs::read(crate::tls::test::CERT_DER_PATH)
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

                    let skey = std::fs::read(crate::tls::test::SK_PATH)
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

                    let skey = std::fs::read(crate::tls::test::SK_DER_PATH)
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

                    let cert = std::fs::read(crate::tls::test::CERT_PEM_PATH)
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

                    let cert = std::fs::read(crate::tls::test::CERT_DER_PATH)
                        .expect("failed to read the certificate");
                    let cert = Ossl::certificate_from_der(cert);
                    let cert = cert.unwrap();
                    assert!(!cert.as_ptr().is_null());

                    Ossl::ssl_context_append_certificate_to_trust_store(&ssl, cert).unwrap();
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
    };
}
