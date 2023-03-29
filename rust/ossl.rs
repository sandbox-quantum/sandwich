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
//!
//! Author: thb-sb

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

    /// Performs the handshake.
    fn ssl_handshake(
        ssl: *mut Self::NativeSsl,
        mode: crate::Mode,
    ) -> (pb::tunnel::HandshakeState, Option<pb::State>);

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
pub(crate) enum OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    /// Client mode.
    Client(crate::Pimpl<'ctx, OsslInterface::NativeSslCtx>),
    /// Server mode.
    Server(crate::Pimpl<'ctx, OsslInterface::NativeSslCtx>),
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
        io: &'io mut (dyn crate::IO + 'io),
    ) -> crate::Result<Box<dyn crate::Tunnel<'io, 'tun> + 'tun>>
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

        let flags = common_options.map(|co| co.flags).unwrap_or(0);
        let mut ctx = match mode {
            crate::Mode::Client => {
                OsslInterface::ssl_context_set_verify_mode(&mut ssl_ctx, flags as u32);
                Self::Client(ssl_ctx)
            }
            crate::Mode::Server => Self::Server(ssl_ctx),
        };
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
        match *self {
            Self::Client(ref ctx) => ctx,
            Self::Server(ref ctx) => ctx,
        }
    }
}

/// Borrows as mutable the SSL context from [`OsslContext`].
impl<'ctx, OsslInterface> std::borrow::BorrowMut<crate::Pimpl<'ctx, OsslInterface::NativeSslCtx>>
    for OsslContext<'ctx, OsslInterface>
where
    OsslInterface: Ossl,
{
    fn borrow_mut(&mut self) -> &mut crate::Pimpl<'ctx, OsslInterface::NativeSslCtx> {
        match *self {
            Self::Client(ref mut ctx) => ctx,
            Self::Server(ref mut ctx) => ctx,
        }
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
        match *self {
            Self::Client(ref mut ssl_ctx) => {
                let tls = configuration.client().tls();
                for cert in tls.trusted_certificates.iter() {
                    read_certificate(cert)
                        .and_then(|(format, cert)| match format {
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => OsslInterface::certificate_from_pem(cert),
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => OsslInterface::certificate_from_der(cert),
                        })
                        .and_then(|cert| OsslInterface::ssl_context_append_certificate_to_trust_store(ssl_ctx, cert))
                        .map_err(|e| e >> pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE)?;
                }
                Ok(())
            }
            Self::Server(ref mut ssl_ctx) => {
                if let Some(cert) = configuration.server().tls().certificate.as_ref() {
                    read_certificate(cert)
                        .and_then(|(format, cert)| match format {
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => OsslInterface::certificate_from_pem(cert),
                            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => OsslInterface::certificate_from_der(cert),
                        })
                        .and_then(|cert| OsslInterface::ssl_context_set_certificate(ssl_ctx, cert))
                        .map_err(|e| e >> pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Sets the private key.
    fn set_private_key(&mut self, configuration: &pb_api::Configuration) -> crate::Result<()> {
        if let Self::Server(ref mut ssl_ctx) = *self {
            if let Some(private_key) = configuration.server().tls().private_key.as_ref() {
                read_private_key(private_key)
                    .and_then(|(format, private_key)| match format {
                        pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => OsslInterface::private_key_from_pem(private_key),
                        pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => OsslInterface::private_key_from_der(private_key),
                    })
                    .and_then(|private_key| OsslInterface::ssl_context_set_private_key(ssl_ctx, private_key))
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
    OsslInterface: Ossl,
{
    /// The current mode.
    pub(crate) mode: crate::Mode,

    /// The SSL handle.
    pub(crate) ssl: crate::Pimpl<'tun, OsslInterface::NativeSsl>,

    /// The BIO handle.
    pub(crate) bio: crate::Pimpl<'tun, OsslInterface::NativeBio>,

    /// The IO.
    pub(crate) io: &'io mut (dyn crate::IO + 'io),

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
        &'io mut (dyn crate::IO + 'io),
    )> for OsslTunnel<'io, 'tun, OsslInterface>
where
    'io: 'tun,
    'ctx: 'tun,
    OsslInterface: Ossl,
{
    type Error = crate::Error;

    fn try_from(
        (ctx, io): (
            &mut OsslContext<'ctx, OsslInterface>,
            &'io mut (dyn crate::IO + 'io),
        ),
    ) -> crate::Result<OsslTunnel<'io, 'tun, OsslInterface>> {
        use std::borrow::BorrowMut;
        let mode = match *ctx {
            OsslContext::Client(_) => crate::Mode::Client,
            OsslContext::Server(_) => crate::Mode::Server,
        };
        let ssl = OsslInterface::new_ssl_handle(ctx.borrow_mut())?;
        let bio = crate::Pimpl::from_raw(OsslInterface::new_ssl_bio()?.into_raw(), None);
        Ok(Self {
            mode,
            ssl,
            bio,
            io,
            state: pb::State::STATE_NOT_CONNECTED,
        })
    }
}

/// Implements [`crate::Tunnel`] for [`OssTunnel`].
impl<'io: 'tun, 'tun, OsslInterface> crate::Tunnel<'io, 'tun>
    for OsslTunnel<'io, 'tun, OsslInterface>
where
    OsslInterface: Ossl + 'static,
{
    fn state(&self) -> crate::tunnel::State {
        self.state.into()
    }

    fn handshake(&mut self) -> crate::tunnel::HandshakeState {
        if self.state == pb::State::STATE_HANDSHAKE_DONE {
            return pb::HandshakeState::HANDSHAKESTATE_DONE.into();
        }

        let state = OsslInterface::ssl_get_handshake_state(self.ssl.as_ptr());
        if state == pb::HandshakeState::HANDSHAKESTATE_DONE {
            self.state = pb::State::STATE_HANDSHAKE_DONE;
            return state.into();
        }

        let (handshake_state, tunnel_state) =
            OsslInterface::ssl_handshake(self.ssl.as_mut_ptr(), self.mode);
        if let Some(tunnel_state) = tunnel_state {
            self.state = tunnel_state;
        }
        handshake_state.into()
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
        io: &'io mut (dyn crate::IO + 'io),
    ) -> crate::Result<Box<dyn crate::Tunnel<'io, 'tun> + 'tun>>
    where
        'ctx: 'tun,
    {
        let mut tun: Box<OsslTunnel<'io, 'tun, OsslInterface>> =
            Box::new(Self::try_from((ctx, io))?);
        OsslInterface::ssl_set_bio(
            tun.bio.as_mut_ptr(),
            tun.ssl.as_mut_ptr(),
            (&mut *tun as *mut Self) as *mut std::ffi::c_void,
        )?;
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
