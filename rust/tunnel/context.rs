// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Context`] trait.
//!
//! ## [`Context`] trait
//!
//! [`Context`] trait is the entrypoint for Sandwich. It is created
//! from a protobuf configuration (see `proto/api/v1`).
//!
//! A [`Context`] is tied to a specific underlying implementation and a
//! protocol. From it, developers may spawn tunnels (see [`Tunnel`].
//! Any objects derived from a [`Context`] will use its configuration.

use pb::ConfigurationError;

use crate::implementation::ossl;

use super::Tunnel;

use crate::tunnel::tls;

/// Mode for a [`Context`].
///
/// A [`Context`] is either a context for client-side applications or
/// server-side applications.
#[derive(PartialEq, Eq, Copy, Clone)]
pub(crate) enum Mode {
    /// Client mode.
    Client,
    /// Server mode.
    Server,
}

/// The result type of [`Context::new_tunnel`].
/// In case of success, [`Context::new_tunnel`] returns the tunnel.
/// In case of error, [`Context::new_tunnel`] returns an error code
/// ([`crate::Error`]) along with the I/O that was meant to be used to create
/// the tunnel.
/// Returning the I/O interface in case of error allows the caller to re-use it
/// without having to create a new one.
pub type TunnelResult<'a> = Result<Tunnel<'a>, (crate::Error, Box<dyn crate::IO>)>;

/// A Sandwich context.
pub enum Context<'a> {
    /// OpenSSL 1.1.1 context.
    #[cfg(feature = "openssl1_1_1")]
    OpenSSL1_1_1(ossl::openssl1_1_1::Context<'a>),

    /// BoringSSL context.
    #[cfg(feature = "boringssl")]
    BoringSSL(ossl::boringssl::Context<'a>),
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            #[cfg(feature = "openssl1_1_1")]
            Self::OpenSSL1_1_1(c) => write!(f, "Context(OpenSSL1_1_1({c:?}))"),
            #[cfg(feature = "boringssl")]
            Self::BoringSSL(c) => write!(f, "Context(BoringSSL({c:?}))"),
        }
    }
}

impl<'a> Context<'a> {
    /// Instantiates a [`Context`] from a protobuf configuration message.
    ///
    /// # Examples
    ///
    /// ## Constructs a configuration in Rust.
    /// ```
    /// use sandwich_api_proto as pb_api;
    ///
    /// Instantiates a top-level context.
    /// let sw = sandwich::Context;
    ///
    /// // Creates a protobuf configuration
    /// let mut configuration = pb_api::Configuration::new();
    ///
    /// // Sets the implementation to be used by Sandwich. Here it's OpenSSL 1.1.1
    /// // with liboqs.
    /// configuration.set_impl(pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS);
    ///
    /// // Sets the client or server configuration according to the implementation
    /// // and the protocol.
    /// // …
    ///
    /// // Creates the Sandwich context that will make use of the supplied
    /// // configuration.
    ///
    /// match sandwich::context::try_from(&sw, &configuration) {
    ///     Err(e) => eprintln!("Failed to instantiate a Sandwich context: {}", e),
    ///     Ok(context) => {
    ///         // Do something with `context`.
    ///     }
    /// };
    ///
    /// ```
    pub fn try_from(
        _context: &'a crate::Context,
        configuration: &pb_api::Configuration,
    ) -> crate::Result<Self> {
        tls::assert_compliance(configuration)?;
        configuration
        .impl_
        .enum_value()
        .map_err(|_| errors!{ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => ConfigurationError::CONFIGURATIONERROR_INVALID})
        .and_then(|v| match v {
            #[cfg(feature = "openssl1_1_1")]
            pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS => {
                ossl::openssl1_1_1::Context::try_from(configuration)
                    .map(Self::OpenSSL1_1_1)
                    .map_err(|e| e >> ConfigurationError::CONFIGURATIONERROR_INVALID)
            }
            #[cfg(feature = "boringssl")]
            pb_api::Implementation::IMPL_BORINGSSL_OQS => {
                ossl::boringssl::Context::try_from(configuration)
                    .map(Self::BoringSSL)
                    .map_err(|e| e >> ConfigurationError::CONFIGURATIONERROR_INVALID)
            }
            _ => Err(
                errors!{ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => ConfigurationError::CONFIGURATIONERROR_INVALID}
            ),
        })
        .map_err(|e| e >> pb::APIError::APIERROR_CONFIGURATION)
    }

    /// Creates a new tunnel from an I/O interface. See [`crate::IO`] from [`crate::io`] module.
    ///
    /// The I/O interface must outlive the tunnel, as the tunnel makes use
    /// of it to send and receive data.
    ///
    /// If an error occured, the IO interface is returned to the user.
    pub fn new_tunnel(
        &self,
        io: Box<dyn crate::IO>,
        configuration: pb_api::TunnelConfiguration,
    ) -> TunnelResult<'_> {
        match self {
            #[cfg(feature = "openssl1_1_1")]
            Self::OpenSSL1_1_1(c) => Ok(Tunnel::OpenSSL1_1_1(ossl::openssl1_1_1::Tunnel(
                c.0.new_tunnel(io, configuration)?,
            ))),
            #[cfg(feature = "boringssl")]
            Self::BoringSSL(c) => Ok(Tunnel::BoringSSL(ossl::boringssl::Tunnel(
                c.0.new_tunnel(io, configuration)?,
            ))),
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) mod test {
    use super::*;
    use crate::test::resolve_runfile;

    /// The following tests target the OpenSSL 1.1.1 + liboqs Implementation
    /// (`sandwich_api_proto::Implementation::IMPL_OPENSSL1_1_1_OQS`).
    #[cfg(feature = "openssl1_1_1")]
    pub(crate) mod openssl1_1_1 {
        use super::*;
        use crate::tunnel::tls;

        /// Tests a [`sandwich_api_proto::Configuration`] for OpenSSL.
        #[test]
        fn test_configuration() {
            let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
                format!(
                    r#"
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
                      alpn_protocols: "h2"
                      alpn_protocols: "http/1.1"
                    >
                  >
                >
                "#,
                    resolve_runfile(tls::test::CERT_PEM_PATH),
                )
                .as_str(),
            )
            .unwrap();
            config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
            let sw_ctx = crate::Context;
            let ctx = Context::try_from(&sw_ctx, &config);
            ctx.unwrap();
        }

        /// Tests a [`sandwich_api_proto::Configuration`] for OpenSSL, but
        /// but with missing implementation field.
        #[test]
        fn test_configuration_no_impl() {
            let config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
                format!(
                    r#"
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
            let sw_ctx = crate::Context;
            let ctx = Context::try_from(&sw_ctx, &config);
            assert!(ctx.is_err());
            assert!(
                ctx.unwrap_err().is(
                &errors! {ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => ConfigurationError::CONFIGURATIONERROR_INVALID => pb::APIError::APIERROR_CONFIGURATION}
            ));
        }

        /// Tests a [`sandwich_api_proto::Configuration`] for OpenSSL, but with
        /// an certificate supplied.
        #[test]
        fn test_configuration_bad_cert() {
            let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
                format!(
                    r#"
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
                            format: ENCODING_FORMAT_DER
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
            config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
            let sw_ctx = crate::Context;
            let ctx = Context::try_from(&sw_ctx, &config);
            assert!(ctx.is_err());
            assert!(ctx.unwrap_err().is(&errors! {
                pb::ASN1Error::ASN1ERROR_MALFORMED
                    => pb::CertificateError::CERTIFICATEERROR_MALFORMED
                        => pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID
                            => ConfigurationError::CONFIGURATIONERROR_INVALID
                                => pb::APIError::APIERROR_CONFIGURATION
            }));
        }

        /// Tests a [`sandwich_api_proto::Configuration`] for OpenSSL, but with
        /// an invalid private key supplied.
        #[test]
        fn test_configuration_bad_sk() {
            let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
                format!(
                    r#"
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
                              filename: "{cert}"
                            >
                            format: ENCODING_FORMAT_PEM
                          >
                        >
                      >
                      identity <
                        certificate <
                          static <
                            data <
                              filename: "{cert}"
                            >
                            format: ENCODING_FORMAT_PEM
                          >
                        >
                        private_key <
                          static <
                            data <
                              filename: "{private_key}"
                            >
                            format: ENCODING_FORMAT_DER
                          >
                        >
                      >
                    >
                  >
                >
                "#,
                    cert = resolve_runfile(tls::test::CERT_PEM_PATH),
                    private_key = resolve_runfile(tls::test::SK_PATH),
                )
                .as_str(),
            )
            .unwrap();
            config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
            let sw_ctx = crate::Context;
            let ctx = Context::try_from(&sw_ctx, &config);
            assert!(ctx.is_err());
            assert!(ctx.unwrap_err().is(&errors! {
                pb::ASN1Error::ASN1ERROR_MALFORMED
                    => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED
                        => pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID
                            => ConfigurationError::CONFIGURATIONERROR_INVALID
                                => pb::APIError::APIERROR_CONFIGURATION
            }));
        }
    }
}
