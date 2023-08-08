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

use super::Tunnel;

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
pub type TunnelResult<'io, 'tun> =
    Result<Box<dyn Tunnel<'io, 'tun> + 'tun>, (crate::Error, Box<dyn crate::IO + 'io>)>;

/// A Sandwich context.
/// A Sandwich context is usually instantiated from a protobuf [`sandwich_api_proto::Configuration`].
pub trait Context<'ctx>: std::fmt::Debug {
    /// Creates a new tunnel from an I/O interface. See [`crate::IO`] from [`crate::io`] module.
    ///
    /// The I/O interface must outlive the tunnel, as the tunnel makes use
    /// of it to send and receive data.
    ///
    /// If an error occured, the IO interface is returned to the user.
    fn new_tunnel<'io: 'tun, 'tun>(
        &mut self,
        io: Box<dyn crate::IO + 'io>,
        configuration: pb_api::TunnelConfiguration,
    ) -> TunnelResult<'io, 'tun>
    where
        'ctx: 'tun;
}

/// Instantiates a [`Context`] from a protobuf configuration message.
///
/// # Examples
///
/// ## Constructs a configuration in Rust.
/// ```
/// use sandwich_api_proto as pb_api;
///
/// // Creates a protobuf configuration
/// let mut configuration = pb_api::Configuration::new();

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
/// match sandwich::context::try_from(&configuration) {
///     Err(e) => eprintln!("Failed to instantiate a Sandwich context: {}", e),
///     Ok(context) => {
///         // Do something with `context`.
///     }
/// };
///
/// ```
pub fn try_from<'ctx>(
    configuration: &pb_api::Configuration,
) -> crate::Result<Box<dyn Context<'ctx> + 'ctx>> {
    configuration
        .impl_
        .enum_value()
        .map_err(|_| errors!{ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => ConfigurationError::CONFIGURATIONERROR_INVALID})
        .and_then(|v| match v {
            #[cfg(feature = "openssl1_1_1")]
            pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS => {
                crate::implementation::ossl::openssl1_1_1::try_from(configuration)
                    .map_err(|e| e >> ConfigurationError::CONFIGURATIONERROR_INVALID)
            }
            #[cfg(feature = "boringssl")]
            pb_api::Implementation::IMPL_BORINGSSL_OQS => {
                crate::implementation::ossl::boringssl::try_from(configuration)
                    .map_err(|e| e >> ConfigurationError::CONFIGURATIONERROR_INVALID)
            }
            _ => Err(
                errors!{ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => ConfigurationError::CONFIGURATIONERROR_INVALID}
            ),
        })
        .map_err(|e| e >> pb::APIError::APIERROR_CONFIGURATION)
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

        /// Creates a [`pb_api::Certificate`].
        #[allow(dead_code)]
        pub(crate) fn create_cert(
            path: &'_ str,
            fmt: Option<pb_api::encoding_format::ASN1EncodingFormat>,
        ) -> pb_api::Certificate {
            let mut cert = pb_api::Certificate::new();
            let src = cert.mut_static();
            if let Some(f) = fmt {
                src.format = f.into();
            }
            let ds = src.data.mut_or_insert_default();
            ds.set_filename(path.to_string());
            cert
        }

        /// Creates a [`sandwich_api_proto::Configuration`] for TLS 1.3.
        #[allow(dead_code)]
        pub(crate) fn create_configuration(
            mode: crate::tunnel::Mode,
            skip_impl: bool,
        ) -> pb_api::Configuration {
            let mut conf = pb_api::Configuration::new();
            match mode {
                crate::tunnel::Mode::Client => conf.mut_client().mut_tls(),
                crate::tunnel::Mode::Server => conf.mut_client().mut_tls(),
            };
            if !skip_impl {
                conf.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
            }
            conf
        }

        /// Tests a [`sandwich_api_proto::Configuration`] for OpenSSL.
        #[test]
        fn test_configuration() {
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
            let ctx = super::super::try_from(&config);
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
            let ctx = super::super::try_from(&config);
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
                      kem: "kyber512"
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
            let ctx = super::super::try_from(&config);
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
                      kem: "kyber512"
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
            let ctx = super::super::try_from(&config);
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
