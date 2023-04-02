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

//! Defines [`Context`] trait.
//!
//! ## [`Context`] trait
//!
//! [`Context`] trait is the entrypoint for Sandwich. It is created
//! from a protobuf configuration (see `proto/api/v1`).
//!
//! A [`Context`] is tied to a specific underlying implementation and a
//! protocol. From it, developers may spawn tunnels (see [`crate::Tunnel`].
//! Any objects derived from a [`Context`] will use its configuration.

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

/// A Sandwich context.
/// A Sandwich context is usually instantiated from a protobuf [`api_rust_proto::Configuration`].
pub trait Context<'ctx>: std::fmt::Debug {
    /// Creates a new tunnel from an I/O interface. See [`crate::IO`] from [`crate::io`] module.
    ///
    /// The I/O interface must outlive the tunnel, as the tunnel makes use
    /// of it to send and receive data.
    fn new_tunnel<'io: 'tun, 'tun>(
        &mut self,
        io: &'io mut (dyn crate::IO + 'io),
    ) -> crate::Result<Box<dyn crate::Tunnel<'io, 'tun> + 'tun>>
    where
        'ctx: 'tun;
}

/// Instantiates a [`Context`] from a protobuf configuration message.
///
/// # Examples
///
/// ## Constructs a configuration in Rust.
/// ```
/// use api_rust_proto as pb_api;
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
        .map_err(|_| errors!{pb::ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => pb::ConfigurationError::CONFIGURATIONERROR_INVALID})
        .and_then(|v| match v {
            #[cfg(feature = "openssl")]
            pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS => {
                crate::openssl::ossl::try_from(configuration)
                    .map_err(|e| e >> pb::ConfigurationError::CONFIGURATIONERROR_INVALID)
            }
            _ => Err(
                errors!{pb::ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => pb::ConfigurationError::CONFIGURATIONERROR_INVALID}
            ),
        })
        .map_err(|e| e >> pb::APIError::APIERROR_CONFIGURATION)
}

#[cfg(test)]
pub(crate) mod test {
    /// The following tests target the OpenSSL 1.1.1 + liboqs Implementation
    /// (`api_rust_proto::Implementation::IMPL_OPENSSL1_1_1_OQS`).
    #[cfg(feature = "openssl")]
    pub(crate) mod openssl {
        /// Creates a [`pb_api::Certificate`].
        pub(crate) fn create_cert(
            path: &'static str,
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

        /// Creates a [`pb_api::PrivateKey`].
        pub(crate) fn create_sk(
            path: &'static str,
            fmt: Option<pb_api::encoding_format::ASN1EncodingFormat>,
        ) -> pb_api::PrivateKey {
            let mut sk = pb_api::PrivateKey::new();
            let src = sk.mut_static();
            if let Some(f) = fmt {
                src.format = f.into();
            }
            let ds = src.data.mut_or_insert_default();
            ds.set_filename(path.to_string());
            sk
        }

        /// Creates a [`api_rust_proto::Configuration`] for TLS 1.3.
        pub(crate) fn create_configuration(
            mode: crate::Mode,
            skip_impl: bool,
        ) -> pb_api::Configuration {
            let mut conf = pb_api::Configuration::new();
            match mode {
                crate::Mode::Client => conf.mut_client().mut_tls(),
                crate::Mode::Server => conf.mut_client().mut_tls(),
            };
            if !skip_impl {
                conf.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
            }
            conf
        }

        /// Tests a [`api_rust_proto::Configuration`] for OpenSSL.
        #[test]
        fn test_configuration() {
            let mut config = create_configuration(crate::Mode::Client, false);
            config
                .mut_client()
                .mut_tls()
                .trusted_certificates
                .push(create_cert(
                    crate::tls::test::CERT_PEM_PATH,
                    Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
                ));
            config
                .mut_client()
                .mut_tls()
                .common_options
                .mut_or_insert_default()
                .kem
                .push("kyber1024".to_string());
            let ctx = super::super::try_from(&config);
            ctx.unwrap();
        }

        /// Tests a [`api_rust_proto::Configuration`] for OpenSSL, but
        /// but with missing implementation field.
        #[test]
        fn test_configuration_no_impl() {
            let mut config = create_configuration(crate::Mode::Client, true);
            config
                .mut_client()
                .mut_tls()
                .trusted_certificates
                .push(create_cert(
                    crate::tls::test::CERT_PEM_PATH,
                    Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
                ));
            config
                .mut_client()
                .mut_tls()
                .common_options
                .mut_or_insert_default()
                .kem
                .push("kyber1024".to_string());
            let ctx = super::super::try_from(&config);
            assert!(ctx.is_err());
            assert!(
                ctx.unwrap_err().is(
                &errors! {pb::ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => pb::ConfigurationError::CONFIGURATIONERROR_INVALID => pb::APIError::APIERROR_CONFIGURATION}
            ));
        }

        /// Tests a [`api_rust_proto::Configuration`] for OpenSSL, but with
        /// an certificate supplied.
        #[test]
        fn test_configuration_bad_cert() {
            let mut config = create_configuration(crate::Mode::Client, false);
            config
                .mut_client()
                .mut_tls()
                .trusted_certificates
                .push(create_cert(
                    crate::tls::test::CERT_PEM_PATH,
                    Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
                ));
            config
                .mut_client()
                .mut_tls()
                .common_options
                .mut_or_insert_default()
                .kem
                .push("kyber1024".to_string());
            let ctx = super::super::try_from(&config);
            assert!(ctx.is_err());
            assert!(
                ctx.unwrap_err().is(&
                errors! {
                    pb::ASN1Error::ASN1ERROR_MALFORMED
                        => pb::CertificateError::CERTIFICATEERROR_MALFORMED
                            => pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE
                                => pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
                                    => pb::ConfigurationError::CONFIGURATIONERROR_INVALID
                                        => pb::APIError::APIERROR_CONFIGURATION
                }
            ));
        }

        /// Tests a [`api_rust_proto::Configuration`] for OpenSSL, but with
        /// an invalid private key supplied.
        #[test]
        fn test_configuration_bad_sk() {
            let mut config = create_configuration(crate::Mode::Server, false);
            config.mut_server().mut_tls().certificate = Some(create_cert(
                crate::tls::test::CERT_DER_PATH,
                Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
            ))
            .into();
            config.mut_server().mut_tls().private_key = Some(create_sk(
                crate::tls::test::SK_PATH,
                Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
            ))
            .into();
            config
                .mut_server()
                .mut_tls()
                .common_options
                .mut_or_insert_default()
                .kem
                .push("kyber1024".to_string());
            let ctx = super::super::try_from(&config);
            assert!(ctx.is_err());
            assert!(
                ctx.unwrap_err().is(
                &errors! {
                    pb::ASN1Error::ASN1ERROR_MALFORMED
                        => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED
                            => pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY
                                => pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
                                    => pb::ConfigurationError::CONFIGURATIONERROR_INVALID
                                        => pb::APIError::APIERROR_CONFIGURATION
                }
            ));
        }
    }
}
