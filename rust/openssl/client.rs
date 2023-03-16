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

//! Defines [`Context`] struct.
//!
//! This context is instantiated for protobuf messages that specified
//! `IMPL_OPENSSL1_1_1_OQS`, in client mode.
//!
//! Author: thb-sb

use pb::OpenSSLClientConfigurationError::*;

/// An OpenSSL context.
pub(super) struct Context<'ctx>(super::Context<'ctx>);

/// Implements [`crate::Context`] for [`Context`].
impl<'ctx: 'handle, 'handle> crate::Context<'ctx> for Context<'ctx> {
    fn new_tunnel<'io: 'tun, 'tun>(
        &mut self,
        io: &'io mut (dyn crate::IO + 'io),
    ) -> crate::Result<Box<dyn crate::Tunnel<'io, 'tun> + 'tun>>
    where
        'ctx: 'tun,
    {
        let handle = unwrap_or!(
            super::tunnel::SSLHandle::<'io, 'tun>::try_from(((&mut self.0), io)),
            pb::APIError::APIERROR_TUNNEL
        );
        let mut b: Box<super::tunnel::SSLHandle<'io, 'tun>> = Box::new(handle);
        b.finalize_bio();
        Ok(b)
    }
}

/// Implements [`std::fmt::Debug`] for [`Context`].
impl<'ctx> std::fmt::Debug for Context<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL client context")
    }
}

/// Instantiates a [`Context`] from a protobuf configuration message.
impl<'conf, 'ctx> std::convert::TryFrom<&'conf pb_api::Configuration> for Context<'ctx> {
    type Error = crate::Error;
    fn try_from(configuration: &'conf pb_api::Configuration) -> crate::Result<Self> {
        let conf_tls = if configuration.has_client() {
            let client = configuration.client();
            if client.has_tls() {
                Ok(client.tls())
            } else {
                Err(OPENSSLCLIENTCONFIGURATIONERROR_EMPTY)
            }
        } else {
            Err(OPENSSLCLIENTCONFIGURATIONERROR_EMPTY)
        }?;

        let mut ctx = super::Context::try_from(configuration)?;

        let ptr = unsafe { openssl::X509_STORE_new() };
        if ptr.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
        }
        unsafe {
            openssl::SSL_CTX_set_cert_store((&mut ctx).into(), ptr);
        }
        unsafe {
            openssl::X509_STORE_set_trust(ptr, 1);
        }

        for c in conf_tls.trusted_certificates.iter() {
            unwrap_or!(
                ctx.push_cert(c),
                OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE
            );
        }

        Ok(Self(ctx))
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::super::certificate;
    use super::Context;

    /// Creates and returns a basic protobuf configuration.
    pub(in crate::openssl) fn create_basic_configuration(
        certpath: &'static str,
        fmt: Option<pb_api::encoding_format::ASN1EncodingFormat>,
        kem: &'static str,
    ) -> pb_api::Configuration {
        let cert = certificate::test::create_cert(certpath, fmt);
        let mut config = pb_api::Configuration::new();
        let cli = config.mut_client().mut_tls();

        cli.trusted_certificates.push(cert);
        cli.common_options
            .mut_or_insert_default()
            .kem
            .push(kem.to_string());
        config
    }

    /// Tests constructor of [`Context`] from a well-formed configuration.
    #[test]
    fn test_constructor() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let ctx = Context::try_from(&config);
        assert!(ctx.is_ok());
    }

    /// Tests constructor of [`Context`] from a configuration with an invalid certificate.
    #[test]
    fn test_constructor_invalid_cert() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
            "kyber1024",
        );
        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert!(
            ctx.unwrap_err().is(&
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED => pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE}
        ));
    }

    /// Tests constructor of [`Context`] from a configuration with an invalid KEM.
    #[test]
    fn test_constructor_invalid_kem() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1023",
        );

        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert!(
            ctx.unwrap_err().is(&
            errors! {pb::KEMError::KEMERROR_INVALID => pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_KEM}
        ));
    }

    /// Tests constructor of [`Context`] from a configuration without any client configuration.
    #[test]
    fn test_constructor_invalid_no_client() {
        let config = pb_api::Configuration::new();

        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert!(ctx.unwrap_err().is(&errors! {
            pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_EMPTY
        }));
    }

    /// Tests constructor of [`Context`] from a configuration without any TLS configuration.
    #[test]
    fn test_constructor_invalid_no_tls() {
        let mut config = pb_api::Configuration::new();
        config.mut_client();

        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert!(ctx.unwrap_err().is(&errors! {
            pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_EMPTY
        }));
    }

    /// Tests [`std::convert::Into<Box<Self>>`] for [`Context`].
    #[test]
    fn test_constructor_into_box() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let ctx = Context::try_from(&config);
        assert!(ctx.is_ok());
        let ctx = ctx.unwrap();
        let _: Box<Context> = ctx.into();
    }
}
