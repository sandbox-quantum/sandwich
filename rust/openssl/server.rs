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
//! This context is instanciated for protobuf messages that specified
//! `IMPL_OPENSSL1_1_1_OQS`, in server mode.
//!
//! Author: thb-sb

use pb::OpenSSLServerConfigurationError::*;

/// An OpenSSL context.
pub(super) struct Context<'ctx>(super::Context<'ctx>);

/// Implements [`crate::Context`] for [`Context`].
impl<'ctx> crate::Context<'ctx> for Context<'ctx> {
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
        write!(f, "OpenSSL server context")
    }
}

/// Instantiates a [`Context`] from a protobuf configuration message.
impl<'conf, 'ctx> std::convert::TryFrom<&'conf pb_api::Configuration> for Context<'ctx> {
    type Error = crate::Error;
    fn try_from(configuration: &'conf pb_api::Configuration) -> crate::Result<Self> {
        let conf_tls = if configuration.has_server() {
            let server = configuration.get_server();
            if server.has_tls() {
                Ok(server.get_tls())
            } else {
                Err(OPENSSLSERVERCONFIGURATIONERROR_EMPTY)
            }
        } else {
            Err(OPENSSLSERVERCONFIGURATIONERROR_EMPTY)
        }?;

        let mut ctx = super::Context::try_from(configuration)?;

        if conf_tls.has_certificate() {
            unwrap_or!(
                ctx.push_cert(conf_tls.get_certificate()),
                OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE
            );
        }

        if conf_tls.has_private_key() {
            super::PrivateKey::try_from(conf_tls.get_private_key())
                .and_then(|mut pkey| {
                    match unsafe {
                        openssl::SSL_CTX_use_PrivateKey((&mut ctx).into(), pkey.as_mut_ptr())
                    } {
                        1 => Ok(()),
                        _ => Err(OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY.into()),
                    }
                })
                .map_err(|e| e >> OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY)?;
        }

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

        Ok(Self(ctx))
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::super::{certificate, private_key};
    use super::Context;

    /// Creates and returns a basic configuration.
    pub(in crate::openssl) fn create_basic_configuration(
        certpath: &'static str,
        certfmt: Option<pb_api::encoding_format::ASN1EncodingFormat>,
        keypath: &'static str,
        keyfmt: Option<pb_api::encoding_format::ASN1EncodingFormat>,
        kem: &'static str,
    ) -> pb_api::Configuration {
        let mut config = pb_api::Configuration::new();
        let serv = config.mut_server().mut_tls();

        serv.set_certificate(certificate::test::create_cert(certpath, certfmt));
        serv.set_private_key(private_key::test::create_pkey(keypath, keyfmt));
        serv.mut_common_options().mut_kem().push(kem.to_string());
        config
    }

    /// Tests constructor of [`Context`] from a configuration.
    #[test]
    fn test_constructor() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
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
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert_eq!(
            ctx.unwrap_err(),
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED => pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE}
        );
    }

    /// Tests constructor of [`Context`] from a configuration with an invalid KEM.
    #[test]
    fn test_constructor_invalid_kem() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1023",
        );

        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert_eq!(
            ctx.unwrap_err(),
            errors! {pb::KEMError::KEMERROR_INVALID => pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_KEM}
        );
    }

    /// Tests constructor of [`Context`] from a configuration without any server configuration.
    #[test]
    fn test_constructor_invalid_no_client() {
        let config = pb_api::Configuration::new();

        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert_eq!(
            ctx.unwrap_err(),
            pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_EMPTY
        );
    }

    /// Tests constructor of [`Context`] from a configuration without any TLS configuration.
    #[test]
    fn test_constructor_invalid_no_tls() {
        let mut config = pb_api::Configuration::new();
        config.mut_server();

        let ctx = Context::try_from(&config);
        assert!(ctx.is_err());
        assert_eq!(
            ctx.unwrap_err(),
            pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_EMPTY
        );
    }

    /// Tests `Into<Box<Self>>` for [`Context`].
    #[test]
    fn test_constructor_into_box() {
        let config = create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let ctx = Context::try_from(&config);
        assert!(ctx.is_ok());
        let ctx = ctx.unwrap();
        let _: Box<Context> = ctx.into();
    }
}
