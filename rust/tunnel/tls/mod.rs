// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS module.

use pb::TunnelError;

pub(crate) use security::assert_compliance;

mod security;

/// A set of security requirements that can be updated with new requirements
/// described in a given verifier `V`.
/// A sanitizer check for security requirements described in a given verifier
/// `V`.
pub(crate) trait VerifierSanitizer<V> {
    /// Updates the current security requirements with a verifier `V`.
    fn run_sanitizer_checks(&self, verifier: &V) -> crate::Result<()>;
}

/// Security requirements to enforce on TLS tunnels.
/// These requirements are described by the verifiers that comes with the
/// `TLSOptions` configuration message.
#[derive(Clone)]
pub(crate) struct TunnelSecurityRequirements {
    /// Allows expired certificates.
    /// This switch comes from the X.509 verifier `X509Verifier`.
    pub(crate) allow_expired_certificate: bool,
}

/// Instantiates a [`TunnelSecurityRequirements`] from a [`pb_api::X509Verifier`].
impl From<&pb_api::X509Verifier> for TunnelSecurityRequirements {
    fn from(x509_verifier: &pb_api::X509Verifier) -> Self {
        Self {
            allow_expired_certificate: x509_verifier.allow_expired_certificate,
        }
    }
}

/// Implements [`Default`] for [`TunnelSecurityRequirements`].
impl Default for TunnelSecurityRequirements {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`TunnelSecurityRequirements`].
impl TunnelSecurityRequirements {
    /// Instantiates a [`TunnelSecurityRequirements`].
    fn new() -> Self {
        Self {
            allow_expired_certificate: false,
        }
    }

    /// Assesses an error returned by a X.509 trusted store.
    /// The error usually comes from the call to
    /// <https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_CTX_get_error.html>.
    /// This function is used for the following implementations:
    ///   - OpenSSL 1.1.1
    ///   - BoringSSL
    ///
    /// Because this function is an assessor, a `false` returned value means
    /// that there is a security issue here.
    #[cfg(any(feature = "openssl1_1_1", feature = "boringssl"))]
    pub(crate) fn assess_x509_store_error<OsslInterface>(&self, error: i32) -> bool
    where
        OsslInterface: crate::implementation::ossl::Ossl + ?Sized,
    {
        if self.allow_expired_certificate
            && OsslInterface::x509_error_code_is_certificate_expired(error)
        {
            return true;
        }

        false
    }
}

/// Implements [`VerifierSanitizer`] for [`TunnelSecurityRequirements`]
/// with the [`pb_api::SANVerifier`] verifier.
impl VerifierSanitizer<pb_api::SANVerifier> for TunnelSecurityRequirements {
    fn run_sanitizer_checks(&self, verifier: &pb_api::SANVerifier) -> crate::Result<()> {
        use pb_api::verifiers::sanmatcher::San;

        if verifier.alt_names.is_empty() {
            return Err((
                TunnelError::TUNNELERROR_VERIFIER,
                "SAN list in SANVerifier is empty",
            )
                .into());
        }

        let mut has_email = false;
        let mut has_ip = false;
        for (i, san) in verifier.alt_names.iter().enumerate() {
            match san.san.as_ref() {
                Some(San::Dns(_)) => Ok::<(), crate::error::ErrorCode>(()),
                Some(San::Email(_)) => {
                    if has_email {
                        Err((
                            TunnelError::TUNNELERROR_VERIFIER,
                            "cannot have multiple email addresses as SANs",
                        )
                            .into())
                    } else {
                        has_email = true;
                        Ok(())
                    }
                }
                Some(San::IpAddress(_)) => {
                    if has_ip {
                        Err((
                            TunnelError::TUNNELERROR_VERIFIER,
                            "cannot have multiple IP addresses as SANs",
                        )
                            .into())
                    } else {
                        has_ip = true;
                        Ok(())
                    }
                }
                Some(t) => Err((
                    TunnelError::TUNNELERROR_VERIFIER,
                    format!("unsupported SAN type '{t:?}' at position {i}"),
                )
                    .into()),
                None => Err((
                    TunnelError::TUNNELERROR_VERIFIER,
                    format!("empty SANMatcher at position {i}"),
                )
                    .into()),
            }?;
        }
        Ok(())
    }
}

/// Implements [`VerifierSanitizer`] for [`TunnelSecurityRequirements`]
/// with the [`pb_api::TunnelVerifier`] verifier.
impl VerifierSanitizer<pb_api::TunnelVerifier> for TunnelSecurityRequirements {
    /// Updates the current security requirements with a verifier `V`.
    fn run_sanitizer_checks(&self, verifier: &pb_api::TunnelVerifier) -> crate::Result<()> {
        match verifier.verifier.as_ref() {
            Some(pb_api::verifiers::tunnel_verifier::Verifier::SanVerifier(san_verifier)) => {
                self.run_sanitizer_checks(san_verifier)
            }
            Some(pb_api::verifiers::tunnel_verifier::Verifier::EmptyVerifier(_)) => Ok(()),
            Some(_) => unreachable!(),
            None => Err((
                TunnelError::TUNNELERROR_VERIFIER,
                "tunnel verifier must specify a verifier",
            )
                .into()),
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test {
    /// Path to a valid PEM certificate.
    pub(crate) const CERT_PEM_PATH: &str = "testdata/dilithium5.cert.pem";

    /// Path to an invalid DER certificate.
    pub(crate) const CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH: &str =
        "testdata/cert_unknown_sig_alg.der";

    /// Path to an expired PEM certificate.
    pub(crate) const CERT_EXPIRED_PEM_PATH: &str = "testdata/cert_expired.pem";

    /// Path to the private key associated with the expired PEM certificate.
    pub(crate) const CERT_EXPIRED_PRIVATE_KEY_PEM_PATH: &str =
        "testdata/private_key_cert_expired.pem";

    /// Path to a valid DER certificate.
    pub(crate) const CERT_DER_PATH: &str = "testdata/dilithium5.cert.der";

    /// Path to a valid PEM private key.
    pub(crate) const SK_PATH: &str = "testdata/dilithium5.key.pem";

    /// Path to a valid DER private key.
    pub(crate) const SK_DER_PATH: &str = "testdata/dilithium5.key.der";

    /// Path to a valid private key using a post-quantum algorithm, in PEM format.
    pub(crate) const PQ_PRIVATE_KEY_PEM_PATH: &str = "testdata/dilithium5.key.pem";

    /// Path to another valid private key using a post-quantum algorithm, in DER format.
    pub(crate) const PQ_PRIVATE_KEY_DER_PATH: &str = "testdata/dilithium5.key.der";

    /// Path to a certificate signed for the `example.com` DNS name.
    pub(crate) const EXAMPLE_COM_CERT_PATH: &str = "testdata/example.com.cert.pem";

    /// Path to a certificate signed for the `user@example.com` email address.
    pub(crate) const USER_AT_EXAMPLE_COM_CERT_PATH: &str =
        "testdata/user@example.com.cert.pem";

    /// Path to a certificate signed for the `127.0.0.1` IP address.
    pub(crate) const IP_127_0_0_1_CERT_PATH: &str = "testdata/127.0.0.1.cert.pem";

    /// Path to a certificate signed for the email address `zadig@example.com`
    /// and the DNS wildcard name `*.example.com`.
    pub(crate) const EMAIL_AND_DNS_WILDCARD_CERT_PATH: &str =
        "testdata/email_and_dns_wildcard.cert.pem";

    /// Tests the behavior of [`TunnelSecurityRequirements`] being updated with
    /// a [`pb_api::TunnelVerifier`].
    #[test]
    fn test_security_requirements_update_tunnel_verifier() {
        use super::{TunnelSecurityRequirements, VerifierSanitizer};
        use protobuf::text_format::parse_from_str;

        let secr = TunnelSecurityRequirements::new();

        let tunnel_verifier = pb_api::TunnelVerifier::new();

        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect_err("must fail on empty protobuf message");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                empty_verifier <>
            "#,
        )
        .unwrap();

        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect("empty verifier must be a valid value");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <>
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect_err("must fail on empty SAN verifier");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <>
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect_err("must fail on san verifier with empty entry");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect("san verifier with a dns entry must be valid");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                    alt_names <
                        dns: "*.example.com"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect("san verifier with multiple dns entries must be valid");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "zadig@example.com"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect("san verifier with an email entry must be valid");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "zadig@example.com"
                    >
                    alt_names <
                        email: "thomas@example.com"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect_err("san verifier with multiple email entries must fail");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        ip_address: "127.0.0.1"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect("san verifier with IP address entry must be valid");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        ip_address: "127.0.0.1"
                    >
                    alt_names <
                        ip_address: "127.0.0.2"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier)
            .expect_err("san verifier with multiple IP address entries must fail");

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        email: "zadig@example.com"
                    >
                    alt_names <
                        ip_address: "127.0.0.1"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier).expect(
            "san verifier with different types of entries (email and IP address) must be valid",
        );

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                    alt_names <
                        ip_address: "127.0.0.1"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier).expect(
            "san verifier with different types of entries (dns and IP address) must be valid",
        );

        let tunnel_verifier = parse_from_str::<pb_api::TunnelVerifier>(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                    alt_names <
                        email: "zadig@example.com"
                    >
                >
            "#,
        )
        .unwrap();
        secr.run_sanitizer_checks(&tunnel_verifier).expect(
            "san verifier with different types of entries (dns and email address) must be valid",
        );
    }
}
