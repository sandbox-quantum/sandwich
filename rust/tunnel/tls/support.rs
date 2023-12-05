// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS support module.

use pb_api::{Configuration, TLSOptions, X509Verifier};

use crate::support::DataSource;
use crate::tunnel::Mode;
use crate::Result;

use super::TlsVersion;

/// Returns the execution mode (Client or Server) and the tls options (`TLSOptions`).
pub(crate) fn configuration_get_mode_and_options(
    configuration: &Configuration,
) -> Result<(Mode, &TLSOptions)> {
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
        .ok_or(pb::TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY.into())
}

/// Returns the minimum and the maximum TLS versions depending on a given TLS config.
pub(crate) fn tls_options_get_min_max_tls_version(
    tls_options: &TLSOptions,
) -> (TlsVersion, TlsVersion) {
    match (tls_options.tls12.is_some(), tls_options.tls13.is_some()) {
        (false, false) => (TlsVersion::Tls13, TlsVersion::Tls13),
        (true, false) => (TlsVersion::Tls12, TlsVersion::Tls12),
        (false, true) => (TlsVersion::Tls13, TlsVersion::Tls13),
        (true, true) => (TlsVersion::Tls12, TlsVersion::Tls13),
    }
}

/// Returns the X.509 verifier if exists.
/// If no X.509 verifier is found, and `EmptyVerifier` isn't specified, then
/// it's an error.
pub(crate) fn tls_options_get_x509_verifier(
    tls_options: &TLSOptions,
) -> Result<Option<&X509Verifier>> {
    use pb_api::tlsoptions::Peer_verifier;
    tls_options
        .peer_verifier
        .as_ref()
        .ok_or(
            (
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY,
                "no verifier specified",
            )
                .into(),
        )
        .and_then(|v| match v {
            Peer_verifier::X509Verifier(x509) => Ok(Some(x509)),
            Peer_verifier::EmptyVerifier(_) => Ok(None),
            _ => unreachable!(),
        })
}

/// Verifies that a X.509 verifier isn't empty.
pub(crate) fn x509_verifier_verify_emptiness(
    x509_verifier: Option<&X509Verifier>,
) -> Result<Option<&X509Verifier>> {
    let Some(x509) = x509_verifier else {
        return Ok(None);
    };

    if x509.trusted_cas.is_empty() && !x509.load_cas_from_default_verify_path {
        Err((
            pb::TLSConfigurationError::TLSCONFIGURATIONERROR_EMPTY,
            "X.509 verifier empty",
        )
            .into())
    } else {
        Ok(x509_verifier)
    }
}

/// Reads the content of a certificate as described in a protobuf message.
pub(crate) fn configuration_read_certificate(
    cert: &pb_api::Certificate,
) -> Result<(pb_api::ASN1EncodingFormat, DataSource<'_>)> {
    use pb_api::certificate::certificate;
    cert.source
        .as_ref()
        .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
        .and_then(|oneof| match oneof {
            certificate::Source::Static(ref asn1ds) => asn1ds
                .data
                .as_ref()
                .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
                .and_then(DataSource::try_from)
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
pub(crate) fn configuration_read_private_key(
    private_key: &pb_api::PrivateKey,
) -> Result<(pb_api::ASN1EncodingFormat, DataSource<'_>)> {
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
                .and_then(DataSource::try_from)
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

/// Builds a ciphersuite string from a list of ciphers.
pub(crate) fn build_ciphersuites_list<S>(
    ciphers: impl IntoIterator<Item = S>,
    invalid_chars: &str,
) -> Result<String>
where
    S: AsRef<str>,
{
    let mut output = String::new();
    for c in ciphers.into_iter() {
        if crate::support::contains_any_of(c.as_ref(), invalid_chars) {
            return Err(
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CONTROL_CHARACTERS
                    .into(),
            );
        }
        output.push_str(c.as_ref());
        output.push(':');
    }
    output.pop();
    Ok(output)
}

#[cfg(test)]
pub(crate) mod test {
    use protobuf::text_format::parse_from_str;

    /// Formats a [`pb_api::ASN1EncodingFormat`] to a string.
    #[allow(dead_code)]
    fn format_to_str(format: pb_api::ASN1EncodingFormat) -> &'static str {
        match format {
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM => "ENCODING_FORMAT_PEM",
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_DER => "ENCODING_FORMAT_DER",
        }
    }

    /// Creates a [`pb_api::X509Identity`].
    #[allow(dead_code)]
    pub(crate) fn create_x509_identity(
        certificate_file: impl AsRef<str>,
        certificate_format: pb_api::ASN1EncodingFormat,
        private_key_file: impl AsRef<str>,
        private_key_format: pb_api::ASN1EncodingFormat,
    ) -> pb_api::X509Identity {
        let certificate_file = crate::test::resolve_runfile(certificate_file.as_ref());
        let private_key_file = crate::test::resolve_runfile(private_key_file.as_ref());
        let certificate_format = format_to_str(certificate_format);
        let private_key_format = format_to_str(private_key_format);
        parse_from_str::<pb_api::X509Identity>(&format!(
            r#"
                certificate <
                    static <
                        data <
                            filename: "{certificate_file}"
                        >
                        format: {certificate_format}
                    >
                >
                private_key <
                    static <
                        data <
                            filename: "{private_key_file}"
                        >
                        format: {private_key_format}
                    >
                >
            "#
        ))
        .unwrap()
    }

    /// Creates a [`pb_api::X509Verifier`].
    #[allow(dead_code)]
    pub(crate) fn create_x509_verifier<S>(
        certificates: impl IntoIterator<Item = (S, pb_api::ASN1EncodingFormat)>,
        allow_expired_certificate: bool,
        max_verify_depth: impl Into<u32>,
        load_cas_from_default_verify_path: bool,
    ) -> pb_api::X509Verifier
    where
        S: AsRef<str>,
    {
        parse_from_str::<pb_api::X509Verifier>(&format!(
            r#"
                {certificates}
                allow_expired_certificate: {allow_expired_certificate}
                max_verify_depth: {max_verify_depth}
                load_cas_from_default_verify_path : {load_cas_from_default_verify_path}
            "#,
            certificates = certificates
                .into_iter()
                .map(|(path, format)| format!(
                    r#"trusted_cas < static < data < filename: "{path}" > format: {format} > >"#,
                    path = path.as_ref(),
                    format = format_to_str(format)
                ))
                .collect::<Vec<_>>()
                .join("\n"),
            max_verify_depth = max_verify_depth.into()
        ))
        .unwrap()
    }
}
