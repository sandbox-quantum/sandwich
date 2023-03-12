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

//! Defines [`CertificateASN1Source`] struct and [`Certificate`] type.
//!
//! This module is an helper around the `pb_api::Certificate` protobuf message
//! and OpenSSL certificates (X509).
//!
//! Author: thb-sb

extern crate openssl;

/// A type (fmt, DataSource) for certificates.
/// This is based on [`crate::DataSource`].
struct CertificateASN1Source<'ds>(
    /// Format of the certificate.
    pb_api::encoding_format::ASN1EncodingFormat,
    /// [`crate::DataSource`] where the certificate is stored.
    crate::DataSource<'ds>,
);

/// An OpenSSL certificate.
pub(super) type Certificate<'pimpl> = crate::Pimpl<'pimpl, openssl::x509_st>;

/// Implements [`std::fmt::Debug`] for [`Certificate`].
impl<'pimpl> std::fmt::Debug for Certificate<'pimpl> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL certificate at {:?}", self.as_ptr())
    }
}

/// Extracts the certificate format and its [`crate::DataSource`] from [`pb_api::Certificate`].
impl<'cert: 'ds, 'ds> std::convert::TryFrom<&'cert pb_api::Certificate>
    for CertificateASN1Source<'ds>
{
    type Error = crate::Error;

    fn try_from(cert: &'cert pb_api::Certificate) -> crate::Result<Self> {
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
                        if ds.len() <= (std::i32::MAX as usize) {
                            asn1ds
                                .format
                                .enum_value()
                                .map_err(|_| pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into())
                                .map(|f| CertificateASN1Source(f, ds))
                        } else {
                            Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW.into())
                        }
                    }),
                _ => Err(pb::DataSourceError::DATASOURCEERROR_EMPTY.into()),
            })
    }
}

/// Instantiates a [`Certificate`] from a protobuf certificate message.
impl<'pimpl> std::convert::TryFrom<&pb_api::Certificate> for Certificate<'pimpl> {
    type Error = crate::Error;

    fn try_from(cert: &pb_api::Certificate) -> crate::Result<Self> {
        let certasn1 = unwrap_or!(
            CertificateASN1Source::try_from(cert),
            pb::CertificateError::CERTIFICATEERROR_MALFORMED
        );

        let mut bio = unwrap_or!(
            super::Bio::try_from(certasn1.1.as_ref()),
            pb::CertificateError::CERTIFICATEERROR_UNKNOWN
        );
        let x509 = match certasn1.0 {
            pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM => unsafe {
                openssl::PEM_read_bio_X509(
                    bio.as_raw_mut(),
                    std::ptr::null_mut() as *mut *mut openssl::x509_st,
                    None,
                    std::ptr::null_mut(),
                )
            },
            pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER => unsafe {
                openssl::d2i_X509_bio(
                    bio.as_raw_mut(),
                    std::ptr::null_mut() as *mut *mut openssl::x509_st,
                )
            },
        };
        if x509.is_null() {
            return Err(match (unsafe { openssl::ERR_get_error() } as u32) >> 24 {
                openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
                }
                _ => pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED.into(),
            });
        }
        Ok(crate::Pimpl::from_raw(
            x509,
            Some(|x| unsafe {
                openssl::X509_free(x);
            }),
        ))
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::{Certificate, CertificateASN1Source};

    pub(in crate::openssl) fn create_cert(
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

    /// Tests [`std::convert::TryFrom<&pb_api::Certificate>`] for [`CertificateASN1Source`] using
    /// a PEM certificate.
    #[test]
    fn test_tryfrom_certificate_certificateasn1source_pem() {
        let cert = create_cert(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        let asn1src: crate::Result<CertificateASN1Source> = (&cert).try_into();
        assert!(asn1src.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&pb_api::Certificate>`] for [`CertificateASN1Source`] using
    /// a PEM certificate.
    #[test]
    fn test_tryfrom_certificate_certificateasn1source_der() {
        let cert = create_cert(
            crate::openssl::test::CERT_DER_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
        );
        let asn1src: crate::Result<CertificateASN1Source> = (&cert).try_into();
        assert!(asn1src.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&pb_api::Certificate>`] for [`Certificate`] using
    /// a PEM certificate.
    #[test]
    fn test_tryfrom_certificate_certificate_pem() {
        let cert = create_cert(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        let c: crate::Result<Certificate> = (&cert).try_into();
        assert!(c.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&pb_api::Certificate>`] for [`Certificate`] using
    /// a DER certificate.
    #[test]
    fn test_tryfrom_certificate_certificate_der() {
        let cert = create_cert(
            crate::openssl::test::CERT_DER_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
        );
        let c: crate::Result<Certificate> = (&cert).try_into();
        assert!(c.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&pb_api::Certificate>`] for [`Certificate`] using
    /// a DER certificate as PEM.
    #[test]
    fn test_tryfrom_certificate_certificate_der_pem() {
        let cert = create_cert(
            crate::openssl::test::CERT_DER_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        let c: crate::Result<Certificate> = (&cert).try_into();
        assert!(c.is_err());
        let e = c.unwrap_err();
        assert_eq!(e, pb::ASN1Error::ASN1ERROR_MALFORMED);
    }

    /// Tests [`std::convert::TryFrom<&pb_api::Certificate>`] for [`Certificate`] using
    /// a PEM certificate as DER.
    #[test]
    fn test_tryfrom_certificate_certificate_pem_der() {
        let cert = create_cert(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
        );
        let c: crate::Result<Certificate> = (&cert).try_into();
        assert!(c.is_err());
        let e = c.unwrap_err();
        assert_eq!(e, pb::ASN1Error::ASN1ERROR_MALFORMED);
    }
}
