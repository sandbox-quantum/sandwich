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

//! Defines [`PrivateKeyASN1Source`] struct and [`PrivateKey`] type.
//!
//! This module is an helper around the pb_api::PrivateKey protobuf message
//! and OpenSSL private keys (EVP_PKEY).
//!
//!
//! Author: thb-sb

extern crate openssl;

/// A type (fmt, DataSource) for private_keys.
/// This is based on [`crate::DataSource<'ds>`].
struct PrivateKeyASN1Source<'ds>(
    /// Format of the private key.
    pb_api::encoding_format::ASN1EncodingFormat,
    /// [`DataSource<'ds>`] where the certificate is stored.
    crate::DataSource<'ds>,
);

/// An OpenSSL private_key.
pub(super) type PrivateKey<'pimpl> = crate::Pimpl<'pimpl, openssl::evp_pkey_st>;

/// Implements [`std::fmt::Debug`] for [`PrivateKey`].
impl<'pimpl> std::fmt::Debug for PrivateKey<'pimpl> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL private_key at {:?}", self.as_ptr())
    }
}

/// Extracts the private key format and its [`crate::DataSource`] from a protobuf
/// private key message.
impl<'pkey: 'ds, 'ds> std::convert::TryFrom<&'pkey pb_api::PrivateKey>
    for PrivateKeyASN1Source<'ds>
{
    type Error = crate::Error;

    fn try_from(pkey: &'pkey pb_api::PrivateKey) -> crate::Result<Self> {
        pkey.source
            .as_ref()
            .ok_or_else(|| pb::DataSourceError::DATASOURCEERROR_EMPTY.into())
            .and_then(|oneof| match oneof {
                pb_api::PrivateKey_oneof_source::field_static(ref asn1ds) => {
                    if asn1ds.has_data() {
                        crate::DataSource::try_from(asn1ds.get_data()).and_then(|ds| {
                            if ds.len() <= (std::i32::MAX as usize) {
                                Ok(PrivateKeyASN1Source(asn1ds.get_format(), ds))
                            } else {
                                Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)?
                            }
                        })
                    } else {
                        Err(pb::DataSourceError::DATASOURCEERROR_EMPTY)?
                    }
                }
            })
    }
}

/// Instantiates a [`PrivateKey`] from a protobuf private key message.
impl<'pimpl> std::convert::TryFrom<&pb_api::PrivateKey> for PrivateKey<'pimpl> {
    type Error = crate::Error;

    fn try_from(pkey: &pb_api::PrivateKey) -> crate::Result<Self> {
        let pkeyasn1 = unwrap_or!(
            PrivateKeyASN1Source::try_from(pkey),
            pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED
        );

        let mut bio = unwrap_or!(
            super::Bio::try_from(pkeyasn1.1.as_ref()),
            pb::PrivateKeyError::PRIVATEKEYERROR_UNKNOWN
        );
        let x509 = match pkeyasn1.0 {
            pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM => unsafe {
                openssl::PEM_read_bio_PrivateKey(
                    bio.as_raw_mut(),
                    std::ptr::null_mut() as *mut *mut openssl::evp_pkey_st,
                    None,
                    std::ptr::null_mut(),
                )
            },
            pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER => unsafe {
                openssl::d2i_PrivateKey_bio(
                    bio.as_raw_mut(),
                    std::ptr::null_mut() as *mut *mut openssl::evp_pkey_st,
                )
            },
        };
        if x509.is_null() {
            return Err(match (unsafe { openssl::ERR_get_error() } as u32) >> 24 {
                openssl::ERR_LIB_PEM | openssl::ERR_LIB_ASN1 => {
                    errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED}
                }
                _ => pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED.into(),
            });
        }
        Ok(crate::Pimpl::from_raw(
            x509,
            Some(|x| unsafe {
                openssl::EVP_PKEY_free(x);
            }),
        ))
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::{PrivateKey, PrivateKeyASN1Source};

    pub(in crate::openssl) fn create_pkey(
        path: &'static str,
        fmt: Option<pb_api::encoding_format::ASN1EncodingFormat>,
    ) -> pb_api::PrivateKey {
        let mut pkey = pb_api::PrivateKey::new();
        let src = pkey.mut_field_static();
        if let Some(f) = fmt {
            src.set_format(f);
        }
        let ds = src.mut_data();
        ds.set_filename(path.to_string());
        pkey
    }

    /// Tests [`std::convert::TryFrom<&pb_api::PrivateKey>`] for [`PrivateKeyASN1Source`] using
    /// a PEM private key.
    #[test]
    fn test_tryfrom_private_key_private_keyasn1source_pem() {
        let pkey = create_pkey(
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        let asn1src: crate::Result<PrivateKeyASN1Source> = (&pkey).try_into();
        assert!(asn1src.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&pb_api::PrivateKey>`] for [`PrivateKey`] using
    /// a PEM private key.
    #[test]
    fn test_tryfrom_private_key_private_key_pem() {
        let pkey = create_pkey(
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        let c: crate::Result<PrivateKey> = (&pkey).try_into();
        assert!(c.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&pb_api::PrivateKey>`] for [`PrivateKey`] using
    /// a PEM private key as DER.
    #[test]
    fn test_tryfrom_private_key_private_key_pem_der() {
        let pkey = create_pkey(
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
        );
        let c: crate::Result<PrivateKey> = (&pkey).try_into();
        assert!(c.is_err());
        let e = c.unwrap_err();
        assert_eq!(e, pb::ASN1Error::ASN1ERROR_MALFORMED);
    }
}
