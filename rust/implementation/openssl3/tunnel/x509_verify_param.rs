// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Wrapper around the X509_VERIFY_PARAM object for OpenSSL 3 tunnels.

use pb_api::sanmatcher::San as SANEntry;

use std::ffi::{c_int, c_ulong, CString};
use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::ossl3::support;
use crate::support::Pimpl;
use crate::tunnel::tls;
use crate::Result;

use support::{NativeSsl, NativeSslCtx, NativeX509VerifyParam};

/// Wrapper around the X509_VERIFY_PARAM object.
#[derive(Debug)]
pub(super) struct X509VerifyParam<'a>(
    NonNull<NativeX509VerifyParam>,
    PhantomData<&'a NativeX509VerifyParam>,
);

/// Instantiates an [`X509VerifyParam`] from an SSL context.
impl<'a> TryFrom<&Pimpl<'a, NativeSslCtx>> for X509VerifyParam<'a> {
    type Error = crate::Error;

    fn try_from(ssl_ctx: &Pimpl<'a, NativeSslCtx>) -> Result<Self> {
        let ptr =
            NonNull::new(unsafe { openssl3::SSL_CTX_get0_param(ssl_ctx.as_nonnull().as_ptr()) })
                .ok_or((
                    pb::SystemError::SYSTEMERROR_MEMORY,
                    "no X509_VERIFY_PARAM attached to the given SSL context",
                ))?;
        Ok(Self(ptr, PhantomData))
    }
}

/// Instantiates an [`X509VerifyParam`] from an SSL object.
impl<'a> TryFrom<NonNull<NativeSsl>> for X509VerifyParam<'a> {
    type Error = crate::Error;

    fn try_from(ssl: NonNull<NativeSsl>) -> Result<Self> {
        let ptr = NonNull::new(unsafe { openssl3::SSL_get0_param(ssl.as_ptr()) }).ok_or((
            pb::SystemError::SYSTEMERROR_MEMORY,
            "no X509_VERIFY_PARAM attached to the given SSL object",
        ))?;
        Ok(Self(ptr, PhantomData))
    }
}

/// Instantiates an [`X509VerifyParam`] from an SSL object.
impl<'a> TryFrom<&'a Pimpl<'a, NativeSsl>> for X509VerifyParam<'a> {
    type Error = crate::Error;

    fn try_from(ssl: &'a Pimpl<'a, NativeSsl>) -> Result<Self> {
        Self::try_from(ssl.as_nonnull())
    }
}

impl<'a> X509VerifyParam<'a> {
    /// Applies the default parameters.
    ///
    /// This function sets the following default values:
    ///
    ///  - Maximum depth for certificate chain validation
    pub(super) fn set_default_parameters(&self) -> Result<()> {
        self.set_certificate_chain_validation_depth(
            tls::DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH as i32,
        );
        self.enable_crl_check_for_all_certificates()?;
        self.enable_strict_x509_verification()?;
        self.enable_trusted_first_from_trust_store()
    }

    /// Adds a Subject Alternative Name (SAN).
    pub(super) fn add_san(&self, san: &SANEntry) -> Result<()> {
        fn create_cstring(value: impl AsRef<str>) -> Result<CString> {
            let value = value.as_ref();
            CString::new(value).map_err(|e| {
                (
                    pb::TunnelError::TUNNELERROR_VERIFIER,
                    format!("invalid SAN value '{value}': {e}"),
                )
                    .into()
            })
        }

        if match san {
            SANEntry::Dns(ref value) => {
                let cstring = create_cstring(value)?;
                unsafe {
                    openssl3::X509_VERIFY_PARAM_add1_host(
                        self.0.as_ptr(),
                        cstring.as_ptr(),
                        value.len(),
                    )
                }
            }
            SANEntry::Email(ref value) => {
                let cstring = create_cstring(value)?;
                unsafe {
                    openssl3::X509_VERIFY_PARAM_set1_email(
                        self.0.as_ptr(),
                        cstring.as_ptr(),
                        value.len(),
                    )
                }
            }
            SANEntry::IpAddress(ref value) => {
                let cstring = create_cstring(value)?;
                unsafe {
                    openssl3::X509_VERIFY_PARAM_set1_ip_asc(self.0.as_ptr(), cstring.as_ptr())
                }
            }
            _ => unreachable!(),
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("failed to add the SAN entry {san:?}: {}", support::errstr()),
            )
                .into())
        }
    }

    /// Sets the depth for the certificate chain validation.
    pub(super) fn set_certificate_chain_validation_depth(&self, depth: impl Into<c_int>) {
        unsafe {
            openssl3::X509_VERIFY_PARAM_set_depth(self.0.as_ptr(), depth.into());
        }
    }

    /// Updates the depth for the certificate validation using the
    /// `X509Verifier` configuration object.
    pub(super) fn update_certificate_chain_validation_depth_from_x509_verifier(
        &self,
        x509_verifier: Option<&pb_api::X509Verifier>,
    ) {
        if let Some(depth) = x509_verifier
            .map(|x| x.max_verify_depth)
            .filter(|depth| *depth > 0)
        {
            self.set_certificate_chain_validation_depth(depth as i32)
        }
    }

    /// Enables CRL checking for the entire chain of certificates.
    pub(super) fn enable_crl_check_for_all_certificates(&self) -> Result<()> {
        self.enable_flag(openssl3::X509_V_FLAG_CRL_CHECK_ALL)
    }

    /// Enables the strict verification for X509.
    pub(super) fn enable_strict_x509_verification(&self) -> Result<()> {
        self.enable_flag(openssl3::X509_V_FLAG_X509_STRICT)
    }

    /// Enables the trusted first feature.
    ///
    /// When enabled, certificate authority certificates stored in the certificate
    /// store (X509_STORE) will be used first during the certificate chain
    /// validation.
    pub(super) fn enable_trusted_first_from_trust_store(&self) -> Result<()> {
        self.enable_flag(openssl3::X509_V_FLAG_TRUSTED_FIRST)
    }

    /// Enable a flag.
    ///
    /// This function calls `X509_VERIFY_PARAM_set_flags` to enable a flag.
    /// Even if the function's name is `set_flags`, it actually does a OR
    /// between the existing flags and the given flag.
    pub fn enable_flag(&self, flag: impl Into<c_ulong>) -> Result<()> {
        let flag = flag.into();
        if unsafe { openssl3::X509_VERIFY_PARAM_set_flags(self.0.as_ptr(), flag) } == 1 {
            Ok(())
        } else {
            Err((
                pb::SystemError::SYSTEMERROR_BACKEND,
                format!("failed to enable flag {flag}: {}", support::errstr()),
            )
                .into())
        }
    }
}

#[cfg(test)]
mod test {
    use std::ffi::CStr;
    use std::ptr;

    use crate::ossl3::certificate_chain::CertificateChain;
    use crate::ossl3::{CertificateChainBuilder, LibCtx};

    use super::*;

    /// Instantiates an [`X509VerifyParam`] from a certificate chain.
    impl<'a> TryFrom<&'a CertificateChain<'a>> for X509VerifyParam<'a> {
        type Error = crate::Error;

        fn try_from(certificate_chain: &'a CertificateChain<'a>) -> Result<Self> {
            certificate_chain
                .get_x509_verify_param()
                .ok_or_else(|| {
                    (
                        pb::SystemError::SYSTEMERROR_BACKEND,
                        "no X509 verify param is attached to the certificate chain",
                    )
                        .into()
                })
                .map(|r| unsafe {
                    NonNull::new_unchecked((r as *const NativeX509VerifyParam).cast_mut())
                })
                .map(|ptr| Self(ptr, PhantomData))
        }
    }

    /// Creates a library context, a ssl context and a [`X509VerifyParam`].
    fn create_x509_verify_param<'a>() -> (LibCtx<'a>, Pimpl<'a, NativeSslCtx>, X509VerifyParam<'a>)
    {
        let lib_ctx = LibCtx::<'a>::try_new().unwrap();
        let ssl_ctx = unsafe {
            Pimpl::new(
                openssl3::SSL_CTX_new_ex(
                    lib_ctx.as_nonnull().as_ptr(),
                    ptr::null(),
                    openssl3::TLS_client_method(),
                ),
                |x| openssl3::SSL_CTX_free(x),
            )
        }
        .unwrap();
        let x509_verify_param = X509VerifyParam::try_from(&ssl_ctx).unwrap();
        (lib_ctx, ssl_ctx, x509_verify_param)
    }

    /// Tests the constructor from a SSL_CTX.
    #[test]
    fn test_try_from_ssl_ctx() {
        let lib_ctx = LibCtx::try_new().unwrap();
        let ssl_ctx = unsafe {
            Pimpl::new(
                openssl3::SSL_CTX_new_ex(
                    lib_ctx.as_nonnull().as_ptr(),
                    ptr::null(),
                    openssl3::TLS_client_method(),
                ),
                |x| openssl3::SSL_CTX_free(x),
            )
        }
        .unwrap();

        let result = X509VerifyParam::try_from(&ssl_ctx);

        result.expect("constructor failed");
    }

    /// Tests [`set_default_parameters`].
    #[test]
    fn test_set_default_parameters() {
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param.set_default_parameters().unwrap();

        let result = unsafe { openssl3::X509_VERIFY_PARAM_get_flags(x509_verify_param.0.as_ptr()) };

        assert_eq!(
            result,
            (openssl3::X509_V_FLAG_CRL_CHECK_ALL
                | openssl3::X509_V_FLAG_X509_STRICT
                | openssl3::X509_V_FLAG_TRUSTED_FIRST)
                .into()
        );
    }

    /// Tests [`set_certificate_chain_validation_depth`].
    #[test]
    fn test_set_certificate_chain_validation_depth() {
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param.set_certificate_chain_validation_depth(3);

        let result = unsafe { openssl3::X509_VERIFY_PARAM_get_depth(x509_verify_param.0.as_ptr()) };

        assert_eq!(result, 3);
    }

    /// Tests [`set_certificate_chain_validation_depth`] with an actual chain of certificate.
    #[test]
    fn test_set_certificate_chain_validation_depth_with_certificate_chain() {
        let lib_ctx = LibCtx::try_new().unwrap();
        let certificate_chain = CertificateChainBuilder::build_from_testdata_chain_pem(
            &lib_ctx,
            "chain_example_com/ca.pem",
            [
                "chain_example_com/intermediate0.pem",
                "chain_example_com/intermediate1.pem",
            ],
            "chain_example_com/leaf.pem",
        )
        .unwrap();
        let x509_verify_param = X509VerifyParam::try_from(&certificate_chain).unwrap();
        x509_verify_param.set_certificate_chain_validation_depth(2);

        let result_expect_ok = certificate_chain.verify();
        x509_verify_param.set_certificate_chain_validation_depth(1);
        let result_expect_err = certificate_chain.verify();

        assert_eq!((result_expect_ok, result_expect_err), (true, false));
    }

    /// Tests [`add_san`] with a DNS entry.
    #[test]
    fn test_add_san_dns() {
        let dns = "example.com".to_string();
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param
            .add_san(&SANEntry::Dns(dns.clone()))
            .unwrap();
        let ptr = unsafe { openssl3::X509_VERIFY_PARAM_get0_host(x509_verify_param.0.as_ptr(), 0) };

        let result = unsafe { CStr::from_ptr(ptr.cast()) }.to_str();

        assert_eq!(result, Ok(dns.as_ref()));
    }

    /// Tests [`add_san`] with a DNS entry on a certificate chain.
    #[test]
    fn test_add_san_dns_certificate_chain() {
        let lib_ctx = LibCtx::try_new().unwrap();
        let certificate_chain = CertificateChainBuilder::build_from_testdata_chain_pem(
            &lib_ctx,
            "chain_example_com/ca.pem",
            [
                "chain_example_com/intermediate0.pem",
                "chain_example_com/intermediate1.pem",
            ],
            "chain_example_com/leaf.pem",
        )
        .unwrap();
        let x509_verify_param = X509VerifyParam::try_from(&certificate_chain).unwrap();
        x509_verify_param.set_default_parameters().unwrap();
        x509_verify_param
            .add_san(&SANEntry::Dns("subdomain.example.com".to_string()))
            .unwrap();
        let result_ok = certificate_chain.verify();
        unsafe {
            openssl3::X509_VERIFY_PARAM_set1_host(x509_verify_param.0.as_ptr(), ptr::null(), 0)
        };
        x509_verify_param
            .add_san(&SANEntry::Dns("subdomain.example2.com".to_string()))
            .unwrap();
        let result_err = certificate_chain.verify();

        assert_eq!((result_ok, result_err), (true, false));
    }

    /// Tests [`add_san`] with a multiple DNS entry.
    #[test]
    fn test_add_san_multiple_dns() {
        let dns1 = "example.com".to_string();
        let dns2 = "test.example.com".to_string();
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param
            .add_san(&SANEntry::Dns(dns1.clone()))
            .unwrap();
        x509_verify_param
            .add_san(&SANEntry::Dns(dns2.clone()))
            .unwrap();
        let ptr1 =
            unsafe { openssl3::X509_VERIFY_PARAM_get0_host(x509_verify_param.0.as_ptr(), 0) };
        let ptr2 =
            unsafe { openssl3::X509_VERIFY_PARAM_get0_host(x509_verify_param.0.as_ptr(), 1) };
        let ptr3 =
            unsafe { openssl3::X509_VERIFY_PARAM_get0_host(x509_verify_param.0.as_ptr(), 2) };

        let result = (
            unsafe { CStr::from_ptr(ptr1.cast()) }.to_str(),
            unsafe { CStr::from_ptr(ptr2.cast()) }.to_str(),
            ptr3.is_null(),
        );

        assert_eq!(result, (Ok(dns1.as_ref()), Ok(dns2.as_ref()), true));
    }

    /// Tests [`add_san`] with an email address.
    #[test]
    fn test_add_san_email() {
        let email = "user@example.com".to_string();
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param
            .add_san(&SANEntry::Email(email.clone()))
            .unwrap();
        let ptr = unsafe { openssl3::X509_VERIFY_PARAM_get0_email(x509_verify_param.0.as_ptr()) };

        let result = unsafe { CStr::from_ptr(ptr.cast()) }.to_str();

        assert_eq!(result, Ok(email.as_ref()));
    }

    /// Tests [`add_san`] with an IP address.
    #[test]
    fn test_add_san_ip_address() {
        let ip = "127.0.0.1".to_string();
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param
            .add_san(&SANEntry::IpAddress(ip.clone()))
            .unwrap();
        let ptr = unsafe { openssl3::X509_VERIFY_PARAM_get1_ip_asc(x509_verify_param.0.as_ptr()) };

        let result = unsafe { CStr::from_ptr(ptr.cast()) }.to_str();

        assert_eq!(result, Ok(ip.as_ref()));
        unsafe {
            openssl3::CRYPTO_free(
                ptr.cast(),
                b"line\x00" as *const u8 as *const std::ffi::c_char,
                42,
            )
        };
    }

    /// Tests [`update_certificate_chain_validation_depth_from_x509_verifier`].
    #[test]
    fn test_update_certificate_chain_validation_depth_from_x509_verifier() {
        let (_lib_ctx, _ssl_ctx, x509_verify_param) = create_x509_verify_param();
        x509_verify_param.set_default_parameters().unwrap();
        let initial_depth =
            unsafe { openssl3::X509_VERIFY_PARAM_get_depth(x509_verify_param.0.as_ptr()) };
        x509_verify_param.update_certificate_chain_validation_depth_from_x509_verifier(Some(
            &pb_api::X509Verifier {
                max_verify_depth: (initial_depth + 1) as u32,
                ..pb_api::X509Verifier::default()
            },
        ));

        let result = (initial_depth, unsafe {
            openssl3::X509_VERIFY_PARAM_get_depth(x509_verify_param.0.as_ptr())
        });

        assert_eq!(
            result,
            (
                tls::DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH as i32,
                (tls::DEFAULT_MAXIMUM_VERIFY_CERT_CHAIN_DEPTH + 1) as i32
            )
        );
    }

    /// Tests [`enable_strict_x509_verification`] with an broken certificate chain.
    /// One of the intermediate certificate does not have the extension
    /// `keyUsage=keyCertSign`, which is detected by `X509_V_FLAG_X509_STRICT`.
    #[test]
    fn test_enable_strict_x509_verification() {
        let lib_ctx = LibCtx::try_new().unwrap();
        let certificate_chain = CertificateChainBuilder::build_from_testdata_chain_pem(
            &lib_ctx,
            "not_x509_strict/ca.pem",
            [
                "not_x509_strict/intermediate0.pem",
                "not_x509_strict/intermediate1.pem",
            ],
            "not_x509_strict/leaf.pem",
        )
        .unwrap();
        let x509_verify_param = X509VerifyParam::try_from(&certificate_chain).unwrap();
        x509_verify_param.set_certificate_chain_validation_depth(2);
        unsafe {
            openssl3::X509_VERIFY_PARAM_clear_flags(
                x509_verify_param.0.as_ptr(),
                openssl3::X509_V_FLAG_X509_STRICT.into(),
            )
        };

        let result_expect_ok = certificate_chain.verify();
        x509_verify_param.enable_strict_x509_verification().unwrap();
        let result_expect_err = certificate_chain.verify();
        unsafe {
            openssl3::X509_VERIFY_PARAM_clear_flags(
                x509_verify_param.0.as_ptr(),
                openssl3::X509_V_FLAG_X509_STRICT.into(),
            )
        };
        x509_verify_param.set_default_parameters().unwrap();
        let result_expect_err_bis = certificate_chain.verify();

        assert_eq!(
            (result_expect_ok, result_expect_err, result_expect_err_bis),
            (true, false, false)
        );
    }
}
