// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Support for certificate chains.

use std::ptr::{self, NonNull};

use openssl3::{OPENSSL_STACK as NativeStack, X509_STORE_CTX as NativeX509StoreCtx};

use crate::ossl3::{support, LibCtx};
use crate::support::Pimpl;

use support::{NativeX509Certificate, NativeX509VerifyParam};

/// Convenient wrapper around a `X509_STORE_CTX`.
struct X509StoreCtx<'a>(&'a LibCtx<'a>, Pimpl<'a, NativeX509StoreCtx>);

impl std::fmt::Debug for X509StoreCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "X509_STORE_CTX({:p})", self.1.as_nonnull().as_ptr())
    }
}

impl<'a> TryFrom<&'a LibCtx<'a>> for X509StoreCtx<'a> {
    type Error = &'static str;

    fn try_from(lib_ctx: &'a LibCtx<'a>) -> Result<Self, Self::Error> {
        let store = unsafe {
            Pimpl::new(
                openssl3::X509_STORE_CTX_new_ex(lib_ctx.as_nonnull().as_ptr(), ptr::null()),
                |x| openssl3::X509_STORE_CTX_free(x),
            )
        }
        .ok_or("failed to instantiate a new `X509_STORE_CTX`")?;
        unsafe {
            openssl3::X509_STORE_CTX_init(
                store.as_nonnull().as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        Ok(Self(lib_ctx, store))
    }
}

impl<'a> X509StoreCtx<'a> {
    /// Sets untrusted certificates.
    fn set_untrusted_certificates(&self, stack: &'a Pimpl<'a, NativeStack>) {
        unsafe {
            openssl3::X509_STORE_CTX_set0_untrusted(
                self.1.as_nonnull().as_ptr(),
                stack.as_nonnull().as_ptr().cast(),
            )
        };
    }

    /// Sets trusted certificates.
    fn set_trusted_certificates(&self, stack: &'a Pimpl<'a, NativeStack>) {
        unsafe {
            openssl3::X509_STORE_CTX_set0_trusted_stack(
                self.1.as_nonnull().as_ptr(),
                stack.as_nonnull().as_ptr().cast(),
            )
        };
    }

    /// Sets the target certificate.
    fn set_target_certificate(&self, certificate: &'a Certificate<'a>) {
        unsafe {
            openssl3::X509_STORE_CTX_set_cert(
                self.1.as_nonnull().as_ptr(),
                certificate.as_nonnull().as_ptr(),
            )
        };
    }

    /// Returns the X509_VERIFY_PARAM object associated to the current X509 store context.
    fn get_x509_verify_param(&self) -> Option<NonNull<NativeX509VerifyParam>> {
        NonNull::new(unsafe { openssl3::X509_STORE_CTX_get0_param(self.1.as_nonnull().as_ptr()) })
    }
}

/// Alias to a certificate wrapped in a Pimpl.
type Certificate<'a> = Pimpl<'a, NativeX509Certificate>;

/// A certificate chain.
pub(crate) struct CertificateChain<'a> {
    /// The X509 store context.
    x509_store_ctx: X509StoreCtx<'a>,

    /// The root CA.
    _root_ca: Certificate<'a>,

    /// The intermediate certificates (untrusted).
    _intermediate_certificates: Vec<Certificate<'a>>,

    /// The certificate to test.
    target_certificate: Certificate<'a>,

    /// The OpenSSL 3 stack of intermediate certificates.
    intermediate_certificate_stack: Pimpl<'a, NativeStack>,

    /// The OpenSSL 3 stack of trusted certificates (the root CA).
    trusted_certificate_stack: Pimpl<'a, NativeStack>,
}

impl std::fmt::Debug for CertificateChain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL3CertificateChain")
    }
}

impl<'a> CertificateChain<'a> {
    /// Returns the X509_VERIFY_PARAM object associated to the current X509 store context.
    pub(crate) fn get_x509_verify_param(&self) -> Option<&NativeX509VerifyParam> {
        self.x509_store_ctx
            .get_x509_verify_param()
            .map(|x| unsafe { x.as_ref() })
    }

    /// Verifies the chain.
    pub(crate) fn verify(&self) -> bool {
        (unsafe { openssl3::X509_STORE_CTX_verify(self.x509_store_ctx.1.as_nonnull().as_ptr()) })
            == 1
    }
}

/// Certificate chain builder.
pub(crate) struct CertificateChainBuilder<'a> {
    /// Context library.
    lib_ctx: &'a LibCtx<'a>,

    /// The root CA.
    root_ca: Option<Certificate<'a>>,

    /// The intermediate certificates (untrusted).
    intermediate_certificates: Vec<Certificate<'a>>,

    /// The certificate to test.
    target_certificate: Option<Certificate<'a>>,
}

impl std::fmt::Debug for CertificateChainBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL3CertificateChainBuilder(")?;
        write!(
            f,
            "root CA: {}",
            self.root_ca.as_ref().map(|_| "present").unwrap_or("absent")
        )?;
        write!(
            f,
            ", intermediate certificate count: {}",
            self.intermediate_certificates.len()
        )?;
        write!(
            f,
            ", target certificate: {})",
            self.target_certificate
                .as_ref()
                .map(|_| "present")
                .unwrap_or("absent")
        )
    }
}

impl<'a> From<&'a LibCtx<'a>> for CertificateChainBuilder<'a> {
    fn from(lib_ctx: &'a LibCtx<'a>) -> Self {
        Self {
            lib_ctx,
            root_ca: None,
            intermediate_certificates: Vec::new(),
            target_certificate: None,
        }
    }
}

/// Creates an OpenSSL stack of certificates.
fn new_certificate_stack<'a>(
    certs: impl IntoIterator<Item = NonNull<NativeX509Certificate>>,
) -> Result<Pimpl<'a, NativeStack>, &'static str> {
    let stack = unsafe {
        Pimpl::new(openssl3::OPENSSL_sk_new_null(), |x| {
            openssl3::OPENSSL_sk_free(x)
        })
    }
    .ok_or("failed to instantiate a new stack")?;
    for cert in certs.into_iter() {
        if unsafe { openssl3::OPENSSL_sk_push(stack.as_nonnull().as_ptr(), cert.as_ptr().cast()) }
            == 0
        {
            return Err("failed to push a certificate to the stack");
        }
    }
    Ok(stack)
}

impl<'a> CertificateChainBuilder<'a> {
    /// Sets the root certificate.
    pub(crate) fn root_ca(&mut self, root_ca: Certificate<'a>) -> &mut Self {
        self.root_ca = Some(root_ca);
        self
    }

    /// Sets the root certificate from a file in the testdata directory.
    pub(crate) fn root_ca_from_testdata(
        &mut self,
        root_ca_path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<&mut Self> {
        self.root_ca(support::test::get_certificate_from_testdata_file(
            self.lib_ctx,
            root_ca_path,
            format,
        )?);
        Ok(self)
    }

    /// Sets the root certificate from a file in the certificate chain directory of testdata.
    pub(crate) fn root_ca_from_testdata_cc(
        &mut self,
        root_ca_path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<&mut Self> {
        self.root_ca_from_testdata(
            format!(
                "testdata/certificate_chain/{}",
                root_ca_path.as_ref()
            ),
            format,
        )
    }

    /// Pushes an intermediate certificate.
    pub(crate) fn push_intermediate_certificate(
        &mut self,
        intermediate_certificate: Certificate<'a>,
    ) -> &mut Self {
        self.intermediate_certificates
            .push(intermediate_certificate);
        self
    }

    /// Pushes an intermediate certificate from a file in the testdata directory.
    pub(crate) fn push_intermediate_certificate_from_testdata(
        &mut self,
        intermediate_certificate_path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<&mut Self> {
        self.push_intermediate_certificate(support::test::get_certificate_from_testdata_file(
            self.lib_ctx,
            intermediate_certificate_path,
            format,
        )?);
        Ok(self)
    }

    /// Pushes an intermediate certificate from a file in the certificate chain directory of testdata.
    pub(crate) fn push_intermediate_certificate_from_testdata_cc(
        &mut self,
        intermediate_certificate_path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<&mut Self> {
        self.push_intermediate_certificate_from_testdata(
            format!(
                "testdata/certificate_chain/{}",
                intermediate_certificate_path.as_ref()
            ),
            format,
        )
    }

    /// Builds the certificate chain with a given leaf certificate.
    pub(crate) fn build_with_leaf(
        self,
        leaf_certificate: Certificate<'a>,
    ) -> Result<CertificateChain<'a>, &'static str> {
        let Some(root_ca) = self.root_ca else {
            return Err("`root_ca` not present");
        };
        let x509_store_ctx = X509StoreCtx::try_from(self.lib_ctx)?;
        let intermediate_certificate_stack = new_certificate_stack(
            self.intermediate_certificates
                .iter()
                .map(|c| c.as_nonnull()),
        )?;
        let trusted_certificate_stack = new_certificate_stack([root_ca.as_nonnull()])?;

        let chain = CertificateChain {
            x509_store_ctx,
            _root_ca: root_ca,
            _intermediate_certificates: self.intermediate_certificates,
            target_certificate: leaf_certificate,
            intermediate_certificate_stack,
            trusted_certificate_stack,
        };
        chain
            .x509_store_ctx
            .set_untrusted_certificates(&chain.intermediate_certificate_stack);
        chain
            .x509_store_ctx
            .set_trusted_certificates(&chain.trusted_certificate_stack);
        chain
            .x509_store_ctx
            .set_target_certificate(&chain.target_certificate);

        Ok(chain)
    }

    /// Builds the certificate chain with a given leaf certificate from a file in the testdata directory.
    pub(crate) fn build_with_leaf_from_testdata(
        self,
        leaf_certificate_path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<CertificateChain<'a>> {
        let cert = support::test::get_certificate_from_testdata_file(
            self.lib_ctx,
            leaf_certificate_path,
            format,
        )?;
        self.build_with_leaf(cert)
            .map_err(|e| (pb::SystemError::SYSTEMERROR_BACKEND, e).into())
    }

    /// Builds the certificate chain with a given leaf certificate from a file in the certificate chain directory of testdata.
    pub(crate) fn build_with_leaf_from_testdata_cc(
        self,
        leaf_certificate_path: impl AsRef<str>,
        format: pb_api::ASN1EncodingFormat,
    ) -> crate::Result<CertificateChain<'a>> {
        self.build_with_leaf_from_testdata(
            format!(
                "testdata/certificate_chain/{}",
                leaf_certificate_path.as_ref()
            ),
            format,
        )
    }

    /// Builds a certificate chain from files that belong to the certificate chain directory of testdata.
    pub(crate) fn build_from_testdata_chain_pem<S>(
        lib_ctx: &'a LibCtx<'a>,
        root_ca_path: impl AsRef<str>,
        intermediate_certificate_paths: impl IntoIterator<Item = S>,
        leaf_certificate_path: impl AsRef<str>,
    ) -> crate::Result<CertificateChain<'a>>
    where
        S: AsRef<str>,
    {
        let mut builder = Self::from(lib_ctx);

        builder.root_ca_from_testdata_cc(
            root_ca_path,
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )?;
        for cert in intermediate_certificate_paths.into_iter() {
            builder.push_intermediate_certificate_from_testdata_cc(
                cert,
                pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
            )?;
        }
        builder.build_with_leaf_from_testdata_cc(
            leaf_certificate_path,
            pb_api::ASN1EncodingFormat::ENCODING_FORMAT_PEM,
        )
    }
}
