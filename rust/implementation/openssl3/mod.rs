// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich OpenSSL 3 implementation module.

extern crate openssl3;

use sandwich_proto as pb;

use std::ffi::c_char;
use std::ptr::NonNull;

use crate::support::Pimpl;

mod error;
mod support;
#[cfg(feature = "tunnel")]
pub(crate) mod tunnel;

#[cfg(test)]
pub(crate) mod certificate_chain;
#[cfg(test)]
pub(crate) use certificate_chain::CertificateChainBuilder;

/// The default provider name.
const DEFAULT_PROVIDER_NAME: &[u8; 8] = b"default\x00";

/// Pointer to the default provider name.
const DEFAULT_PROVIDER_NAME_PTR: *const c_char = (DEFAULT_PROVIDER_NAME as *const u8).cast();

/// The oqs-provider provider name.
const OQS_PROVIDER_NAME: &[u8; 12] = b"oqsprovider\x00";

/// Pointer to the oqs-provider provider name.
const OQS_PROVIDER_NAME_PTR: *const c_char = (OQS_PROVIDER_NAME as *const u8).cast();

/// A wrapper around an `OSSL_PROVIDER`.
struct Provider<'a>(Pimpl<'a, openssl3::OSSL_PROVIDER>);

impl std::fmt::Debug for Provider<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Provider({:p}", self.0.as_nonnull().as_ptr())
    }
}

/// A convenient builder for providers.
struct ProviderBuilder {
    /// Name of the provider, C format.
    name: Option<*const c_char>,

    /// Library context.
    lib_ctx: Option<NonNull<openssl3::OSSL_LIB_CTX>>,
}

impl Default for ProviderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderBuilder {
    /// Initializes a builder.
    fn new() -> Self {
        Self {
            name: None,
            lib_ctx: None,
        }
    }

    /// Sets the name.
    fn name(self, name: *const c_char) -> Self {
        Self {
            name: Some(name),
            ..self
        }
    }

    /// Sets the library context.
    fn lib_ctx(self, lib_ctx: NonNull<openssl3::OSSL_LIB_CTX>) -> Self {
        Self {
            lib_ctx: Some(lib_ctx),
            ..self
        }
    }

    /// Builds the provider.
    fn build<'a>(self) -> crate::Result<Provider<'a>> {
        let Some(name) = self.name else {
            return Err((
                pb::SystemError::SYSTEMERROR_BACKEND,
                "missing name for provider",
            )
                .into());
        };
        let Some(lib_ctx) = self.lib_ctx else {
            return Err((
                pb::SystemError::SYSTEMERROR_BACKEND,
                "missing library context for provider",
            )
                .into());
        };
        let provider = unsafe {
            Pimpl::new(openssl3::OSSL_PROVIDER_load(lib_ctx.as_ptr(), name), |x| {
                openssl3::OSSL_PROVIDER_unload(x);
            })
        }
        .ok_or_else(|| {
            (
                pb::SystemError::SYSTEMERROR_BACKEND,
                format!("failed to load provider: {}", support::errstr()),
            )
        })?;

        Ok(Provider(provider))
    }
}

/// An `OSSL_LIB_CTX` object wrapped in a `Pimpl`.
pub(crate) struct LibCtx<'a> {
    /// The OQS provider.
    _oqs_provider: Provider<'a>,

    /// The default provilder.
    _default_provider: Provider<'a>,

    /// The library context.
    lib_ctx: Pimpl<'a, openssl3::OSSL_LIB_CTX>,
}

impl<'a> LibCtx<'a> {
    /// Instantiates a new top-level library context.
    pub(crate) fn try_new() -> crate::Result<Self> {
        let libctx = unsafe {
            Pimpl::new(openssl3::OSSL_LIB_CTX_new(), |ptr| {
                openssl3::OSSL_LIB_CTX_free(ptr);
            })
        }
        .ok_or((
            pb::SystemError::SYSTEMERROR_MEMORY,
            "failed to create an OSSL_LIB_CTX",
        ))?;

        let default_provider = ProviderBuilder::new()
            .name(DEFAULT_PROVIDER_NAME_PTR)
            .lib_ctx(libctx.as_nonnull())
            .build()?;

        #[cfg(debug_assertions)]
        {
            std::env::set_var("OQSPROV", "1");
        }
        if unsafe {
            openssl3::OSSL_PROVIDER_add_builtin(
                libctx.as_nonnull().as_ptr(),
                OQS_PROVIDER_NAME_PTR,
                Some(openssl3::oqs_provider_init),
            )
        } != 1
        {
            return Err((
                pb::SystemError::SYSTEMERROR_MEMORY,
                format!("failed to add the oqsprovider: {}", support::errstr()),
            )
                .into());
        }
        let oqs_provider = ProviderBuilder::new()
            .name(OQS_PROVIDER_NAME_PTR)
            .lib_ctx(libctx.as_nonnull())
            .build()?;

        #[cfg(debug_assertions)]
        {
            let name =
                unsafe { openssl3::OSSL_PROVIDER_get0_name(oqs_provider.0.as_nonnull().as_ptr()) };
            if name.is_null() {
                return Err((
                    pb::SystemError::SYSTEMERROR_MEMORY,
                    "provider's name is null",
                )
                    .into());
            }
            let name = unsafe { std::ffi::CStr::from_ptr(name) };
            if name.to_str() != Ok("oqsprovider") {
                return Err((
                    pb::SystemError::SYSTEMERROR_MEMORY,
                    format!("provider's name does not match 'oqsprovider': got {name:?}"),
                )
                    .into());
            }
            if unsafe { openssl3::OSSL_PROVIDER_self_test(oqs_provider.0.as_nonnull().as_ptr()) }
                != 1
            {
                return Err((
                    pb::SystemError::SYSTEMERROR_MEMORY,
                    "provider's self-test failed",
                )
                    .into());
            }
        }

        Ok(Self {
            lib_ctx: libctx,
            _default_provider: default_provider,
            _oqs_provider: oqs_provider,
        })
    }

    /// Returns a pointer to the top-level library context.
    pub(crate) fn as_nonnull(&self) -> NonNull<openssl3::OSSL_LIB_CTX> {
        self.lib_ctx.as_nonnull()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Tests [`LibCtx::try_new`].
    #[test]
    fn test_libctx_try_new() {
        LibCtx::try_new().unwrap();
    }

    /// Tests [`LibCtx::try_new`] with several competiting threads.
    #[test]
    fn test_libctx_try_new_threaded() {
        let mut handles = Vec::new();
        for _ in 0..32 {
            handles.push(std::thread::spawn(move || LibCtx::try_new().is_ok()));
        }

        for handle in handles {
            let res = handle.join().unwrap();
            assert!(res, "at least one constructor failed");
        }
    }
}
