// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Implementation of the verify callback method for OpenSSL 3.

use std::ffi::c_int;
use std::ptr::NonNull;

use super::Ssl;
use crate::ossl3::support;
use support::{NativeSsl, NativeX509StoreCtx};

/// Returns the SSL object from a X509 store context.
fn x509_store_context_get_ssl(
    store_ctx: NonNull<NativeX509StoreCtx>,
) -> Option<NonNull<NativeSsl>> {
    let ssl_index = unsafe { openssl3::SSL_get_ex_data_X509_STORE_CTX_idx() };
    if ssl_index < 0 {
        return None;
    }
    NonNull::new(
        unsafe { openssl3::X509_STORE_CTX_get_ex_data(store_ctx.as_ptr(), ssl_index) }.cast(),
    )
}

/// Returns the error stored in the X509 store context.
fn x509_store_context_get_error(store_ctx: NonNull<NativeX509StoreCtx>) -> c_int {
    unsafe { openssl3::X509_STORE_CTX_get_error(store_ctx.as_ptr()) }
}

/// Records an error in the X509 store context.
fn x509_store_context_record_error(
    store_ctx: NonNull<NativeX509StoreCtx>,
    error: impl Into<c_int>,
) {
    unsafe { openssl3::X509_STORE_CTX_set_error(store_ctx.as_ptr(), error.into()) };
}

/// The verify callback to be used.
/// This callback is passed to `SSL_set_verify`.
pub(super) extern "C" fn verify_callback(
    mut verify_code: c_int,
    store_ctx: *mut NativeX509StoreCtx,
) -> c_int {
    if verify_code == 1 {
        return verify_code;
    }
    let Some(store_ctx) = NonNull::new(store_ctx) else {
        return 0;
    };
    let Some(ssl) = x509_store_context_get_ssl(store_ctx) else {
        return 0;
    };
    let ssl_wrapped = Ssl::from(ssl);
    let Some(security_requirements) = ssl_wrapped.get_tunnel_security_requirements() else {
        return 0;
    };

    let current_error = x509_store_context_get_error(store_ctx);
    if security_requirements.openssl3_assess_x509_store_error(current_error) {
        verify_code = 1;
        x509_store_context_record_error(store_ctx, openssl3::X509_V_OK as c_int);
    }
    verify_code
}
