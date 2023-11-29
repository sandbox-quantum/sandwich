// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel implementation using OpenSSL 3 and oqs-provider.

use bio_method::BIO_METHOD;
pub use context::Context;
pub(crate) use ssl::Tunnel;
use ssl::{Ssl, TunnelBuilder};
use verify_callback::verify_callback;
use x509_verify_param::X509VerifyParam;

mod bio_method;
mod context;
mod ssl;
mod verify_callback;
mod x509_verify_param;
