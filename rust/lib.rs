// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich is a simple, unified and hard to misue API for developers to use
//! cryptographic algorithms and protocols.
//!
//! ## Installation
//!
//! Sandwich can be added to an existing `Cargo.toml` configuration file:
//!
//! ```toml
//! [dependencies]
//! sandwich = {  git = "https://github.com/sandbox-quantum/sandwich.git" }
//! ```
//!
//! Alternatively, `cargo add` can also be used:
//!
//! ```sh
//! $ cargo add --git 'https://github.com/sandbox-quantum/sandwich.git' sandwich
//! ```
//!
//! ### From source
//!
//! Sandwich can also be built from source:
//!
//! ```sh
//! $ cargo build --release
//! $ cargo test --release
//! ```
//!
//! ## Protobuf API
//!
//! Sandwich uses a protobuf based configuration.
//! Definitions of this configuration are available in the git repository:
//! <https://github.com/sandbox-quantum/sandwich/tree/main/proto/api/v1>.
//!
//! For convenience reasons, the Rust protobuf API is re-exposed in Sandwich
//! as `sandwich::pb_api`.
//!
//! ## Examples
//!
//! In the following example, we create a [`tunnel::Context`] from a configuration,
//! then we instantiate a [`tunnel::Tunnel`] to establish a TLS connection to `google.com`.
//!
//! ```no_run
//! extern crate protobuf;
//!
//! use sandwich::pb;
//! use sandwich::pb_api;
//! use sandwich::tunnel::{Context, Tunnel};
//!
//! let configuration = protobuf::text_format::parse_from_str::<pb_api::Configuration>(r#"
//! implementation: IMPL_OPENSSL1_1_1_OQS
//! client <
//!     tls <
//!         common_options <
//!             kem: "X25519"
//!             x509_verifier <
//!                 trusted_cas <
//!                     static <
//!                         data <
//!                             filename: "/etc/ssl/cert.pem"
//!                         >
//!                         format: ENCODING_FORMAT_PEM
//!                     >
//!                 >
//!             >
//!             alpn_protocol: "h2"
//!             alpn_protocol: "http/1.1"
//!         >
//!     >
//! >
//! "#).expect("invalid protobuf message");
//! let sw = sandwich::Context;
//! let context = Context::try_from(&sw, &configuration).expect("invalid configuration");
//!
//! let io = new_tcp_connection(); // This returns a `Box<dyn sandwich::IO>`.
//!
//! let tunnel_verifier = protobuf::text_format::parse_from_str::<pb_api::TunnelVerifier>(r#"
//! verifier <
//!     san_verifier <
//!         alt_names <
//!             dns: "google.com"
//!         >
//!         alt_names <
//!             dns: "www.google.com"
//!         >
//!     >
//! >
//! "#).expect("invalid protobuf message");
//! let tunnel = context.new_tunnel(io, tunnel_verifier).expect("cannot instantiate a tunnel");
//!
//! loop {
//!     tunnel.handshake().expect("an error occurred during the handshake");
//!     match tunnel.state() {
//!         pb::STATE_HANDSHAKE_DONE    => break,
//!         pb::STATE_BEING_SHUTDOWN |
//!         pb::STATE_DISCONNECTED      => panic!("tunnel is closed"),
//!         pb::STATE_ERROR             => panic!("an error occurred"),
//!         _ => {},
//!     }
//! }
//!
//! tunnel.write(b"GET / HTTP/1.1\r\nHostname: google.com\r\n\r\n").expect("failed to write the HTTP GET request");
//! let mut buf = vec![0u8; 1024];
//! tunnel.read(&mut buf).expect("failed to read the HTTP response");
//! tunnel.close();
//! ```

#![deny(bare_trait_objects)]
#![deny(unused_qualifications)]

/// The Sandwich API.
#[doc(inline)]
pub extern crate sandwich_api_proto as pb_api;

/// Common definitions.
#[doc(inline)]
pub extern crate sandwich_proto as pb;

pub use crate::error::{Error, ErrorCode, ProtoBasedErrorCode};
#[doc(inline)]
pub use crate::io::IO;

#[macro_use]
mod error;
mod implementation;
pub mod io;
mod support;

#[cfg(all(
    any(feature = "openssl1_1_1", feature = "boringssl"),
    feature = "tunnel"
))]
pub mod tunnel;

#[cfg(feature = "ffi")]
pub(crate) mod ffi;

/// Top-level context.
///
/// This context is used to create tunnel contexts.
pub struct Context;

/// A [`Result`](std::result::Result) using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    #[cfg(not(feature = "bazel"))]
    extern crate testdata;
    #[cfg(not(feature = "bazel"))]
    use std::path::Path;

    /// Resolves the filepath of a runfiles file (data attributes).
    #[allow(dead_code)]
    #[cfg(feature = "bazel")]
    pub(crate) fn resolve_runfile(path: &str) -> String {
        extern crate runfiles;
        let r = runfiles::Runfiles::create().unwrap();
        r.rlocation(format!(
            "{workspace}/{path}",
            workspace = r.current_repository()
        ))
        .into_os_string()
        .into_string()
        .unwrap()
    }

    #[cfg(not(feature = "bazel"))]
    pub(crate) fn resolve_runfile(path: impl AsRef<Path>) -> String {
        let path = path.as_ref();
        testdata::resolve_file(path)
            .or_else(|_| {
                if !path.is_file() {
                    panic!("{} does not exist", path.display());
                }
                Ok::<String, String>(String::from(path.to_string_lossy()))
            })
            .unwrap()
    }
}
