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

//! Sandwich is a library developed by [SandboxAQ] to ease the integration of
//! cryptographic primitives inside any applications. Written in Rust, it also
//! provides a C interface that can be used in any other languages.
//! To achieve its goal, Sandwich wraps existing well-known libraries
//! (such as [OpenSSL]) and exposes their functions through a generic
//! configuration based on [protobuf].
//!
//! # Motivation
//!
//! While it is common to use cryptography to secure communications and to
//! authenticate peers, it can often be difficult to maintain pieces of code
//! that make use of cryptography. Developers have to stay up-to-date with
//! the latest technology and also have to learn how to use low-level
//! cryptographic libraries. Thus, it is easy to make mistakes.
//! Sandwich brings a new way to secure communications by exposing a simple,
//! short configuration that is easy to maintain.
//!
//! # Common use
//!
//! Sandwich can be used to establish a secure channel between two peers using
//! TLS.
//!
//! # Features
//!
//! This crate comes with one feature called [`ffi`].
//!
//! [`ffi`] enables the C interface, that can be used to use Sandwich from
//! any language. See module [`ffi`] for more information.
//!
//! [SandboxAQ]: https://sandboxaq.com/
//! [OpenSSL]: https://openssl.org/
//! [protobuf]: https://protobuf.dev/
//!
//! Author: thb-sb

/// Protobuf definitions crate for Sandwich API.
extern crate api_rust_proto as pb_api;

/// Protobuf definitions crate for Sandwich.
extern crate sandwich_rust_proto as pb;

/// A structured error around [`ErrorCode`].
pub type Error = error::Error;

/// An error code.
pub type ErrorCode = error::ErrorCode;

/// A generic [`std::result::Result`], using Sandwich [`Error`].
pub type Result<T> = std::result::Result<T, error::Error>;

#[macro_use]
pub mod error;
pub mod context;
pub mod io;
pub mod tunnel;

/// A Sandwich context.
pub use context::Context;

/// An I/O abstraction.
pub use io::IO;

/// A secure tunnel.
pub use tunnel::Tunnel;

#[cfg(feature = "ffi")]
pub(crate) mod ffi;

pub(crate) mod data_source;
#[cfg(feature = "openssl")]
pub(crate) mod openssl;
pub(crate) mod pimpl;

pub(crate) use context::Mode;
pub(crate) use data_source::DataSource;
pub(crate) use pimpl::Pimpl;
