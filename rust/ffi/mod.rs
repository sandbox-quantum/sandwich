// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich frontend module for foreign languages.
//!
//! # Sandwich FFI
//!
//! Sandwich FFI exposes various APIs to allow developers to use Sandwich
//! from a different programming language than Rust.
//!
//! The following APIs are defined:
//!
//! - [`error::sandwich_error_free`]: releases the memory occupied by an error
//!   chain.
//! - [`error::sandwich_error_stack_str_new`]: generates an error stack string
//!    for a SandwichError
//! - [`error::sandwich_error_stack_str_free`]: releases the memory occupied by
//!    an error stack string.

pub(crate) use error::Error;
pub(crate) mod io;

pub(crate) mod error;
mod io_helpers;
