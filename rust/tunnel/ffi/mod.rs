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
//! - [`context::sandwich_tunnel_context_new`]: creates a new context from a serialized
//!   protobuf configuration message.
//! - [`context::sandwich_tunnel_context_free`]: releases the memory occupied by a Context.
//! - [`tunnel::sandwich_tunnel_new`]: creates a tunnel from a configuration.
//! - [`tunnel::sandwich_tunnel_free`]: releases the memory occupied by a Tunnel.
//! - [`tunnel::sandwich_tunnel_handshake`]: performs the handshake operation
//!   on a Tunnel.
//! - [`tunnel::sandwich_tunnel_read`]: reads data from the Tunnel.
//! - [`tunnel::sandwich_tunnel_write`]: writes data to the Tunnel.
//! - [`tunnel::sandwich_tunnel_state`]: returns the state of the Tunnel.
//! - [`tunnel::sandwich_tunnel_close`]: closes the tunnel.

mod context;
mod tunnel;
