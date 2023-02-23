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

//! Sandwich frontend module for foreign languages.
//!
//! # Sandwich FFI
//!
//! Sandwich FFI exposes various APIs to allow developers to use Sandwich
//! from a different programming language than Rust.
//!
//! The following APIs are defined:
//!
//!     * [`sandwich_context_new`]: creates a new context from a serialized
//!       protobuf configuration message.
//!     * [`sandwich_context_free`]: releases the memory occupied by a Context.
//!     * [`sandwich_io_new`]: creates a new I/O interface from a set of
//!       function pointers.
//!     * [`sandwich_io_free`]: releases the memory occupied by an I/O
//!       interface.
//!     * [`sandwich_tunnel_new`]: creates a tunnel from a configuration.
//!     * [`sandwich_tunnel_free`]: releases the memory occupied by a Tunnel.
//!     * [`sandwich_tunnel_handshake`]: performs the handshake operation
//!       on a Tunnel.
//!     * [`sandwich_tunnel_read`]: reads data from the Tunnel.
//!     * [`sandwich_tunnel_write`]: writes data to the Tunnel.
//!     * [`sandwich_tunnel_state`]: returns the state of the Tunnel.
//!     * [`sandwich_tunnel_close`]: closes the tunnel.
//!     * [`sandwich_error_free`]: releases the memory occupied by an error
//!       chain.
//!
//! Author: thb-sb

pub(self) mod error;
pub(self) use error::Error;

pub(self) mod context;
pub(self) mod io;
pub(self) mod tunnel;
