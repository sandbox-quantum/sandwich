// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Module containing helpers to create basic IO interface.

pub use systemsocket::SystemSocketIo;
pub use tcp::TcpIo;

/// Contains the system socket implementation for wrapping UNIX file descriptors.
pub mod systemsocket;
/// Contains the TCP implementation for both [`TcpIo`] and [`crate::io::helpers::tcp::TcpListener`].
pub mod tcp;
