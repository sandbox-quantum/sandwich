// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Module containing helpers to create basic IO interface.

pub use systemsocket::SystemSocketIo;
pub use tcp::TcpIo;

mod systemsocket;
mod tcp;
