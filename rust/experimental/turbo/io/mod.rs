// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich I/O interfaces for Turbo transport.

mod client;
mod datagram_stream;
#[allow(dead_code)]
mod engine;
mod partial_datagram;
mod server;

pub use client::Client;
use datagram_stream::DatagramStream;

pub(crate) use engine::Engine;
pub(crate) use engine::FutureTCPLink;
pub use engine::TurboListener;

use partial_datagram::PartialDatagram;
pub use server::Server;

#[cfg(test)]
mod test {
    pub(crate) use super::partial_datagram::test as partial_datagram;
}
