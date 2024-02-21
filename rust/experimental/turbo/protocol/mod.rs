// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Turbo transport protocol definitions and implementation.

#![allow(dead_code)]

mod metadata;
mod packet;

pub(crate) use metadata::{
    serialize as serialize_metadata, set_index_in_buffer as set_index_in_metadata_buffer,
    ConnectionID, Metadata, METADATA_SIZE,
};

pub(crate) use packet::{Packet, PACKET_PAYLOAD_MAX_SIZE};

/// Maximum size for a datagram.
pub(crate) const DATAGRAM_MAX_SIZE: usize = PACKET_PAYLOAD_MAX_SIZE + METADATA_SIZE;

/// The target number of packets to be sent
/// from the client when initiating the
/// TLS handshake over UDP
pub(crate) const TARGET_NUMBER_PACKETS: usize = 15;

#[cfg(test)]
pub(crate) mod test {
    pub(crate) use super::packet::test as packet;
}
