// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Implementation of Turbo transport metadata for UDP packets.

#![allow(dead_code)]

use std::io::ErrorKind;

use crate::experimental::turbo::protocol::{serialize_metadata, ConnectionID};

/// Maximum size for the UDP payload.
/// The payload does NOT include the metadata.
pub(crate) const PACKET_PAYLOAD_MAX_SIZE: usize = 0x400; // 1Ko

/// The target number of packets to be sent
/// from the client when initiating the
/// TLS handshake over UDP
pub(crate) const TARGET_NUMBER_PACKETS: usize = 10;

/// A packet.
pub(crate) struct Packet {
    /// The metadata.
    metadata: super::Metadata,

    /// The payload.
    payload: [u8; PACKET_PAYLOAD_MAX_SIZE],

    /// The payload's size.
    n: usize,
}

/// Implements [`std::fmt::Debug`] for [`Packet`].
impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Packet[metadata={:?}, payload={:#x}B]",
            self.metadata, self.n
        )
    }
}

/// Instantiates a [`Packet`] from a buffer.
impl TryFrom<&'_ [u8]> for Packet {
    type Error = std::io::Error;

    fn try_from(buffer: &'_ [u8]) -> Result<Self, Self::Error> {
        if buffer.len() < super::metadata::METADATA_SIZE {
            return Err(std::io::Error::new(
                ErrorKind::OutOfMemory,
                "Not enough bytes to create packet",
            ));
        }
        if buffer.len() > super::DATAGRAM_MAX_SIZE {
            return Err(std::io::Error::new(
                ErrorKind::OutOfMemory,
                "Too many bytes to fit in a packet",
            ));
        }
        let mut p = Self {
            metadata: super::Metadata::try_from(buffer)?,
            payload: [0u8; PACKET_PAYLOAD_MAX_SIZE],
            n: buffer.len() - super::metadata::METADATA_SIZE,
        };
        unsafe {
            p.payload
                .as_mut_ptr()
                .copy_from(buffer.as_ptr().add(super::metadata::METADATA_SIZE), p.n);
        }
        Ok(p)
    }
}

/// Instantiates a serializes a [`Packet`] into a buffer.
impl From<&Packet> for Vec<u8> {
    fn from(value: &Packet) -> Vec<u8> {
        let n = value.n;
        let cid = value.metadata().cid();
        let index = value.metadata().index();
        let mut v = Vec::with_capacity(super::metadata::METADATA_SIZE + n);
        log::debug!("Building new packet of size: {n} cid: {cid:?} index: {index}");
        if let Err(e) = serialize_metadata(value.metadata().cid(), value.metadata().index(), &mut v)
        {
            log::error!("Failed to serialize metadata: {e}");
            // Return empty vector if write fails
            return v;
        }
        use std::io::Write;
        if let Err(e) = v.write(&value.payload[..n]) {
            log::debug!("Failed to serialize metadata: {e}");
            // Return empty vector if write fails
            v.clear();
        }
        v
    }
}

/// Implements [`Packet`].
impl Packet {
    /// Create a new Packet.
    pub fn new(cid: ConnectionID, index: u8, payload: &[u8], n: usize) -> std::io::Result<Packet> {
        if n > PACKET_PAYLOAD_MAX_SIZE {
            log::debug!("Packet::new n ({n}) is larger than {PACKET_PAYLOAD_MAX_SIZE}");
            return Err(ErrorKind::OutOfMemory.into());
        }
        let mut b = [0u8; PACKET_PAYLOAD_MAX_SIZE];

        unsafe {
            b.as_mut_ptr().copy_from(payload.as_ptr(), n);
        }
        Ok(Packet {
            metadata: (cid, index).into(),
            payload: b,
            n,
        })
    }

    /// Returns the metadata.
    pub(crate) fn metadata(&self) -> &super::Metadata {
        &self.metadata
    }

    /// Returns the payload.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload[..self.n]
    }

    /// Returns the size of the payload.
    pub(crate) fn payload_len(&self) -> usize {
        self.n
    }

    /// Returns the packet's index.
    pub(crate) fn index(&self) -> u8 {
        self.metadata().index()
    }

    /// Writes the packet to a [`std::io::Write`].
    pub(crate) fn write_to(&self, out: &mut impl std::io::Write) -> std::io::Result<usize> {
        let mut payload = [0u8; super::DATAGRAM_MAX_SIZE];
        unsafe {
            self.metadata.serialize_unsafe(&mut payload[..]);
            payload
                .as_mut_ptr()
                .add(super::metadata::METADATA_SIZE)
                .copy_from(self.payload().as_ptr(), self.n)
        }
        out.write(&payload[..super::metadata::METADATA_SIZE + self.n])
    }

    /// Instantiates a packet from a io::Read.
    pub(crate) fn from_reader(reader: &mut impl std::io::Read) -> std::io::Result<Self> {
        let mut payload = [0u8; super::DATAGRAM_MAX_SIZE];
        let n = reader.read(&mut payload)?;
        Self::try_from(&payload[..n])
    }

    /// Instantiates a packet from a UDP client socket.
    pub(crate) fn from_udp(reader: &mut std::net::UdpSocket) -> std::io::Result<Self> {
        let mut payload = [0u8; super::DATAGRAM_MAX_SIZE];
        let n = reader.recv(&mut payload)?;
        log::debug!("just read {n:#x} bytes from the UDP wire");
        Self::try_from(&payload[..n])
    }
}

#[warn(dead_code)]
#[cfg(test)]
pub(crate) mod test {
    use super::Packet;
    use crate::experimental::turbo::protocol::{ConnectionID, Metadata, METADATA_SIZE};
    use crate::experimental::turbo::rand::rand;

    /// Helper to create a packet.
    pub(crate) fn create_packet(payload_size: usize) -> Packet {
        let packet_len = METADATA_SIZE + payload_size;

        let metadata = Metadata::from((ConnectionID::from_rand(), 42u8));

        let mut data = vec![0u8; packet_len];
        let n = metadata
            .serialize(&mut std::io::Cursor::new(&mut data))
            .expect("serialization of metadata should work");
        assert_eq!(n, METADATA_SIZE);

        rand(&mut data[n..]);
        Packet::try_from(&data[..]).expect("packet parsing should succeed")
    }

    /// Helper to create a packet with a specific index..
    pub(crate) fn create_packet_with_index(payload_size: usize, index: u8) -> Packet {
        let packet_len = METADATA_SIZE + payload_size;

        let metadata = Metadata::from((ConnectionID::from_rand(), index));

        let mut data = vec![0u8; packet_len];
        let n = metadata
            .serialize(&mut std::io::Cursor::new(&mut data))
            .expect("serialization of metadata should work");
        assert_eq!(n, METADATA_SIZE);

        rand(&mut data[n..]);
        Packet::try_from(&data[..]).expect("packet parsing should succeed")
    }

    /// Tests parsing a packet from a buffer.
    #[test]
    fn test_parsing() {
        let packet_len = METADATA_SIZE + 17;

        let metadata = Metadata::from((ConnectionID::from_rand(), 42u8));

        let mut data = vec![0u8; packet_len];
        let n = metadata
            .serialize(&mut std::io::Cursor::new(&mut data))
            .expect("serialization of metadata should work");
        assert_eq!(n, METADATA_SIZE);

        rand(&mut data[n..]);
        let packet = Packet::try_from(&data[..]).expect("packet parsing should succeed");

        assert_eq!(packet.metadata, metadata);
        assert_eq!(packet.metadata(), &metadata);
        assert_eq!(packet.metadata.cid(), metadata.cid());
        assert_eq!(packet.n, packet_len - METADATA_SIZE);
        assert_eq!(&packet.payload[0..packet.n], &data[n..]);
        assert_eq!(packet.payload(), &data[n..]);
        assert_eq!(packet.payload().len(), packet_len - METADATA_SIZE);
        assert_eq!(packet.payload().len(), packet.n);
        assert_eq!(packet.payload_len(), packet.n);
    }

    /// Tests parsing a packet from a buffer too small.
    #[test]
    fn test_parsing_buffer_too_small() {
        Packet::try_from(&vec![0u8; METADATA_SIZE - 1][..])
            .expect_err("packet parsing should failed because buffer size is too small");
    }

    /// Tests parsing a packet from a buffer too large.
    #[test]
    fn test_parsing_buffer_too_large() {
        Packet::try_from(
            &vec![0u8; crate::experimental::turbo::protocol::DATAGRAM_MAX_SIZE + 1][..],
        )
        .expect_err("packet parsing should failed because buffer size is too large");
    }

    /// Tests [`Packet::write_to`] method.
    #[test]
    fn test_write_to() {
        let packet_len = METADATA_SIZE + 17;

        let metadata = Metadata::from((ConnectionID::from_rand(), 42u8));

        let mut data = vec![0u8; packet_len];
        let n = metadata
            .serialize(&mut std::io::Cursor::new(&mut data))
            .expect("serialization of metadata should work");
        assert_eq!(n, METADATA_SIZE);

        rand(&mut data[n..]);
        let packet = Packet::try_from(&data[..]).expect("packet parsing should succeed");
        let packet_data2: Vec<u8> = (&packet).into();
        assert_eq!(data, packet_data2);

        let mut data_out = vec![0u8; 0];
        let n = packet
            .write_to(&mut std::io::Cursor::new(&mut data_out))
            .expect("`write_to` should succeed");
        assert_eq!(n, packet_len);

        assert_eq!(data_out, data);
    }

    /// Tests [`Packet::from_reader`] method.
    #[test]
    fn test_from_reader() {
        let packet_len = METADATA_SIZE + 17;
        let metadata = Metadata::from((ConnectionID::from_rand(), 42u8));
        let mut data = vec![0u8; packet_len];
        let n = metadata
            .serialize(&mut std::io::Cursor::new(&mut data))
            .expect("serialization of metadata should work");
        assert_eq!(n, METADATA_SIZE);
        rand(&mut data[n..]);

        let pd =
            Packet::from_reader(&mut std::io::Cursor::new(&data)).expect("from_reader should work");
        assert_eq!(pd.metadata(), &metadata);
        assert_eq!(pd.payload(), &data[n..]);
    }
}
