// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Partial Datagram implementation.
//!
//! A partial datagram is a datagram that haven't been
//! fully consumed by the peer yet.

#![allow(dead_code)]

use crate::experimental::turbo::protocol;

/// Partial datagram content.
/// Sometimes, a datagram isn't fully consumed. This wrapper keeps track of
/// the consumed bytes.
pub(crate) struct PartialDatagram {
    /// The payload.
    payload: [u8; protocol::PACKET_PAYLOAD_MAX_SIZE],

    /// The size of the datagram.
    n: usize,

    /// The index of the datagram.
    index: u8,
}

/// Implements [`std::fmt::Debug`] for [`PartialDatagram`].
impl std::fmt::Debug for PartialDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "PartialDatagram[index={:#x}, n={:#x}]",
            self.index, self.n
        )
    }
}

/// Implements [`PartialEq`] for [`PartialDatagram`].
impl PartialEq for PartialDatagram {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl Eq for PartialDatagram {}

/// Implements [`Ord`] for [`PartialDatagram`].
impl Ord for PartialDatagram {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

/// Implements [`PartialOrd`] for [`PartialDatagram`].
impl PartialOrd for PartialDatagram {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements [`std::borrow::Borrow`] of u8 for [`PartialDatagram`].
impl std::borrow::Borrow<u8> for PartialDatagram {
    #[inline]
    fn borrow(&self) -> &u8 {
        &self.index
    }
}

/// Consumes a [`protocol::Packet`] to create a [`PartialDatagram`].
impl From<protocol::Packet> for PartialDatagram {
    fn from(packet: protocol::Packet) -> Self {
        let mut pd = Self {
            payload: [0u8; protocol::PACKET_PAYLOAD_MAX_SIZE],
            n: packet.payload_len(),
            index: packet.metadata().index(),
        };
        unsafe {
            pd.payload
                .as_mut_ptr()
                .add(protocol::PACKET_PAYLOAD_MAX_SIZE - pd.n)
                .copy_from(packet.payload().as_ptr(), pd.n);
        }
        pd
    }
}

/// Returns a slice for the payload in [`PartialDatagram`].
impl AsRef<[u8]> for PartialDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.payload[protocol::PACKET_PAYLOAD_MAX_SIZE - self.n..]
    }
}

/// Implements [`PartialDatagram`].
impl PartialDatagram {
    /// Returns the payload.
    pub(crate) fn payload(&self) -> &[u8] {
        self.as_ref()
    }

    /// Returns the payload' size.
    pub(crate) fn len(&self) -> usize {
        self.n
    }

    /// Returns the emptiness of the payload.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Returns the index of the packet
    pub(crate) fn index(&self) -> u8 {
        self.index
    }

    pub(crate) fn payload_from(&self, index: usize) -> &[u8] {
        if index > self.n {
            &[]
        } else {
            &self.as_ref()[index..]
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::super::super::protocol;
    use super::PartialDatagram;

    /// Helper for creating a [`PartialDatagram`].
    pub(crate) fn create_pd(payload_size: usize, index: u8) -> PartialDatagram {
        let packet1 = protocol::test::packet::create_packet_with_index(payload_size, index);
        packet1.into()
    }

    /// Tests constructor from a packet.
    #[test]
    fn test_constructor_from_packet() {
        let packet_size = 42;
        let packet = protocol::test::packet::create_packet_with_index(packet_size, 42u8);
        let payload = std::vec::Vec::from(packet.payload());
        let pd: PartialDatagram = packet.into();
        assert_eq!(pd.n, packet_size);
        assert_eq!(pd.as_ref().len(), packet_size);
        assert_eq!(pd.index, 42u8);
        assert_eq!(
            &pd.payload[protocol::PACKET_PAYLOAD_MAX_SIZE - packet_size..],
            &payload[..]
        );
        assert_eq!(pd.as_ref(), &payload[..]);

        unsafe {
            assert_eq!(
                pd.as_ref().as_ptr(),
                pd.payload
                    .as_ptr()
                    .add(protocol::PACKET_PAYLOAD_MAX_SIZE)
                    .sub(packet_size)
            );
        }

        assert_eq!(pd.len(), payload.len());
    }

    /// Tests [`PartialDatagram::payload_from`] method.
    #[test]
    fn test_take_method() {
        let packet_size = 42;
        let packet = protocol::test::packet::create_packet(packet_size);
        let payload = std::vec::Vec::from(packet.payload());
        let pd: PartialDatagram = packet.into();

        unsafe {
            assert_eq!(
                pd.as_ref().as_ptr(),
                pd.payload
                    .as_ptr()
                    .add(protocol::PACKET_PAYLOAD_MAX_SIZE)
                    .sub(packet_size)
            );
        }

        assert_eq!(pd.len(), payload.len());

        unsafe {
            assert_eq!(
                pd.payload_from(41).as_ptr(),
                pd.payload
                    .as_ptr()
                    .add(protocol::PACKET_PAYLOAD_MAX_SIZE)
                    .sub(1)
            );
        }
        assert!(pd.payload_from(42).is_empty());
    }

    /// Tests [`Ordering`] and [`Eq`] for [`PartialDatagram`].
    #[test]
    fn test_ordering() {
        let pd1 = create_pd(42, 42);
        assert_eq!(pd1.index, 42u8);

        let pd2 = create_pd(42, 42);

        assert_eq!(pd1, pd2);

        let pd2 = create_pd(42, 41);

        assert_ne!(pd1, pd2);
    }

    /// Tests [`PartialOrdering`] for [`PartialDatagram`].
    #[test]
    fn test_partial_ordering() {
        let pd1 = create_pd(42, 42);
        assert_eq!(pd1.index, 42u8);

        let pd2 = create_pd(42, 41);
        assert_eq!(pd2.index, 41u8);

        assert!(pd2 < pd1);
    }
}
