// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Implementation of Turbo transport metadata for UDP packets.

extern crate byteorder;

/// Size of a [`ConnectionID`].
pub(crate) const CONNECTION_ID_SIZE: usize = 0x10;

/// A random unique identifier for a single Turbo based session.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct ConnectionID([u8; CONNECTION_ID_SIZE]);

/// Implements [`std::fmt::Debug`] for [`ConnectionID`].
impl std::fmt::Debug for ConnectionID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ConnectionID[")?;
        for c in self.0.iter() {
            write!(f, "{:02x}", c)?;
        }
        write!(f, "]")
    }
}

/// Implements [`Default`] for [`ConnectionID`].
impl Default for ConnectionID {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a span of the [`ConnectionID`].
impl AsRef<[u8]> for ConnectionID {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Returns a mutable span of the [`ConnectionID`].
impl AsMut<[u8]> for ConnectionID {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

/// Returns the pointer to the buffer in [`ConnectionID`].
impl From<&ConnectionID> for *const u8 {
    fn from(s: &ConnectionID) -> Self {
        s.0.as_ptr()
    }
}

/// Returns the mutable pointer to the buffer in [`ConnectionID`].
impl From<&mut ConnectionID> for *mut u8 {
    fn from(s: &mut ConnectionID) -> Self {
        s.0.as_mut_ptr()
    }
}

/// Implements [`ConnectionID`].
impl ConnectionID {
    /// Instantiates a new [`ConnectionID`].
    fn new() -> Self {
        Self([0u8; CONNECTION_ID_SIZE])
    }

    /// Instantiates a new [`ConnectionID`] with random bytes.
    pub(crate) fn from_rand() -> Self {
        let mut s = Self::new();
        crate::experimental::turbo::rand::rand(&mut s);
        s
    }

    /// Returns the pointer to the buffer in [`ConnectionID`].
    fn as_ptr(&self) -> *const u8 {
        self.into()
    }

    /// Returns the pointer to the buffer in [`ConnectionID`].
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.into()
    }
}

/// Metadata fields describing the Turbo transport UDP packet.
#[derive(Eq)]
pub(crate) struct Metadata {
    /// The [`ConnectionID`].
    cid: ConnectionID,

    /// The index of the packet.
    index: u8,
}

/// Size of [`Metadata`] when serialized.
pub(crate) const METADATA_SIZE: usize = CONNECTION_ID_SIZE + 1;

/// Implements [`std::fmt::Debug`] for [`Metadata`].
impl std::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Metadata[cid={:?}, index={:#x}]", self.cid, self.index)
    }
}

/// Implements [`PartialEq`] for [`Metadata`].
impl PartialEq for Metadata {
    fn eq(&self, other: &Self) -> bool {
        if self.index != other.index {
            return false;
        }
        self.cid == other.cid
    }
}

/// Instantiates a [`Metadata`] from a [`ConnectionID`].
impl From<&ConnectionID> for Metadata {
    fn from(cid: &ConnectionID) -> Self {
        Self {
            cid: *cid,
            index: 0,
        }
    }
}

/// Instantiates a [`Metadata`] from a [`ConnectionID`].
impl From<ConnectionID> for Metadata {
    fn from(cid: ConnectionID) -> Self {
        Self { cid, index: 0 }
    }
}

/// Instantiates a [`Metadata`] from a [`ConnectionID`] and an index.
impl From<(&ConnectionID, u8)> for Metadata {
    fn from((cid, index): (&ConnectionID, u8)) -> Self {
        Self { cid: *cid, index }
    }
}

/// Instantiates a [`Metadata`] from a [`ConnectionID`] and an index.
impl From<(ConnectionID, u8)> for Metadata {
    fn from((cid, index): (ConnectionID, u8)) -> Self {
        Self { cid, index }
    }
}

/// Deserializes a [`Metadata`] from a buffer.
impl TryFrom<&'_ [u8]> for Metadata {
    type Error = std::io::Error;

    fn try_from(buffer: &'_ [u8]) -> Result<Self, Self::Error> {
        if buffer.len() < METADATA_SIZE {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        let mut m = Self {
            cid: ConnectionID([0u8; CONNECTION_ID_SIZE]),
            index: 0,
        };
        unsafe {
            m.cid
                .as_mut_ptr()
                .copy_from(buffer.as_ptr(), CONNECTION_ID_SIZE);
            m.index = buffer[CONNECTION_ID_SIZE];
        }
        Ok(m)
    }
}

/// Serializes a [`ConnectionID`] and an index,  and writes the output to a stream.
pub(crate) fn serialize(
    cid: &ConnectionID,
    index: u8,
    out: &mut impl std::io::Write,
) -> std::io::Result<usize> {
    log::debug!("serialize cid: {:?}, index: {}", cid, index);
    out.write_all(cid.as_ref())?;
    <_ as byteorder::WriteBytesExt>::write_u8(out, index)?;
    Ok(METADATA_SIZE)
}

/// Sets the index in a buffer.
///
/// # Safety
///
/// This method doesn't check that the buffer is at least METADATA_SIZE long.
pub(crate) unsafe fn set_index_in_buffer(buffer: &mut [u8], index: u8) {
    *buffer.as_mut_ptr().add(CONNECTION_ID_SIZE) = index;
}

/// Implements [`Metadata`].
impl Metadata {
    /// Sets the index of the packet.
    pub(crate) fn set_index(&mut self, index: u8) {
        self.index = index;
    }

    /// Returns the index.
    pub(crate) fn index(&self) -> u8 {
        self.index
    }

    /// Returns the ConnectionID.
    pub(crate) fn cid(&self) -> &ConnectionID {
        &self.cid
    }

    /// Serializes [`Metadata`] and writes the output to a stream.
    pub(crate) fn serialize(&self, out: &mut impl std::io::Write) -> std::io::Result<usize> {
        serialize(&self.cid, self.index, out)
    }

    /// Serializes [`Metadata`] and writes the output to a buffer.
    ///
    /// # Safety
    ///
    /// This method makes use of raw pointers, the output buffer size isn't
    /// checked.
    pub(crate) unsafe fn serialize_unsafe(
        &self,
        buffer: &mut (impl AsMut<[u8]> + ?Sized),
    ) -> usize {
        let mut ptr = buffer.as_mut().as_mut_ptr();
        ptr.copy_from(self.cid.as_ptr(), CONNECTION_ID_SIZE);
        ptr = ptr.add(CONNECTION_ID_SIZE);

        *ptr = self.index;
        debug_assert!(
            (ptr.offset_from(buffer.as_mut().as_mut_ptr()) as usize) == CONNECTION_ID_SIZE
        );

        METADATA_SIZE
    }
}

#[cfg(test)]
mod test {
    /// Tests for [`ConnectionID`].
    mod sessionid {
        use crate::experimental::turbo::protocol::ConnectionID;

        /// Tests comparison operator.
        #[test]
        fn test_partialeq() {
            let mut s1 = ConnectionID::from_rand();
            let s2 = ConnectionID::new();
            s1.as_mut().copy_from_slice(s2.as_ref());
            assert_eq!(s1, s2);
            s1.as_mut()[0] = if s1.as_ref()[0] == std::u8::MAX {
                0
            } else {
                s1.as_ref()[0] + 1
            };
            assert_ne!(s1, s2);
            s1.as_mut()[1] = if s1.as_ref()[1] == std::u8::MAX {
                0
            } else {
                s1.as_ref()[1] + 1
            };
            assert_ne!(s1, s2);
        }
    }

    /// Tests for [`Metadata`].
    mod metadata {
        use crate::experimental::turbo::protocol::metadata::CONNECTION_ID_SIZE;
        use crate::experimental::turbo::protocol::{ConnectionID, Metadata, METADATA_SIZE};

        /// Tests constructor of [`Metadata`] from a [`ConnectionID`].
        #[test]
        fn test_constructor_cid() {
            let cid = ConnectionID::from_rand();
            let m: Metadata = (&cid).into();
            assert_eq!(m.index, 0u8);
            assert_eq!(m.cid, cid);
        }

        /// Tests constructor of [`Metadata`] from a [`ConnectionID`] and an index.
        #[test]
        fn test_constructor_cid_index() {
            let cid = ConnectionID::from_rand();
            let m: Metadata = ((&cid), 42u8).into();
            assert_eq!(m.index, 42u8);
            assert_eq!(m.cid, cid);
        }

        /// Tests method [`Metadata::set_index`].
        #[test]
        fn test_set_index() {
            let cid = ConnectionID::from_rand();
            let mut m: Metadata = ((&cid), 42u8).into();
            assert_eq!(m.cid, cid);
            assert_eq!(m.index, 42u8);
            assert_eq!(m.index(), 42u8);
            m.set_index(41);
            assert_eq!(m.index, 41u8);
            assert_eq!(m.index(), 41u8);
        }

        /// Tests method [`set_index_in_buffer`].
        #[test]
        fn test_set_index_in_buffer() {
            let cid = ConnectionID::from_rand();
            let m: Metadata = ((&cid), 42u8).into();
            let mut data = std::vec::Vec::<u8>::with_capacity(METADATA_SIZE);
            let n = m
                .serialize(&mut std::io::Cursor::new(&mut data))
                .expect("serialization should not fail");
            assert_eq!(n, METADATA_SIZE);
            assert_eq!(data.len(), METADATA_SIZE);
            unsafe {
                crate::experimental::turbo::protocol::metadata::set_index_in_buffer(
                    &mut data, 0x41,
                );
            }

            let m = Metadata::try_from(&data[..]).expect("deserialization should not fail");
            assert_eq!(m.index(), 0x41);
        }

        /// Tests serialization using a [`std::io::Write`].
        #[test]
        fn test_serialization_writer() {
            let m = Metadata::from((ConnectionID::from_rand(), 42u8));
            let mut data = std::vec::Vec::<u8>::with_capacity(METADATA_SIZE);
            let mut cursor = std::io::Cursor::new(&mut data);
            let n = m
                .serialize(&mut cursor)
                .expect("serialization shoult not fail");
            assert_eq!(n, METADATA_SIZE);
            assert_eq!(data.len(), METADATA_SIZE);
            assert_eq!(&data[..CONNECTION_ID_SIZE], m.cid.as_ref());
            assert_eq!(data[METADATA_SIZE - 1], m.index);
            assert_eq!(data[METADATA_SIZE - 1], m.index());
        }

        /// Tests unsafe serialization using a buffer.
        #[test]
        fn test_unsafe_serialization_buffer() {
            let m = Metadata::from((ConnectionID::from_rand(), 42u8));
            let mut data = vec![0u8; METADATA_SIZE];
            assert_eq!(METADATA_SIZE, unsafe { m.serialize_unsafe(&mut data) });
            assert_eq!(&data[0..CONNECTION_ID_SIZE], m.cid.as_ref());
            assert_eq!(data[METADATA_SIZE - 1], m.index);
            assert_eq!(data[METADATA_SIZE - 1], m.index());
        }

        /// Test deserialization.
        #[test]
        fn test_deserialization() {
            let m = Metadata::from((ConnectionID::from_rand(), 42u8));
            let mut data = vec![0u8; METADATA_SIZE];
            assert_eq!(METADATA_SIZE, unsafe { m.serialize_unsafe(&mut data) });
            let m2 = Metadata::try_from(&data[..]).expect("deserialization should not fail");
            assert_eq!(m2.cid, m.cid);
            assert_eq!(m2.cid(), m.cid());
            assert_eq!(m2.index, m.index);
            assert_eq!(m2.index(), m.index());
        }

        /// Test deserialization with a buffer with not enough bytes.
        #[test]
        fn test_deserialization_buffer_too_small() {
            let m = Metadata::from((ConnectionID::from_rand(), 42u8));
            let mut data = vec![0u8; METADATA_SIZE];
            assert_eq!(METADATA_SIZE, unsafe { m.serialize_unsafe(&mut data) });
            Metadata::try_from(&data[..CONNECTION_ID_SIZE])
                .expect_err("deserialization should fail");
        }
    }
}
