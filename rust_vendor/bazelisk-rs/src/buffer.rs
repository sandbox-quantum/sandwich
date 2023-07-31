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

//! Implements the enum [`Buffer`] consisting of a buffer backed by either
//! a [`bytes::Bytes`] or a [`std::vec::Vec`].

extern crate bytes;

/// A buffer backed by either a [`bytes::Bytes`] object or a [`std::vec::Vec`]
/// object.
pub(crate) enum Buffer {
    /// Data backed by [`bytes::Bytes`].
    B(bytes::Bytes),

    /// Data backed by a [`std::vec::Vec`].
    V(Vec<u8>),
}

/// Implements [`std::fmt::Debug`] for [`Buffer`].
impl std::fmt::Debug for Buffer {
    #[allow(unreachable_patterns)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::B(b) => write!(f, "Data(B({} bytes))", b.len()),
            Self::V(v) => write!(f, "Data(V({} bytes))", v.len()),
            _ => unreachable!(),
        }
    }
}

/// Implements [`std::convert::AsRef`] for [`Buffer`].
impl std::convert::AsRef<[u8]> for Buffer {
    #[allow(unreachable_patterns)]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::B(b) => b.as_ref(),
            Self::V(v) => v.as_ref(),
        }
    }
}

/// Wraps a [`bytes::Bytes`] object into a [`Buffer`].
impl std::convert::From<bytes::Bytes> for Buffer {
    #[allow(unreachable_patterns)]
    fn from(b: bytes::Bytes) -> Self {
        Self::B(b)
    }
}

/// Wraps a [`std::vec::Vec`] into a [`Buffer`].
impl std::convert::From<Vec<u8>> for Buffer {
    #[allow(unreachable_patterns)]
    fn from(v: Vec<u8>) -> Self {
        Self::V(v)
    }
}

/// Implements [`Buffer`].
impl Buffer {
    /// Returns the length of data.
    pub(crate) fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Returns the emptiness of data.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Tests [`Buffer`] with a vector.
    #[test]
    fn test_vector() {
        let mut data = vec![0u8; 42];
        data[41] = 0x41;
        let buffer = Buffer::from(data);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 42);
        assert_eq!(buffer.as_ref().len(), 42);
        assert_eq!(buffer.as_ref()[41], 0x41);

        let data: Vec<u8> = Vec::new();
        let buffer: Buffer = data.into();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    /// Tests [`Buffer`] with a [`bytes::Bytes`].
    #[test]
    fn test_bytes() {
        let b = bytes::Bytes::from_static(b"AAAA");
        let buffer = Buffer::from(b);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_ref().len(), 4);
        assert_eq!(buffer.as_ref()[0], 0x41);

        let b = bytes::Bytes::new();
        let buffer = Buffer::from(b);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }
}
