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

//! Defines [`OpenSSLBIO`] type and [`Bio`] struct.
//!
//! This module is an helper around the buffered I/O interface from OpenSSL,
//! also called BIO.
//!
//! Author: thb-sb

extern crate openssl;

/// Alias for `[crate::Pimpl<'pimpl, T>`] where `T` is a BIO structure.
type OpenSSLBIO<'pimpl> = crate::Pimpl<'pimpl, openssl::bio_st>;

/// A BIO.
/// The data carried by a BIO is borrowed.
pub(super) struct Bio<'data>(OpenSSLBIO<'data>);

/// Implements [`std::fmt::Debug`] for [`Bio`].
impl<'data> std::fmt::Debug for Bio<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL BIO")
    }
}

/// Instantiates a [`Bio`] from an u8 buffer.
impl<'slice: 'data, 'data> std::convert::TryFrom<&'slice [u8]> for Bio<'data> {
    type Error = crate::Error;

    fn try_from(obj: &[u8]) -> crate::Result<Self> {
        let ptr = if obj.len() <= (std::i32::MAX as usize) {
            unsafe {
                Ok::<*mut openssl::bio_st, _>(openssl::BIO_new_mem_buf(
                    obj.as_ptr() as *const std::ffi::c_void,
                    obj.len() as i32,
                ))
            }
        } else {
            Err(pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)
        }?;
        if !ptr.is_null() {
            Ok(Self(OpenSSLBIO::from_raw(
                ptr,
                Some(|p| unsafe {
                    openssl::BIO_free_all(p);
                }),
            )))
        } else {
            Err(pb::SystemError::SYSTEMERROR_MEMORY)?
        }
    }
}

/// Implements [`Bio`].
impl<'data> Bio<'data> {
    /// Returns the mutable raw pointer to the OpenSSL BIO object.
    /// This method is unsafe because we can't tie a lifetime to
    /// a raw pointer.
    pub(super) unsafe fn as_raw_mut(&mut self) -> *mut openssl::bio_st {
        self.0.as_mut_ptr()
    }
}

#[cfg(test)]
mod test {
    use super::Bio;

    /// Tests [`std::convert::TryFrom<&[u8]>`] for [`BIO`].
    #[test]
    fn test_tryfrom() {
        let vec = vec![0u8; 42];
        let b = Bio::try_from(vec.as_ref());
        assert!(b.is_ok());
    }

    /// Tests [`std::convert::TryFrom<&[u8]>`] for [`BIO`] with a too large buffer.
    #[test]
    fn test_tryfrom_too_large() {
        let vec = vec![0u8; (std::i32::MAX as usize) + 1usize];
        let b = Bio::try_from(vec.as_ref());
        assert!(b.is_err());
        assert_eq!(
            b.unwrap_err(),
            pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW
        );
    }
}
