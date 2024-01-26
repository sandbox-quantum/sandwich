// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! This module provides the definition of I/O interfaces.
//!
//! I/O interfaces are used to abstract the I/O plane.

use std::io::{Read, Write};

/// Support for errors.
pub mod error;

/// A set of functions that implement common I/O objects.
pub mod helpers;

/// The listener trait provides an object that can accept
/// new connections and create I/O objects.
pub mod listener;

/// An IO interface that implements both [`Read`] and [`Write`] traits.
pub trait IO: Read + Write {}
impl<T> IO for T where T: Read + Write {}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test {
    use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

    use std::io::{ErrorKind as IOErrorKind, Result as IOResult};

    type Buffer = Vec<u8>;

    /// A simple IO implementation, backed by mpsc channels.
    pub(crate) struct MpscIO {
        /// Write stream.
        write_stream: Option<Sender<Buffer>>,

        /// Read stream.
        read_stream: Option<Receiver<Buffer>>,

        /// Buffer.
        buffer: Buffer,
    }

    impl std::fmt::Debug for MpscIO {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "MpscIO")
        }
    }

    impl Default for MpscIO {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MpscIO {
        /// Instantiates a new MpscIO.
        pub(crate) fn new() -> Self {
            Self {
                write_stream: None,
                read_stream: None,
                buffer: Buffer::new(),
            }
        }

        /// Links two MpscIO together.
        pub(crate) fn link_with(&mut self, other: &mut Self) {
            (self.write_stream, other.read_stream) = {
                let (s, r) = mpsc::channel();
                (Some(s), Some(r))
            };
            (other.write_stream, self.read_stream) = {
                let (s, r) = mpsc::channel();
                (Some(s), Some(r))
            };
        }

        /// Creates a pair of linked MpscIO.
        pub(crate) fn new_pair() -> (Self, Self) {
            let mut left = Self::new();
            let mut right = Self::new();
            left.link_with(&mut right);
            (left, right)
        }
    }

    impl std::io::Read for MpscIO {
        fn read(&mut self, buf: &mut [u8]) -> IOResult<usize> {
            let n = std::cmp::min(buf.len(), self.buffer.len());
            if n > 0 {
                buf[0..n].copy_from_slice(&self.buffer[0..n]);
                self.buffer.drain(0..n);
            }
            let mut r = buf.len() - n;
            if r == 0 {
                return Ok(n);
            }
            let mut it = &mut buf[n..];
            let mut bread = n;

            let read_stream = self.read_stream.as_ref().ok_or(IOErrorKind::WouldBlock)?;
            while r != 0 {
                let result = match read_stream.try_recv() {
                    Ok(mut new_buffer) => {
                        let s = std::cmp::min(new_buffer.len(), r);
                        it[0..s].copy_from_slice(&new_buffer[0..s]);
                        it = &mut it[s..];
                        r -= s;
                        bread += s;
                        new_buffer.drain(0..s);
                        if !new_buffer.is_empty() {
                            self.buffer.extend(new_buffer);
                        }
                        Ok(())
                    }
                    Err(TryRecvError::Empty) => Err(IOErrorKind::WouldBlock),
                    Err(TryRecvError::Disconnected) => Err(IOErrorKind::ConnectionAborted),
                };
                if let Err(ek) = result {
                    if bread == 0 {
                        return Err(ek.into());
                    } else {
                        return Ok(bread);
                    }
                }
            }
            Ok(bread)
        }
    }

    impl std::io::Write for MpscIO {
        fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
            let write_stream = self.write_stream.as_ref().ok_or(IOErrorKind::WouldBlock)?;
            write_stream
                .send(buf.into())
                .map(|_| buf.len())
                .map_err(|_| IOErrorKind::ConnectionAborted.into())
        }

        fn flush(&mut self) -> IOResult<()> {
            Ok(())
        }
    }

    #[cfg(all(
        any(feature = "openssl1_1_1", feature = "boringssl", feature = "openssl3"),
        feature = "tunnel"
    ))]
    impl crate::tunnel::IO for MpscIO {}
}
