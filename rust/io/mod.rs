// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`IO`] trait.
//!
//! This module provides the definition of an I/O interface.
//!
//! An [`IO`] trait must implements the following methods:
//!  * `Read`
//!  * `Write`
//!
//! Each of these methods may return an [`Error`], such as `ConnectionRefused`
//! or `WouldBlock`.
//!
//! I/O interfaces are used to abstract the I/O plane.

/// Support for errors.
pub mod error;

/// A set of functions that implement common I/O objects.
pub mod helpers;

/// The listener trait provides an object that can accept
/// new connections and create I/O objects.
pub mod listener;

/// An I/O interface.
///
/// # Example
///
/// ```
///
/// use sandwich_proto as pb;
/// use sandwich::io::Result as IOResult;
///
/// /// A simple variable-sized buffer.
/// type Buffer = Vec<u8>;
///
/// /// A stream backed by `std::sync::mpsc::channel`.
/// struct BufferedChannel {
///     outs: Option<std::sync::mpsc::Sender<Buffer>>,
///     ins: Option<std::sync::mpsc::Receiver<Buffer>>,
///     buffer: Buffer,
/// }
///
/// /// Implements `BufferedChannel`.
/// impl BufferedChannel {
///     /// Instantiates a `BufferedChannel` and returns the sender to
///     /// itself.
///     fn new() -> Self {
///         Self{
///             outs: None,
///             ins: None,
///             buffer: Buffer::with_capacity(4096usize),
///         }
///     }
///
///     /// Links two `BufferedChannel` together.
///     fn link(a: &mut Self, b: &mut Self) {
///         (a.outs, b.ins) = { let (s, r) = std::sync::mpsc::channel(); (Some(s), Some(r)) };
///         (b.outs, a.ins) = { let (s, r) = std::sync::mpsc::channel(); (Some(s), Some(r)) };
///     }
/// }
///
/// /// Implements `sandwich::IO` for `BufferedChannel`.
/// impl sandwich::IO for BufferedChannel {
///     fn read(&mut self, buf: &mut [u8], _state: pb::State) -> IOResult<usize> {
///         let n = std::cmp::min(buf.len(), self.buffer.len());
///         if n > 0 {
///             buf.copy_from_slice(&self.buffer[0 .. n]);
///             self.buffer.drain(0..n);
///         }
///         let r = buf.len() - n;
///         if r == 0 {
///             return Ok(n);
///         }
///         let mut it = &mut buf[n..];
///         let bread = n;
///
///         let e = match self.ins {
///             Some(ref ins) => match ins.try_recv() {
///                 Ok(v) => {
///                     self.buffer.extend(v);
///                     Ok(self.buffer.len())
///                 },
///                 Err(std::sync::mpsc::TryRecvError::Empty) => Err(pb::IOError::IOERROR_WOULD_BLOCK),
///                 Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(pb::IOError::IOERROR_CLOSED),
///             },
///             None => Err(pb::IOError::IOERROR_IN_PROGRESS),
///         };
///         match e {
///             Ok(s) => {
///                 let n = std::cmp::min(it.len(), s);
///                 Ok(bread + if n > 0 {
///                     it.copy_from_slice(&self.buffer[0 .. n]);
///                     self.buffer.drain(0..n);
///                     n
///                 } else {
///                     0
///                 })
///             },
///             Err(e) => match bread {
///                 0 => Err(e.into()),
///                 _ => Ok(bread)
///             }
///         }
///     }
///
///     fn write(&mut self, buf: &[u8], _state: pb::State) -> IOResult<usize> {
///         match self.outs {
///             Some(ref s) => match s.send(buf.into()) {
///                 Ok(_) => Ok(buf.len()),
///                 Err(_) => Err(pb::IOError::IOERROR_CLOSED.into()),
///             },
///             None => Err(pb::IOError::IOERROR_IN_PROGRESS.into()),
///         }
///     }
///
/// }
/// ```
pub trait IO: Send {
    /// Reads some bytes from the I/O plane.
    fn read(&mut self, buf: &mut [u8], state: pb::State) -> Result<usize, std::io::Error>;

    /// Writes some bytes to the I/O plane.
    fn write(&mut self, buf: &[u8], state: pb::State) -> Result<usize, std::io::Error>;

    /// Flushes bytes from the I/O interface.
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// Implements [`std::fmt::Debug`] for [`IO`].
impl std::fmt::Debug for dyn IO {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IO")
    }
}

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

    impl crate::IO for MpscIO {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> IOResult<usize> {
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

        fn write(&mut self, buf: &[u8], _state: pb::State) -> IOResult<usize> {
            let write_stream = self.write_stream.as_ref().ok_or(IOErrorKind::WouldBlock)?;
            write_stream
                .send(buf.into())
                .map(|_| buf.len())
                .map_err(|_| IOErrorKind::ConnectionAborted.into())
        }
    }

    /// Tests [`MpscIO`].
    #[test]
    fn test_mpscio() {
        use crate::IO;

        let (mut left, mut right) = MpscIO::new_pair();
        let s = pb::State::STATE_HANDSHAKE_DONE;

        let mut buffer = vec![0u8; 42];

        assert_eq!(
            left.read(&mut buffer, s).map_err(|e| e.kind()),
            Err(IOErrorKind::WouldBlock)
        );

        assert_eq!(right.write(b"hello world", s).map_err(|e| e.kind()), Ok(11));
        assert_eq!(
            left.read(&mut buffer[0..10], s).map_err(|e| e.kind()),
            Ok(10)
        );
        assert_eq!(&buffer[0..10], b"hello worl");
        assert_eq!(right.write(b"another msg", s).map_err(|e| e.kind()), Ok(11));
        assert_eq!(
            left.read(&mut buffer[10..11], s).map_err(|e| e.kind()),
            Ok(1)
        );
        assert_eq!(&buffer[0..11], b"hello world");
        assert_eq!(left.read(&mut buffer[..], s).map_err(|e| e.kind()), Ok(11));
        assert_eq!(&buffer[0..11], b"another msg");
    }
}
