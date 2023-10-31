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
}

/// Implements [`std::fmt::Debug`] for [`IO`].
impl std::fmt::Debug for dyn IO {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IO")
    }
}
