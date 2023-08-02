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

//! Defines [`IO`] trait.
//!
//! This module provides the definition of an I/O interface.
//!
//! An [`IO`] trait must implements the following methods:
//!  * `Read`
//!  * `Write`
//!  * `Close`
//!
//! Each of these methods may return an [`Error`], such as `ConnectionRefused`
//! or `WouldBlock`.
//!
//! I/O interfaces are used to abstract the I/O plane.

/// An I/O error.
/// To see the list of I/O errors, see [`sandwich_proto::IOError`].
pub struct Error(pb::IOError);

/// Implements [`std::fmt::Display`] for [`Error`].
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ioerror: {}",
            match self.0 {
                pb::IOError::IOERROR_OK => "no error",
                pb::IOError::IOERROR_IN_PROGRESS => "in progress",
                pb::IOError::IOERROR_WOULD_BLOCK => "would block",
                pb::IOError::IOERROR_REFUSED => "refused",
                pb::IOError::IOERROR_CLOSED => "closed",
                pb::IOError::IOERROR_INVALID => "invalid I/O plane",
                pb::IOError::IOERROR_UNKNOWN => "unknown error",
            }
        )
    }
}

/// Implements [`std::fmt::Debug`] for [`Error`].
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ioerror: {}",
            match self.0 {
                pb::IOError::IOERROR_OK => "no error",
                pb::IOError::IOERROR_IN_PROGRESS => "in progress",
                pb::IOError::IOERROR_WOULD_BLOCK => "would block",
                pb::IOError::IOERROR_REFUSED => "refused",
                pb::IOError::IOERROR_CLOSED => "closed",
                pb::IOError::IOERROR_INVALID => "invalid I/O plane",
                pb::IOError::IOERROR_UNKNOWN => "unknown error",
            }
        )
    }
}

/// Instantiates an [`Error`] with an enum value from the
/// [`sandwich_proto::IOError`] enum.
impl std::convert::From<pb::IOError> for Error {
    fn from(e: pb::IOError) -> Self {
        Self(e)
    }
}

/// Consumes an [`Error`] back into the the [`sandwich_proto::IOError`]
/// enum value.
impl std::convert::From<Error> for pb::IOError {
    fn from(e: Error) -> Self {
        e.0
    }
}

/// A Result from an I/O operation.
pub type Result<T> = std::result::Result<T, Error>;

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
/// type Buffer = std::vec::Vec<u8>;
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
///     fn close(&mut self) -> IOResult<()> {
///         self.ins = None;
///         self.outs = None;
///         Ok(())
///     }
/// }
/// ```
pub trait IO {
    /// Reads some bytes from the I/O plane.
    fn read(&mut self, buf: &mut [u8], state: pb::State) -> Result<usize>;

    /// Writes some bytes to the I/O plane.
    fn write(&mut self, buf: &[u8], state: pb::State) -> Result<usize>;

    /// Closes the I/O plane.
    fn close(&mut self) -> Result<()>;
}

/// Implements [`std::fmt::Debug`] for [`IO`].
impl std::fmt::Debug for dyn IO {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IO")
    }
}

pub(crate) mod helpers;
