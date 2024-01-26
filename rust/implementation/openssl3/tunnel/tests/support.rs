// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Support for OpenSSL 3 test suite.

pub extern crate sandwich;
pub extern crate sandwich_api_proto;
pub extern crate sandwich_proto;

#[cfg(not(feature = "bazel"))]
extern crate testdata;
#[cfg(not(feature = "bazel"))]
use std::path::Path;

use std::net;

pub use sandwich_api_proto as pb_api;
pub use sandwich_proto as pb;

/// Resolves the filepath of a runfiles file (data attributes).
#[cfg(feature = "bazel")]
pub fn resolve_runfile(path: impl AsRef<str>) -> String {
    extern crate runfiles;
    let path = path.as_ref();
    let r = runfiles::Runfiles::create().unwrap();
    r.rlocation(format!(
        "{workspace}/{path}",
        workspace = r.current_repository()
    ))
    .into_os_string()
    .into_string()
    .unwrap()
}

/// Resolves the filepath of a runfiles file (data attributes).
#[cfg(not(feature = "bazel"))]
pub fn resolve_runfile(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    testdata::resolve_file(path)
        .or_else(|_| {
            if !path.is_file() {
                panic!("{} does not exist", path.display());
            }
            Ok::<String, String>(String::from(path.to_string_lossy()))
        })
        .unwrap()
}

pub mod io {
    use std::io::{ErrorKind as IOErrorKind, Read, Result as IOResult, Write};
    use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

    use super::*;

    /// A simple buffer.
    type Buffer = Vec<u8>;

    /// A simple IO implementation, backed by mpsc channels.
    pub struct MpscIO {
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
        pub fn new() -> Self {
            Self {
                write_stream: None,
                read_stream: None,
                buffer: Buffer::new(),
            }
        }

        /// Links two MpscIO together.
        pub fn link_with(&mut self, other: &mut Self) {
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
        pub fn new_pair() -> (Self, Self) {
            let mut left = Self::new();
            let mut right = Self::new();
            left.link_with(&mut right);
            (left, right)
        }
    }

    impl Read for MpscIO {
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

            let read_stream = self
                .read_stream
                .as_ref()
                .ok_or_else(|| IOErrorKind::WouldBlock)?;
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

    impl Write for MpscIO {
        fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
            let write_stream = self
                .write_stream
                .as_ref()
                .ok_or_else(|| IOErrorKind::WouldBlock)?;
            write_stream
                .send(buf.into())
                .map(|_| buf.len())
                .map_err(|_| IOErrorKind::ConnectionAborted.into())
        }

        fn flush(&mut self) -> IOResult<()> {
            Ok(())
        }
    }

    impl sandwich::tunnel::IO for MpscIO {}

    /// Wrapper around a `TcpStream` object.
    #[derive(Debug)]
    pub struct TcpStream(pub net::TcpStream);

    impl Read for TcpStream {
        fn read(&mut self, buf: &mut [u8]) -> IOResult<usize> {
            self.0.read(buf)
        }
    }

    impl Write for TcpStream {
        fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> IOResult<()> {
            self.0.flush()
        }
    }

    impl sandwich::tunnel::IO for TcpStream {}
}
