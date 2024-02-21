// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines owned IO.

use std::ffi::{c_int, c_void};
use std::io::{self, Read, Write};

use protobuf::Enum as _;

#[cfg(feature = "turbo")]
use crate::experimental::{TurboClientIo, TurboServerIo};
use crate::ffi::support;
use crate::io::error::IntoIOError as _;

use super::IO;

/// A routine that frees the memory occupied by an FFI IO object.
pub type FreeFn = extern "C" fn(uarg: *mut IO);

/// An IO owned by Sandwich.
/// This IO must be freed by calling `sandwich_owned_io_free`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OwnedIo {
    /// The base IO object.
    /// The `uarg` pointer points to an [`OwnedIoUarg`].
    pub(crate) io: *mut IO,

    /// The routine for freeing the base IO object.
    pub(crate) freeptr: Option<FreeFn>,
}

impl AsRef<IO> for OwnedIo {
    fn as_ref(&self) -> &IO {
        unsafe { &*self.io }
    }
}

impl AsRef<OwnedIoUarg> for OwnedIo {
    fn as_ref(&self) -> &OwnedIoUarg {
        let io: &IO = self.as_ref();
        unsafe { &*io.uarg.cast() }
    }
}

/// The uarg value of an IO owned by an [`OwnedIo`].
pub(crate) enum OwnedIoUarg {
    /// A generic crate::IO value.
    Generic(Box<dyn crate::IO>),

    /// A Turbo client.
    #[cfg(feature = "turbo")]
    TurboClient(TurboClientIo),

    /// A Turbo server.
    #[cfg(feature = "turbo")]
    TurboServer(Box<TurboServerIo>),
}

macro_rules! dispatch {
    ($self:ident, $func:ident, $($arg:tt) *) => {
        match $self {
            Self::Generic(gen) => gen.$func($($arg)*),
            #[cfg(feature = "turbo")]
            Self::TurboClient(turbo_client) => turbo_client.$func($($arg)*),
            #[cfg(feature = "turbo")]
            Self::TurboServer(turbo_server) => turbo_server.$func($($arg)*),
        }
    };
    ($self:ident, $func:ident) => {
        match $self {
            Self::Generic(gen) => gen.$func(),
            #[cfg(feature = "turbo")]
            Self::TurboClient(turbo_client) => turbo_client.$func(),
            #[cfg(feature = "turbo")]
            Self::TurboServer(turbo_server) => turbo_server.$func(),
        }
    };
}

impl Read for OwnedIoUarg {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        dispatch!(self, read, buf)
    }
}

impl Write for OwnedIoUarg {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        dispatch!(self, write, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        dispatch!(self, flush)
    }
}

impl std::fmt::Debug for OwnedIo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ForeignOwnedIO(io={io:?}, freeptr={freeptr:?})",
            io = self.io,
            freeptr = self.freeptr,
        )
    }
}

impl std::fmt::Debug for OwnedIoUarg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OwnedIoUarg::")?;
        match self {
            Self::Generic(_) => write!(f, "Generic()"),
            #[cfg(feature = "turbo")]
            Self::TurboClient(ref turbo_client) => {
                write!(f, "TurboClient({:p})", turbo_client as *const _)
            }
            #[cfg(feature = "turbo")]
            Self::TurboServer(ref turbo_server) => {
                write!(f, "TurboServer({:p})", turbo_server as *const _)
            }
        }
    }
}

/// The read function used by owned IOs.
pub(crate) extern "C" fn sandwich_owned_io_read(
    uarg: *mut c_void,
    buf: *mut c_void,
    count: usize,
    err: *mut c_int,
) -> usize {
    let owned_uio_arg: &mut OwnedIoUarg = unsafe { &mut *uarg.cast() };
    let err: &mut c_int = unsafe { &mut *err };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf.cast(), count) };
    match owned_uio_arg.read(slice) {
        Ok(n) => {
            *err = support::to_c_int(pb::IOError::IOERROR_OK.value());
            n
        }
        Err(e) => {
            *err = support::to_c_int(e.into_io_error().value());
            0
        }
    }
}

/// The write function used by owned IOs.
pub(crate) extern "C" fn sandwich_owned_io_write(
    uarg: *mut c_void,
    buf: *const c_void,
    count: usize,
    err: *mut c_int,
) -> usize {
    let owned_uio_arg: &mut OwnedIoUarg = unsafe { &mut *uarg.cast() };
    let err: &mut c_int = unsafe { &mut *err };
    let slice = unsafe { std::slice::from_raw_parts(buf.cast(), count) };
    match owned_uio_arg.write(slice) {
        Ok(n) => {
            *err = support::to_c_int(pb::IOError::IOERROR_OK.value());
            n
        }
        Err(e) => {
            *err = support::to_c_int(e.into_io_error().value());
            0
        }
    }
}

/// The flush function used by owned IOs.
pub(crate) extern "C" fn sandwich_owned_io_flush(uarg: *mut c_void) -> c_int {
    let owned_uio_arg: &mut OwnedIoUarg = unsafe { &mut *uarg.cast() };
    match owned_uio_arg.flush() {
        Ok(_) => support::to_c_int(pb::IOError::IOERROR_OK.value()),
        Err(e) => support::to_c_int(e.into_io_error().value()),
    }
}

/// Frees the memory occupied by an [`OwnedIo`]..
#[no_mangle]
pub extern "C" fn sandwich_io_owned_free(owned_io: *mut OwnedIo) {
    let mut owned_io = unsafe { Box::from_raw(owned_io) };
    if let Some(free) = owned_io.freeptr {
        (free)(owned_io.io);
        owned_io.freeptr = None;
    }
}

/// Frees an [`IO`] owned by an [`OwnedIo`].
pub(crate) extern "C" fn owned_io_free_io(io: *mut IO) {
    let io: Box<IO> = unsafe { Box::from_raw(io.cast()) };
    let _: Box<OwnedIoUarg> = unsafe { Box::from_raw(io.uarg.cast()) };
}

impl From<OwnedIoUarg> for Box<OwnedIo> {
    fn from(uarg: OwnedIoUarg) -> Self {
        let uarg = Box::into_raw(Box::new(uarg)).cast();
        Box::new(OwnedIo {
            io: Box::into_raw(Box::new(IO {
                readfn: sandwich_owned_io_read,
                writefn: sandwich_owned_io_write,
                flushfn: Some(sandwich_owned_io_flush),
                uarg,
            })),
            freeptr: Some(owned_io_free_io),
        })
    }
}

impl From<Box<dyn crate::IO>> for Box<OwnedIo> {
    fn from(io: Box<dyn crate::IO>) -> Self {
        Box::<OwnedIo>::from(OwnedIoUarg::Generic(io))
    }
}

impl OwnedIo {
    /// Instantiates a new boxed OwnedIo from an object that implements
    /// [`Read`] and [`Write`].
    pub(crate) fn from_std_io_boxed<T>(std_io: T) -> Box<Self>
    where
        T: Read + Write + 'static,
    {
        Box::<Self>::from(OwnedIoUarg::Generic(Box::new(std_io)))
    }

    /// Instantiates a new OwnedIo from a turbo client.
    #[cfg(feature = "turbo")]
    pub(crate) fn from_turbo_client_boxed(turbo_client: TurboClientIo) -> Box<Self> {
        Box::<Self>::from(OwnedIoUarg::TurboClient(turbo_client))
    }

    /// Instantiates a new OwnedIo from a turbo server.
    #[cfg(feature = "turbo")]
    pub(crate) fn from_turbo_server_boxed(turbo_server: Box<TurboServerIo>) -> Box<Self> {
        Box::<Self>::from(OwnedIoUarg::TurboServer(turbo_server))
    }
}
