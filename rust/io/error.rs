// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! IO errors module.

use std::io::{Error, ErrorKind};

/// Types that can be converted to a [`pb::IOError`].
pub(crate) trait IntoIOError {
    /// Convert the type to an IOError.
    fn into_io_error(self) -> pb::IOError;
}

impl IntoIOError for ErrorKind {
    fn into_io_error(self) -> pb::IOError {
        match self {
            Self::WouldBlock | Self::WriteZero | Self::Interrupted => {
                pb::IOError::IOERROR_WOULD_BLOCK
            }
            Self::NotConnected => pb::IOError::IOERROR_IN_PROGRESS,
            Self::ConnectionRefused
            | Self::ConnectionReset
            | Self::ConnectionAborted
            | Self::TimedOut => pb::IOError::IOERROR_REFUSED,
            Self::BrokenPipe => pb::IOError::IOERROR_CLOSED,
            Self::NotFound
            | Self::PermissionDenied
            | Self::AlreadyExists
            | Self::InvalidInput
            | Self::InvalidData => pb::IOError::IOERROR_INVALID,
            Self::Unsupported | Self::OutOfMemory => pb::IOError::IOERROR_SYSTEM_ERROR,
            Self::AddrInUse | Self::AddrNotAvailable => pb::IOError::IOERROR_ADDRESS_IN_USE,
            _ => pb::IOError::IOERROR_UNKNOWN,
        }
    }
}

impl IntoIOError for Error {
    fn into_io_error(self) -> pb::IOError {
        self.kind().into_io_error()
    }
}

/// Instantiates an [`ErrorKind`] from a [`pb::IOError`].
#[cfg(feature = "ffi")]
pub(crate) fn error_kind_from_io_error(io_error: pb::IOError) -> ErrorKind {
    match io_error {
        pb::IOError::IOERROR_WOULD_BLOCK => ErrorKind::WouldBlock,
        pb::IOError::IOERROR_IN_PROGRESS => ErrorKind::NotConnected,
        pb::IOError::IOERROR_REFUSED => ErrorKind::ConnectionRefused,
        pb::IOError::IOERROR_CLOSED => ErrorKind::BrokenPipe,
        pb::IOError::IOERROR_SYSTEM_ERROR => ErrorKind::Unsupported,
        pb::IOError::IOERROR_ADDRESS_IN_USE => ErrorKind::AddrInUse,
        _ => ErrorKind::InvalidInput,
    }
}
