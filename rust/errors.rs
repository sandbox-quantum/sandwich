// Copyright 2022 SandboxAQ
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

//! Sandwich error module.
//!
//! This API provides error types by implementing an ErrorBase.
//!
//! Author: thb-sb

extern crate protobuf;
extern crate sandwich_rust_proto;

/// An error enum with an OK value.
pub trait Error {
    /// The underlying type, based on protobuf.
    type ErrorEnum: protobuf::ProtobufEnum;

    /// The default value.
    const DEFAULT_VALUE: Self::ErrorEnum;

    /// The OK value.
    const OK_VALUE: Self::ErrorEnum;

    /// Returns the string associated to the error.
    fn get_error_string(&self) -> Option<&'static str>;
}

/// Base error.
#[derive(Debug)]
pub struct ErrorBase<ErrorEnum: protobuf::ProtobufEnum>(ErrorEnum);

impl<ErrorEnum: protobuf::ProtobufEnum> ErrorBase<ErrorEnum>
where
    Self: Error<ErrorEnum = ErrorEnum>,
{
    /// Creates an error from an enum code.
    pub fn new(e: ErrorEnum) -> Self {
        Self(e)
    }

    /// Get the enum from a i32
    pub fn enum_from_i32(e: i32) -> ErrorEnum {
        <ErrorEnum as protobuf::ProtobufEnum>::from_i32(e).unwrap_or(<Self as Error>::DEFAULT_VALUE)
    }

    /// Creates an error from a C value (u32).
    pub fn from_c(e: u32) -> Self {
        Self(Self::enum_from_i32(e as i32))
    }

    /// Creates a Result<T, Error<ErrorEnum>> from a C value (u32).
    pub fn from_c_or<T, Arg>(e: u32, f: fn(Arg) -> T, arg: Arg) -> Result<T, Self> {
        let e = Self::enum_from_i32(e as i32);
        if e == <Self as Error>::OK_VALUE {
            Ok(f(arg))
        } else {
            Err(Self(e))
        }
    }

    /// Returns true if the error holds the OK_VALUE.
    pub fn ok(&self) -> bool {
        self.0 == <Self as Error>::OK_VALUE
    }

    /// Returns the error code enum.
    pub fn what(&self) -> ErrorEnum {
        self.0
    }
}

/// Converts an error to an i32.
impl<ErrorEnum: protobuf::ProtobufEnum> Into<i32> for ErrorBase<ErrorEnum> {
    fn into(self) -> i32 {
        self.0.value()
    }
}

/// Converts an error to an u32.
impl<ErrorEnum: protobuf::ProtobufEnum> Into<u32> for ErrorBase<ErrorEnum> {
    fn into(self) -> u32 {
        self.0.value() as u32
    }
}

/// Implements std::fmt::Display for errors.
impl<ErrorEnum: protobuf::ProtobufEnum> std::fmt::Display for ErrorBase<ErrorEnum>
where
    Self: Error<ErrorEnum = ErrorEnum>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}",
            self.0.value(),
            self.get_error_string().unwrap_or("unknown error code")
        )
    }
}

/// A global error.
/// Global errors are defined in `errors.proto`, enum `Error`.
/// It defines errors that can happen all across the library.
pub type GlobalError = ErrorBase<sandwich_rust_proto::Error>;

/// Implements Error for `HandshakeState`.
impl Error for GlobalError {
    type ErrorEnum = sandwich_rust_proto::Error;

    const DEFAULT_VALUE: Self::ErrorEnum = sandwich_rust_proto::Error::ERROR_UNKNOWN;
    const OK_VALUE: Self::ErrorEnum = sandwich_rust_proto::Error::ERROR_OK;

    fn get_error_string(&self) -> Option<&'static str> {
        use sandwich_rust_proto::Error as PbError;
        #[allow(unreachable_patterns)]
        match self.0 {
            PbError::ERROR_OK => Some("no error"),
            PbError::ERROR_INVALID_ARGUMENT => Some("invalid argument"),
            PbError::ERROR_MEMORY => Some("memory error"),
            PbError::ERROR_IO => Some("I/O error"),
            PbError::ERROR_UNKNOWN => Some("unknown error"),
            PbError::ERROR_INVALID_CONFIGURATION => Some("invalid configuration"),
            PbError::ERROR_UNSUPPORTED_IMPLEMENTATION => Some("unsupported implementation"),
            PbError::ERROR_UNSUPPORTED_PROTOCOL => Some("unsupported protocol"),
            PbError::ERROR_IMPLEMENTATION_PROTOCOL_MISMATCH => {
                Some("implementation and protocol mismatch")
            }
            PbError::ERROR_PROTOBUF => Some("protobuf error"),
            PbError::ERROR_NETWORK_INVALID_ADDRESS => Some("invalid network address"),
            PbError::ERROR_NETWORK_INVALID_PORT => Some("invalid network port"),
            PbError::ERROR_INVALID_CONTEXT => Some("invalid context"),
            PbError::ERROR_BAD_FD => Some("bad file descriptor"),
            PbError::ERROR_UNSUPPORTED_TUNNEL_METHOD => Some("unsupported tunnel method"),
            PbError::ERROR_INTEGER_OVERFLOW => Some("integer overflow"),
            PbError::ERROR_MEMORY_OVERFLOW => Some("memory overflow"),
            PbError::ERROR_IMPLEMENTATION => Some("implementation error"),
            PbError::ERROR_INVALID_TUNNEL => Some("invalid tunnel"),
            PbError::ERROR_INVALID_KEM => Some("invalid KEM"),
            PbError::ERROR_TIMEOUT => Some("timeout reached"),
            PbError::ERROR_NETWORK_ADDRESS_RESOLVE => Some("failed to resolve network address"),
            PbError::ERROR_NETWORK_CONNECT => Some("failed to connect"),
            PbError::ERROR_SOCKET_FAILED => Some("failed to create socket"),
            PbError::ERROR_SOCKET_OPT_FAILED => Some("`getsockopt`/`setsockopt` failed"),
            PbError::ERROR_SOCKET_INVALID_AI_FAMILY => Some("invalid socket AI family"),
            PbError::ERROR_CONNECTION_REFUSED => Some("connection refused"),
            PbError::ERROR_NETWORK_UNREACHABLE => Some("network unreachable"),
            PbError::ERROR_SOCKET_POLL_FAILED => Some("socket poll failed"),
            PbError::ERROR_INVALID_CERTIFICATE => Some("invalid certificate"),
            PbError::ERROR_UNSUPPORTED_CERTIFICATE => Some("unsupported certificate"),
            PbError::ERROR_INVALID_PRIVATE_KEY => Some("invalid certificate"),
            PbError::ERROR_UNSUPPORTED_PRIVATE_KEY => Some("unsupported certificate"),
            PbError::ERROR_UNSUPPORTED_PROTOCOL_VERSION => Some("unsupported protocol version"),
            _ => None,
        }
    }
}

/// The handshake states. These states are defined in `tunnel.proto`,
/// enum `HandshakeState`.
/// This error is returned by `Tunnel::handshake`.
pub type HandshakeState = ErrorBase<sandwich_rust_proto::HandshakeState>;

/// Implements Error for `HandshakeState`.
impl Error for HandshakeState {
    type ErrorEnum = sandwich_rust_proto::HandshakeState;

    const DEFAULT_VALUE: Self::ErrorEnum =
        sandwich_rust_proto::HandshakeState::HANDSHAKESTATE_ERROR;
    const OK_VALUE: Self::ErrorEnum = sandwich_rust_proto::HandshakeState::HANDSHAKESTATE_DONE;

    fn get_error_string(&self) -> Option<&'static str> {
        use sandwich_rust_proto::HandshakeState as PbHandshakeState;
        #[allow(unreachable_patterns)]
        match self.0 {
            PbHandshakeState::HANDSHAKESTATE_IN_PROGRESS => Some("in progress"),
            PbHandshakeState::HANDSHAKESTATE_DONE => Some("done"),
            PbHandshakeState::HANDSHAKESTATE_WANT_READ => Some("the implementation wants to read from the wire, but the underlying I/O is non-blocking"),
            PbHandshakeState::HANDSHAKESTATE_WANT_WRITE => Some("the implementation wants to write to the wire, but the underlying I/O is non-blocking"),
            PbHandshakeState::HANDSHAKESTATE_ERROR => Some("a critical error occurred"),
            _ => None

        }
    }
}

/// State of a tunnel. The states are defined in `tunnel.proto`, enum `State`.
pub type State = ErrorBase<sandwich_rust_proto::State>;

/// Implements Error for `State`.
impl Error for State {
    type ErrorEnum = sandwich_rust_proto::State;

    const DEFAULT_VALUE: Self::ErrorEnum = sandwich_rust_proto::State::STATE_ERROR;
    const OK_VALUE: Self::ErrorEnum = sandwich_rust_proto::State::STATE_HANDSHAKE_DONE;

    fn get_error_string(&self) -> Option<&'static str> {
        use sandwich_rust_proto::State as PbState;
        #[allow(unreachable_patterns)]
        match self.0 {
            PbState::STATE_NOT_CONNECTED => Some("not connected"),
            PbState::STATE_CONNECTION_IN_PROGRESS => Some("connection in progress"),
            PbState::STATE_HANDSHAKE_IN_PROGRESS => Some("handshake in progress"),
            PbState::STATE_HANDSHAKE_DONE => Some("handshake done"),
            PbState::STATE_BEING_SHUTDOWN => Some("being shutdown"),
            PbState::STATE_DISCONNECTED => Some("disconnected"),
            PbState::STATE_ERROR => Some("a critical error occurred"),
            _ => None,
        }
    }
}

/// I/O errors. These errors are defined in `io.proto`, enum `IOError`.
/// They are returned by `IO::read` and `IO::write`.
pub type IOError = ErrorBase<sandwich_rust_proto::IOError>;

/// Implements Error for `IOError`.
impl Error for IOError {
    type ErrorEnum = sandwich_rust_proto::IOError;

    const DEFAULT_VALUE: Self::ErrorEnum = Self::ErrorEnum::IOERROR_UNKNOWN;
    const OK_VALUE: Self::ErrorEnum = Self::ErrorEnum::IOERROR_OK;

    fn get_error_string(&self) -> Option<&'static str> {
        use sandwich_rust_proto::IOError as PbIOError;
        #[allow(unreachable_patterns)]
        match self.0 {
            PbIOError::IOERROR_OK => Some("no error"),
            PbIOError::IOERROR_IN_PROGRESS => Some("connection in progress"),
            PbIOError::IOERROR_WOULD_BLOCK => Some("the i/o operation would block"),
            PbIOError::IOERROR_REFUSED => Some("the I/O interface has been refused connection"),
            PbIOError::IOERROR_CLOSED => Some("the I/O interface is closed"),
            PbIOError::IOERROR_INVALID => Some("the I/O interface isn't valid"),
            PbIOError::IOERROR_UNKNOWN => Some("the I/O interface raised an unknown error"),
            _ => None,
        }
    }
}

/// Record plane errors. These errors are defined in `tunnel.proto`, enum `RecordError`.
/// They are returned by `Tunnel::read` and `Tunnel::write`.
pub type RecordPlaneError = ErrorBase<sandwich_rust_proto::RecordError>;

/// Implements Error for `RecordPlaneError`.
impl Error for RecordPlaneError {
    type ErrorEnum = sandwich_rust_proto::RecordError;

    const DEFAULT_VALUE: Self::ErrorEnum = sandwich_rust_proto::RecordError::RECORDERROR_UNKNOWN;
    const OK_VALUE: Self::ErrorEnum = sandwich_rust_proto::RecordError::RECORDERROR_OK;

    fn get_error_string(&self) -> Option<&'static str> {
        use sandwich_rust_proto::RecordError as PbRecordError;
        #[allow(unreachable_patterns)]
        match self.0 {
            PbRecordError::RECORDERROR_OK => Some("no error"),
            PbRecordError::RECORDERROR_WANT_READ => {
                Some("wants to read data, but the underlying I/O interface is non-blocking")
            }
            PbRecordError::RECORDERROR_WANT_WRITE => {
                Some("wants to write data, but the underlying I/O interface is non-blocking")
            }
            PbRecordError::RECORDERROR_BEING_SHUTDOWN => Some("tunnel is being closed"),
            PbRecordError::RECORDERROR_CLOSED => Some("tunnel is closed"),
            PbRecordError::RECORDERROR_UNKNOWN => Some("unknown error"),
            _ => None,
        }
    }
}
