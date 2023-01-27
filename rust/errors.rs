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

//! Sandwich error module.
//!
//! This API provides error types by implementing an ErrorBase.
//!
//! Author: thb-sb

extern crate protobuf;
extern crate sandwich_c;
extern crate sandwich_rust_proto;

use super::pimpl;
use sandwich_rust_proto::ErrorKind;

/// `struct SandwichError` wrapper.
type ErrorHandleC = pimpl::Pimpl<sandwich_c::SandwichError>;

/// Create an ErrorHandleC from a raw pointer.
pub(crate) fn error_handle_c_from_raw(ptr: *mut sandwich_c::SandwichError) -> ErrorHandleC {
    ErrorHandleC::from_raw(
        ptr,
        Some(|ptr| unsafe {
            sandwich_c::sandwich_error_free(ptr);
        }),
    )
}

/// Defines the enum `ErrorCode` using a list of
/// symbols from sandwich_rust_proto.
/// These symbols have to be enums.
macro_rules! DefineErrorCodeEnum {
    ( $( $pbenum:ident ), * ) => {
        pub enum ErrorCode {
            $(
                $pbenum(sandwich_rust_proto::$pbenum),
            )*
            UnknownError { kind: i32, code: i32 },
        }
    };
}

DefineErrorCodeEnum!(
    APIError,
    ConfigurationError,
    ProtobufError,
    OpenSSLConfigurationError,
    OpenSSLClientConfigurationError,
    OpenSSLServerConfigurationError,
    CertificateError,
    PrivateKeyError,
    ASN1Error,
    DataSourceError,
    KEMError,
    SystemError,
    SocketError
);

/// Implements std::convert::From<ErrorEnum> for a given list of symbols
/// from ErrorCode.
macro_rules! DefineImplementationTraitFromProtobufEnum {
    ( $( $pbenum:ident ), * ) => {
        $(
            impl std::convert::From<sandwich_rust_proto::$pbenum> for ErrorCode {
                fn from(v: sandwich_rust_proto::$pbenum) -> Self {
                    Self::$pbenum(v)
                }
            }
        )*
    };
}
DefineImplementationTraitFromProtobufEnum!(
    APIError,
    ConfigurationError,
    ProtobufError,
    OpenSSLConfigurationError,
    OpenSSLClientConfigurationError,
    OpenSSLServerConfigurationError,
    CertificateError,
    PrivateKeyError,
    ASN1Error,
    DataSourceError,
    KEMError,
    SystemError,
    SocketError
);

macro_rules! MatchKindWithEnumVariant {
    ($k:ident, $code:ident; $( ($kindvalue:ident, $pbenum:ident), ) *) => {
        match $k {
            $(
            ErrorKind::$kindvalue => {
                <sandwich_rust_proto::$pbenum as protobuf::ProtobufEnum>::from_i32($code)
                .and_then(|x| Some(ErrorCode::$pbenum(x)))
            }
            )*
        }
    };
}

macro_rules! MatchEnumVariantWithKind {
    ($enu:expr; $( ($kindvalue:ident, $pbenum:ident), ) *) => {
        match $enu {
            $(
                ErrorCode::$pbenum(_) => Some(ErrorKind::$kindvalue),
            )*
            ErrorCode::UnknownError{..} => None
        }
    };
}

macro_rules! MatchEnumVariantCode {
   ($enum:expr; $( $pbenum:ident ), *) => {
        match $enum {
            $(
                ErrorCode::$pbenum(e) => <pb::$pbenum as protobuf::ProtobufEnum>::value(&e),
            )*
            ErrorCode::UnknownError{code, ..} => code
        }
   };
}

/// Implements ErrorCode.
impl ErrorCode {
    /// Creates an error code from a kind integer and a code integer.
    fn new(kind: i32, code: i32) -> ErrorCode {
        match <ErrorKind as protobuf::ProtobufEnum>::from_i32(kind) {
            Some(k) => MatchKindWithEnumVariant!(k, code;
                (ERRORKIND_API, APIError),
                (ERRORKIND_CONFIGURATION, ConfigurationError),
                (ERRORKIND_OPENSSL_CONFIGURATION, OpenSSLConfigurationError),
                (ERRORKIND_OPENSSL_CLIENT_CONFIGURATION, OpenSSLClientConfigurationError),
                (ERRORKIND_OPENSSL_SERVER_CONFIGURATION, OpenSSLServerConfigurationError),
                (ERRORKIND_CERTIFICATE, CertificateError),
                (ERRORKIND_PRIVATE_KEY, PrivateKeyError),
                (ERRORKIND_PROTOBUF, ProtobufError),
                (ERRORKIND_ASN1, ASN1Error),
                (ERRORKIND_DATA_SOURCE, DataSourceError),
                (ERRORKIND_KEM, KEMError),
                (ERRORKIND_SYSTEM, SystemError),
                (ERRORKIND_SOCKET, SocketError),
            )
            .unwrap_or(ErrorCode::UnknownError {
                kind: kind,
                code: code,
            }),
            None => ErrorCode::UnknownError {
                kind: kind,
                code: code,
            },
        }
    }

    /// Returns the kind of error.
    pub fn kind(&self) -> Option<ErrorKind> {
        MatchEnumVariantWithKind!(*self;
                    (ERRORKIND_API, APIError),
                    (ERRORKIND_CONFIGURATION, ConfigurationError),
                    (ERRORKIND_OPENSSL_CONFIGURATION, OpenSSLConfigurationError),
                    (ERRORKIND_OPENSSL_CLIENT_CONFIGURATION, OpenSSLClientConfigurationError),
                    (ERRORKIND_OPENSSL_SERVER_CONFIGURATION, OpenSSLServerConfigurationError),
                    (ERRORKIND_CERTIFICATE, CertificateError),
                    (ERRORKIND_PRIVATE_KEY, PrivateKeyError),
                    (ERRORKIND_PROTOBUF, ProtobufError),
                    (ERRORKIND_ASN1, ASN1Error),
                    (ERRORKIND_DATA_SOURCE, DataSourceError),
                    (ERRORKIND_KEM, KEMError),
                    (ERRORKIND_SYSTEM, SystemError),
                    (ERRORKIND_SOCKET, SocketError),
        )
    }

    /// Returns the code.
    pub fn code(&self) -> i32 {
        use sandwich_rust_proto as pb;
        MatchEnumVariantCode!(*self;
            APIError,
            ConfigurationError,
            ProtobufError,
            OpenSSLConfigurationError,
            OpenSSLClientConfigurationError,
            OpenSSLServerConfigurationError,
            CertificateError,
            PrivateKeyError,
            ASN1Error,
            DataSourceError,
            KEMError,
            SystemError,
            SocketError
        )
    }
}

/// Implements std::fmt::Display for ErrorCode.
impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use sandwich_rust_proto as pb;
        match *self {
            ErrorCode::APIError(e) => write!(f, "{}: {}", "api error", match e {
                pb::APIError::APIERROR_CONFIGURATION => "invalid configuration",
                pb::APIError::APIERROR_SOCKET => "socket error",
                pb::APIError::APIERROR_TUNNEL => "tunnel error",
            }),
            ErrorCode::ConfigurationError(e) => write!(f, "{}: {}", "configuration error", match e {
                pb::ConfigurationError::CONFIGURATIONERROR_INVALID_IMPLEMENTATION => "invalid implementation",
                pb::ConfigurationError::CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "unsupported implementation",
                pb::ConfigurationError::CONFIGURATIONERROR_INVALID => "invalid configuration",
            }),
            ErrorCode::OpenSSLConfigurationError(e) => write!(f, "{}: {}", "OpenSSL configuration error", match e {
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "unsupported implementation",
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION => "unsupported TLS version",
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY => "empty configuration",
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE => "invalid oneof case",
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID => "invalid OpenSSL configuration",
            }),
            ErrorCode::OpenSSLClientConfigurationError(e) => write!(f, "{}: {}", "OpenSSL client configuration error", match e {
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_EMPTY => "empty configuration",
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE => "certificate error",
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_SSL_CTX_FAILED => "SSL_CTX* creation failed",
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_KEM => "KEM error",
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_FLAGS => "flags error",
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_SSL_FAILED => "SSL* creation failed",
                pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_BIO_FAILED => "BIO* creation failed",
            }),
            ErrorCode::OpenSSLServerConfigurationError(e) => write!(f, "{}: {}", "OpenSSL server configuration error", match e {
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_EMPTY => "empty configuration",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE => "certificate error",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_SSL_CTX_FAILED => "SSL_CTX* creation failed",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_KEM => "KEM error",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_FLAGS => "flags error",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY => "private key error",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_SSL_FAILED => "SSL* creation failed",
                pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_BIO_FAILED => "BIO* creation failed",
            }),
            ErrorCode::CertificateError(e) => write!(f, "{}: {}", "certificate error", match e {
                pb::CertificateError::CERTIFICATEERROR_MALFORMED => "certificate malformed",
                pb::CertificateError::CERTIFICATEERROR_EXPIRED => "certificate expired",
                pb::CertificateError::CERTIFICATEERROR_NOT_FOUND => "certificate not found on disk",
                pb::CertificateError::CERTIFICATEERROR_UNKNOWN => "unknown error",
                pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED => "certificate not supported by underlying implementation",
            }),
            ErrorCode::PrivateKeyError(e) => write!(f, "{}: {}", "private key error", match e {
                pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED => "private key malformed",
                pb::PrivateKeyError::PRIVATEKEYERROR_NOT_FOUND => "private key not found on disk",
                pb::PrivateKeyError::PRIVATEKEYERROR_UNKNOWN => "unknown error",
                pb::PrivateKeyError::PRIVATEKEYERROR_UNSUPPORTED => "private key not supported by underlying implementation",
                pb::PrivateKeyError::PRIVATEKEYERROR_NOT_SERVER => "not a server configuration",
            }),
            ErrorCode::ProtobufError(e) => write!(f, "{}: {}", "protobuf error", match e {
                pb::ProtobufError::PROTOBUFERROR_EMPTY => "empty message",
                pb::ProtobufError::PROTOBUFERROR_TOO_BIG => "message too large",
                pb::ProtobufError::PROTOBUFERROR_PARSE_FAILED => "message parsing failed",
            }),
            ErrorCode::ASN1Error(e) => write!(f, "{}: {}", "ASN.1 error", match e {
                pb::ASN1Error::ASN1ERROR_INVALID_FORMAT => "invalid format",
            }),
            ErrorCode::DataSourceError(e) => write!(f, "{}: {}", "DataSource error", match e {
                pb::DataSourceError::DATASOURCEERROR_EMPTY => "empty DataSource",
                pb::DataSourceError::DATASOURCEERROR_INVALID_CASE => "invalid oneof case",
            }),
            ErrorCode::KEMError(e) => write!(f, "{}: {}", "KEM error", match e {
                pb::KEMError::KEMERROR_INVALID => "invalid or unsupported KEM",
                pb::KEMError::KEMERROR_TOO_MANY => "too many KEMs",
            }),
            ErrorCode::SystemError(e) => write!(f, "{}: {}", "system error", match e {
                pb::SystemError::SYSTEMERROR_MEMORY => "memory error",
                pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW => "integer overflow",
            }),
            ErrorCode::SocketError(e) => write!(f, "{}: {}", "socket error", match e {
                pb::SocketError::SOCKETERROR_BAD_FD => "bad file descriptor",
                pb::SocketError::SOCKETERROR_CREATION_FAILED => "socket creation failed",
                pb::SocketError::SOCKETERROR_BAD_NETADDR => "bad network address",
                pb::SocketError::SOCKETERROR_NETADDR_UNKNOWN => "network address resolution failed",
                pb::SocketError::SOCKETERROR_FSTAT_FAILED => "fstat failed",
                pb::SocketError::SOCKETERROR_NOT_SOCK => "not a socket",
                pb::SocketError::SOCKETERROR_GETSOCKNAME_FAILED => "getsockname failed",
                pb::SocketError::SOCKETERROR_SETSOCKOPT_FAILED => "setsockopt failed",
                pb::SocketError::SOCKETERROR_INVALID_AI_FAMILY => "invalid AI family",
            }),
            ErrorCode::UnknownError{kind, code} => write!(f, "unknown error kind:{} code:{}", kind, code)
        }
    }
}

/// Implements std::fmt::Debug for ErrorCode.
impl std::fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)?;
        write!(
            f,
            ": kind:{}, code:{}",
            if let ErrorCode::UnknownError { kind, .. } = *self {
                kind
            } else {
                <ErrorKind as protobuf::ProtobufEnum>::value(&self.kind().unwrap())
            },
            self.code()
        )
    }
}

/// An error.
#[derive(Debug)]
pub struct Error(std::vec::Vec<ErrorCode>);

/// Implements an error.
impl Error {
    /// Constructs an error from a C pointer.
    fn new(mut err: *const sandwich_c::SandwichError) -> Error {
        let mut root = Error(std::vec::Vec::new());
        while err != std::ptr::null() {
            root.0
                .push(unsafe { ErrorCode::new((*err).kind as i32, (*err).code) });
            err = unsafe { *err }.details;
        }
        root
    }

    /// Returns an iterator over the errors.
    pub fn iter(&self) -> std::slice::Iter<ErrorCode> {
        self.0.iter()
    }
}

/// Implements std::convert::From<ErrorHandleC> for Error.
impl std::convert::From<ErrorHandleC> for Error {
    fn from(e: ErrorHandleC) -> Self {
        Self::new(e.as_raw().unwrap())
    }
}

/// Implements std::convert::From<ErrorCode> for Error.
impl std::convert::From<ErrorCode> for Error {
    fn from(ec: ErrorCode) -> Self {
        let mut e = Self(std::vec::Vec::new());
        e.0.push(ec);
        e
    }
}

/// Implements std::convert::From<ErrorCode> for Error.
impl<ErrorEnum: protobuf::ProtobufEnum> std::convert::From<ErrorEnum> for Error
where
    ErrorCode: From<ErrorEnum>,
{
    fn from(v: ErrorEnum) -> Self {
        let ec = ErrorCode::from(v);
        let mut e = Self(std::vec::Vec::new());
        e.0.push(ec);
        e
    }
}

/// Implements std::fmt::Display for Error.
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut n = 0usize;
        for errc in self.0.iter() {
            for _ in 0..n {
                write!(f, "{}", '\t')?;
            }
            write!(f, "-> {}\n", errc)?;
            n += 1;
        }
        Ok(())
    }
}

/// Implements std::error::Error for Error.
impl std::error::Error for Error {}

/// An error that is based on a protobuf enum.
/// Such an error has an OK value and a default value.
/// An error enum with an OK value.
pub trait ProtoBasedError {
    /// The underlying type, based on protobuf.
    type ErrorEnum: protobuf::ProtobufEnum;

    /// The default value.
    const DEFAULT_VALUE: Self::ErrorEnum;

    /// The OK value.
    const OK_VALUE: Self::ErrorEnum;

    /// Returns the string associated to the error.
    fn get_error_string(&self) -> Option<&'static str>;
}

/// Base error for ProtoBasedError.
pub struct ProtoErrorBase<ErrorEnum: protobuf::ProtobufEnum>(ErrorEnum);

/// Implements ProtoErrorBase.
impl<ErrorEnum: protobuf::ProtobufEnum> ProtoErrorBase<ErrorEnum>
where
    Self: ProtoBasedError<ErrorEnum = ErrorEnum>,
{
    /// Constructs a ProtoErrorBase from an enum code.
    pub fn new(e: ErrorEnum) -> Self {
        Self(e)
    }

    /// Constructs a ProtoErrorBase from a C value.
    pub fn from_c(i: i32) -> Self {
        Self(
            <ErrorEnum as protobuf::ProtobufEnum>::from_i32(i)
                .unwrap_or(<Self as ProtoBasedError>::DEFAULT_VALUE),
        )
    }

    /// Constructs a Result<T, ProtoBasedError<ErrorEnum>> from a C value.
    pub fn from_c_or<T, Arg>(i: i32, f: fn(Arg) -> T, arg: Arg) -> Result<T, Self> {
        let e = <ErrorEnum as protobuf::ProtobufEnum>::from_i32(i)
            .unwrap_or(<Self as ProtoBasedError>::DEFAULT_VALUE);
        if e == <Self as ProtoBasedError>::OK_VALUE {
            Ok(f(arg))
        } else {
            Err(Self(e))
        }
    }

    /// Returns true if the error holds the OK_VALUE.
    pub fn ok(&self) -> bool {
        self.0 == <Self as ProtoBasedError>::OK_VALUE
    }

    /// Returns the error code enum.
    pub fn what(&self) -> ErrorEnum {
        self.0
    }
}

/// Converts an error to an i32.
impl<ErrorEnum: protobuf::ProtobufEnum> Into<i32> for ProtoErrorBase<ErrorEnum> {
    fn into(self) -> i32 {
        self.0.value()
    }
}

/// Converts an error to an u32.
impl<ErrorEnum: protobuf::ProtobufEnum> Into<u32> for ProtoErrorBase<ErrorEnum> {
    fn into(self) -> u32 {
        self.0.value() as u32
    }
}

/// Implements std::fmt::Display for ProtoErrorBase.
impl<ErrorEnum: protobuf::ProtobufEnum> std::fmt::Display for ProtoErrorBase<ErrorEnum>
where
    Self: ProtoBasedError<ErrorEnum = ErrorEnum>,
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

/// Implements std::fmt::Debug for ProtoErrorBase.
impl<ErrorEnum: protobuf::ProtobufEnum> std::fmt::Debug for ProtoErrorBase<ErrorEnum>
where
    Self: ProtoBasedError<ErrorEnum = ErrorEnum>,
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

/// Implements std::error::Error for ProtoErrorBase.
impl<ErrorEnum: protobuf::ProtobufEnum> std::error::Error for ProtoErrorBase<ErrorEnum> where
    Self: ProtoBasedError<ErrorEnum = ErrorEnum>
{
}

/// The handshake states. These states are defined in `tunnel.proto`,
/// enum `HandshakeState`.
/// This error is returned by `Tunnel::handshake`.
pub type HandshakeState = ProtoErrorBase<sandwich_rust_proto::HandshakeState>;

/// Implements ProtoBasedError for `HandshakeState`.
impl ProtoBasedError for HandshakeState {
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
pub type State = ProtoErrorBase<sandwich_rust_proto::State>;

/// Implements Error for `State`.
impl ProtoBasedError for State {
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
pub type IOError = ProtoErrorBase<sandwich_rust_proto::IOError>;

/// Implements Error for `IOError`.
impl ProtoBasedError for IOError {
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
pub type RecordPlaneError = ProtoErrorBase<sandwich_rust_proto::RecordError>;

/// Implements Error for `RecordPlaneError`.
impl ProtoBasedError for RecordPlaneError {
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
