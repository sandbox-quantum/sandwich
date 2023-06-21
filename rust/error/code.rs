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

//! Defines [`ProtoBasedErrorCode`] enum and [`AllowedProtoBasedErrorCodeEnum`] trait.
//!
//! This module implements the structured errors for Sandwich.
//!
//! Structured errors are errors that can wrap another one to provide
//! more details.
//!
//! Errors are classified by type, also called kind. The `ErrorKind` enum
//! lists all error kinds.
//!
//! Errors are defined in the `errors.proto` protobuf file by enums.

extern crate protobuf;
extern crate sandwich_rust_proto as pb;

/// An enum allowed in [`ProtoBasedErrorCode`].
pub(crate) trait AllowedProtoBasedErrorCodeEnum: Copy + Clone + Sized {}

/// Generates the definition of [`ProtoBasedErrorCode` enum] and implementations of the
/// following traits:
///
///   * `std::convert::From<ErrorEnum>` for each error enum.
///   * `std::fmt::Display` for [`ProtoBasedErrorCode`].
///   * `std::convert::Into<(i32, i32)>` for [`ProtoBasedErrorCode`].
///
/// This macro accepts a variadic list of dictionaries ({}) as input.
/// Dictionaries MUST respect the following format:
///
/// ```text
///   {
///     kind: KIND,
///     sym: SYM,
///     desc: ESTR,
///     values: [
///        VALUE_SYM => VALUE_STR,
///        …
///     ],
///   },
///   …
/// ```
///
/// The key (`kind`, `sym`, etc.) must be in the right order, defined above.
///
/// `KIND` is the kind of error, as described by the protobuf enum `ErrorKind`.
/// `SYM` is the name of the protobuf enum.
/// `ESTR` is the string description of the error kind.
/// `values` is the list of the enum values, as described by the protobuf enum.
/// `VALUE_SYM` is the enum value symbol.
/// `VALUE_STR` is the string description of the enum value.
macro_rules! GenProtoBasedErrorCode {
    ( $( {kind: $kind:ident, sym: $sym:ident, desc: $desc:expr, values: [$( $vsym:ident => $vstr:expr,)*], },) *) => {
        /// An error code.
        /// An error code holds one of the error described in `errors.proto`
        /// and listed in `ErrorKind`.
        #[derive(Clone,Eq,PartialEq,Debug)]
        pub enum ProtoBasedErrorCode {
            $(
                #[doc=$desc]
                $sym(sandwich_rust_proto::$sym),
            )*
        }

        $(
            /// Implements `[std::convert::From<sandwich_rust_proto::ErrorEnum>]` for [`ProtoBasedErrorCode`].
            impl std::convert::From<sandwich_rust_proto::$sym> for ProtoBasedErrorCode {
                fn from(v: sandwich_rust_proto::$sym) -> Self {
                    Self::$sym(v)
                }
            }

            /// Implements `[std::convert::From<sandwich_rust_proto::ErrorEnum>]` for [`ErrorCode`].
            impl std::convert::From<sandwich_rust_proto::$sym> for ErrorCode {
                fn from(v: sandwich_rust_proto::$sym) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: None
                    }
                }
            }

            /// Instantiates an [`ErrorCode`] from an error enum and a string.
            impl<S> std::convert::From<(sandwich_rust_proto::$sym, &S)> for ErrorCode
                where S: std::convert::AsRef<str>
            {
                fn from((v, s): (sandwich_rust_proto::$sym, &S)) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: Some(s.as_ref().into())
                    }
                }
            }

            /// Instantiates an [`ErrorCode`] from an error enum and a string.
            impl std::convert::From<(sandwich_rust_proto::$sym, &str)> for ErrorCode
            {
                fn from((v, s): (sandwich_rust_proto::$sym, &str)) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: Some(s.into())
                    }
                }
            }

            /// Instantiates an [`ErrorCode`] from an error enum and a [`std::string::String`].
            impl std::convert::From<(sandwich_rust_proto::$sym, std::string::String)> for ErrorCode
            {
                fn from((v, s): (sandwich_rust_proto::$sym, std::string::String)) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: Some(s)
                    }
                }
            }

            /// Adds `ErrorEnum` to the list of [`AllowedProtoBasedErrorCodeEnum`] trait.
            impl AllowedProtoBasedErrorCodeEnum for pb::$sym {}
            impl AllowedProtoBasedErrorCodeEnum for &pb::$sym {}

            /// Implements comparison operator between [`ProtoBasedErrorCode`] and the current error enum.
            impl PartialEq<ProtoBasedErrorCode> for sandwich_rust_proto::$sym {
                fn eq(&self, other: &ProtoBasedErrorCode) -> bool {
                    match other {
                        ProtoBasedErrorCode::$sym(ec) => ec == self,
                        _ => false,
                    }
                }
            }

            /// Implements comparison operator between [`ProtoBasedErrorCode`] and the current error enum.
            impl PartialEq<sandwich_rust_proto::$sym> for ProtoBasedErrorCode {
                fn eq(&self, other: &sandwich_rust_proto::$sym) -> bool {
                    other == self
                }
            }
        )*

        /// Implements `std::convert::Into<sandwich_rust_proto::ErrorKind>` for [`ProtoBasedErrorCode`].
        impl std::convert::From<&ProtoBasedErrorCode> for sandwich_rust_proto::ErrorKind {
            fn from(ec: &ProtoBasedErrorCode) -> Self {
                match ec {
                    $(
                        ProtoBasedErrorCode::$sym(_) => sandwich_rust_proto::ErrorKind::$kind,

                    )*
                }
            }
        }

        /// Implements [`std::fmt::Display`] for [`ProtoBasedErrorCode`].
        impl std::fmt::Display for ProtoBasedErrorCode {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match *self {
                    $(
                        ProtoBasedErrorCode::$sym(e) => write!(f, "{}: {}", $desc, match e {
                            $(
                                sandwich_rust_proto::$sym::$vsym => $vstr,
                            )*
                        }),
                    )*
                }
            }
        }

        /// Implements [`std::convert::Into<(i32, i32)>`] for [`ProtoBasedErrorCode`].
        /// The first `i32` is the error kind, the second one is the error code.
        impl std::convert::From<&ProtoBasedErrorCode> for (i32, i32) {
            fn from(ec: &ProtoBasedErrorCode) -> Self {
                use protobuf::Enum;
                match ec {
                    $(
                        ProtoBasedErrorCode::$sym(e) => (sandwich_rust_proto::ErrorKind::$kind.value(),  e.value()),
                    )*
                }
            }
        }

        #[cfg(test)]
        #[allow(non_snake_case)]
        mod test_symbols {
            use super::{ProtoBasedErrorCode, pb};

            $(
            /// Tests the constructor from an protobuf enum value,
            /// and the soundness of error kind and pair (i32,i32).
            #[test]
            fn $sym() {
                use protobuf::Enum;
                $(
                    let e = ProtoBasedErrorCode::from(pb::$sym::$vsym);
                    assert_eq!(std::convert::Into::<pb::ErrorKind>::into(&e), pb::ErrorKind::$kind);
                    let pair = std::convert::Into::<(i32,i32)>::into(&e);
                    assert_eq!(pair.0, pb::ErrorKind::$kind.value());
                    assert_eq!(pair.1, pb::$sym::$vsym.value());
                    assert_eq!(ProtoBasedErrorCode::from(pb::$sym::$vsym), pb::$sym::$vsym);
                    assert_eq!(pb::$sym::$vsym, ProtoBasedErrorCode::from(pb::$sym::$vsym));
                )*
            }
            )*

        }
    };
}

GenProtoBasedErrorCode!(
    {
        kind: ERRORKIND_API,
        sym: APIError,
        desc: "api error",
        values: [
            APIERROR_CONFIGURATION => "invalid configuration",
            APIERROR_SOCKET => "socket error",
            APIERROR_TUNNEL => "tunnel error",
        ],
    },
    {
        kind: ERRORKIND_CONFIGURATION,
        sym: ConfigurationError,
        desc: "configuration error",
        values: [
            CONFIGURATIONERROR_INVALID_IMPLEMENTATION => "invalid implementation",
            CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "unsupported implementation",
            CONFIGURATIONERROR_INVALID => "invalid configuration",
        ],
    },
    {
        kind: ERRORKIND_TLS_CONFIGURATION,
        sym: TLSConfigurationError,
        desc: "TLS configuration error",
        values: [
            TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "unsupported implementation",
            TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION => "unsupported TLS version",
            TLSCONFIGURATIONERROR_EMPTY => "empty configuration",
            TLSCONFIGURATIONERROR_INVALID_CASE => "invalid oneof case",
            TLSCONFIGURATIONERROR_INVALID => "invalid TLS configuration",
        ],
    },
    {
        kind: ERRORKIND_CERTIFICATE,
        sym: CertificateError,
        desc: "certificate error",
        values: [
            CERTIFICATEERROR_MALFORMED => "certificate malformed",
            CERTIFICATEERROR_EXPIRED => "certificate expired",
            CERTIFICATEERROR_NOT_FOUND => "certificate not found on disk",
            CERTIFICATEERROR_UNKNOWN => "unknown error",
            CERTIFICATEERROR_UNSUPPORTED => "certificate not supported by underlying implementation",
        ],
    },
    {
        kind: ERRORKIND_PRIVATE_KEY,
        sym: PrivateKeyError,
        desc: "private key error",
        values: [
            PRIVATEKEYERROR_MALFORMED => "private key malformed",
            PRIVATEKEYERROR_NOT_FOUND => "private key not found on disk",
            PRIVATEKEYERROR_UNKNOWN => "unknown error",
            PRIVATEKEYERROR_UNSUPPORTED => "private key not supported by underlying implementation",
            PRIVATEKEYERROR_NOT_SERVER => "not a server configuration",
        ],
    },
    {
        kind: ERRORKIND_PROTOBUF,
        sym: ProtobufError,
        desc: "protobuf error",
        values: [
            PROTOBUFERROR_EMPTY => "empty message",
            PROTOBUFERROR_TOO_BIG => "message too large",
            PROTOBUFERROR_PARSE_FAILED => "message parsing failed",
            PROTOBUFERROR_NULLPTR => "null pointer",
        ],
    },
    {
        kind: ERRORKIND_ASN1,
        sym: ASN1Error,
        desc: "ASN.1 error",
        values: [
            ASN1ERROR_INVALID_FORMAT => "invalid format",
            ASN1ERROR_MALFORMED => "ASN.1 or PEM malformed",
        ],
    },
    {
        kind: ERRORKIND_DATA_SOURCE,
        sym: DataSourceError,
        desc: "DataSource error",
        values: [
            DATASOURCEERROR_EMPTY => "empty DataSource",
            DATASOURCEERROR_INVALID_CASE => "invalid oneof case",
            DATASOURCEERROR_NOT_FOUND => "data not found on local filesystem",
        ],
    },
    {
        kind: ERRORKIND_KEM,
        sym: KEMError,
        desc: "KEM error",
        values: [
            KEMERROR_INVALID => "invalid or unsupported KEM",
            KEMERROR_TOO_MANY => "too many KEMs",
        ],
    },
    {
        kind: ERRORKIND_SYSTEM,
        sym: SystemError,
        desc: "system error",
        values: [
            SYSTEMERROR_MEMORY => "memory error",
            SYSTEMERROR_INTEGER_OVERFLOW => "integer overflow",
        ],
    },
    {
        kind: ERRORKIND_SOCKET,
        sym: SocketError,
        desc: "socket error",
        values: [
            SOCKETERROR_BAD_FD => "bad file descriptor",
            SOCKETERROR_CREATION_FAILED => "socket creation failed",
            SOCKETERROR_BAD_NETADDR => "bad network address",
            SOCKETERROR_NETADDR_UNKNOWN => "network address resolution failed",
            SOCKETERROR_FSTAT_FAILED => "fstat failed",
            SOCKETERROR_NOT_SOCK => "not a socket",
            SOCKETERROR_GETSOCKNAME_FAILED => "getsockname failed",
            SOCKETERROR_SETSOCKOPT_FAILED => "setsockopt failed",
            SOCKETERROR_INVALID_AI_FAMILY => "invalid AI family",
        ],
    },
    {
        kind: ERRORKIND_HANDSHAKE,
        sym: HandshakeError,
        desc: "handshake error",
        values: [
            HANDSHAKEERROR_INVALID_SERVER_NAME => "invalid server name",
            HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED => "certificate verification failed",
            HANDSHAKEERROR_CERTIFICATE_EXPIRED => "certificate has expired",
            HANDSHAKEERROR_CERTIFICATE_REVOKED => "certificate was revoked",
            HANDSHAKEERROR_INVALID_CERTIFICATE => "certificate is invalid",
            HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED => "certificate signature verification failed",
            HANDSHAKEERROR_UNKNOWN_ERROR => "unknown handshake error",
        ],
    },
    {
        kind: ERRORKIND_TUNNEL,
        sym: TunnelError,
        desc: "tunnel error",
        values: [
            TUNNELERROR_INVALID => "invalid tunnel configuration",
            TUNNELERROR_VERIFIER => "invalid verifier",
            TUNNELERROR_UNKNOWN => "unknown error",
        ],
    },
);

/// An error code.
/// An error code consists of an error code based on a protobuf enum - [`ProtoBasedErrorCode`]
/// and an arbitrary string.
#[derive(Debug)]
pub struct ErrorCode {
    /// The error code, based on a protobuf enum.
    ec: ProtoBasedErrorCode,

    /// An arbitrary string.
    msg: Option<std::string::String>,
}

/// Implements [`std::borrow::Borrow`] for [`ErrorCode`] and [`ProtoBasedErrorCode`].
impl std::borrow::Borrow<ProtoBasedErrorCode> for ErrorCode {
    fn borrow(&self) -> &ProtoBasedErrorCode {
        &self.ec
    }
}

/// Implements [`std::fmt::Display`] for [`ErrorCode`].
impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ec)?;
        if let Some(msg) = self.msg.as_deref() {
            write!(f, ": {msg}")?;
        }
        Ok(())
    }
}

/// Instantiates an [`ErrorCode`] by consuming a [`ProtoBasedErrorCode`].
impl std::convert::From<ProtoBasedErrorCode> for ErrorCode {
    fn from(ec: ProtoBasedErrorCode) -> Self {
        Self { ec, msg: None }
    }
}

/// Implements [`ErrorCode`].
impl ErrorCode {
    /// Returns the protobuf based error code.
    pub fn code(&self) -> &ProtoBasedErrorCode {
        &self.ec
    }

    /// Compares the protobuf based error code with another.
    pub fn is(&self, pbcode: &impl std::borrow::Borrow<ProtoBasedErrorCode>) -> bool {
        return self.ec == *pbcode.borrow();
    }
}

/// Implements [`std::convert::Into<(i32, i32)>`] for [`ErrorCode`].
/// The first `i32` is the error kind, the second one is the error code.
impl std::convert::From<&ErrorCode> for (i32, i32) {
    fn from(ec: &ErrorCode) -> Self {
        <_ as Into<_>>::into(&ec.ec)
    }
}

impl<S> std::convert::From<(ProtoBasedErrorCode, &S)> for ErrorCode
where
    S: std::convert::AsRef<str>,
{
    fn from((ec, s): (ProtoBasedErrorCode, &S)) -> Self {
        Self {
            ec,
            msg: Some(s.as_ref().into()),
        }
    }
}

/// Instantiates an [`ErrorCode`] by consuming a [`ProtoBasedErrorCode`] and a string.
impl std::convert::From<(ProtoBasedErrorCode, &str)> for ErrorCode {
    fn from((ec, s): (ProtoBasedErrorCode, &str)) -> Self {
        Self {
            ec,
            msg: Some(s.into()),
        }
    }
}

/// Instantiates an [`ErrorCode`] by consuming a [`ProtoBasedErrorCode`] and a string.
impl std::convert::From<(ProtoBasedErrorCode, std::string::String)> for ErrorCode {
    fn from((ec, s): (ProtoBasedErrorCode, std::string::String)) -> Self {
        Self { ec, msg: Some(s) }
    }
}

/// Implements [`ErrorCode`].
impl ErrorCode {
    /// Returns the message, if any.
    pub fn msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

#[cfg(test)]
mod test {
    extern crate sandwich_rust_proto as pb;
    use super::ProtoBasedErrorCode;

    /// Tests trivial copy.
    #[test]
    pub fn test_trivial_copy() {
        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_TUNNEL);
        let _f = e;
    }

    /// Tests comparison between [`ProtoBasedErrorCode`] and a protobuf enum.
    #[test]
    pub fn test_comparison_error_code_proto_enum() {
        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        assert_eq!(e, pb::APIError::APIERROR_SOCKET);
        assert_ne!(e, pb::APIError::APIERROR_CONFIGURATION);
        assert_ne!(e, pb::CertificateError::CERTIFICATEERROR_MALFORMED);
        assert_ne!(e, pb::CertificateError::CERTIFICATEERROR_MALFORMED);
        assert_ne!(pb::CertificateError::CERTIFICATEERROR_MALFORMED, e);
        assert_eq!(pb::APIError::APIERROR_SOCKET, e);
    }

    /// Tests comparison between [`ProtoBasedErrorCode`] and [`ProtoBasedErrorCode`].
    #[test]
    pub fn test_comparison_error_code_error_code() {
        let e0 = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let e1 = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        assert_eq!(e0, e1);
    }

    /// Tests the [`std::fmt::Display`] implementation of `ProtoBasedErrorCode`.
    #[test]
    pub fn test_display_impl_proto_based_error_code() {
        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let s = format!("{}", e);
        assert_eq!(s, "api error: socket error");
    }

    /// Tests the [`std::fmt::Display`] and [`std::fmt::Debug`] implementations of `ErrorCode`.
    #[test]
    pub fn test_display_impl_error_code() {
        let e = super::ErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let s = format!("{}", e);
        assert_eq!(s, "api error: socket error");

        let s = format!("{:?}", e);
        assert_eq!(s, "ErrorCode { ec: APIError(APIERROR_SOCKET), msg: None }");
    }

    /// Tests that [`ErrorCode::code`] returns the correct error code.
    #[test]
    pub fn test_error_code_code_method() {
        let e = super::ErrorCode::from(pb::APIError::APIERROR_SOCKET);
        assert_eq!(
            e.code(),
            &ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET)
        );
    }

    /// Tests the [`ErrorCode`] constructor from a [`ProtoBasedErrorCode`] and
    /// an arbitrary string.
    #[test]
    pub fn test_error_code_constructor_arbitrary_string() {
        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let ec = super::ErrorCode::from((e, "port already in use"));
        assert_eq!(
            ec.code(),
            &ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET)
        );
        assert_eq!(
            format!("{}", ec),
            "api error: socket error: port already in use"
        );
        assert_eq!(ec.msg(), Some("port already in use"));

        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let ec = super::ErrorCode::from((e, "port already in use".to_string()));
        assert_eq!(
            ec.code(),
            &ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET)
        );
        assert_eq!(
            format!("{}", ec),
            "api error: socket error: port already in use"
        );
        assert_eq!(ec.msg(), Some("port already in use"));

        let errstr: std::string::String = "port already in use".into();
        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let ec = super::ErrorCode::from((e, &errstr));
        assert_eq!(
            ec.code(),
            &ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET)
        );
        assert_eq!(
            format!("{}", ec),
            "api error: socket error: port already in use"
        );
        assert_eq!(ec.msg(), Some("port already in use"));
    }
}
