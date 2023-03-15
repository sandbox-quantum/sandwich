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

//! Defines [`ErrorCode`] enum and [`AllowedErrorCodeEnum`] trait.
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
//!
//! Author: thb-sb

extern crate protobuf;
extern crate sandwich_rust_proto as pb;

/// An enum allowed in [`ErrorCode`].
pub(crate) trait AllowedErrorCodeEnum: Copy + Clone + Sized {}

/// Generates the definition of [`ErrorCode` enum] and implementations of the
/// following traits:
///
///   * `std::convert::From<ErrorEnum>` for each error enum.
///   * `std::fmt::Display` for [`ErrorCode`].
///   * `std::convert::Into<(i32, i32)>` for [`ErrorCode`].
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
macro_rules! GenErrorCode {
    ( $( {kind: $kind:ident, sym: $sym:ident, desc: $desc:expr, values: [$( $vsym:ident => $vstr:expr,)*], },) *) => {
        /// An error code.
        /// An error code holds one of the error described in `errors.proto`
        /// and listed in `ErrorKind`.
        #[derive(Clone,Copy,Eq,PartialEq,Debug)]
        pub enum ErrorCode {
            $(
                #[doc=$desc]
                $sym(sandwich_rust_proto::$sym),
            )*
        }

        $(
            /// Implements `[std::convert::From<sandwich_rust_proto::ErrorEnum>]` for [`ErrorCode`].
            impl std::convert::From<sandwich_rust_proto::$sym> for ErrorCode {
                fn from(v: sandwich_rust_proto::$sym) -> Self {
                    Self::$sym(v)
                }
            }

            /// Adds `ErrorEnum` to the list of [`AllowedErrorCodeEnum`] trait.
            impl AllowedErrorCodeEnum for pb::$sym {}
            impl AllowedErrorCodeEnum for &pb::$sym {}

            /// Implements comparison operator between [`ErrorCode`] and the current error enum.
            impl PartialEq<ErrorCode> for sandwich_rust_proto::$sym {
                fn eq(&self, other: &ErrorCode) -> bool {
                    match other {
                        ErrorCode::$sym(ec) => ec == self,
                        _ => false,
                    }
                }
            }

            /// Implements comparison operator between [`ErrorCode`] and the current error enum.
            impl PartialEq<sandwich_rust_proto::$sym> for &ErrorCode {
                fn eq(&self, other: &sandwich_rust_proto::$sym) -> bool {
                    return &other == self
                }
            }
        )*

        /// Implements `std::convert::Into<sandwich_rust_proto::ErrorKind>` for [`ErrorCode`].
        impl std::convert::From<ErrorCode> for sandwich_rust_proto::ErrorKind {
            fn from(ec: ErrorCode) -> Self {
                match ec {
                    $(
                        ErrorCode::$sym(_) => sandwich_rust_proto::ErrorKind::$kind,

                    )*
                }
            }
        }

        /// Implements [`std::fmt::Display`] for [`ErrorCode`].
        impl std::fmt::Display for ErrorCode {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match *self {
                    $(
                        ErrorCode::$sym(e) => write!(f, "{}: {}", $desc, match e {
                            $(
                                sandwich_rust_proto::$sym::$vsym => $vstr,
                            )*
                        }),
                    )*
                }
            }
        }

        /// Implements [`std::convert::Into<(i32, i32)>`] for [`ErrorCode`].
        /// The first `i32` is the error kind, the second one is the error code.
        impl std::convert::From<ErrorCode> for (i32, i32) {
            fn from(ec: ErrorCode) -> Self {
                use protobuf::Enum;
                match ec {
                    $(
                        ErrorCode::$sym(e) => (sandwich_rust_proto::ErrorKind::$kind.value(),  e.value()),
                    )*
                }
            }
        }

        #[cfg(test)]
        #[allow(non_snake_case)]
        mod test_symbols {
            use super::{ErrorCode, pb};

            $(
            /// Tests the constructor from an protobuf enum value,
            /// and the soundness of error kind and pair (i32,i32).
            #[test]
            fn $sym() {
                use protobuf::Enum;
                $(
                    let e = ErrorCode::from(pb::$sym::$vsym);
                    assert_eq!(std::convert::Into::<pb::ErrorKind>::into(e), pb::ErrorKind::$kind);
                    let pair = std::convert::Into::<(i32,i32)>::into(e);
                    assert_eq!(pair.0, pb::ErrorKind::$kind.value());
                    assert_eq!(pair.1, pb::$sym::$vsym.value());
                    assert_eq!(ErrorCode::from(pb::$sym::$vsym), pb::$sym::$vsym);
                    assert_eq!(pb::$sym::$vsym, ErrorCode::from(pb::$sym::$vsym));
                )*
            }
            )*

        }
    };
}

GenErrorCode!(
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
        kind: ERRORKIND_OPENSSL_CONFIGURATION,
        sym: OpenSSLConfigurationError,
        desc: "OpenSSL configuration error",
        values: [
            OPENSSLCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION => "unsupported implementation",
            OPENSSLCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION => "unsupported TLS version",
            OPENSSLCONFIGURATIONERROR_EMPTY => "empty configuration",
            OPENSSLCONFIGURATIONERROR_INVALID_CASE => "invalid oneof case",
            OPENSSLCONFIGURATIONERROR_INVALID => "invalid OpenSSL configuration",
        ],
    },
    {
        kind: ERRORKIND_OPENSSL_CLIENT_CONFIGURATION,
        sym: OpenSSLClientConfigurationError,
        desc: "OpenSSL client configuration error",
        values: [
            OPENSSLCLIENTCONFIGURATIONERROR_EMPTY => "empty configuration",
            OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE => "certificate error",
            OPENSSLCLIENTCONFIGURATIONERROR_SSL_CTX_FAILED => "SSL_CTX* creation failed",
            OPENSSLCLIENTCONFIGURATIONERROR_KEM => "KEM error",
            OPENSSLCLIENTCONFIGURATIONERROR_FLAGS => "flags error",
            OPENSSLCLIENTCONFIGURATIONERROR_SSL_FAILED => "SSL* creation failed",
            OPENSSLCLIENTCONFIGURATIONERROR_BIO_FAILED => "BIO* creation failed",
        ],
    },
    {
        kind: ERRORKIND_OPENSSL_SERVER_CONFIGURATION,
        sym: OpenSSLServerConfigurationError,
        desc: "OpenSSL server configuration error",
        values: [
            OPENSSLSERVERCONFIGURATIONERROR_EMPTY => "empty configuration",
            OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE => "certificate error",
            OPENSSLSERVERCONFIGURATIONERROR_SSL_CTX_FAILED => "SSL_CTX* creation failed",
            OPENSSLSERVERCONFIGURATIONERROR_KEM => "KEM error",
            OPENSSLSERVERCONFIGURATIONERROR_FLAGS => "flags error",
            OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY => "private key error",
            OPENSSLSERVERCONFIGURATIONERROR_SSL_FAILED => "SSL* creation failed",
            OPENSSLSERVERCONFIGURATIONERROR_BIO_FAILED => "BIO* creation failed",
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
);

impl<T: AllowedErrorCodeEnum> PartialEq<T> for ErrorCode
where
    T: AllowedErrorCodeEnum,
    ErrorCode: From<T>,
{
    fn eq(&self, other: &T) -> bool {
        *self == ErrorCode::from(*other)
    }
}

impl PartialEq<&ErrorCode> for ErrorCode {
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}

impl PartialEq<ErrorCode> for &ErrorCode {
    fn eq(&self, other: &ErrorCode) -> bool {
        **self == *other
    }
}

#[cfg(test)]
mod test {
    extern crate sandwich_rust_proto as pb;
    use super::ErrorCode;

    /// Tests trivial copy.
    #[test]
    pub fn test_trivial_copy() {
        let e = ErrorCode::from(pb::APIError::APIERROR_TUNNEL);
        let _f = e;
    }

    /// Tests comparison between [`ErrorCode`] and a protobuf enum.
    #[test]
    pub fn test_comparison_error_code_proto_enum() {
        let e = ErrorCode::from(pb::APIError::APIERROR_SOCKET);
        assert_eq!(e, pb::APIError::APIERROR_SOCKET);
        assert_ne!(e, pb::APIError::APIERROR_CONFIGURATION);
        assert_ne!(e, pb::CertificateError::CERTIFICATEERROR_MALFORMED);
        assert_ne!(&e, pb::CertificateError::CERTIFICATEERROR_MALFORMED);
        assert_ne!(pb::CertificateError::CERTIFICATEERROR_MALFORMED, e);
        assert_eq!(pb::APIError::APIERROR_SOCKET, e);
    }

    /// Tests comparison between [`ErrorCode`] and [`ErrorCode`].
    #[test]
    pub fn test_comparison_error_code_error_code() {
        let e0 = ErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let e1 = e0;
        assert_eq!(e0, e1);
        assert_eq!(e0, &e1);
        assert_eq!(&e0, e1);
        assert_eq!(&e0, &e1);
    }
}
