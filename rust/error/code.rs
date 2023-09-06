// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

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
extern crate sandwich_proto as pb;

/// An enum allowed in [`ProtoBasedErrorCode`].
pub(crate) trait AllowedProtoBasedErrorCodeEnum: Copy + Clone + Sized {}

/// Generates the definition of [`ProtoBasedErrorCode` enum] and implementations of the
/// following traits:
///
///   * `From<ErrorEnum>` for each error enum.
///   * `` for [`ProtoBasedErrorCode`].
///   * `Into<(i32, i32)>` for [`ProtoBasedErrorCode`].
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
                $sym(sandwich_proto::$sym),
            )*
        }

        $(
            /// Implements `[From<sandwich_proto::ErrorEnum>]` for [`ProtoBasedErrorCode`].
            impl From<sandwich_proto::$sym> for ProtoBasedErrorCode {
                fn from(v: sandwich_proto::$sym) -> Self {
                    Self::$sym(v)
                }
            }

            /// Implements `[From<sandwich_proto::ErrorEnum>]` for [`ErrorCode`].
            impl From<sandwich_proto::$sym> for ErrorCode {
                fn from(v: sandwich_proto::$sym) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: None
                    }
                }
            }

            /// Instantiates an [`ErrorCode`] from an error enum and a string.
            impl<S> From<(sandwich_proto::$sym, &S)> for ErrorCode
                where S: AsRef<str>
            {
                fn from((v, s): (sandwich_proto::$sym, &S)) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: Some(s.as_ref().into())
                    }
                }
            }

            /// Instantiates an [`ErrorCode`] from an error enum and a string.
            impl From<(sandwich_proto::$sym, &str)> for ErrorCode
            {
                fn from((v, s): (sandwich_proto::$sym, &str)) -> Self {
                    Self{
                        ec: ProtoBasedErrorCode::from(v),
                        msg: Some(s.into())
                    }
                }
            }

            /// Instantiates an [`ErrorCode`] from an error enum and a [`String`].
            impl From<(sandwich_proto::$sym, String)> for ErrorCode
            {
                fn from((v, s): (sandwich_proto::$sym, String)) -> Self {
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
            impl PartialEq<ProtoBasedErrorCode> for sandwich_proto::$sym {
                fn eq(&self, other: &ProtoBasedErrorCode) -> bool {
                    match other {
                        ProtoBasedErrorCode::$sym(ec) => ec == self,
                        _ => false,
                    }
                }
            }

            /// Implements comparison operator between [`ProtoBasedErrorCode`] and the current error enum.
            impl PartialEq<sandwich_proto::$sym> for ProtoBasedErrorCode {
                fn eq(&self, other: &sandwich_proto::$sym) -> bool {
                    other == self
                }
            }
        )*

        /// Implements `Into<sandwich_proto::ErrorKind>` for [`ProtoBasedErrorCode`].
        impl From<&ProtoBasedErrorCode> for sandwich_proto::ErrorKind {
            fn from(ec: &ProtoBasedErrorCode) -> Self {
                match ec {
                    $(
                        ProtoBasedErrorCode::$sym(_) => sandwich_proto::ErrorKind::$kind,

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
                                sandwich_proto::$sym::$vsym => $vstr,
                            )*
                        }),
                    )*
                }
            }
        }

        /// Implements [`TryFrom`] for [`ProtoBasedErrorCode`].
        impl TryFrom<(i32, i32)> for ProtoBasedErrorCode {
            type Error = crate::Error;

            fn try_from((kind, ec): (i32, i32)) -> crate::Result<Self> {
                use protobuf::Enum;

                let kind = sandwich_proto::ErrorKind::from_i32(kind)
                    .ok_or_else::<Self::Error, _>(|| sandwich_proto::ProtobufError::PROTOBUFERROR_INVALID_ARGUMENT.into())?;

                #[allow(unreachable_patterns)]
                match kind {
                    $(
                        sandwich_proto::ErrorKind::$kind => sandwich_proto::$sym::from_i32(ec).map(ProtoBasedErrorCode::from),
                    )*
                    _ => unreachable!(),
                }
                .ok_or_else(|| sandwich_proto::ProtobufError::PROTOBUFERROR_INVALID_ARGUMENT.into())
            }
        }

        /// Implements [`TryFrom`] for [`ErrorCode`]..
        impl TryFrom<(i32, i32)> for ErrorCode {
            type Error = crate::Error;

            fn try_from((kind, ec): (i32, i32)) -> crate::Result<Self> {
                ProtoBasedErrorCode::try_from((kind, ec))
                    .map(Self::from)
            }
        }

        /// Implements [`Into<(i32, i32)>`] for [`ProtoBasedErrorCode`].
        /// The first `i32` is the error kind, the second one is the error code.
        impl From<&ProtoBasedErrorCode> for (i32, i32) {
            fn from(ec: &ProtoBasedErrorCode) -> Self {
                use protobuf::Enum;
                match ec {
                    $(
                        ProtoBasedErrorCode::$sym(e) => (sandwich_proto::ErrorKind::$kind.value(),  e.value()),
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
                    assert_eq!(Into::<pb::ErrorKind>::into(&e), pb::ErrorKind::$kind);
                    let pair = Into::<(i32,i32)>::into(&e);
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

include!("generated_error_codes.rs");

/// An error code.
/// An error code consists of an error code based on a protobuf enum - [`ProtoBasedErrorCode`]
/// and an arbitrary string.
#[derive(Debug)]
pub struct ErrorCode {
    /// The error code, based on a protobuf enum.
    ec: ProtoBasedErrorCode,

    /// An arbitrary string.
    msg: Option<String>,
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
impl From<ProtoBasedErrorCode> for ErrorCode {
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

/// Implements [`Into<(i32, i32)>`] for [`ErrorCode`].
/// The first `i32` is the error kind, the second one is the error code.
impl From<&ErrorCode> for (i32, i32) {
    fn from(ec: &ErrorCode) -> Self {
        <_ as Into<_>>::into(&ec.ec)
    }
}

impl<S> From<(ProtoBasedErrorCode, &S)> for ErrorCode
where
    S: AsRef<str>,
{
    fn from((ec, s): (ProtoBasedErrorCode, &S)) -> Self {
        Self {
            ec,
            msg: Some(s.as_ref().into()),
        }
    }
}

/// Instantiates an [`ErrorCode`] by consuming a [`ProtoBasedErrorCode`] and a string.
impl From<(ProtoBasedErrorCode, &str)> for ErrorCode {
    fn from((ec, s): (ProtoBasedErrorCode, &str)) -> Self {
        Self {
            ec,
            msg: Some(s.into()),
        }
    }
}

/// Instantiates an [`ErrorCode`] by consuming a [`ProtoBasedErrorCode`] and a string.
impl From<(ProtoBasedErrorCode, String)> for ErrorCode {
    fn from((ec, s): (ProtoBasedErrorCode, String)) -> Self {
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
    extern crate sandwich_proto as pb;
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
        assert_eq!(s, "API errors.\n The following errors can occur during a call to the Context API.: Socket error.");
    }

    /// Tests the [`std::fmt::Display`] and [`std::fmt::Debug`] implementations of `ErrorCode`.
    #[test]
    pub fn test_display_impl_error_code() {
        let e = super::ErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let s = format!("{}", e);
        assert_eq!(s, "API errors.\n The following errors can occur during a call to the Context API.: Socket error.");

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
            "API errors.\n The following errors can occur during a call to the Context API.: Socket error.: port already in use"
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
            "API errors.\n The following errors can occur during a call to the Context API.: Socket error.: port already in use"
        );
        assert_eq!(ec.msg(), Some("port already in use"));

        let errstr: String = "port already in use".into();
        let e = ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET);
        let ec = super::ErrorCode::from((e, &errstr));
        assert_eq!(
            ec.code(),
            &ProtoBasedErrorCode::from(pb::APIError::APIERROR_SOCKET)
        );
        assert_eq!(
            format!("{}", ec),
            "API errors.\n The following errors can occur during a call to the Context API.: Socket error.: port already in use"
        );
        assert_eq!(ec.msg(), Some("port already in use"));
    }

    /// Tests the conversion between a pair of integers to a [`ProtoBasedErrorCode`].
    #[test]
    pub fn test_integers_to_protobasederrorcode() {
        ProtoBasedErrorCode::try_from((9999, 9999)).expect_err("must fail");
        let errcode = ProtoBasedErrorCode::try_from((8, 1)).expect("should work");
        assert_eq!(sandwich_proto::ASN1Error::ASN1ERROR_MALFORMED, errcode);
    }
}
