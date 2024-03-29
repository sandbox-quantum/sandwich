// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Error`] struct and [`ProtoBasedErrorCode`] enum.
//!
//! When an error occurred in Sandwich, an [`Error`] is returned, usually
//! through the Sandwich [`crate::Result`]. An [`Error`] is a chain
//! of [`ProtoBasedErrorCode`], where the first element of the chain is the most general
//! error, and the last element is the most precise error.
//!
//! For instance, a TLS configuration specifying a malformed ASN.1 certificate
//! results in the following error:
//!
//! ```text
//! APIError::APIERROR_CONFIGURATION   // The most global error.
//!   -> ConfigurationError::CONFIGURATIONERROR_INVALID
//!     -> TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID
//!       -> CertificateError::CERTIFICATEERROR_MALFORMED
//!         -> ASN1Error::ASN1ERROR_MALFORMED  // The most precise error.
//! ```
//!
//! Error codes that are being used by Sandwich are defined in the [`code`]
//! module.

pub use code::{ErrorCode, ProtoBasedErrorCode};

mod code;

/// An error.
/// An [`Error`] holds a chain of [`ProtoBasedErrorCode`].
pub struct Error(Vec<ErrorCode>);

/// Instantiates an [`Error`] from an enum value.
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> From<ErrorEnum> for Error
where
    ErrorCode: From<ErrorEnum>,
{
    fn from(e: ErrorEnum) -> Self {
        Self(vec![ErrorCode::from(e)])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<'s, ErrorEnum: code::AllowedProtoBasedErrorCodeEnum, S> From<(ErrorEnum, &'s S)> for Error
where
    S: AsRef<str> + 's,
    ErrorCode: From<(ErrorEnum, &'s S)>,
{
    fn from((e, s): (ErrorEnum, &'s S)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<'s, ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> From<(ErrorEnum, &'s str)> for Error
where
    ErrorCode: From<(ErrorEnum, &'s str)>,
{
    fn from((e, s): (ErrorEnum, &'s str)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> From<(ErrorEnum, String)> for Error
where
    ErrorCode: From<(ErrorEnum, String)>,
{
    fn from((e, s): (ErrorEnum, String)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an [`ProtoBasedErrorCode`].
impl From<ProtoBasedErrorCode> for Error {
    fn from(e: ProtoBasedErrorCode) -> Self {
        Self(vec![ErrorCode::from(e)])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<S> From<(ProtoBasedErrorCode, &S)> for Error
where
    S: AsRef<str>,
{
    fn from((e, s): (ProtoBasedErrorCode, &S)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl From<(ProtoBasedErrorCode, &str)> for Error {
    fn from((e, s): (ProtoBasedErrorCode, &str)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl From<(ProtoBasedErrorCode, String)> for Error {
    fn from((e, s): (ProtoBasedErrorCode, String)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an [`ErrorCode`].
impl From<ErrorCode> for Error {
    fn from(e: ErrorCode) -> Self {
        Self(vec![e])
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator.
///
/// The `>>` operator is used to easily build a chain of error:
/// `child_error -> parent_error`, where `child_error` is more precise than
/// `parent_error`.
///
/// # Example
///
/// ```
///   // Creates a new Error.
///   let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
///   // Creates a new Error, "invalid certificate", and appends the previous one.
///   let e = e >> pb::CertificateError::CERTIFICATEERROR_MALFORMED;
///
///   // Now, the error chain is the following:
///   // CertificateError::CERTIFICATEERROR_MALFORMED -> ASN1Error>>ASN1ERROR_INVALID_FORMAT
///   // It is read as "a certificate error occurred: malformed certificate,
///   // because: an ASN.1 error occurred: invalid format".
/// ```
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> std::ops::Shr<ErrorEnum> for Error
where
    ErrorCode: From<ErrorEnum>,
{
    type Output = Self;

    fn shr(self, e: ErrorEnum) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from(e));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator and a string.
impl<'s, ErrorEnum: code::AllowedProtoBasedErrorCodeEnum, S> std::ops::Shr<(ErrorEnum, &'s S)>
    for Error
where
    ErrorCode: From<(ErrorEnum, &'s S)>,
    S: AsRef<str> + 's,
{
    type Output = Self;

    fn shr(self, (e, s): (ErrorEnum, &'s S)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator and a string.
impl<'s, ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> std::ops::Shr<(ErrorEnum, &'s str)>
    for Error
where
    ErrorCode: From<(ErrorEnum, &'s str)>,
{
    type Output = Self;

    fn shr(self, (e, s): (ErrorEnum, &'s str)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator and a string.
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> std::ops::Shr<(ErrorEnum, String)> for Error
where
    ErrorCode: From<(ErrorEnum, String)>,
{
    type Output = Self;

    fn shr(self, (e, s): (ErrorEnum, String)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator.
impl std::ops::Shr<ProtoBasedErrorCode> for Error {
    type Output = Self;

    fn shr(self, e: ProtoBasedErrorCode) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from(e));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator and a string.
impl<S> std::ops::Shr<(ProtoBasedErrorCode, &S)> for Error
where
    S: AsRef<str>,
{
    type Output = Self;

    fn shr(self, (e, s): (ProtoBasedErrorCode, &S)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator and a string.
impl std::ops::Shr<(ProtoBasedErrorCode, &str)> for Error {
    type Output = Self;

    fn shr(self, (e, s): (ProtoBasedErrorCode, &str)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator.
impl std::ops::Shr<(ProtoBasedErrorCode, String)> for Error {
    type Output = Self;

    fn shr(self, (e, s): (ProtoBasedErrorCode, String)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator.
impl std::ops::Shr<ErrorCode> for Error {
    type Output = Self;

    fn shr(self, e: ErrorCode) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(e);
        n
    }
}

/// Implements [`std::fmt::Display`] for [`Error`].
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for e in self.0.iter() {
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

/// Implements [`std::fmt::Debug`] for [`Error`].
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            for _ in 0..i {
                write!(f, "\t")?;
            }
            writeln!(f, "~>#{i}: {e}")?;
        }
        Ok(())
    }
}

/// Implements [`std::error::Error`] for [`Error`].
impl std::error::Error for Error {}

/// Wrap two error enums to produce an [`Error`].
///
/// # Example
///
/// ```
/// let e = errors!{pb::ASN1Error::ASN1ERROR_INVALID_FORMAT => pb::CertificateError::CERTIFICATEERROR_MALFORMED};
/// ```
macro_rules! errors{
    { $( $e:expr ) => * } => {
        crate::Error::new()
        $(
            >> $e
        )*
    };
}

/// Unwrap a result, or return an new Error from a protobuf error enum.
///
/// This macro is used to unwrap and return a value, or to return a new
/// error chained with the one from the [`crate::Result`] enum.
///
/// # Example
///
/// ```
///     // `parse_asn1_certificate` may return an error of type `ASN1Error`.
///     // If so, returns the chain `pb::CertificateError::CERTIFICATEERROR_MALFORMED -> ASN1Error`.
///     unwrap_or!(ctx.parse_asn1_certificate(&cert), pb::CertificateError::CERTIFICATEERROR_MALFORMED);
/// ```
#[allow(unused_macros)]
macro_rules! unwrap_or {
    ( $res:expr, $err:expr ) => {
        match $res {
            Ok(o) => o,
            Err(e) => Err(e >> $err)?,
        }
    };
}

/// Implements [`Error`].
impl Error {
    /// Instantiates an empty [`Error`].
    pub(crate) fn new() -> Error {
        Error(Vec::<ErrorCode>::new())
    }
    /// Returns an iterator over the [`ProtoBasedErrorCode`] from the chain.
    pub fn iter(&self) -> std::slice::Iter<ErrorCode> {
        self.0.iter()
    }

    /// Returns the length of the chain.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the emptiness of the chain.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Verifies that two [`Error`] share the same protobuf based error codes.
    pub fn is(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        for (i, ec) in self.0.iter().enumerate() {
            if !ec.is(&other.0[i]) {
                return false;
            }
        }
        true
    }
}

/// Implements operator>> between two [`ErrorCode`] to produce
/// an [`Error`].
impl std::ops::Shr<ErrorCode> for ErrorCode {
    type Output = Error;

    fn shr(self, e: ErrorCode) -> Self::Output {
        Error(vec![self, e])
    }
}

#[cfg(test)]
mod test {
    extern crate sandwich_proto as pb;
    use super::{Error, ErrorCode, ProtoBasedErrorCode};

    /// Tests the constructor of [`Error`] from an error enum.
    #[test]
    fn test_constructor_from_error_enum() {
        let e = Error::from(pb::APIError::APIERROR_SOCKET);
        assert_eq!(e.len(), 1);
    }

    /// Tests the constructor of [`Error`] from an [`ProtoBasedErrorCode`].
    #[test]
    fn test_constructor_from_error_code() {
        let e = ProtoBasedErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let e = Error::from(e);
        assert_eq!(e.len(), 1);
    }

    /// Tests the `>>` operator with an error enum.
    #[test]
    fn test_operator_shr_from_error_enum() {
        let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let f = e >> pb::CertificateError::CERTIFICATEERROR_MALFORMED;
        assert_eq!(f.len(), 2);
    }

    /// Tests the `>>` operator with an error enum and a string.
    #[test]
    fn test_operator_shr_from_error_enum_and_string() {
        let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let f = e >> (pb::CertificateError::CERTIFICATEERROR_MALFORMED, &"bla");
        assert_eq!(f.len(), 2);
    }

    /// Tests the `>>` operator with an error enum and a as ref string.
    #[test]
    fn test_operator_shr_from_error_enum_and_as_ref_string() {
        let msg = "msg".to_string();
        let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let f = e >> (pb::CertificateError::CERTIFICATEERROR_MALFORMED, &msg);
        assert_eq!(f.len(), 2);
    }

    /// Tests the `>>` operator with an error enum and a moved string.
    #[test]
    fn test_operator_shr_from_error_enum_and_moved_string() {
        let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let i = 32i32;
        let f = e
            >> (
                pb::CertificateError::CERTIFICATEERROR_MALFORMED,
                format!("msg {i}"),
            );
        assert_eq!(f.len(), 2);
    }

    /// Tests the `>>` operator with an error enum and a &str.
    #[test]
    fn test_operator_shr_from_error_enum_and_str() {
        let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let f = e
            >> (
                pb::CertificateError::CERTIFICATEERROR_MALFORMED,
                "error cert",
            );
        assert_eq!(f.len(), 2);
    }

    /// Tests the `>>` operator with an error code.
    #[test]
    fn test_operator_shr_from_error_code() {
        let e = Error::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)
            >> ProtoBasedErrorCode::from(pb::CertificateError::CERTIFICATEERROR_MALFORMED);
        assert_eq!(e.len(), 2);
    }

    /// Tests the order of the [`ProtoBasedErrorCode`] inside an [`Error`].
    #[test]
    fn test_error_code_order() {
        let p0 = pb::ASN1Error::ASN1ERROR_INVALID_FORMAT;
        let p1 = pb::CertificateError::CERTIFICATEERROR_MALFORMED;
        let p2 = pb::TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID;
        let e = Error::from(p0) >> p1 >> p2;
        assert_eq!(e.len(), 3);

        let mut it = e.iter();
        assert!(it.next().as_ref().unwrap().is(&ErrorCode::from(p0)));
        assert!(it.next().as_ref().unwrap().is(&ErrorCode::from(p1)));
        assert!(it.next().as_ref().unwrap().is(&ErrorCode::from(p2)));
        assert!(it.next().is_none());
    }

    /// Tests macro errors.
    #[test]
    fn test_macro_errors() {
        let e = errors! {pb::ASN1Error::ASN1ERROR_INVALID_FORMAT => pb::CertificateError::CERTIFICATEERROR_MALFORMED};
        assert_eq!(e.len(), 2);
        let mut it = e.iter();
        it.next()
            .as_ref()
            .unwrap()
            .is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT));
        it.next().as_ref().unwrap().is(&ErrorCode::from(
            pb::CertificateError::CERTIFICATEERROR_MALFORMED,
        ));
        assert!(it.next().is_none());
    }

    /// Tests the [`Error`] constructor from an enum value and a string.
    #[test]
    fn test_error_constructor_with_enum_and_string() {
        let e = Error::from((pb::ASN1Error::ASN1ERROR_INVALID_FORMAT, "invalid tag"));
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));

        let e = Error::from((
            pb::ASN1Error::ASN1ERROR_INVALID_FORMAT,
            "invalid tag".to_string(),
        ));
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));

        let msg: String = "invalid tag".into();
        let e = Error::from((pb::ASN1Error::ASN1ERROR_INVALID_FORMAT, &msg));
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));
    }

    /// Tests the [`Error`] constructor from a [`ProtoBasedErrorCode`] and a string.
    #[test]
    fn test_error_constructor_with_proto_based_error_code_and_string() {
        let e = Error::from((
            ProtoBasedErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT),
            "invalid tag",
        ));
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));

        let e = Error::from((
            ProtoBasedErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT),
            "invalid tag".to_string(),
        ));
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));

        let msg: String = "invalid tag".into();
        let e = Error::from((
            ProtoBasedErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT),
            &msg,
        ));
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));
    }

    /// Tests the [`Error`] constructor from a [`ErrorCode`].
    #[test]
    fn test_error_constructor_with_an_error_code() {
        let ec = ErrorCode::from((pb::ASN1Error::ASN1ERROR_INVALID_FORMAT, "invalid tag"));
        let e: Error = ec.into();
        assert_eq!(e.len(), 1);
        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), Some("invalid tag"));
    }

    /// Tests the [`Error`] shr operation with a [`ProtoBasedErrorCode`] and a string.
    #[test]
    fn test_error_shr_proto_based_error_code_and_string() {
        let e: Error = pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into();
        let e = e
            >> (
                ProtoBasedErrorCode::from(pb::CertificateError::CERTIFICATEERROR_MALFORMED),
                "cert err",
            );
        assert_eq!(e.len(), 2);

        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), None);

        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(
            pb::CertificateError::CERTIFICATEERROR_MALFORMED
        )));
        assert_eq!(ec.msg(), Some("cert err"));

        let e: Error = pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into();
        let e = e
            >> (
                ProtoBasedErrorCode::from(pb::CertificateError::CERTIFICATEERROR_MALFORMED),
                "cert err".to_string(),
            );
        assert_eq!(e.len(), 2);

        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), None);

        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(
            pb::CertificateError::CERTIFICATEERROR_MALFORMED
        )));
        assert_eq!(ec.msg(), Some("cert err"));

        let msg: String = "cert err".into();
        let e: Error = pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into();
        let e = e
            >> (
                ProtoBasedErrorCode::from(pb::CertificateError::CERTIFICATEERROR_MALFORMED),
                &msg,
            );
        assert_eq!(e.len(), 2);

        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), None);

        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(
            pb::CertificateError::CERTIFICATEERROR_MALFORMED
        )));
        assert_eq!(ec.msg(), Some("cert err"));
    }

    /// Tests the [`Error`] shr operation with an [`ErrorCode`].
    #[test]
    fn test_error_shr_error_code() {
        let e: Error = pb::ASN1Error::ASN1ERROR_INVALID_FORMAT.into();
        let e = e >> ErrorCode::from(pb::CertificateError::CERTIFICATEERROR_MALFORMED);
        assert_eq!(e.len(), 2);

        let mut it = e.iter();
        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT)));
        assert_eq!(ec.msg(), None);

        let ec = it.next().expect("expected an error code");
        assert!(ec.is(&ErrorCode::from(
            pb::CertificateError::CERTIFICATEERROR_MALFORMED
        )));
        assert_eq!(ec.msg(), None);
    }

    /// Tests the [`ErrorCode`] shr operation with another [`ErrorCode`].
    #[test]
    fn test_error_code_shr_error_code() {
        let e1 = ErrorCode::from(pb::ASN1Error::ASN1ERROR_INVALID_FORMAT);
        let e2 = ErrorCode::from(pb::CertificateError::CERTIFICATEERROR_MALFORMED);

        let e = e1 >> e2;
        assert!(e.is(&errors!{ pb::ASN1Error::ASN1ERROR_INVALID_FORMAT => pb::CertificateError::CERTIFICATEERROR_MALFORMED}));
    }

    /// Tests the [`std::fmt::Display`] and [`std::fmt::Debug`] implementation for [`Error`].
    #[test]
    fn test_error_fmt_display_debug_impl() {
        let e = errors! {pb::ASN1Error::ASN1ERROR_INVALID_FORMAT => pb::CertificateError::CERTIFICATEERROR_MALFORMED};
        assert_eq!(
            format!("{e}"),
            "ASN.1 errors.: Invalid format.Certificate errors.: Malformed certificate."
        );
        assert_eq!(
            format!("{e:?}"),
            "~>#0: ASN.1 errors.: Invalid format.\n\t~>#1: Certificate errors.: Malformed certificate.\n"
        );
    }

    /// Tests the `is_empty` method of a chain.
    #[test]
    fn test_error_emptiness() {
        let e: Error = Error::new();
        assert!(e.is_empty());
        let e = e >> pb::ASN1Error::ASN1ERROR_INVALID_FORMAT;
        assert!(!e.is_empty());
    }
}
