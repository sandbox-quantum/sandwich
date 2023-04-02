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
//!     -> OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
//!       -> OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE
//!         -> CertificateError::CERTIFICATEERROR_MALFORMED
//!           -> ASN1Error::ASN1ERROR_MALFORMED  // The most precise error.
//! ```
//!
//! Error codes that are being used by Sandwich are defined in the [`code`]
//! module.

pub mod code;
pub use code::{ErrorCode, ProtoBasedErrorCode};

/// An error.
/// An [`Error`] holds a chain of [`ProtoBasedErrorCode`].
pub struct Error(std::vec::Vec<ErrorCode>);

/// Instantiates an [`Error`] from an enum value.
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> std::convert::From<ErrorEnum> for Error
where
    ErrorCode: std::convert::From<ErrorEnum>,
{
    fn from(e: ErrorEnum) -> Self {
        Self(vec![ErrorCode::from(e)])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<'s, ErrorEnum: code::AllowedProtoBasedErrorCodeEnum, S> std::convert::From<(ErrorEnum, &'s S)>
    for Error
where
    S: std::convert::AsRef<str> + 's,
    ErrorCode: From<(ErrorEnum, &'s S)>,
{
    fn from((e, s): (ErrorEnum, &'s S)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<'s, ErrorEnum: code::AllowedProtoBasedErrorCodeEnum> std::convert::From<(ErrorEnum, &'s str)>
    for Error
where
    ErrorCode: From<(ErrorEnum, &'s str)>,
{
    fn from((e, s): (ErrorEnum, &'s str)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum>
    std::convert::From<(ErrorEnum, std::string::String)> for Error
where
    ErrorCode: From<(ErrorEnum, std::string::String)>,
{
    fn from((e, s): (ErrorEnum, std::string::String)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an [`ProtoBasedErrorCode`].
impl std::convert::From<ProtoBasedErrorCode> for Error {
    fn from(e: ProtoBasedErrorCode) -> Self {
        Self(vec![ErrorCode::from(e)])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl<S> std::convert::From<(ProtoBasedErrorCode, &S)> for Error
where
    S: std::convert::AsRef<str>,
{
    fn from((e, s): (ProtoBasedErrorCode, &S)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl std::convert::From<(ProtoBasedErrorCode, &str)> for Error {
    fn from((e, s): (ProtoBasedErrorCode, &str)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an enum value and a string.
impl std::convert::From<(ProtoBasedErrorCode, std::string::String)> for Error {
    fn from((e, s): (ProtoBasedErrorCode, std::string::String)) -> Self {
        Self(vec![ErrorCode::from((e, s))])
    }
}

/// Instantiates an [`Error`] from an [`ErrorCode`].
impl std::convert::From<ErrorCode> for Error {
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
    ErrorCode: std::convert::From<ErrorEnum>,
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
    ErrorCode: std::convert::From<(ErrorEnum, &'s S)>,
    S: std::convert::AsRef<str> + 's,
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
    ErrorCode: std::convert::From<(ErrorEnum, &'s str)>,
{
    type Output = Self;

    fn shr(self, (e, s): (ErrorEnum, &'s str)) -> Self::Output {
        let mut n = Self(self.0);
        n.0.push(ErrorCode::from((e, s)));
        n
    }
}

/// Appends an [`Error`] into the chain, using the `>>` operator and a string.
impl<ErrorEnum: code::AllowedProtoBasedErrorCodeEnum>
    std::ops::Shr<(ErrorEnum, std::string::String)> for Error
where
    ErrorCode: std::convert::From<(ErrorEnum, std::string::String)>,
{
    type Output = Self;

    fn shr(self, (e, s): (ErrorEnum, std::string::String)) -> Self::Output {
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
    S: std::convert::AsRef<str>,
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
impl std::ops::Shr<(ProtoBasedErrorCode, std::string::String)> for Error {
    type Output = Self;

    fn shr(self, (e, s): (ProtoBasedErrorCode, std::string::String)) -> Self::Output {
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
        Error(std::vec::Vec::<ErrorCode>::new())
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
    extern crate sandwich_rust_proto as pb;
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
        let p2 = pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE;
        let e = Error::from(p0) >> p1 >> p2;
        assert_eq!(e.len(), 3);

        let mut it = e.iter();
        assert!(it.next().as_ref().unwrap().is(&ErrorCode::from(p0)));
        assert!(it.next().as_ref().unwrap().is(&ErrorCode::from(p1)));
        assert!(it.next().as_ref().unwrap().is(&ErrorCode::from(p2)));
        assert!(matches!(it.next(), None));
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
        assert!(matches!(it.next(), None));
    }
}
