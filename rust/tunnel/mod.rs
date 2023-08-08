// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`Tunnel`] trait.
//!
//! This module defines the trait [`Tunnel`].
//!
//! A Tunnel is created from a Sandwich context. See [`crate::tunnel::Context`] for more
//! information.

pub(crate) use context::Mode;
pub use context::{try_from as context_try_from, Context, TunnelResult};

mod context;

#[cfg(feature = "ffi")]
mod ffi;

/// Structure for states and errors based on protobuf definitions.
pub struct ProtoStateErrorBase<Enum: protobuf::Enum>(Enum, Option<crate::Error>);

/// Implements [`std::cmp::PartialEq`] with Enum for [`ProtoStateErrorBase`].
impl<Enum: protobuf::Enum> std::cmp::PartialEq<Enum> for ProtoStateErrorBase<Enum> {
    fn eq(&self, other: &Enum) -> bool {
        self.0 == *other
    }
}

/// Implements [`std::fmt::Debug`] for [`ProtoStateErrorBase`].
impl<Enum: protobuf::Enum> std::fmt::Debug for ProtoStateErrorBase<Enum>
where
    Self: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} (code {})", self, self.0.value())
    }
}

/// Converts a [`ProtoStateErrorBase`] to a [`crate::Error`].
impl<Enum: protobuf::Enum> From<ProtoStateErrorBase<Enum>> for crate::Error {
    fn from(e: ProtoStateErrorBase<Enum>) -> crate::Error {
        e.1.unwrap()
    }
}

/// Converts an enum value to a [`ProtoStateErrorBase`].
impl<Enum: protobuf::Enum> From<Enum> for ProtoStateErrorBase<Enum> {
    fn from(e: Enum) -> Self {
        Self(e, None)
    }
}

/// Converts an enum value and a [`crate::Error`] to a [`ProtoStateErrorBase`].
impl<Enum: protobuf::Enum> From<(Enum, crate::Error)> for ProtoStateErrorBase<Enum> {
    fn from(p: (Enum, crate::Error)) -> Self {
        Self(p.0, Some(p.1))
    }
}

/// Implements [`ProtoStateErrorBase`].
impl<Enum: protobuf::Enum> ProtoStateErrorBase<Enum> {
    /// Returns true if an error occurred.
    pub fn is_err(&self) -> bool {
        self.1.is_some()
    }

    /// Returns the enum value.
    pub fn value(&self) -> Enum {
        self.0
    }
}

/// The state of a tunnel.
pub type State = ProtoStateErrorBase<pb::State>;

/// Implements [`std::fmt::Display`] for [`State`].
impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.0 {
                pb::State::STATE_NOT_CONNECTED => "not connected",
                pb::State::STATE_CONNECTION_IN_PROGRESS => "connection in progress",
                pb::State::STATE_HANDSHAKE_IN_PROGRESS => "handshake in progress",
                pb::State::STATE_HANDSHAKE_DONE => "handshake done",
                pb::State::STATE_BEING_SHUTDOWN => "being shutdown",
                pb::State::STATE_DISCONNECTED => "disconnected",
                pb::State::STATE_ERROR => "error",
            }
        )
    }
}

/// The state of an handshake operation.
pub type HandshakeState = ProtoStateErrorBase<pb::HandshakeState>;

/// Implements [`std::fmt::Display`] for [`HandshakeState`].
impl std::fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.0 {
                pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS => "in progress",
                pb::HandshakeState::HANDSHAKESTATE_DONE => "done",
                pb::HandshakeState::HANDSHAKESTATE_WANT_READ => "wants to read",
                pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE => "wants to write",
                pb::HandshakeState::HANDSHAKESTATE_ERROR => "error",
            }
        )
    }
}

/// A handshake error.
/// A handshake error can occur during the cryptography handshake
pub type HandshakeError = ProtoStateErrorBase<pb::HandshakeError>;

/// Implements [`std::fmt::Display`] for [`HandshakeError`].
impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.0 {
                pb::HandshakeError::HANDSHAKEERROR_INVALID_SERVER_NAME => "invalid server name",
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED =>
                    "certificate verification failed",
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED => "certificate has expired",
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_REVOKED => "certificate was revoked",
                pb::HandshakeError::HANDSHAKEERROR_INVALID_CERTIFICATE => "invalid certificate",
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED =>
                    "certificate signature verification failed",
                pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR => "unknown handshake error",
            }
        )
    }
}

/// A record error.
/// A record error may occur during a record plane operation: read and write.
pub type RecordError = ProtoStateErrorBase<pb::RecordError>;

/// Implements [`std::fmt::Display`] for [`RecordError`].
impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.0 {
                pb::RecordError::RECORDERROR_OK => "no error",
                pb::RecordError::RECORDERROR_WANT_READ => "want read",
                pb::RecordError::RECORDERROR_WANT_WRITE => "want write",
                pb::RecordError::RECORDERROR_BEING_SHUTDOWN => "being shutdown",
                pb::RecordError::RECORDERROR_CLOSED => "closed",
                pb::RecordError::RECORDERROR_TOO_BIG => "too big",
                pb::RecordError::RECORDERROR_UNKNOWN => "unknown error",
            }
        )
    }
}

/// A record result.
/// A record result is either an amount of bytes read or written, nothing
/// or a record error.
pub type RecordResult<T> = Result<T, RecordError>;

/// A tunnel.
/// A tunnel is tied with a Context, using the 'ctx lifetime.
/// A tunnel is also tied with an I/O interface.
pub trait Tunnel<'io: 'ctx, 'ctx>: Send {
    /// Returns the state of the tunnel.
    fn state(&self) -> State;

    /// Performs the handshake.
    ///
    /// Depending on the return value, this method may need to be called
    /// more than once.
    fn handshake(&mut self) -> crate::Result<HandshakeState>;

    /// Writes data to the tunnel.
    fn write(&mut self, buf: &[u8]) -> RecordResult<usize>;

    /// Reads data from the tunnel.
    fn read(&mut self, buf: &mut [u8]) -> RecordResult<usize>;

    /// Closes the tunnel.
    fn close(&mut self) -> RecordResult<()>;
}

/// Implements [`std::fmt::Debug`] for [`Tunnel`].
impl std::fmt::Debug for dyn Tunnel<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Tunnel")
    }
}

#[cfg(test)]
mod test {
    use super::State;

    /// Tests [`ProtoStateErrorBase`].
    #[test]
    fn test_state() {
        let s = State::from(pb::State::STATE_DISCONNECTED);
        assert!(!s.is_err());
        assert_eq!(s, pb::State::STATE_DISCONNECTED);
    }

    /// Tests [`ProtoStateErrorBase`] with an error.
    #[test]
    fn test_state_error() {
        let s = State::from((
            pb::State::STATE_DISCONNECTED,
            errors! {pb::APIError::APIERROR_SOCKET},
        ));
        assert!(s.is_err());
        assert_eq!(s, pb::State::STATE_DISCONNECTED);
        let e: crate::Error = s.into();
        assert!(e.is(&errors! {pb::APIError::APIERROR_SOCKET}));
    }
}

#[cfg(any(feature = "openssl1_1_1", feature = "boringssl"))]
pub(crate) mod tls;
