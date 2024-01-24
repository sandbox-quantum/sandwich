// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Wrapper around the SSL object for OpenSSL 3 tunnels.

use std::ffi::{c_int, c_void, CString};
use std::pin::Pin;
use std::ptr::NonNull;

use crate::support::Pimpl;
use crate::tunnel::tls::{self, VerifierSanitizer};
use crate::Result;

use crate::ossl3::error::{Error, ErrorLibrary, SslError};
use crate::ossl3::support;

use support::{NativeBio, NativeSsl};

use super::{Context, X509VerifyParam, BIO_METHOD};

/// Index in the SSL user data (`SSL_get_ex_data`/`SSL_set_ex_data`) where
/// the pointer to the tunnel security requirements is stored.
const SSL_EX_DATA_TUNNEL_SECURITY_REQUIREMENTS_INDEX: c_int = 1;

/// Wrapper of the OpenSSL SSL object.
pub(super) struct Ssl(NonNull<NativeSsl>);

impl std::fmt::Debug for Ssl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL3SSLObject({:p})", self.0)
    }
}

impl From<NonNull<NativeSsl>> for Ssl {
    fn from(ssl: NonNull<NativeSsl>) -> Self {
        Self(ssl)
    }
}

impl Ssl {
    /// Returns a pointer to some extra data from a SSL object.
    fn get_extra_data_ptr<T>(&self, extra_data_index: impl Into<c_int>) -> Option<NonNull<T>> {
        NonNull::new(
            unsafe { openssl3::SSL_get_ex_data(self.0.as_ptr(), extra_data_index.into()) }
                .cast::<T>(),
        )
    }

    /// Returns a reference to some extra data from a SSL object.
    fn get_extra_data_ref<'a, T>(&self, extra_data_index: impl Into<c_int>) -> Option<&'a T> {
        self.get_extra_data_ptr::<T>(extra_data_index)
            .map(|ptr| unsafe { ptr.as_ref() })
    }

    /// Returns the last recorded error.
    fn get_last_recorded_error(
        &self,
        ret: impl Into<c_int>,
    ) -> std::result::Result<SslError, c_int> {
        let err = unsafe { openssl3::SSL_get_error(self.0.as_ref(), ret.into()) };
        SslError::try_from(err).map_err(|_| err)
    }

    /// Returns the tunnel security requirements from a SSL object.
    pub(super) fn get_tunnel_security_requirements<'a>(
        &self,
    ) -> Option<&'a tls::TunnelSecurityRequirements> {
        self.get_extra_data_ref::<tls::TunnelSecurityRequirements>(
            SSL_EX_DATA_TUNNEL_SECURITY_REQUIREMENTS_INDEX,
        )
    }

    /// Sets the required Subject Alternative Names (SAN) specified in the [`pb_api::TunnelVerifier`]
    /// object.
    fn set_subject_alternative_names(
        &self,
        tunnel_verifier: Option<&pb_api::TunnelVerifier>,
    ) -> Result<()> {
        let Some(pb_api::verifiers::tunnel_verifier::Verifier::SanVerifier(san_verifier)) =
            tunnel_verifier.and_then(|tv| tv.verifier.as_ref())
        else {
            return Ok(());
        };
        let x509_verify_param = X509VerifyParam::try_from(self.0)?;
        for san in san_verifier.alt_names.iter() {
            let Some(san) = san.san.as_ref() else {
                return Err((pb::TunnelError::TUNNELERROR_VERIFIER, "empty SANMatcher").into());
            };
            x509_verify_param.add_san(san)?;
        }
        Ok(())
    }

    /// Sets the server name indication (SNI).
    fn set_server_name_indication(&self, sni: impl AsRef<str>) -> Result<()> {
        let sni = sni.as_ref();
        if sni.is_empty() {
            return Ok(());
        }
        let cstring = CString::new(sni).map_err(|e| {
            (
                pb::SystemError::SYSTEMERROR_MEMORY,
                format!("failed to create a c-string for the SNI '{sni}': {e}"),
            )
        })?;
        // `SSL_set_tlsext_host_name` is a C macro.
        if unsafe {
            openssl3::SSL_ctrl(
                self.0.as_ptr(),
                openssl3::SSL_CTRL_SET_TLSEXT_HOSTNAME as c_int,
                openssl3::TLSEXT_NAMETYPE_host_name as i64,
                cstring.as_ptr().cast::<c_void>().cast_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::TunnelError::TUNNELERROR_VERIFIER,
                format!("failed to set the SNI to '{sni}': {}", support::errstr()),
            )
                .into())
        }
    }

    /// Creates a new Sandwich BIO and attach it to the SSL object.
    fn create_and_attach_bio(&self) -> Result<()> {
        let bio = support::new_BIO(BIO_METHOD)?;
        let ptr = bio.as_nonnull().as_ptr();
        unsafe {
            openssl3::BIO_set_init(ptr, 1);
            openssl3::SSL_set_bio(self.0.as_ptr(), ptr, ptr);
        }
        let _ = bio.into_raw();
        Ok(())
    }

    /// Returns a pointer to the BIO currently attached to the SSL object.
    fn get_attached_bio(&self) -> Option<NonNull<NativeBio>> {
        NonNull::new(unsafe { openssl3::SSL_get_rbio(self.0.as_ptr()) })
    }

    /// Returns the state of the SSL tunnel.
    fn get_state(&self) -> pb::HandshakeState {
        if unsafe { openssl3::SSL_get_state(self.0.as_ptr()) }
            == openssl3::OSSL_HANDSHAKE_STATE_TLS_ST_OK
        {
            pb::HandshakeState::HANDSHAKESTATE_DONE
        } else {
            pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS
        }
    }

    /// Checks if the tunnel is in a shutdown state.
    fn is_shutdown(&self) -> bool {
        let shutdown_state = unsafe { openssl3::SSL_get_shutdown(self.0.as_ptr()) } as u32;
        (shutdown_state & (openssl3::SSL_SENT_SHUTDOWN | openssl3::SSL_RECEIVED_SHUTDOWN)) != 0
    }

    /// Performs the handshake.
    fn do_handshake(&self) -> (Result<pb::HandshakeState>, Option<pb::State>) {
        let handshake_error = unsafe { openssl3::SSL_do_handshake(self.0.as_ptr()) };

        if handshake_error == 1 {
            return (
                Ok(pb::HandshakeState::HANDSHAKESTATE_DONE),
                Some(pb::State::STATE_HANDSHAKE_DONE),
            );
        }
        let ssl_error = match self.get_last_recorded_error(handshake_error) {
            Ok(ssl_error) => ssl_error,
            Err(error_code) => {
                return (
                    Err((
                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                        format!(
                            "unexpected `SSL_ERROR_SSL` (code {error_code}) from OpenSSL: {}",
                            support::errstr()
                        ),
                    )
                        .into()),
                    None,
                );
            }
        };

        match ssl_error {
            SslError::WantRead => (
                Ok(pb::HandshakeState::HANDSHAKESTATE_WANT_READ),
                Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
            ),
            SslError::WantWrite => (
                Ok(pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE),
                Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
            ),
            SslError::ZeroReturn => (
                Ok(pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS),
                Some(pb::State::STATE_HANDSHAKE_IN_PROGRESS),
            ),
            SslError::WantAccept | SslError::WantConnect => (
                Ok(pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS),
                Some(pb::State::STATE_NOT_CONNECTED),
            ),
            SslError::Ssl => self.handle_ssl_error_ssl(),
            _ => (
                Err((
                    pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                    format!(
                        "unexpected SSL error from OpenSSL: {ssl_error:?} ({})",
                        support::errstr()
                    ),
                )
                    .into()),
                None,
            ),
        }
    }

    /// Reads some data and writes it to a buffer.
    fn read(&self, buffer: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        let buf_len: i32 = buffer
            .len()
            .try_into()
            .map_err(|_| pb::RecordError::RECORDERROR_TOO_BIG)?;

        let err =
            unsafe { openssl3::SSL_read(self.0.as_ptr(), buffer.as_mut_ptr().cast(), buf_len) };
        if err > 0 {
            return Ok(err as usize);
        }
        Err(self.get_error_from_record_stage(err).into())
    }

    /// Write some data.
    fn write(&self, buffer: &[u8]) -> crate::tunnel::RecordResult<usize> {
        let buf_len: i32 = buffer
            .len()
            .try_into()
            .map_err(|_| pb::RecordError::RECORDERROR_TOO_BIG)?;

        let err = unsafe { openssl3::SSL_write(self.0.as_ptr(), buffer.as_ptr().cast(), buf_len) };
        if err > 0 {
            return Ok(err as usize);
        }
        Err(self.get_error_from_record_stage(err).into())
    }

    /// Returns the error that occurred during the record stage.
    ///
    /// The record stage is the stage when `SSL_read` and `SSL_write`
    /// are called.
    fn get_error_from_record_stage(&self, err: c_int) -> pb::RecordError {
        let Ok(ssl_error) = self.get_last_recorded_error(err) else {
            return pb::RecordError::RECORDERROR_UNKNOWN;
        };
        if (ssl_error == SslError::Syscall) && (err == 0) {
            return pb::RecordError::RECORDERROR_CLOSED;
        }
        ssl_error.into()
    }

    /// Closes the tunnel.
    fn close(&self) -> crate::tunnel::RecordResult<()> {
        unsafe { openssl3::SSL_shutdown(self.0.as_ptr()) };
        Ok(())
    }

    /// Handles an SSL error of type `SSL_ERROR_SSL`.
    fn handle_ssl_error_ssl(&self) -> (Result<pb::HandshakeState>, Option<pb::State>) {
        let error = Error::from(support::peek_last_error());

        if error.library() != ErrorLibrary::Ssl {
            return (
                Err((
                    pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                    format!(
                        "unexpected error from OpenSSL: {error:?} ({})",
                        support::errstr()
                    ),
                )
                    .into()),
                None,
            );
        }
        match error.reason() {
            openssl3::SSL_R_UNSUPPORTED_PROTOCOL => {
                return (
                    Err((
                        pb::HandshakeError::HANDSHAKEERROR_UNSUPPORTED_PROTOCOL,
                        format!(
                            "unsupported TLS protocol. error: {error:?} ({})",
                            support::errstr()
                        ),
                    )
                        .into()),
                    None,
                );
            }
            openssl3::SSL_R_NO_SHARED_CIPHER => {
                return (
                    Err((
                        pb::HandshakeError::HANDSHAKEERROR_NO_SHARED_CIPHER,
                        format!("no shared cipher. error: {error:?} ({})", support::errstr()),
                    )
                        .into()),
                    None,
                );
            }
            openssl3::SSL_R_NO_SUITABLE_KEY_SHARE => {
                return (
                    Err((
                        pb::HandshakeError::HANDSHAKEERROR_NO_SUITABLE_KEY_SHARE,
                        format!(
                            "no suitable key share found. error: {error:?} ({})",
                            support::errstr()
                        ),
                    )
                        .into()),
                    None,
                );
            }
            openssl3::SSL_R_CERTIFICATE_VERIFY_FAILED => {}
            _ => {
                return (
                    Err((
                        pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                        format!(
                            "unexpected SSL error from OpenSSL: {error:?} ({})",
                            support::errstr()
                        ),
                    )
                        .into()),
                    None,
                );
            }
        }

        let verify_result = unsafe { openssl3::SSL_get_verify_result(self.0.as_ptr()) } as u32;
        let err: crate::Error = match verify_result {
            openssl3::X509_V_ERR_CERT_HAS_EXPIRED => {
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED.into()
            }
            openssl3::X509_V_ERR_CERT_REVOKED => {
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_REVOKED.into()
            }
            openssl3::X509_V_ERR_CERT_SIGNATURE_FAILURE => {
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED.into()
            }
            openssl3::X509_V_ERR_CA_CERT_MISSING_KEY_USAGE => {
                pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED.into()
            }
            openssl3::X509_V_ERR_HOSTNAME_MISMATCH => (
                pb::HandshakeError::HANDSHAKEERROR_INVALID_SERVER_NAME,
                "hostname mismatches",
            )
                .into(),
            openssl3::X509_V_ERR_EMAIL_MISMATCH => (
                pb::HandshakeError::HANDSHAKEERROR_INVALID_SERVER_NAME,
                "email mismatches",
            )
                .into(),
            openssl3::X509_V_ERR_IP_ADDRESS_MISMATCH => (
                pb::HandshakeError::HANDSHAKEERROR_INVALID_SERVER_NAME,
                "ip address mismatches",
            )
                .into(),
            openssl3::X509_V_ERR_CERT_CHAIN_TOO_LONG => {
                pb::HandshakeError::HANDSHAKEERROR_DEPTH_EXCEEDED.into()
            }
            openssl3::X509_V_ERR_CERT_NOT_YET_VALID
            | openssl3::X509_V_ERR_CERT_UNTRUSTED
            | openssl3::X509_V_ERR_CERT_REJECTED => (
                pb::HandshakeError::HANDSHAKEERROR_INVALID_CERTIFICATE,
                "certificate not yet valid, untrusted or rejected",
            )
                .into(),
            _ => (
                pb::HandshakeError::HANDSHAKEERROR_UNKNOWN_ERROR,
                format!(
                    "verification failed: verify code is {verify_result}, error: {}",
                    support::errstr()
                ),
            )
                .into(),
        };
        (Err(err), None)
    }
}

/// Verifies the tunnel configuration against the security requirements that come
/// from the context.
fn verify_tunnel_verifier(
    tunnel_verifier: Option<&pb_api::TunnelVerifier>,
    security_requirements: &tls::TunnelSecurityRequirements,
) -> Result<()> {
    let Some(tunnel_verifier) = tunnel_verifier else {
        return Err((pb::TunnelError::TUNNELERROR_VERIFIER, "empty verifier").into());
    };

    security_requirements.run_sanitizer_checks(tunnel_verifier)
}

/// A tunnel, wrapper around a SSL object.
pub struct Tunnel<'a> {
    /// Parent SSL_CTX object.
    _ssl_ctx: &'a Context<'a>,

    /// SSL object.
    pub(super) ssl: Pimpl<'a, NativeSsl>,

    /// Security requirements from the verifiers.
    security_requirements: tls::TunnelSecurityRequirements,

    /// IO interface.
    pub(super) io: Box<dyn crate::IO>,

    /// state.
    pub(super) state: pb::State,
}

impl std::fmt::Debug for Tunnel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "OpenSSL3Tunnel(ssl: {:p})",
            self.ssl.as_nonnull().as_ptr()
        )
    }
}

/// Tunnel builder.
/// This is a convenient aggregate of useful values to build a tunnel.
pub(crate) struct TunnelBuilder<'a> {
    /// Parent SSL_CTX object.
    pub(crate) ssl_ctx: &'a Context<'a>,

    /// The IO interface.
    pub(crate) io: Box<dyn crate::IO>,

    /// The tunnel-time configuration.
    pub(crate) configuration: pb_api::TunnelConfiguration,
}

/// Tunnel builder result.
type TunnelBuilderResult<'a> =
    std::result::Result<Pin<Box<Tunnel<'a>>>, (crate::Error, Box<dyn crate::IO>)>;

impl std::fmt::Debug for TunnelBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSL3TunnelBuilder")
    }
}

impl<'a> TunnelBuilder<'a> {
    /// Prepares a tunnel structure.
    fn prepare_ssl(&self) -> Result<Pimpl<'a, NativeSsl>> {
        let tunnel_verifier = self.configuration.verifier.as_ref();
        let security_requirements = self.ssl_ctx.security_requirements();
        verify_tunnel_verifier(tunnel_verifier, security_requirements)?;

        let ssl = self.ssl_ctx.new_ssl()?;
        let ssl_wrapped = Ssl(ssl.as_nonnull());
        ssl_wrapped.set_subject_alternative_names(tunnel_verifier)?;
        ssl_wrapped.set_server_name_indication(&self.configuration.server_name_indication)?;
        ssl_wrapped.create_and_attach_bio()?;
        Ok(ssl)
    }

    /// Builds a tunnel.
    pub(crate) fn build(self) -> TunnelBuilderResult<'a> {
        let ssl = match self.prepare_ssl() {
            Ok(ssl) => ssl,
            Err(e) => {
                return Err((e, self.io));
            }
        };
        let tun = Box::pin(Tunnel {
            _ssl_ctx: self.ssl_ctx,
            ssl,
            io: self.io,
            security_requirements: self.ssl_ctx.security_requirements().clone(),
            state: pb::State::STATE_NOT_CONNECTED,
        });
        if let Err(e) = tun.as_ref().attach_security_requirements() {
            return Err((e, unsafe { Pin::into_inner_unchecked(tun) }.io));
        }
        if let Err(e) = tun.as_ref().attach_to_bio() {
            return Err((e, unsafe { Pin::into_inner_unchecked(tun) }.io));
        }
        Ok(tun)
    }
}

impl<'a> Tunnel<'a> {
    /// Attaches the security requirements structure to the `SSL` object
    /// through `ex_data`.
    fn attach_security_requirements(self: Pin<&Self>) -> Result<()> {
        if unsafe {
            openssl3::SSL_set_ex_data(
                self.ssl.as_nonnull().as_ptr(),
                SSL_EX_DATA_TUNNEL_SECURITY_REQUIREMENTS_INDEX,
                (&self.security_requirements as *const tls::TunnelSecurityRequirements
                    as *const c_void)
                    .cast_mut(),
            )
        } == 1
        {
            Ok(())
        } else {
            Err((
                pb::SystemError::SYSTEMERROR_BACKEND,
                format!("`SSL_set_ex_data` failed: {}", support::errstr()),
            )
                .into())
        }
    }

    /// Attaches itself to the current BIO.
    fn attach_to_bio(self: Pin<&Self>) -> Result<()> {
        let bio = Ssl(self.ssl.as_nonnull()).get_attached_bio().ok_or((
            pb::SystemError::SYSTEMERROR_BACKEND,
            "no BIO attached to the current SSL object",
        ))?;
        unsafe {
            openssl3::BIO_set_data(
                bio.as_ptr(),
                (self.get_ref() as *const Self as *const c_void).cast_mut(),
            )
        };
        Ok(())
    }

    /// Updates the state of the tunnel.
    /// This method must be called after any read or write operation.
    fn update_state(&mut self) {
        if Ssl(self.ssl.as_nonnull()).is_shutdown() {
            self.state = pb::State::STATE_DISCONNECTED;
        }
    }

    pub(crate) fn state(&self) -> crate::tunnel::State {
        self.state.into()
    }

    pub(crate) fn handshake(&mut self) -> Result<crate::tunnel::HandshakeState> {
        if self.state == pb::State::STATE_HANDSHAKE_DONE {
            return Ok(pb::HandshakeState::HANDSHAKESTATE_DONE.into());
        }

        let ssl_wrapped = Ssl(self.ssl.as_nonnull());

        let state = ssl_wrapped.get_state();
        if state == pb::HandshakeState::HANDSHAKESTATE_DONE {
            self.state = pb::State::STATE_HANDSHAKE_DONE;
            return Ok(state.into());
        }

        let (handshake_state, tunnel_state) = ssl_wrapped.do_handshake();
        if let Some(tunnel_state) = tunnel_state {
            self.state = tunnel_state;
        }
        handshake_state.map(crate::tunnel::HandshakeState::from)
    }

    pub(crate) fn read(&mut self, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        let result = Ssl(self.ssl.as_nonnull()).read(buf);
        self.update_state();
        if self.state == pb::State::STATE_DISCONNECTED {
            Err(pb::RecordError::RECORDERROR_CLOSED.into())
        } else {
            result
        }
    }

    pub(crate) fn write(&mut self, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        let result = Ssl(self.ssl.as_nonnull()).write(buf);
        self.update_state();
        if self.state == pb::State::STATE_DISCONNECTED {
            Err(pb::RecordError::RECORDERROR_CLOSED.into())
        } else {
            result
        }
    }

    #[cfg(feature = "tracer")]
    pub(crate) fn add_tracer(&mut self, _tracer: crate::support::tracing::SandwichTracer) {
        unimplemented!("tracing is not supported with OpenSSL 3");
    }

    pub(crate) fn close(&mut self) -> crate::tunnel::RecordResult<()> {
        if self.state == pb::State::STATE_DISCONNECTED {
            return Ok(());
        }
        let result = Ssl(self.ssl.as_nonnull()).close();
        self.update_state();
        if self.state == pb::State::STATE_DISCONNECTED {
            Ok(())
        } else {
            result
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Tests [`verify_tunnel_verifier`].
    #[test]
    fn test_verify_tunnel_verifier() {
        let security_requirements = tls::TunnelSecurityRequirements {
            allow_expired_certificate: false,
        };
        let tunnel_verifier = protobuf::text_format::parse_from_str(
            r#"
                san_verifier <
                    alt_names <
                        dns: "example.com"
                    >
                    alt_names <
                        email: "user@example.com"
                    >
                    alt_names <
                        ip_address: "127.0.0.1"
                    >
                >
            "#,
        )
        .unwrap();

        let result = verify_tunnel_verifier(Some(&tunnel_verifier), &security_requirements);

        result.expect("`verify_tunnel_verifier` failed");
    }

    /// Tests [`verify_tunnel_verifier`] with no specified verifier.
    #[test]
    fn test_verify_tunnel_verifier_none() {
        let security_requirements = tls::TunnelSecurityRequirements {
            allow_expired_certificate: false,
        };
        let tunnel_verifier = protobuf::text_format::parse_from_str("").unwrap();

        let result = verify_tunnel_verifier(Some(&tunnel_verifier), &security_requirements);

        result.expect_err("`verify_tunnel_verifier` succeed");
    }

    /// Tests [`verify_tunnel_verifier`] with an empty verifier.
    #[test]
    fn test_verify_tunnel_verifier_empty() {
        let security_requirements = tls::TunnelSecurityRequirements {
            allow_expired_certificate: false,
        };
        let tunnel_verifier = protobuf::text_format::parse_from_str("empty_verifier<>").unwrap();

        let result = verify_tunnel_verifier(Some(&tunnel_verifier), &security_requirements);

        result.expect("`verify_tunnel_verifier` failed");
    }
}
