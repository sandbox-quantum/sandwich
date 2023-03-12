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

//! Defines [`SSLHandle`] struct.
//!
//! This tunnel is instantiated from context that uses the
//! `IMPL_OPENSSL1_1_1_OQS` implementation.
//!
//! Author: thb-sb

extern crate openssl;

/// Wrapper around SSL*.
pub(super) struct SSLHandle<'io: 'ctx, 'ctx> {
    mode: crate::Mode,
    pub(super) ssl: crate::Pimpl<'ctx, openssl::SSL>,
    pub(super) bio: crate::Pimpl<'ctx, openssl::bio_st>,
    pub(super) io: &'io mut (dyn crate::IO + 'io),
    pub(super) state: pb::State,
}

/// Implements [`std::fmt::Debug`] for [`SSLHandle`].
impl<'io, 'ctx> std::fmt::Debug for SSLHandle<'io, 'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} OpenSSL SSL* object",
            match self.mode {
                crate::Mode::Client => "client",
                crate::Mode::Server => "server",
            }
        )
    }
}

/// Returns a reference to the [`crate::Pimpl`] of `SSL*` from a [`SSLHandle`].
impl<'io, 'ctx> std::convert::AsRef<crate::Pimpl<'ctx, openssl::SSL>> for SSLHandle<'io, 'ctx> {
    fn as_ref(&self) -> &crate::Pimpl<'ctx, openssl::SSL> {
        &self.ssl
    }
}

/// Returns a mutable reference to the [`crate::Pimpl`] of `SSL*` from a [`SSLHandle`].
impl<'io, 'ctx> std::convert::AsMut<crate::Pimpl<'ctx, openssl::SSL>> for SSLHandle<'io, 'ctx> {
    fn as_mut(&mut self) -> &mut crate::Pimpl<'ctx, openssl::SSL> {
        &mut self.ssl
    }
}

/// Returns the raw pointer to `SSL*` from a [`SSLHandle`].
impl<'io, 'ctx> std::convert::From<&SSLHandle<'io, 'ctx>> for *const openssl::SSL {
    fn from(ssl: &SSLHandle<'io, 'ctx>) -> Self {
        ssl.as_ref().as_ptr()
    }
}

/// Returns the raw pointer as mutable to `SSL*` from a [`SSLHandle`].
impl<'io, 'ctx> std::convert::From<&mut SSLHandle<'io, 'ctx>> for *mut openssl::SSL {
    fn from(ssl: &mut SSLHandle<'io, 'ctx>) -> Self {
        ssl.as_mut().as_mut_ptr()
    }
}

/// Implements [`SSLHandle`].
impl<'io, 'ctx> SSLHandle<'io, 'ctx> {
    fn as_raw(&self) -> *const openssl::SSL {
        self.into()
    }
}

/// Instantiates a [`SSLHandle`] from an [`super::context::SSLContext`] and
/// an [`crate::IO` interface].
impl<'io: 'tun, 'ctx: 'tun, 'tun>
    std::convert::TryFrom<(
        &mut super::context::SSLContext<'ctx>,
        &'io mut (dyn crate::IO + 'io),
    )> for SSLHandle<'io, 'tun>
{
    type Error = crate::Error;

    fn try_from(
        (ctx, io): (
            &mut super::context::SSLContext<'ctx>,
            &'io mut (dyn crate::IO + 'io),
        ),
    ) -> crate::Result<SSLHandle<'io, 'tun>> {
        let ptr = unsafe { openssl::SSL_new(ctx.into()) };
        if ptr.is_null() {
            Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
        }
        let ptr = crate::Pimpl::<'tun, openssl::SSL>::from_raw(
            ptr,
            Some(|x| unsafe {
                openssl::SSL_free(x);
            }),
        );
        let bio = unsafe { openssl::BIO_new(&super::BIO_METH as *const openssl::bio_method_st) };
        if bio.is_null() {
            Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
        }
        Ok(Self {
            mode: match ctx {
                super::context::SSLContext::Client(_) => crate::Mode::Client,
                super::context::SSLContext::Server(_) => crate::Mode::Server,
            },
            ssl: ptr,
            bio: crate::Pimpl::<'tun, openssl::bio_st>::from_raw(
                bio, None, // no destructor for this bio, because SSL* is the owner.
            ),
            io,
            state: pb::State::STATE_NOT_CONNECTED,
        })
    }
}

/// Instantiates a [`SSLHandle`] from an OpenSSL [`super::Context`].
impl<'io: 'tun, 'ctx: 'tun, 'tun>
    std::convert::TryFrom<(&mut super::Context<'ctx>, &'io mut (dyn crate::IO + 'io))>
    for SSLHandle<'io, 'tun>
{
    type Error = crate::Error;

    fn try_from(
        (ctx, io): (&mut super::Context<'ctx>, &'io mut (dyn crate::IO + 'io)),
    ) -> crate::Result<SSLHandle<'io, 'tun>> {
        Self::try_from((&mut ctx.0, io))
    }
}

/// Convert an OpenSSL error to a [`crate::tunnel::RecordError`].
fn openssl_error_to_record_error(e: i32, errno: std::io::Error) -> crate::tunnel::RecordError {
    match e as u32 {
        openssl::SSL_ERROR_WANT_READ => pb::RecordError::RECORDERROR_WANT_READ,
        openssl::SSL_ERROR_WANT_WRITE => pb::RecordError::RECORDERROR_WANT_WRITE,
        openssl::SSL_ERROR_ZERO_RETURN => pb::RecordError::RECORDERROR_CLOSED,
        openssl::SSL_ERROR_SYSCALL => match errno.raw_os_error() {
            // EPIPE
            Some(32) => pb::RecordError::RECORDERROR_CLOSED,
            Some(_) | None => pb::RecordError::RECORDERROR_UNKNOWN,
        },
        _ => pb::RecordError::RECORDERROR_UNKNOWN,
    }
    .into()
}

/// Implements [`SSLHandle`].
impl<'io, 'pimpl> SSLHandle<'io, 'pimpl> {
    /// Returns the current SSL error.
    unsafe fn get_ssl_error(&self, e: i32) -> i32 {
        openssl::SSL_get_error(self.into(), e)
    }

    /// Returns the current SSL state.
    unsafe fn get_ssl_state(&self) -> u32 {
        openssl::SSL_get_state(self.into())
    }

    /// Check the state of SSL, regarding the shutdown phase, and update
    /// the tunnel state if necessary.
    fn check_shutdown(&mut self) -> pb::State {
        let err = unsafe { openssl::SSL_get_shutdown(self.as_raw()) } as u32;
        if (err & openssl::SSL_SENT_SHUTDOWN) != 0 {
            // According to the OpenSSL documentation:
            // > SSL_SENT_SHUTDOWN:
            // > […] the connection is being considered closed and the session is
            //       closed and correct.
            //
            // It means that if the flag `SSL_SENT_SHUTDOWN` is set, then the record
            // plane can be considered as closed (and not in the process of being
            // closed)
            self.state = pb::State::STATE_DISCONNECTED;
        }

        self.state
    }

    /// Finalizes the initialization of the BIO structure.
    pub(super) fn finalize_bio(&mut self) {
        unsafe {
            let ptr = self.bio.as_mut_ptr();
            openssl::BIO_set_data(ptr, (self as *mut Self) as *mut std::ffi::c_void);
            openssl::BIO_set_init(ptr, 1);
            openssl::SSL_set_bio(self.ssl.as_mut_ptr(), ptr, ptr);
        }
    }
}

/// Implements [`crate::Tunnel`] for [`SSLHandle`].
impl<'ctx: 'pimpl, 'io: 'ctx, 'pimpl> crate::Tunnel<'io, 'ctx> for SSLHandle<'io, 'pimpl> {
    fn state(&self) -> crate::tunnel::State {
        self.state.into()
    }

    fn read(&mut self, buf: &mut [u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let err = unsafe {
            openssl::SSL_read(
                self.into(),
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as i32,
            )
        };
        let os_error = std::io::Error::last_os_error();

        let new_state = self.check_shutdown();
        if err > 0 {
            return Ok(err as usize);
        }

        match new_state {
            pb::State::STATE_BEING_SHUTDOWN => Err(pb::RecordError::RECORDERROR_BEING_SHUTDOWN)?,
            pb::State::STATE_DISCONNECTED => Err(pb::RecordError::RECORDERROR_CLOSED)?,
            _ => (),
        };

        let serr = unsafe { self.get_ssl_error(err) };
        if (serr == (openssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            self.state = pb::State::STATE_DISCONNECTED;
            return Err(pb::RecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn write(&mut self, buf: &[u8]) -> crate::tunnel::RecordResult<usize> {
        if buf.len() > (std::i32::MAX as usize) {
            return Err(pb::RecordError::RECORDERROR_TOO_BIG.into());
        }

        let err = unsafe {
            openssl::SSL_write(
                self.into(),
                buf.as_ptr() as *const std::ffi::c_void,
                buf.len() as i32,
            )
        };
        let os_error = std::io::Error::last_os_error();

        let new_state = self.check_shutdown();
        if err > 0 {
            return Ok(err as usize);
        }

        match new_state {
            pb::State::STATE_BEING_SHUTDOWN => Err(pb::RecordError::RECORDERROR_BEING_SHUTDOWN)?,
            pb::State::STATE_DISCONNECTED => Err(pb::RecordError::RECORDERROR_CLOSED)?,
            _ => (),
        };

        let serr = unsafe { self.get_ssl_error(err) };
        if (serr == (openssl::SSL_ERROR_SYSCALL as i32)) && (err == 0) {
            self.state = pb::State::STATE_DISCONNECTED;
            return Err(pb::RecordError::RECORDERROR_CLOSED.into());
        }
        Err(openssl_error_to_record_error(serr, os_error))
    }

    fn handshake(&mut self) -> crate::tunnel::HandshakeState {
        if self.state == pb::State::STATE_HANDSHAKE_DONE {
            return pb::HandshakeState::HANDSHAKESTATE_DONE.into();
        }

        let state = unsafe { self.get_ssl_state() };
        if state == openssl::OSSL_HANDSHAKE_STATE_TLS_ST_OK {
            self.state = pb::State::STATE_HANDSHAKE_DONE;
            return pb::HandshakeState::HANDSHAKESTATE_DONE.into();
        }

        let err = match self.mode {
            crate::Mode::Client => unsafe { openssl::SSL_connect(self.into()) },
            crate::Mode::Server => unsafe { openssl::SSL_accept(self.into()) },
        } as u32;

        if err == 1 {
            self.state = pb::State::STATE_HANDSHAKE_DONE;
            return pb::HandshakeState::HANDSHAKESTATE_DONE.into();
        }
        let p = match unsafe { self.get_ssl_error(err as i32) } as u32 {
            openssl::SSL_ERROR_WANT_READ => (
                pb::State::STATE_HANDSHAKE_IN_PROGRESS,
                pb::HandshakeState::HANDSHAKESTATE_WANT_READ,
            ),
            openssl::SSL_ERROR_WANT_WRITE => (
                pb::State::STATE_HANDSHAKE_IN_PROGRESS,
                pb::HandshakeState::HANDSHAKESTATE_WANT_WRITE,
            ),
            openssl::SSL_ERROR_ZERO_RETURN => (
                pb::State::STATE_HANDSHAKE_IN_PROGRESS,
                pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS,
            ),
            openssl::SSL_ERROR_WANT_ACCEPT | openssl::SSL_ERROR_WANT_CONNECT => (
                pb::State::STATE_NOT_CONNECTED,
                pb::HandshakeState::HANDSHAKESTATE_IN_PROGRESS,
            ),
            _ => (
                pb::State::STATE_ERROR,
                pb::HandshakeState::HANDSHAKESTATE_ERROR,
            ),
        };
        self.state = p.0;
        p.1.into()
    }

    fn close(&mut self) -> crate::tunnel::RecordResult<()> {
        unsafe {
            openssl::SSL_shutdown(self.ssl.as_mut_ptr());
        };
        Ok(())
    }
}

#[cfg(test)]
mod test {
    /// A simple I/O interface.
    struct IOBuffer {
        pub(self) read: std::vec::Vec<u8>,
        pub(self) write: std::vec::Vec<u8>,
    }

    /// Implements [`crate::IO`] for [`IOBuffer`].
    impl crate::IO for IOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> crate::io::Result<usize> {
            match std::cmp::min(buf.len(), self.read.len()) {
                0 => Err(pb::IOError::IOERROR_WOULD_BLOCK.into()),
                n => {
                    buf.copy_from_slice(&self.read[0..n]);
                    self.read.drain(0..n);
                    Ok(n)
                }
            }
        }

        fn write(&mut self, buf: &[u8], _state: pb::State) -> crate::io::Result<usize> {
            self.write.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn close(&mut self) -> crate::io::Result<()> {
            self.read.clear();
            self.write.clear();
            Ok(())
        }
    }

    /// Implements [`IOBuffer`].
    impl IOBuffer {
        /// Constructs a new [`IOBuffer`].
        fn new() -> Self {
            Self {
                read: std::vec::Vec::new(),
                write: std::vec::Vec::new(),
            }
        }
    }

    /// An double I/O interface.
    struct LinkedIOBuffer {
        pub(self) buf: std::vec::Vec<u8>,
        pub(self) recv: std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        pub(self) send: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
    }

    /// Implements [`crate::IO`] for [`LinkedIOBuffer`].
    impl crate::IO for LinkedIOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> crate::io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.buf.len());
            if n > 0 {
                buf.copy_from_slice(&self.buf[0..n]);
                self.buf.drain(0..n);
            }
            if n == buf.len() {
                return Ok(n);
            }

            let r = buf.len() - n;
            match self.recv.try_recv() {
                Ok(mut v) => {
                    self.buf.append(&mut v);
                    Ok(())
                }
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => Err(pb::IOError::IOERROR_WOULD_BLOCK),
                    _ => Err(pb::IOError::IOERROR_CLOSED),
                },
            }?;

            let result = n;
            let n = std::cmp::min(r, self.buf.len());
            buf.copy_from_slice(&self.buf[0..n]);
            self.buf.drain(0..n);
            Ok(result + n)
        }

        fn write(&mut self, buf: &[u8], _state: pb::State) -> crate::io::Result<usize> {
            self.send
                .send(std::vec::Vec::from(buf))
                .map(|_| buf.len())
                .map_err(|_| pb::IOError::IOERROR_CLOSED.into())
        }

        fn close(&mut self) -> crate::io::Result<()> {
            self.buf.clear();
            Ok(())
        }
    }

    /// Implements [`LinkedIOBuffer`].
    impl LinkedIOBuffer {
        /// Constructs a new [`LinkedIOBuffer`].
        fn new(
            send: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
            recv: std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        ) -> Self {
            Self {
                buf: std::vec::Vec::new(),
                recv,
                send,
            }
        }
    }

    /// Test tunnel constructor for client.
    #[test]
    fn test_client() {
        let mut config = crate::openssl::client::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber512",
        );
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let mut io = IOBuffer::new();
        let tun = ctx.new_tunnel(&mut io);
        assert!(tun.is_ok());
        let mut tun = tun.unwrap();
        let rec = tun.handshake();
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_READ);
        assert_eq!(tun.state(), pb::State::STATE_HANDSHAKE_IN_PROGRESS);
        let _ = tun.close();
    }

    /// Test tunnel constructor for server.
    #[test]
    fn test_server() {
        let mut config = crate::openssl::server::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber512",
        );
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let mut io = IOBuffer::new();
        let tun = ctx.new_tunnel(&mut io);
        assert!(tun.is_ok());
        let mut tun = tun.unwrap();
        let rec = tun.handshake();
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_READ);
        let _ = tun.close();
    }

    /// Test tunnel between client and server.
    #[test]
    fn test_all() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = crate::openssl::client::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber512",
        );
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let mut client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = crate::openssl::server::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber512",
        );
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let mut server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let mut client = client_ctx.new_tunnel(&mut client_io).unwrap();
        let mut server = server_ctx.new_tunnel(&mut server_io).unwrap();

        assert_eq!(
            client.handshake(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(client.handshake(), pb::HandshakeState::HANDSHAKESTATE_DONE);
    }
}
