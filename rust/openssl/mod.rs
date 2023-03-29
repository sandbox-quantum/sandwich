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

//! Sandwich OpenSSL implementation module.
//!
//! Author: thb-sb

pub(self) mod io;
pub(crate) mod ossl;
pub(self) mod security;

pub(self) use io::BIO_METH;
pub(self) use security::assert_compliance;

#[cfg(test)]
pub(crate) mod test {
    /// Path to a valid PEM certificate.
    pub(crate) const CERT_PEM_PATH: &str = "testdata/cert.pem";

    /// Path to an invalid PEM certificate.
    pub(crate) const CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH: &str =
        "testdata/cert_unknown_sig_alg.der";

    /// Path to a valid DER certificate.
    pub(crate) const CERT_DER_PATH: &str = "testdata/cert.der";

    /// Path to a valid PEM private key.
    pub(crate) const SK_PATH: &str = "testdata/key.pem";

    /// Path to a valid DER private key.
    pub(crate) const SK_DER_PATH: &str = "testdata/key.der";

    /// A simple I/O interface.
    struct IOBuffer {
        pub(self) read: std::vec::Vec<u8>,
        pub(self) write: std::vec::Vec<u8>,
    }

    /// Implements [`crate::IO`] for [`IOBuffer`].
    impl crate::IO for IOBuffer {
        fn read(&mut self, buf: &mut [u8], _state: pb::State) -> crate::io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.read.len());
            if n == 0 {
                Err(pb::IOError::IOERROR_WOULD_BLOCK.into())
            } else {
                buf.copy_from_slice(&self.read[0..n]);
                self.read.drain(0..n);
                Ok(n)
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

    /// A double I/O interface.
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
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                >
                trusted_certificates <
                  static <
                    data <
                      filename: "{}"
                    >
                    format: ENCODING_FORMAT_PEM
                  >
                >
              >
            >
            "#,
                crate::openssl::test::CERT_PEM_PATH
            )
            .as_str(),
        )
        .unwrap();
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
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                >
                certificate <
                  static <
                    data <
                      filename: "{}"
                    >
                    format: ENCODING_FORMAT_PEM
                  >
                >
                private_key <
                  static <
                    data <
                      filename: "{}"
                    >
                    format: ENCODING_FORMAT_PEM
                  >
                >
              >
            >
            "#,
                crate::openssl::test::CERT_PEM_PATH,
                crate::openssl::test::SK_PATH
            )
            .as_str(),
        )
        .unwrap();
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

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                >
                trusted_certificates <
                  static <
                    data <
                      filename: "{}"
                    >
                    format: ENCODING_FORMAT_PEM
                  >
                >
              >
            >
            "#,
                crate::openssl::test::CERT_PEM_PATH
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let mut client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                >
                certificate <
                  static <
                    data <
                      filename: "{}"
                    >
                    format: ENCODING_FORMAT_PEM
                  >
                >
                private_key <
                  static <
                    data <
                      filename: "{}"
                    >
                    format: ENCODING_FORMAT_PEM
                  >
                >
              >
            >
            "#,
                crate::openssl::test::CERT_PEM_PATH,
                crate::openssl::test::SK_PATH
            )
            .as_str(),
        )
        .unwrap();
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
