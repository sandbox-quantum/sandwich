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

pub(self) mod io;
pub(crate) mod ossl;

pub(self) use io::BIO_METH;

pub(crate) const VERIFY_TUNNEL_INDEX: i32 = 0;

#[cfg(test)]
pub(crate) mod test {
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
                buf[0..n].copy_from_slice(&self.buf[0..n]);
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
            buf[result..result + n].copy_from_slice(&self.buf[0..n]);
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
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#,
                crate::tls::test::CERT_PEM_PATH
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();
        let tun = ctx.new_tunnel(Box::new(io));
        assert!(tun.is_ok());
        let mut tun = tun.unwrap();
        let rec = tun.handshake().unwrap();
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_READ);
        assert_eq!(tun.state(), pb::State::STATE_HANDSHAKE_IN_PROGRESS);
        let _ = tun.close();
    }

    /// Test tunnel constructor for server.
    #[test]
    fn test_server() {
        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
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
              >
            >
            "#,
                crate::tls::test::CERT_PEM_PATH,
                crate::tls::test::SK_PATH
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut ctx = crate::context::try_from(&config).unwrap();
        let io = IOBuffer::new();
        let tun = ctx.new_tunnel(Box::new(io));
        assert!(tun.is_ok());
        let mut tun = tun.unwrap();
        let rec = tun.handshake().unwrap();
        assert_eq!(rec, pb::HandshakeState::HANDSHAKESTATE_WANT_READ);
        let _ = tun.close();
    }

    /// Test tunnel between client and server.
    #[test]
    fn test_all() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#,
                crate::tls::test::CERT_PEM_PATH
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
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
              >
            >
            "#,
                crate::tls::test::CERT_PEM_PATH,
                crate::tls::test::SK_PATH
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let mut client = client_ctx.new_tunnel(Box::new(client_io)).unwrap();
        let mut server = server_ctx.new_tunnel(Box::new(server_io)).unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Test tunnel between client and server with an expired certificate.
    #[test]
    fn test_expired() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#,
                crate::tls::test::CERT_EXPIRED_PEM_PATH,
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  empty_verifier <>
                  identity <
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
              >
            >
            "#,
                crate::tls::test::CERT_EXPIRED_PEM_PATH,
                crate::tls::test::SK_PATH
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let mut client = client_ctx.new_tunnel(Box::new(client_io)).unwrap();
        let mut server = server_ctx.new_tunnel(Box::new(server_io)).unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );

        // test that upon an error it always returns the same error
        for _ in 0..10 {
            match client.handshake() {
                Err(e) => {
                    assert_eq!(
                        *(e.iter().next().unwrap().code()),
                        crate::error::ProtoBasedErrorCode::from(
                            pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_EXPIRED
                        )
                    );
                }
                Ok(v) => panic!("Should have errored, but got: {} instead", v),
            }
        }
    }

    /// Test mTLS.
    #[test]
    #[allow(non_snake_case)]
    fn test_mTLS() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let server_certificate = "testdata/dilithium5.cert.pem";
        let server_private_key = "testdata/dilithium5.key.pem";

        let client_certificate = "testdata/falcon1024.cert.pem";
        let client_private_key = "testdata/falcon1024.key.pem";

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{client_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
                      static <
                        data <
                          filename: "{client_private_key}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{client_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
                      static <
                        data <
                          filename: "{server_private_key}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let mut client = client_ctx.new_tunnel(Box::new(client_io)).unwrap();
        let mut server = server_ctx.new_tunnel(Box::new(server_io)).unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );
    }

    /// Test mTLS, but the client doesn't send its identity.
    #[test]
    #[allow(non_snake_case)]
    fn test_mTLS_no_client_cert() {
        let ((cli_send, cli_recv), (serv_send, serv_recv)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());

        let server_certificate = "testdata/dilithium5.cert.pem";
        let server_private_key = "testdata/dilithium5.key.pem";

        let client_certificate = "testdata/falcon1024.cert.pem";

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            client <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut client_ctx = crate::context::try_from(&config).unwrap();
        let client_io = LinkedIOBuffer::new(serv_send, cli_recv);

        let mut config = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            format!(
                r#"
            server <
              tls <
                common_options <
                  kem: "kyber512"
                  x509_verifier <
                    trusted_cas <
                      static <
                        data <
                          filename: "{client_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                  identity <
                    certificate <
                      static <
                        data <
                          filename: "{server_certificate}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                    private_key <
                      static <
                        data <
                          filename: "{server_private_key}"
                        >
                        format: ENCODING_FORMAT_PEM
                      >
                    >
                  >
                >
              >
            >
            "#
            )
            .as_str(),
        )
        .unwrap();
        config.impl_ = pb_api::Implementation::IMPL_OPENSSL1_1_1_OQS.into();
        let mut server_ctx = crate::context::try_from(&config).unwrap();
        let server_io = LinkedIOBuffer::new(cli_send, serv_recv);

        let mut client = client_ctx.new_tunnel(Box::new(client_io)).unwrap();
        let mut server = server_ctx.new_tunnel(Box::new(server_io)).unwrap();

        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            server.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_WANT_READ
        );
        assert_eq!(
            client.handshake().unwrap(),
            pb::HandshakeState::HANDSHAKESTATE_DONE
        );

        server.handshake().unwrap_err();
    }
}
