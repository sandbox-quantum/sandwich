// Copyright 2022 SandboxAQ
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

extern crate api_rust_proto as SandwichAPI;
extern crate protobuf;
extern crate sandwich;
extern crate sandwich_rust_proto as SandwichProto;

/// A socket.
type IOBufferRC = std::rc::Rc<std::cell::RefCell<IOBuffer>>;
struct IOBuffer(Vec<u8>, Option<IOBufferRC>);

/// Implements sandwich::IO for IOBuffer.
impl sandwich::IO for IOBuffer {
    fn read(
        &mut self,
        b: &mut [u8],
        _: sandwich_rust_proto::State,
    ) -> sandwich::io::IOResult<usize> {
        if self.0.is_empty() {
            return Err(sandwich::errors::IOError::new(
                SandwichProto::IOError::IOERROR_WOULD_BLOCK,
            ));
        } else {
            let min = std::cmp::min(b.len(), self.0.len());
            b.clone_from_slice(&self.0[..min]);
            self.0.drain(..min);
            Ok(min)
        }
    }

    fn write(&mut self, b: &[u8], _: sandwich_rust_proto::State) -> sandwich::io::IOResult<usize> {
        self.1
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow_mut()
            .0
            .extend_from_slice(b);
        Ok(b.len())
    }

    fn close(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    /// Path to the PEM-encoded certificate.
    static PEM_CERT_PATH: &str = "testdata/cert.pem";

    /// Path to the PEM-encoded private key.
    static PEM_KEY_PATH: &str = "testdata/key.pem";

    /// Default KEM.
    static DEFAULT_KEM: &str = "kyber512";

    /// Ping message.
    static PING_MSG: [u8; 4] = [0x50, 0x49, 0x4e, 0x47];

    /// Pong message.
    static PONG_MSG: [u8; 4] = [0x50, 0x4f, 0x4e, 0x47];

    /// Creates the Context for the client.
    fn create_client() -> Result<sandwich::Context, sandwich::errors::GlobalError> {
        let mut conf = SandwichAPI::Configuration::new();
        conf.protocol = SandwichAPI::Protocol::PROTO_TLS_13;
        conf.field_impl = SandwichAPI::Implementation::IMPL_OPENSSL1_1_1_OQS;
        let tls_client = conf.mut_client().mut_tls();
        tls_client
            .mut_common_options()
            .mut_kem()
            .push(DEFAULT_KEM.to_string());

        tls_client.mut_trusted_certificates().push({
            let mut cert = SandwichAPI::Certificate::new();
            let mut asn1 = cert.mut_field_static();
            asn1.mut_data().set_filename(PEM_CERT_PATH.to_string());
            asn1.format = SandwichAPI::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM;
            cert
        });

        sandwich::Context::try_from(&conf)
    }

    /// Creates the Context for the server.
    fn create_server() -> Result<sandwich::Context, sandwich::errors::GlobalError> {
        let mut conf = SandwichAPI::Configuration::new();
        conf.protocol = SandwichAPI::Protocol::PROTO_TLS_13;
        conf.field_impl = SandwichAPI::Implementation::IMPL_OPENSSL1_1_1_OQS;
        let tls_server = conf.mut_server().mut_tls();
        tls_server
            .mut_common_options()
            .mut_kem()
            .push(DEFAULT_KEM.to_string());

        tls_server.set_certificate({
            let mut cert = SandwichAPI::Certificate::new();
            let mut asn1 = cert.mut_field_static();
            asn1.mut_data().set_filename(PEM_CERT_PATH.to_string());
            asn1.format = SandwichAPI::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM;
            cert
        });

        tls_server.set_private_key({
            let mut pkey = SandwichAPI::PrivateKey::new();
            let mut asn1 = pkey.mut_field_static();
            asn1.mut_data().set_filename(PEM_KEY_PATH.to_string());
            asn1.format = SandwichAPI::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM;
            pkey
        });

        sandwich::Context::try_from(&conf)
    }

    /// Creates the I/O.
    fn create_ios() -> (super::IOBufferRC, super::IOBufferRC) {
        let client = std::rc::Rc::new(std::cell::RefCell::new(super::IOBuffer(
            Vec::<u8>::new(),
            None,
        )));
        let server = std::rc::Rc::new(std::cell::RefCell::new(super::IOBuffer(
            Vec::<u8>::new(),
            None,
        )));

        client.as_ref().borrow_mut().1 = Some(server.clone());
        server.as_ref().borrow_mut().1 = Some(client.clone());
        (client, server)
    }

    /// Test a simple tunnel
    #[test]
    fn test() {
        type Buf = Vec<u8>;
        let mut client_ctx = create_client().unwrap();
        let mut server_ctx = create_server().unwrap();

        let (client_io, server_io) = create_ios();

        let mut client_tun =
            sandwich::Tunnel::new(&mut client_ctx, &mut *client_io.as_ref().borrow_mut()).unwrap();
        let mut server_tun =
            sandwich::Tunnel::new(&mut server_ctx, &mut *server_io.as_ref().borrow_mut()).unwrap();

        {
            let e = client_tun.handshake();
            assert!(e.is_err());
            assert_eq!(
                e.unwrap_err().what(),
                SandwichProto::HandshakeState::HANDSHAKESTATE_WANT_READ
            );
        }

        {
            let e = server_tun.handshake();
            assert!(e.is_err());
            assert_eq!(
                e.unwrap_err().what(),
                SandwichProto::HandshakeState::HANDSHAKESTATE_WANT_READ
            );
        }

        {
            let e = client_tun.handshake();
            assert!(e.is_ok());
        }

        {
            let e = server_tun.handshake();
            assert!(e.is_ok());
        }

        {
            let op = client_tun.write(&PING_MSG);
            assert!(op.is_ok());
            assert_eq!(op.unwrap(), PING_MSG.len());
        }

        {
            let mut buf = Buf::new();
            buf.resize(PING_MSG.len(), 0u8);
            let op = server_tun.read(&mut buf);
            assert!(op.is_ok());
            assert_eq!(op.unwrap(), PING_MSG.len());
            assert_eq!(&buf, &PING_MSG);
        }

        {
            let op = server_tun.write(&PONG_MSG);
            assert!(op.is_ok());
            assert_eq!(op.unwrap(), PONG_MSG.len());
        }

        {
            let mut buf = Buf::new();
            buf.resize(PONG_MSG.len(), 0u8);
            let op = client_tun.read(&mut buf);
            assert!(op.is_ok());
            assert_eq!(op.unwrap(), PONG_MSG.len());
            assert_eq!(&buf, &PONG_MSG);
        }
    }
}
