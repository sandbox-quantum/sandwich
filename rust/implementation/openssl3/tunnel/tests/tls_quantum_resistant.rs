// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test a TLS tunnel using quantum-resistant cryptography.

mod support;

use support::{pb, pb_api, sandwich};

use protobuf::text_format::parse_from_str;

use sandwich::tunnel::Context;
use support::io::MpscIO;
use support::resolve_runfile as runfile;

/// Simple message to send.
const MSG: &[u8] = b"hello world";

/// Test a simple tunnel using quantum-resistant cryptography.
///
/// Configuration:
///
///     Client:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier:
///             trusted_cas: `falcon1024.cert.pem`
///             allow_expired_certificate: false
///             max_verify_depth: default (100)
///         X509Identity: not present
///         alpn_protocols: none.
///         TunnelVerifier: empty.
///
///     Server:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier: empty
///         X509Identity: `falcon1024.cert.pem` and `falcon1024.key.pem`.
///         alpn_protocols: none.
///         TunnelVerifier: empty.
#[test]
fn test() {
    let lib_ctx = sandwich::Context::new();

    let cert_path = runfile("testdata/ed25519.cert.pem");
    let key_path = runfile("testdata/ed25519.key.pem");
    let client_context = Context::try_from(
        &lib_ctx,
        &parse_from_str::<pb_api::Configuration>(&format!(
            r#"
            impl: IMPL_OPENSSL3_OQS_PROVIDER
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "kyber768"
                            compliance <
                                hybrid_choice: HYBRID_ALGORITHMS_ALLOW
                                quantum_safe_choice: QUANTUM_SAFE_ALGORITHMS_ALLOW
                                classical_choice: CLASSICAL_ALGORITHMS_ALLOW
                                bit_strength_choice: BIT_STRENGTH_AT_LEAST_128
                            >
                        >
                        x509_verifier <
                            trusted_cas <
                                static <
                                    data <
                                        filename: "{cert_path}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                        >
                    >
                >
            >
        "#
        ))
        .unwrap(),
    )
    .unwrap();
    let client_tunnel_configuration = parse_from_str::<pb_api::TunnelConfiguration>(
        r#"
            verifier <
                empty_verifier<>
            >
        "#,
    )
    .unwrap();

    let server_context = Context::try_from(
        &lib_ctx,
        &parse_from_str::<pb_api::Configuration>(&format!(
            r#"
            impl: IMPL_OPENSSL3_OQS_PROVIDER
            server <
                tls <
                    common_options <
                        tls13 <
                            ke: "kyber768"
                            compliance <
                                hybrid_choice: HYBRID_ALGORITHMS_ALLOW
                                quantum_safe_choice: QUANTUM_SAFE_ALGORITHMS_ALLOW
                                classical_choice: CLASSICAL_ALGORITHMS_ALLOW
                                bit_strength_choice: BIT_STRENGTH_AT_LEAST_128
                            >
                        >
                        empty_verifier <>
                        identity <
                            certificate <
                                static <
                                    data <
                                        filename: "{cert_path}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                            private_key <
                                static <
                                    data <
                                        filename: "{key_path}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                        >
                    >
                >
            >
        "#
        ))
        .unwrap(),
    )
    .unwrap();
    let server_tunnel_configuration = parse_from_str::<pb_api::TunnelConfiguration>(
        r#"
            verifier <
                empty_verifier<>
            >
        "#,
    )
    .unwrap();

    let (client_io, server_io) = MpscIO::new_pair();

    let mut client_tunnel = client_context
        .new_tunnel(Box::new(client_io), client_tunnel_configuration)
        .unwrap();
    let mut server_tunnel = server_context
        .new_tunnel(Box::new(server_io), server_tunnel_configuration)
        .unwrap();

    assert_eq!(
        client_tunnel.handshake().unwrap(),
        pb::HandshakeState::HANDSHAKESTATE_WANT_READ
    );
    assert_eq!(
        server_tunnel.handshake().unwrap(),
        pb::HandshakeState::HANDSHAKESTATE_WANT_READ
    );
    assert_eq!(
        client_tunnel.handshake().unwrap(),
        pb::HandshakeState::HANDSHAKESTATE_DONE
    );
    assert_eq!(
        server_tunnel.handshake().unwrap(),
        pb::HandshakeState::HANDSHAKESTATE_DONE
    );
    let mut buffer = vec![0u8; MSG.len()];
    assert_eq!(client_tunnel.write(&MSG).unwrap(), 11);
    assert_eq!(server_tunnel.read(&mut buffer).unwrap(), 11);
    assert_eq!(&buffer[0..MSG.len()], MSG);
}
