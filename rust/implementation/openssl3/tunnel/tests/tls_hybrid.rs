// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test a TLS tunnel using hybrid cryptography.
use std::net::TcpStream;

mod support;

use support::{pb, pb_api, sandwich};

use protobuf::text_format::parse_from_str;

use sandwich::tunnel::Context;
use support::io::MpscIO;
use support::resolve_runfile as runfile;

/// Simple message to send.
const MSG: &[u8] = b"hello world";
const ADDRESS: &'static str = "google.com";

/// Test a simple tunnel using classical and hybrid cryptography (HPKE).
///
/// Configuration:
///
///     Client:
///         Compliance: classical allowed, hybrid allowed
///         kem: x25519_kyber768
///         X509Verifier:
///             trusted_cas: `p384_dilithium3.cert.pem`
///             allow_expired_certificate: false
///             max_verify_depth: default (100)
///             load_cas_from_default_verify_path: false
///         X509Identity: not present
///         alpn_protocols: none.
///         TunnelVerifier: empty.
///
///     Server:
///         Compliance: classical allowed, hybrid allowed
///         kem: x25519_kyber768
///         X509Verifier: empty
///         X509Identity: `p384_dilithium3.cert.pem` and `p384_dilithium3.pem`.
///         alpn_protocols: none.
///         TunnelVerifier: empty.
#[test]
fn test() {
    let lib_ctx = sandwich::Context::new();

    let cert_path = runfile("testdata/p384_dilithium3.cert.pem");
    let key_path = runfile("testdata/p384_dilithium3.key.pem");
    let client_context = Context::try_from(
        &lib_ctx,
        &parse_from_str::<pb_api::Configuration>(&format!(
            r#"
            impl: IMPL_OPENSSL3_OQS_PROVIDER
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "x25519_kyber768"
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
                            ke: "x25519_kyber768"
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

/// Tests Hybrid KE by connecting to a website using empty_verifier.
#[test]
#[ignore = "CI/CD is unreliable to pass this test, at local it works"]
fn test_external_empty_verifier() {
    let lib_ctx = sandwich::Context::new();
    let client_context = Context::try_from(
        &lib_ctx,
        &parse_from_str::<pb_api::Configuration>(&format!(
            r#"
            impl: IMPL_OPENSSL3_OQS_PROVIDER
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "x25519_kyber768"
                        >
                        empty_verifier <>
                        alpn_protocols: "http/2"
                    >
                >
            >
        "#
        ))
        .unwrap(),
    )
    .unwrap();
    let client_tunnel_configuration = parse_from_str::<pb_api::TunnelConfiguration>(&format!(
        r#"
        verifier <
            empty_verifier<>
        >
        server_name_indication: "{ADDRESS}"
        "#
    ))
    .unwrap();
    let client_io = TcpStream::connect((ADDRESS, 443)).expect("failed to connect");
    client_io.set_nonblocking(false).unwrap();

    let mut client_tunnel = client_context
        .new_tunnel(
            Box::new(support::io::TcpStream(client_io)),
            client_tunnel_configuration,
        )
        .unwrap();

    assert_eq!(
        client_tunnel.handshake().unwrap(),
        pb::HandshakeState::HANDSHAKESTATE_DONE
    );
}

/// Tests Hybrid KE to a website using system-default CA.
#[test]
#[ignore = "CI/CD is unreliable to pass this test, at local it works"]
fn test_external_load_cas_from_default_verify_path() {
    let lib_ctx = sandwich::Context::new();
    let client_context = Context::try_from(
        &lib_ctx,
        &parse_from_str::<pb_api::Configuration>(&format!(
            r#"
            impl: IMPL_OPENSSL3_OQS_PROVIDER
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "x25519_kyber768"
                        >
                        x509_verifier <
                            load_cas_from_default_verify_path : true
                        >
                        alpn_protocols: "http/2"
                    >
                >
            >
        "#
        ))
        .unwrap(),
    )
    .unwrap();
    let client_tunnel_configuration = parse_from_str::<pb_api::TunnelConfiguration>(&format!(
        r#"
        verifier <
            empty_verifier<>
        >
        server_name_indication: "{ADDRESS}"
        "#
    ))
    .unwrap();
    let client_io = TcpStream::connect((ADDRESS, 443)).expect("failed to connect");
    client_io.set_nonblocking(false).unwrap();

    let mut client_tunnel = client_context
        .new_tunnel(
            Box::new(support::io::TcpStream(client_io)),
            client_tunnel_configuration,
        )
        .unwrap();

    assert_eq!(
        client_tunnel.handshake().unwrap(),
        pb::HandshakeState::HANDSHAKESTATE_DONE
    );
}

/// Tests Hybrid KE to a website without using system-default CA but a local trusted CA. It must fail.
#[test]
fn test_external_load_cas_from_trusted_cas_must_fail() {
    let lib_ctx = sandwich::Context::new();
    let cert_path = runfile("testdata/p384_dilithium3.cert.pem");
    let client_context = Context::try_from(
        &lib_ctx,
        &parse_from_str::<pb_api::Configuration>(&format!(
            r#"
            impl: IMPL_OPENSSL3_OQS_PROVIDER
            client <
                tls <
                    common_options <
                        tls13 <
                            ke: "x25519_kyber768"
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
                        alpn_protocols: "http/2"
                    >
                >
            >
        "#
        ))
        .unwrap(),
    )
    .unwrap();
    let client_tunnel_configuration = parse_from_str::<pb_api::TunnelConfiguration>(&format!(
        r#"
        verifier <
            empty_verifier<>
        >
        server_name_indication: "{ADDRESS}"
        "#
    ))
    .unwrap();
    let client_io = TcpStream::connect((ADDRESS, 443)).expect("failed to connect");
    client_io.set_nonblocking(false).unwrap();

    let mut client_tunnel = client_context
        .new_tunnel(
            Box::new(support::io::TcpStream(client_io)),
            client_tunnel_configuration,
        )
        .unwrap();

    client_tunnel
        .handshake()
        .expect_err("The handshake must failed.");
}
