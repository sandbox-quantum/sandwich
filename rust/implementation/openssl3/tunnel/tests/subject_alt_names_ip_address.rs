// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test a TLS tunnel using Subject Alternative Names (SAN), IP address variant.

mod support;

use support::{pb, pb_api, sandwich};

use protobuf::text_format::parse_from_str;

use sandwich::tunnel::Context;
use support::io::MpscIO;
use support::resolve_runfile as runfile;

/// Test a tunnel with enforced SAN using an IP address.
///
/// Configuration:
///
///     Client:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier:
///             trusted_cas: `chain_example_com`
///             allow_expired_certificate: false
///             max_verify_depth: default (100)
///         X509Identity: not present
///         alpn_protocols: none.
///         TunnelVerifier: san_verifier with IP address '::1'.
///
///     Server:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier: empty
///         X509Identity: `chain_example_com` leaf and fullchain
///         alpn_protocols: none.
///         TunnelVerifier: empty.
#[test]
fn test_ok() {
    let lib_ctx = sandwich::Context::new();

    let root_ca = runfile("testdata/certificate_chain/chain_example_com/ca.pem");
    let fullchain =
        runfile("testdata/certificate_chain/chain_example_com/fullchain.pem");
    let key = runfile("testdata/certificate_chain/chain_example_com/leaf.key");
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
                                        filename: "{root_ca}"
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
                san_verifier <
                    alt_names <
                        ip_address: "::1"
                    >
                >
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
                                        filename: "{fullchain}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                            private_key <
                                static <
                                    data <
                                        filename: "{key}"
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
}

/// Same as above, but SANs don't match.
///
/// Configuration:
///
///     Client:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier:
///             trusted_cas: `chain_example_com` CA
///             allow_expired_certificate: false
///             max_verify_depth: default (100)
///         X509Identity: not present
///         alpn_protocols: none.
///         TunnelVerifier: san_verifier with IP address '::ffff:7f00:101' (127.0.1.1)
///
///     Server:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier: empty
///         X509Identity: `chain_example_com` leaf and fullchain
///         alpn_protocols: none.
///         TunnelVerifier: empty.
#[test]
fn test_nok_sans_dont_match() {
    let lib_ctx = sandwich::Context::new();

    let root_ca = runfile("testdata/certificate_chain/chain_example_com/ca.pem");
    let fullchain =
        runfile("testdata/certificate_chain/chain_example_com/fullchain.pem");
    let key = runfile("testdata/certificate_chain/chain_example_com/leaf.key");
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
                                        filename: "{root_ca}"
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
                san_verifier <
                    alt_names <
                        ip_address: "::ffff:7f00:101"
                    >
                >
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
                                        filename: "{fullchain}"
                                    >
                                    format: ENCODING_FORMAT_PEM
                                >
                            >
                            private_key <
                                static <
                                    data <
                                        filename: "{key}"
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
    let err = client_tunnel.handshake().unwrap_err();
    assert!(err.is(&sandwich::Error::from(
        pb::HandshakeError::HANDSHAKEERROR_INVALID_SERVER_NAME
    )));
}
