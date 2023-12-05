// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test a TLS tunnel where the certificate chain is not fully X509 compliant.
//! This test is intented to be sure that `X509_V_FLAG_X509_STRICT` is
//! well enabled.

mod support;

use support::{pb, pb_api, sandwich};

use protobuf::text_format::parse_from_str;

use sandwich::tunnel::Context;
use support::io::MpscIO;
use support::resolve_runfile as runfile;

/// Test a TLS tunnel with a not fully X509 compliant certificate chain.
///
/// Configuration:
///
///     Client:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier:
///             trusted_cas: ca of chain_example_com.
///             allow_expired_certificate: false
///             max_verify_depth: default
///             load_cas_from_default_verify_path: false
///         X509Identity: not present
///         alpn_protocols: none.
///         TunnelVerifier: empty.
///
///     Server:
///         Compliance: classical allowed, quantum-resistant allowed
///         kem: kyber768
///         X509Verifier: empty
///         X509Identity: `chain_example_com` and `falcon1024.key.pem`.
///         alpn_protocols: none.
///         TunnelVerifier: empty.
#[test]
fn test_nok_x509_not_strict() {
    let lib_ctx = sandwich::Context::new();

    let root_ca = runfile("testdata/certificate_chain/not_x509_strict/ca.pem");

    let fullchain =
        runfile("testdata/certificate_chain/not_x509_strict/fullchain.pem");
    let key = runfile("testdata/certificate_chain/not_x509_strict/leaf.key");

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
        pb::HandshakeError::HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED
    )));
}
