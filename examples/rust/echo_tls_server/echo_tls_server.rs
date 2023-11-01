// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate log;
extern crate protobuf;
extern crate sandwich;

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use sandwich::pb::HandshakeState;
use sandwich::pb_api as sw_api;
use sandwich::tunnel::Context;
use std::sync::mpsc::Sender;

/// Creates the Sandwich configuration.
fn create_server_configuration(
    cert: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
) -> Result<sw_api::Configuration, String> {
    protobuf::text_format::parse_from_str::<sw_api::Configuration>(&format!(
        r#"
impl: IMPL_BORINGSSL_OQS
server <
    tls <
        common_options <
            tls13 <
                ke: "prime256v1"
                ke: "kyber768"
                compliance <
                    classical_choice: CLASSICAL_ALGORITHMS_ALLOW
                >
            >
            tls12 <
                ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                ciphersuite: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                ciphersuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                ciphersuite: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                ciphersuite: "TLS_RSA_WITH_AES_256_GCM_SHA384"
            >
            empty_verifier <>
            identity <
                certificate <
                    static <
                        data <
                            filename: "{cert_path}"
                        >
                    >
                >
                private_key <
                    static <
                        data <
                            filename: "{private_key_path}"
                        >
                    >
                >
            >
        >
    >
>
    "#,
        cert_path = cert.as_ref().display(),
        private_key_path = private_key.as_ref().display(),
    ))
    .map_err(|e| format!("failed to create the Sandwich configuration: {e}"))
}

/// Creates the tunnel configuration.
/// Since we are acting as a server, we do not need to verify the client.
fn create_tunnel_configuration() -> Result<sw_api::TunnelConfiguration, String> {
    protobuf::text_format::parse_from_str::<sw_api::TunnelConfiguration>(
        "
        verifier < empty_verifier <> >",
    )
    .map_err(|e| format!("failed to create the TunnelVerifier: {e}"))
}

/// Handles tunnel for each tcp connection and echos back.
fn tunnel_echo_handler(
    connection: TcpStream,
    server_ctx: &Context,
    tunnel_verifier: &sw_api::TunnelConfiguration,
) {
    let mut tunnel = server_ctx
        .new_tunnel(Box::new(connection), tunnel_verifier.clone())
        .expect("cannot create the tunnel");

    match tunnel.handshake() {
        Ok(hs) => match hs.value() {
            HandshakeState::HANDSHAKESTATE_DONE => {
                log::info!("handshake: done");
            }
            HandshakeState::HANDSHAKESTATE_ERROR => log::error!("handshake: error"),
            _ => (),
        },
        Err(e) => log::error!("handshake: an error occured: {e}"),
    }

    let mut buf = [0u8; 256];
    loop {
        let n = match tunnel.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                log::error!("cannot read from the tunnel: {e}");
                break;
            }
        };

        if let Err(e) = tunnel.write(&buf[..n]) {
            log::error!("failed to write to tunnel: {e}");
        }
    }

    log::info!("closing tunnel");
    let _ = tunnel.close();
}

/// Creates echo_tls_server from certificate, privatekey, hostname and port.
#[allow(dead_code)]
pub fn echo_tls_server(cert: PathBuf, key: PathBuf, host: String, port: u16) {
    let server_conf =
        create_server_configuration(cert, key).expect("failed to create the server configuration");

    let sw = sandwich::Context;
    let server_ctx =
        Context::try_from(&sw, &server_conf).expect("failed to create a server context");

    let tunnel_verifier =
        create_tunnel_configuration().expect("failed to create the tunnel configuration object");

    let address = format!("{}:{}", host, port);

    let tcp_server_listener = TcpListener::bind(address).expect("failed to bind to {address:?}");

    for connection in tcp_server_listener.incoming() {
        match connection {
            Ok(conn) => {
                tunnel_echo_handler(conn, &server_ctx, &tunnel_verifier);
            }
            Err(e) => log::error!("couldn't get client {e:?}"),
        }
    }
}

/// Creates echo_tls_server from certificate, privatekey, hostname and kernel allocated port
/// We return the random port via mpsc Sender `port_w`.
#[allow(dead_code)]
pub fn echo_tls_server_mpsc(cert: PathBuf, key: PathBuf, host: String, port_w: Sender<u16>) {
    let server_conf =
        create_server_configuration(cert, key).expect("failed to create the server configuration");

    let sw = sandwich::Context;
    let server_ctx =
        Context::try_from(&sw, &server_conf).expect("failed to create a server context");

    let tunnel_verifier =
        create_tunnel_configuration().expect("failed to create the tunnel configuration object");

    // Bind to port 0 so kernel can allocate a random port
    let address = format!("{}:{}", host, 0);

    let tcp_server_listener = TcpListener::bind(address).expect("failed to bind to {address:?}");

    // Send the port number via channel
    let port = tcp_server_listener.local_addr().unwrap().port();
    port_w.send(port).unwrap();

    let (conn, _) = tcp_server_listener.accept().unwrap();
    tunnel_echo_handler(conn, &server_ctx, &tunnel_verifier)
}
