// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate log;
extern crate polling;
extern crate protobuf;
extern crate sandwich;

use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::mpsc::{Receiver, Sender};

use sandwich::pb::HandshakeState;
use sandwich::pb_api as sw_api;

use polling::{Event, Poller};
use sandwich::tunnel::{Context, RecordResult};

pub struct TcpIo {
    pub socket: TcpStream,
    pub fd: i32,
}

/// Creates the Sandwich configuration.
pub fn create_client_configuration(tls_version: &str) -> Result<sw_api::Configuration, String> {
    let tls_config = match tls_version {
        "tls12" => {
            r#"
            tls12 <
                ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                ciphersuite: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                ciphersuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                ciphersuite: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                ciphersuite: "TLS_RSA_WITH_AES_256_GCM_SHA384"
                ciphersuite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                ciphersuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                ciphersuite: "TLS_RSA_WITH_AES_128_GCM_SHA256"
            >
            "#
        }
        "tls13" => {
            r#"
            tls13 <
                ke: "prime256v1"
                ke: "kyber768"
                compliance <
                    classical_choice: CLASSICAL_ALGORITHMS_ALLOW
                >
                ciphersuite: "TLS_CHACHA20_POLY1305_SHA256"
                ciphersuite: "TLS_AES_256_GCM_SHA384"
                ciphersuite: "TLS_AES_128_GCM_SHA256"
            >
            "#
        }

        _ => panic!("tls_version is not supported."),
    };

    protobuf::text_format::parse_from_str::<sw_api::Configuration>(
        format!(
            r#"
        impl: IMPL_OPENSSL1_1_1_OQS
        client <
            tls <
                common_options <
                    {tls_config}
                    empty_verifier <>
                >
            >
        >
    "#
        )
        .as_str(),
    )
    .map_err(|e| format!("failed to create the Sandwich configuration: {e}"))
}

/// Creates the tunnel configuration.
/// The verifier corresponds to an EmptyVerifier, meaning that the Subject
/// Alternative Names of the server is not going to be verified.
fn create_tunnel_configuration() -> Result<sw_api::TunnelConfiguration, String> {
    protobuf::text_format::parse_from_str::<sw_api::TunnelConfiguration>(
        "verifier < empty_verifier <> >",
    )
    .map_err(|e| format!("failed to create the TunnelVerifier: {e}"))
}

/// Creates Sandwich I/O from TcpStream.
pub fn create_tcpio_from_tcpstream(host: &str, port: u16) -> TcpIo {
    let tcp_socket: TcpStream =
        TcpStream::connect((host, port)).expect("cannot connect to the remote peer");
    tcp_socket
        .set_nonblocking(true)
        .expect("unable to set nonblocking");
    let tcp_socket_fd = tcp_socket.as_raw_fd();

    TcpIo {
        socket: tcp_socket,
        fd: tcp_socket_fd,
    }
}

#[allow(dead_code)]
/// Connection to server with &Context, TcpIO.
/// For stdin/stdout test.
pub fn connect_to_server(
    client_ctx: &Context,
    tcp_io: TcpIo,
    mut input_r: impl BufRead + AsRawFd,
    mut output_w: impl Write,
) -> RecordResult<()> {
    let tunnel_verifier =
        create_tunnel_configuration().expect("failed to create the tunnel configuration object");

    let mut tunnel = client_ctx
        .new_tunnel(
            Box::new(tcp_io.socket.try_clone().expect("failed to clone socket")),
            tunnel_verifier,
        )
        .expect("cannot create the tunnel");
    loop {
        match tunnel.handshake() {
            Ok(hs) => match hs.value() {
                HandshakeState::HANDSHAKESTATE_DONE => {
                    log::info!("handshake: done");
                    break;
                }
                HandshakeState::HANDSHAKESTATE_ERROR => log::error!("handshake: error"),
                _ => (),
            },
            Err(e) => panic!("handshake: an error occured: {e}"),
        }
    }

    let key_input_r = 123;

    // Sets I/O polling.
    let poller = Poller::new().expect("creating poller failed");
    poller
        .add(&tcp_io.socket, Event::readable(tcp_io.fd as usize))
        .unwrap();
    poller.add(&input_r, Event::readable(key_input_r)).unwrap();

    let mut events = Vec::new();
    let mut static_buffer = [0u8; 256];
    let mut dynamic_buffer = Vec::new();
    'outer: loop {
        // Waits for I/O.
        events.clear();

        poller
            .wait(&mut events, None)
            .expect("polling error while waiting");

        for event in &events {
            if event.key == key_input_r {
                // Event is read, forwards data to tunnel.

                let n = input_r
                    .read_until(10, &mut dynamic_buffer)
                    .expect("error reading from input_r");

                if n == 0 {
                    // EOF, removes input_r from poller.
                    poller
                        .delete(&input_r)
                        .expect("error removing input_r from poller");
                } else {
                    // Writes data to tunnel.
                    if tunnel.write(&dynamic_buffer).is_err() {
                        break 'outer;
                    }
                }
                dynamic_buffer.clear();

                // Enables input_r event again if it's not removed.
                poller
                    .modify(&input_r, Event::readable(key_input_r))
                    .unwrap();
            } else if event.key == tcp_io.fd as usize {
                // Event is socket.
                // Reads from tunnel to output_w.

                let n: usize = match tunnel.read(&mut static_buffer) {
                    Ok(n) => n,
                    Err(e) => {
                        log::error!("error reading from tunnel: {e}");
                        break 'outer;
                    }
                };

                output_w
                    .write_all(b">")
                    .expect("error while writing to output_w");
                output_w
                    .write_all(&static_buffer[..n])
                    .expect("error while writing to output_w");

                // Enables tcp_io event again.
                poller
                    .modify(&tcp_io.socket, Event::readable(tcp_io.fd as usize))
                    .unwrap();
            }
        }
    }

    tunnel.close()
}

#[allow(dead_code)]
/// Connection to server with &Context, TcpIO.
/// For threading test.
pub fn connect_to_server_mpsc(
    client_ctx: &Context,
    tcp_io: TcpIo,
    input_r: Receiver<Vec<u8>>,
    output_w: Sender<Vec<u8>>,
) -> RecordResult<()> {
    let tunnel_verifier =
        create_tunnel_configuration().expect("failed to create the tunnel configuration object");

    let mut tunnel = client_ctx
        .new_tunnel(
            Box::new(tcp_io.socket.try_clone().expect("failed to clone socket")),
            tunnel_verifier,
        )
        .expect("cannot create the tunnel");

    loop {
        if let Ok(hs) = tunnel.handshake() {
            if hs.value() == HandshakeState::HANDSHAKESTATE_DONE {
                break;
            }
        }
    }

    let mut static_buffer = [0u8; 256];

    // Reads input_r and forwards data to tunnel.
    let data = input_r.recv().expect("error reading from input_r");
    tunnel.write(&data).expect("error while writing to tunnel");

    // Reads data from tunnel and forwards data to output_w.
    let mut n = 0;
    while n == 0 {
        // Waits until data is in the tunnel.
        n = if let Ok(m) = tunnel.read(&mut static_buffer) {
            m
        } else {
            0
        }
    }

    output_w
        .send(static_buffer[..n].to_vec())
        .expect("error while writing to output_w");

    tunnel.close()
}
