// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate clap;
extern crate env_logger;
extern crate log;
extern crate protobuf;
extern crate sandwich;

use std::net::{TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};

use sandwich::pb::HandshakeState;
use sandwich::pb_api as sw_api;

/// Default server's IP address.
const DEFAULT_SERVER_IP_ADDRESS: &str = "::1";

/// Default server's port.
const DEFAULT_SERVER_PORT: u16 = 1337;

#[derive(clap::Parser, Debug)]
#[command(about = "Simple TLS server")]
struct Cli {
    /// Path to the certificate.
    #[arg(short = 'c', long)]
    certificate: PathBuf,

    /// Path to the private key.
    #[arg(short = 'k', long)]
    private_key: PathBuf,

    /// Hostname of the server.
    #[arg(short = 'H', long, default_value_t = DEFAULT_SERVER_IP_ADDRESS.to_string())]
    hostname: String,

    /// Port of the server.
    #[arg(short = 'p', long, value_parser = clap::value_parser!(u16).range(1..), default_value_t = DEFAULT_SERVER_PORT)]
    port: u16,
}

/// Creates a socket and binds/listens to a given hostname/port.
fn tcp_listen(hostname: impl ToSocketAddrs) -> Result<TcpListener, String> {
    TcpListener::bind(hostname).map_err(|e| format!("failed to bind: {e}"))
}

/// Creates the Sandwich configuration.
fn create_sandwich_configuration(
    cert: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
) -> Result<sw_api::Configuration, String> {
    protobuf::text_format::parse_from_str::<sw_api::Configuration>(&format!(
        r#"
impl: IMPL_BORINGSSL_OQS
compliance <
    classical_choice: CLASSICAL_ALGORITHMS_ALLOW
>
server <
    tls <
        common_options <
            kem: "prime256v1"
            kem: "kyber768"
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

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = <Cli as clap::Parser>::parse();
    if !args.certificate.is_file() {
        panic!(
            "{} does not point to a valid file",
            args.certificate.display()
        );
    }

    let configuration = create_sandwich_configuration(&args.certificate, &args.private_key)
        .expect("failed to create the Sandwich configuration");
    let mut context = sandwich::tunnel::context_try_from(&configuration)
        .expect("failed to create a Sandwich context");

    let tunnel_verifier =
        create_tunnel_configuration().expect("failed to create the tunnel configuration object");

    let tcp_serv = tcp_listen((args.hostname.as_str(), args.port)).expect("failed to listen");
    let (tcp_client, _) = tcp_serv.accept().expect("failed to accept a new client");

    let tcp_io = sandwich::io::helpers::TcpIo::from(tcp_client);

    let mut tun = context
        .new_tunnel(Box::new(tcp_io), tunnel_verifier)
        .expect("cannot create the tunnel");
    match tun.handshake() {
        Ok(hs) => match hs.value() {
            HandshakeState::HANDSHAKESTATE_DONE => {
                log::info!("handshake: done");
            }
            HandshakeState::HANDSHAKESTATE_ERROR => log::error!("handshake: error"),
            v => log::error!("unexpected tunnel handshake status {:?}", v),
        },
        Err(e) => panic!("handshake: an error occured: {e}"),
    }

    let mut rx = vec![0u8; 256];
    loop {
        match tun.read(&mut rx) {
            Ok(n) => {
                rx.resize(n, 0);
            }
            Err(e) => {
                log::error!("cannot read from the server: {e}");
                break;
            }
        }
        if let Err(e) = tun.write(&rx) {
            log::error!("failed to write to tunnel: {e}");
        }
    }

    log::info!("closing tunnel");
    let _ = tun.close();
}
