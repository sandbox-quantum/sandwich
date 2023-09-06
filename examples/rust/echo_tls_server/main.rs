// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate clap;
extern crate env_logger;

use clap::Parser;
use std::path::PathBuf;

mod echo_tls_server;

/// Default server's IP address.
const DEFAULT_SERVER_IP_ADDRESS: &str = "::1";

/// Default server's port.
const DEFAULT_SERVER_PORT: u16 = 1337;

#[derive(Parser, Debug)]
#[command(about = "Simple echo TLS server")]
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

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Cli::parse();
    if !args.certificate.is_file() {
        panic!(
            "{} does not point to a valid file",
            args.certificate.display()
        );
    }
    if !args.private_key.is_file() {
        panic!(
            "{} does not point to a valid file",
            args.private_key.display()
        );
    }

    echo_tls_server::echo_tls_server(args.certificate, args.private_key, args.hostname, args.port);
}
