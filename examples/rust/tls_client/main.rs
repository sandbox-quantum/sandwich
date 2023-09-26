// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate clap;
extern crate env_logger;

use clap::Parser;
use std::io;

mod tls_client;

#[derive(Parser, Debug)]
#[command(about = "Simple TLS client")]
struct Cli {
    /// Hostname of the server.
    #[arg(short = 'H', long)]
    hostname: String,

    /// Port of the server.
    #[arg(short = 'p', long, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
}

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Cli::parse();
    let tcp_io = tls_client::create_tcpio_from_tcpstream(&args.hostname, args.port);

    let client_conf = tls_client::create_client_configuration()
        .expect("failed to create the Sandwich configuration");

    let sw = sandwich::Context;
    let client_ctx = sandwich::tunnel::Context::try_from(&sw, &client_conf)
        .expect("failed to create a Sandwich context");

    let input_r = io::stdin().lock();
    let output_w = io::stdout().lock();

    let _ = tls_client::connect_to_server(&client_ctx, tcp_io, input_r, output_w);
}
