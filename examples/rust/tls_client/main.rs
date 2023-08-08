// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

extern crate clap;
extern crate env_logger;
extern crate libc;
extern crate log;
extern crate protobuf;
extern crate sandwich;

use std::cmp::min;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::ptr;

use sandwich::pb::HandshakeState;
use sandwich::pb_api as sw_api;

use libc::{
    c_int, epoll_create1, epoll_ctl, epoll_event, EPOLLIN, EPOLL_CTL_ADD, EPOLL_CTL_DEL, FIONREAD,
};

#[derive(clap::Parser, Debug)]
#[command(about = "Simple TLS client")]
struct Cli {
    /// Hostname of the server.
    #[arg(short = 'H', long)]
    hostname: String,

    /// Port of the server.
    #[arg(short = 'p', long, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
}

/// Creates the Sandwich configuration.
fn create_sandwich_configuration() -> Result<sw_api::Configuration, String> {
    protobuf::text_format::parse_from_str::<sw_api::Configuration>(
        r#"
impl: IMPL_OPENSSL1_1_1_OQS
compliance <
    classical_choice: CLASSICAL_ALGORITHMS_ALLOW
>
client <
    tls <
        common_options <
            kem: "prime256v1"
            kem: "kyber768"
            empty_verifier <>
        >
    >
>
    "#,
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

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = <Cli as clap::Parser>::parse();

    let configuration =
        create_sandwich_configuration().expect("failed to create the Sandwich configuration");
    let mut context = sandwich::tunnel::context_try_from(&configuration)
        .expect("failed to create a Sandwich context");

    let tunnel_verifier =
        create_tunnel_configuration().expect("failed to create the tunnel configuration object");

    let tcp_sock = TcpStream::connect((args.hostname.as_str(), args.port))
        .expect("cannot connect to the remote peer");
    let tcp_fd = tcp_sock.as_raw_fd();

    let tcp_io = sandwich::io::helpers::SystemSocketIo::new(tcp_fd).unwrap();

    let mut tun = context
        .new_tunnel(Box::new(tcp_io), tunnel_verifier)
        .expect("cannot create the tunnel");
    loop {
        match tun.handshake() {
            Ok(hs) => match hs.value() {
                HandshakeState::HANDSHAKESTATE_DONE => {
                    log::info!("handshake: done");
                    break;
                }
                HandshakeState::HANDSHAKESTATE_ERROR => log::error!("handshake: error"),
                v => log::error!("unexpected tunnel handshake status {:?}", v),
            },
            Err(e) => panic!("handshake: an error occured: {e}"),
        }
    }

    // Setup epoll
    let epoll_fd = unsafe { epoll_create1(0) };
    if epoll_fd == -1 {
        log::error!("epoll_create error {}", io::Error::last_os_error());
    }

    let mut event = epoll_event {
        events: EPOLLIN as u32,
        u64: tcp_fd as u64,
    };
    if unsafe { epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tcp_fd, &mut event) } == -1 {
        log::error!("epoll_ctl error {}", io::Error::last_os_error());
    }

    let stdin_fd = io::stdin().as_raw_fd();
    let mut stdin_event = epoll_event {
        events: EPOLLIN as u32,
        u64: stdin_fd as u64,
    };
    if unsafe { epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stdin_fd, &mut stdin_event) } == -1 {
        log::error!("epoll_ctl error {}", io::Error::last_os_error());
    }

    let mut events: [epoll_event; 2] = [epoll_event { events: 0, u64: 0 }; 2];
    let mut buffer: [u8; 1024] = [0; 1024];
    'outer: loop {
        let num_events = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 2 as c_int, -1) };
        if num_events == -1 {
            log::error!("epoll_wait error: {}", io::Error::last_os_error());
        }

        for event in events.iter().take(num_events as usize) {
            let event_fd = event.u64 as c_int;

            if event_fd == stdin_fd {
                let mut available_bytes: c_int = 0;
                let result = unsafe { libc::ioctl(stdin_fd, FIONREAD, &mut available_bytes) };
                if result == -1 {
                    log::error!("ioctl FIONREAD error: {}", io::Error::last_os_error());
                }

                if available_bytes == 0 {
                    // EOF reached, unregister stdin from epoll
                    unsafe {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, stdin_fd, ptr::null_mut());
                    }
                } else {
                    let toread = min(buffer.len(), available_bytes as usize);
                    let n = io::stdin()
                        .read(&mut buffer[..toread])
                        .expect("error while reading stdin");
                    tun.write(&buffer[..n])
                        .expect("error while writing to tunnel");
                }
            } else if event_fd == tcp_fd {
                let num_bytes = tun.read(&mut buffer).expect("error while reading tunnel");
                if num_bytes == 0 {
                    break 'outer;
                }
                io::stdout()
                    .write_all(&buffer[..num_bytes])
                    .expect("error while writing to stdout");
            }
        }
    }

    let _ = tun.close();
}
