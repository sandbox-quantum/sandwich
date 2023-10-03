// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! SystemSocket helper functions

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::RawFd;

/// A [`File`] sandwich wrapper.
pub struct SystemSocketIo(File);

/// Implements [`SystemSocketIo`]
impl SystemSocketIo {
    #[allow(dead_code)]
    /// Instantiates a [`SystemSocketIo`] given a raw file descriptor.
    pub fn new(fd: RawFd) -> Result<SystemSocketIo, std::io::Error> {
        use std::os::fd::FromRawFd;
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(SystemSocketIo(file))
    }
}

/// Instantiates a [`SystemSocketIo`] from a [`File`].
impl From<File> for SystemSocketIo {
    fn from(file: File) -> Self {
        SystemSocketIo(file)
    }
}

/// Implements [`crate::IO`] for [`SystemSocketIo`].
impl crate::IO for SystemSocketIo {
    fn read(&mut self, buf: &mut [u8], _state: pb::State) -> Result<usize, std::io::Error> {
        self.0.read(buf)
    }

    fn write(&mut self, buf: &[u8], _state: pb::State) -> Result<usize, std::io::Error> {
        self.0.write(buf)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::IO;

    fn create_server(hostname: &str, port: &u16, is_blocking: bool) -> std::net::TcpListener {
        let addr = hostname.to_owned() + ":" + &port.to_string();
        use std::net::ToSocketAddrs;
        let sock_addr: std::net::SocketAddr = match addr.to_socket_addrs() {
            Ok(sa) => sa.collect::<Vec<_>>()[0],
            Err(e) => {
                panic!("{e}");
            }
        };
        let listener = std::net::TcpListener::bind(sock_addr).expect("Failed to bind");
        match listener.set_nonblocking(!is_blocking) {
            Ok(_) => listener,
            Err(_) => panic!("failed set_nonblocking({}) call", !is_blocking),
        }
    }

    fn create_client(hostname: &str, port: &u16) -> SystemSocketIo {
        let addr = hostname.to_owned() + ":" + &port.to_string();
        let stream = std::net::TcpStream::connect(addr).expect("failed to connect");
        let fd = std::net::TcpStream::into_raw_fd(stream);
        use std::os::fd::IntoRawFd;
        SystemSocketIo::new(fd as RawFd).expect("Failed to create client")
    }

    fn blocking_listener_thread(listener: std::net::TcpListener) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                handle_client_blocking(stream);
            }
            Err(e) => panic!("Failed to accept a connection: {e}"),
        }
    }

    fn handle_client_blocking(mut stream: std::net::TcpStream) {
        let mut recv = [0u8; 5];
        let send = [2u8; 3];
        match stream.read(&mut recv) {
            Ok(5) => {}
            Ok(v) => panic!("Read the wrong amount of bytes. Expected 5, got {v}"),
            Err(e) => panic!("Failed to read: {}", e),
        }
        assert_eq!(recv, [0u8, 1u8, 2u8, 3u8, 4u8]);
        match stream.write(&send) {
            Ok(3) => {}
            Ok(v) => panic!("Wrote wrong amount of bytes. Expected 3, got {v}"),
            Err(e) => panic!("Failed to write: {}", e),
        }
        _ = stream.shutdown(std::net::Shutdown::Both);
    }

    fn client_blocking_communicate(mut io: SystemSocketIo) {
        let send = [0u8, 1u8, 2u8, 3u8, 4u8];
        let mut recv = [0u8; 3];
        use sandwich_proto::State::STATE_CONNECTION_IN_PROGRESS;
        match io.write(&send, STATE_CONNECTION_IN_PROGRESS) {
            Ok(5) => {}
            Ok(v) => panic!("Wrote wrong amount of bytes. Expected 5, got {v}"),
            Err(e) => panic!("Failed to write 5 bytes: {}", e),
        }
        match io.read(&mut recv, STATE_CONNECTION_IN_PROGRESS) {
            Ok(3) => {}
            Ok(v) => panic!("Read the wrong amount of bytes. Expected 3, got {v}"),
            Err(e) => panic!("Failed to read 3 bytes: {}", e),
        }
        assert_eq!(recv, [2u8; 3]);
    }

    fn generate_seed() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        since_the_epoch.as_nanos().try_into().unwrap()
    }

    fn pseudo_random(seed: u64) -> u16 {
        // Simple pseudo-random algorithm (Linear Congruential Generator)
        const MULTIPLIER: u64 = 1103515245;
        const INCREMENT: u64 = 12345;
        const MODULUS: u64 = 2u64.pow(31);

        let next_seed = (seed.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT)) % MODULUS;
        (next_seed as u16) % 64510 + 1026 // Scale and shift to the desired range (1026 to 65535)
    }

    #[test]
    fn test_blocking_io() {
        let port = pseudo_random(generate_seed());
        let hostname = "localhost";
        let listener = create_server("localhost", &port, true);
        std::thread::spawn(move || blocking_listener_thread(listener));
        // give enough time for thread to set itself up before trying to connect
        std::thread::sleep(std::time::Duration::from_secs(1));
        let io = create_client(hostname, &port);
        client_blocking_communicate(io);
    }
}
