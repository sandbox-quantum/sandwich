// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{TcpListener as RustTcpListener, ToSocketAddrs};

/// A [`std::net::TcpListener`] sandwich wrapper.
pub(crate) struct TcpListener {
    /// The [`std::net::TcpListener`] being wrapped.
    listener: RustTcpListener,
    /// Indicates whether this listener is blocking or not.
    is_blocking: bool,
}

/// Implements [`crate::io::helpers::tcp::TcpListener`].
impl TcpListener {
    /// Instantiates a [`crate::io::helpers::tcp::TcpListener`].
    #[allow(dead_code)]
    pub(crate) fn new(
        hostname: impl ToSocketAddrs,
        is_blocking: bool,
    ) -> Result<TcpListener, std::io::Error> {
        for listener in hostname
            .to_socket_addrs()?
            .filter_map(|sock_addr| RustTcpListener::bind(sock_addr).ok())
        {
            if listener.set_nonblocking(!is_blocking).is_err() {
                continue;
            } else {
                return Ok(TcpListener {
                    listener,
                    is_blocking,
                });
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "An unknown error has ocurred.",
        ))
    }
}

/// Implements [`crate::io::listener::Listener`] for [`crate::io::helpers::tcp::TcpListener`].
impl crate::io::listener::Listener for TcpListener {
    fn listen(&mut self) -> Result<(), std::io::Error> {
        // Rust's [`std::net::TcpListener`] performs a listen() call implicitly
        // when it `bind()`s therefore, this is a no-op.
        Ok(())
    }

    fn accept(&mut self) -> Result<Box<dyn crate::IO>, std::io::Error> {
        let stream = self.listener.accept()?.0;
        stream.set_nonblocking(!self.is_blocking)?;
        Ok(Box::new(stream))
    }

    fn close(&mut self) -> Result<(), std::io::Error> {
        // Rust's [`std::net::TcpListener`] does not have an explicit close()
        // function. The connection gets closed when the TcpListener gets
        // dropped, therefore this is a no-op.
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::net::TcpStream;

    use pb::State::STATE_CONNECTION_IN_PROGRESS;

    use crate::IO;

    use super::*;

    fn create_server(hostname: &str, port: &u16, is_blocking: bool) -> RustTcpListener {
        let addr = hostname.to_owned() + ":" + &port.to_string();
        let sock_addr: std::net::SocketAddr = match addr.to_socket_addrs() {
            Ok(sa) => sa.collect::<Vec<_>>()[0],
            Err(e) => {
                panic!("{e}");
            }
        };
        let listener = RustTcpListener::bind(sock_addr).expect("Failed to bind");
        match listener.set_nonblocking(!is_blocking) {
            Ok(_) => listener,
            Err(_) => panic!("failed set_nonblocking({}) call", !is_blocking),
        }
    }

    fn create_client(addr: &str, port: u16, is_blocking: bool) -> TcpStream {
        let stream = TcpStream::connect((addr, port)).expect("failed to connect");
        stream
            .set_nonblocking(!is_blocking)
            .expect("failed to set non blocking");
        stream
    }

    fn blocking_listener_thread(listener: RustTcpListener) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                handle_client_blocking(stream);
            }
            Err(e) => panic!("Failed to accept a connection: {e}"),
        }
    }

    fn handle_client_blocking(mut stream: TcpStream) {
        let mut recv = [0u8; 5];
        let send = [2u8; 3];
        match stream.read(&mut recv, STATE_CONNECTION_IN_PROGRESS) {
            Ok(5) => {}
            Ok(v) => panic!("Read the wrong amount of bytes. Expected 5, got {v}"),
            Err(e) => panic!("Failed to read: {}", e),
        }
        assert_eq!(recv, [0u8, 1u8, 2u8, 3u8, 4u8]);
        match stream.write(&send, STATE_CONNECTION_IN_PROGRESS) {
            Ok(3) => {}
            Ok(v) => panic!("Wrote wrong amount of bytes. Expected 3, got {v}"),
            Err(e) => panic!("Failed to write: {}", e),
        }
        _ = stream.shutdown(std::net::Shutdown::Both);
    }

    fn client_blocking_communicate(mut io: TcpStream) {
        let send = [0u8, 1u8, 2u8, 3u8, 4u8];
        let mut recv = [0u8; 3];
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
    fn test_blocking_io_with_std() {
        let port = pseudo_random(generate_seed());
        let hostname = "localhost";
        let listener = create_server("localhost", &port, true);
        std::thread::spawn(move || blocking_listener_thread(listener));
        // give enough time for thread to set itself up before trying to connect
        std::thread::sleep(std::time::Duration::from_secs(1));
        let io = create_client(hostname, port, true);
        client_blocking_communicate(io);
    }
}
