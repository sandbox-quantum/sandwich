// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TCP helper functions

/// A [`std::net::TcpStream`] sandwich wrapper.
pub(crate) struct TcpIo {
    stream: std::net::TcpStream,
}

/// Implements [`TcpIo`]
impl TcpIo {
    #[allow(dead_code)]
    /// Instantiates a [`TcpIo`] given a hostname, port, and whether it is blocking.
    pub(crate) fn new_client(
        hostname: &str,
        port: &u16,
        is_blocking: bool,
    ) -> crate::io::Result<TcpIo> {
        let addr = hostname.to_owned() + ":" + &port.to_string();
        use std::net::ToSocketAddrs;
        let sock_addr: std::net::SocketAddr = if let Ok(sa) = addr.to_socket_addrs() {
            sa.collect::<Vec<_>>()[0]
        } else {
            return Err(pb::IOError::IOERROR_INVALID.into());
        };
        let stream = match std::net::TcpStream::connect(sock_addr) {
            Ok(s) => s,
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    return Err(pb::IOError::IOERROR_REFUSED.into());
                }
                _ => return Err(pb::IOError::IOERROR_INVALID.into()),
            },
        };
        stream
            .set_nonblocking(!is_blocking)
            .map(|_| TcpIo { stream })
            .map_err(|_| pb::IOError::IOERROR_UNKNOWN.into())
    }

    #[allow(dead_code)]
    pub(crate) fn flush(&mut self) -> crate::io::Result<()> {
        self.stream
            .flush()
            .map_err(|_| pb::IOError::IOERROR_UNKNOWN.into())
    }
}

/// Instantiates a [`TcpIo`] from a [`std::net::TcpStream`].
impl std::convert::From<std::net::TcpStream> for TcpIo {
    fn from(stream: std::net::TcpStream) -> Self {
        Self { stream }
    }
}

use std::io::Read;
use std::io::Write;

/// implements [`crate::IO`] for [`TcpIo`].
impl crate::IO for TcpIo {
    fn read(&mut self, buf: &mut [u8], _state: pb::State) -> crate::io::Result<usize> {
        self.stream.read(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => pb::IOError::IOERROR_INVALID.into(),
            std::io::ErrorKind::BrokenPipe => pb::IOError::IOERROR_CLOSED.into(),
            std::io::ErrorKind::ConnectionAborted => pb::IOError::IOERROR_CLOSED.into(),
            std::io::ErrorKind::NotConnected => pb::IOError::IOERROR_CLOSED.into(),
            std::io::ErrorKind::WouldBlock => pb::IOError::IOERROR_WOULD_BLOCK.into(),
            _ => pb::IOError::IOERROR_UNKNOWN.into(),
        })
    }

    fn write(&mut self, buf: &[u8], _state: pb::State) -> crate::io::Result<usize> {
        self.stream.write(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => pb::IOError::IOERROR_INVALID.into(),
            std::io::ErrorKind::BrokenPipe => pb::IOError::IOERROR_CLOSED.into(),
            std::io::ErrorKind::ConnectionAborted => pb::IOError::IOERROR_CLOSED.into(),
            std::io::ErrorKind::NotConnected => pb::IOError::IOERROR_CLOSED.into(),
            std::io::ErrorKind::WouldBlock => pb::IOError::IOERROR_WOULD_BLOCK.into(),
            _ => pb::IOError::IOERROR_UNKNOWN.into(),
        })
    }

    fn close(&mut self) -> crate::io::Result<()> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .or_else(|e| match e.kind() {
                std::io::ErrorKind::NotConnected => Ok(()),
                _ => Err(e),
            })
            .map_err(|_| pb::IOError::IOERROR_UNKNOWN.into())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::io::helpers::tcp::TcpIo;
    use crate::io::IO;
    use std::io::Read;
    use std::io::Write;
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

    fn create_client(addr: &str, port: &u16, is_blocking: bool) -> TcpIo {
        TcpIo::new_client(addr, port, is_blocking).expect("Failed to create client")
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

    fn client_blocking_communicate(mut io: TcpIo) {
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
        match io.close() {
            Ok(()) => {}
            Err(e) => panic!("failed to close io: {}", e),
        }
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
        let io = create_client(hostname, &port, true);
        client_blocking_communicate(io);
    }
}
