// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Turbo transport client IO implementation.

extern crate socket2;

use std::io::ErrorKind;
use std::net::ToSocketAddrs;

use crate::experimental::turbo::protocol::{self, ConnectionID, Packet, METADATA_SIZE};
use crate::experimental::turbo::support;

/// A client.
pub struct Client {
    /// The UDP socket.
    udp: std::net::UdpSocket,

    /// The TCP socket.
    tcp: socket2::Socket,

    /// The datagram stream.
    dg_stream: super::DatagramStream<support::Set<super::PartialDatagram>>,

    /// The current tunnel state.
    current_state: crate::pb::State,

    /// The ConnectionID.
    cid: ConnectionID,

    /// The index of the next UDP packet.
    index_out: u8,

    /// SID sent.
    tombstone_sent: bool,

    /// The duration to wait for operations to complete.
    /// Some(Duration(0s)) == NONBLOCKING
    /// None               == BLOCKING
    duration: Option<std::time::Duration>,
}

/// Implements [`std::fmt::Debug`] for [`Client`].
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Client[cid={:?}]", self.cid)
    }
}

/// Implements [`Client`].
impl Client {
    /// Instantiates a client using an socket address for TCP and a socket
    /// address for UDP.
    pub fn new(
        udp_addr: impl ToSocketAddrs,
        tcp_addr: impl ToSocketAddrs,
        is_blocking: bool,
    ) -> std::io::Result<Self> {
        let (tcp, _tcp_addr) = tcp_addr
            .to_socket_addrs()?
            .find_map(|sock_addr| {
                let tcp_addr: socket2::SockAddr = sock_addr.into();
                let tcp_sock = socket2::Socket::new(
                    tcp_addr.domain(),
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )
                .ok()?;
                if tcp_sock.set_nonblocking(true).is_err() {
                    return None;
                }
                // There is not an operating system agnostic way to check if the error to
                // connect is EINPROGRESS or another error. So for now we will assume all
                // errors returned by connect are EINPROGRESS (or the equivalent on other
                // platforms).
                let _ = tcp_sock.connect(&tcp_addr);
                Some((tcp_sock, tcp_addr))
            })
            .ok_or(ErrorKind::AddrNotAvailable)?;

        let mut err = std::io::Error::from(ErrorKind::AddrNotAvailable);
        let duration = if is_blocking {
            None
        } else {
            Some(std::time::Duration::from_secs(0))
        };
        let udp = udp_addr
            .to_socket_addrs()?
            .find_map(|sock_addr| {
                let udp_sock =
                    std::net::UdpSocket::bind((std::net::Ipv4Addr::new(0, 0, 0, 0), 0u16)).ok()?;
                if duration.is_some() {
                    udp_sock
                        .set_nonblocking(true)
                        .and_then(|_| udp_sock.connect(sock_addr))
                        .map_err(|e| {
                            err = e;
                        })
                        .ok()?;
                } else {
                    udp_sock
                        .set_nonblocking(false)
                        .and_then(|_| udp_sock.connect(sock_addr))
                        .map_err(|e| {
                            err = e;
                        })
                        .ok()?;
                }
                Some(udp_sock)
            })
            .ok_or(err)?;

        Ok(Self {
            udp,
            tcp,
            dg_stream: super::DatagramStream::new(),
            current_state: crate::pb::State::STATE_NOT_CONNECTED,
            cid: ConnectionID::from_rand(),
            index_out: 1u8,
            tombstone_sent: false,
            duration,
        })
    }
}

/// Implements [`crate::io::IO`] for [`Client`].
impl std::io::Read for Client {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_so_far = 0;
        let mut slice = &mut buf[..];
        log::debug!("Ask for reading {:#x} byte(s)", slice.len());
        // If the handshake is not done, read from UDP,
        // otherwise attempt to read from TCP.
        match self.current_state {
            crate::pb::State::STATE_HANDSHAKE_DONE => {
                log::debug!("TCP  for {:#x} byte(s)", slice.len());
                std::io::Read::read(&mut self.tcp, slice)
            }
            crate::pb::State::STATE_NOT_CONNECTED
            | crate::pb::State::STATE_CONNECTION_IN_PROGRESS
            | crate::pb::State::STATE_HANDSHAKE_IN_PROGRESS => loop {
                if let Ok((n, _index)) = self
                    .dg_stream
                    .read(Some(std::time::Duration::from_secs(0)), slice)
                {
                    log::debug!("Read {n:#x} bytes from dgstream");
                    read_so_far += n;
                    slice = &mut slice[n..]
                }
                if read_so_far > 0 {
                    log::debug!("read {read_so_far:#x} bytes");
                    return Ok(read_so_far);
                }
                let packet = Packet::from_udp(&mut self.udp);
                if let Ok(packet) = packet {
                    if packet.metadata().cid() != &self.cid {
                        log::warn!(
                            "Not same SID: self={:?}, other={:?}, index={:#x}",
                            self.cid,
                            packet.metadata().cid(),
                            packet.metadata().index()
                        );
                        return Err(ErrorKind::WouldBlock.into());
                    }
                    log::debug!("Received new packet {packet:?} from UDP");
                    self.dg_stream.insert(packet)?;
                } else {
                    log::debug!("Failed to read from UDP: {}", packet.unwrap_err());
                }
                if read_so_far == 0 && self.duration.is_none() {
                    continue;
                } else {
                    return Err(ErrorKind::WouldBlock.into());
                }
            },
            crate::pb::State::STATE_BEING_SHUTDOWN
            | crate::pb::State::STATE_DISCONNECTED
            | crate::pb::State::STATE_ERROR => {
                unreachable!();
            }
        }
    }
}

impl std::io::Write for Client {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        log::debug!("Ask for writing {:#x} bytes", buf.len());
        // If the handshake is not done, write to UDP,
        // otherwise attempt to write to TCP.
        match self.current_state {
            crate::pb::State::STATE_HANDSHAKE_DONE => {
                if !self.tombstone_sent {
                    let mut b = Vec::with_capacity(METADATA_SIZE);
                    b.write_all(self.cid.as_ref())?;
                    b.write_all(&[self.dg_stream.index() - 1])?;
                    if self.duration.is_none() {
                        self.tcp.set_nonblocking(false)?;
                    }
                    self.tcp.write_all(&b)?;
                    self.tombstone_sent = true;
                }
                log::debug!("writing to TCP");
                std::io::Write::write(&mut self.tcp, buf)
            }
            crate::pb::State::STATE_NOT_CONNECTED
            | crate::pb::State::STATE_CONNECTION_IN_PROGRESS
            | crate::pb::State::STATE_HANDSHAKE_IN_PROGRESS => {
                log::debug!("Writing {:#x} bytes to UDP", buf.len());
                let mut payload = [0u8; protocol::DATAGRAM_MAX_SIZE];
                protocol::serialize_metadata(
                    &self.cid,
                    self.index_out,
                    &mut std::io::Cursor::new(&mut payload[..]),
                )?;
                let mut slice = buf;
                let mut total_written = 0;
                let _ = std::cmp::min(protocol::PACKET_PAYLOAD_MAX_SIZE, slice.len());
                while !slice.is_empty()
                    || (self.index_out as usize) < protocol::TARGET_NUMBER_PACKETS
                {
                    let n = unsafe {
                        protocol::set_index_in_metadata_buffer(&mut payload[..], self.index_out);
                        if slice.is_empty() {
                            0
                        } else {
                            let n = std::cmp::min(protocol::PACKET_PAYLOAD_MAX_SIZE, slice.len());
                            payload
                                .as_mut_ptr()
                                .add(METADATA_SIZE)
                                .copy_from(slice.as_ptr(), n);
                            n
                        }
                    };
                    log::debug!(
                        "Sending {:#x} bytes ({n:#x} payload) to UDP",
                        METADATA_SIZE + n
                    );
                    self.udp.send(&payload[0..METADATA_SIZE + n])?;
                    slice = &slice[n..];
                    self.index_out += 1;
                    total_written += n;
                }
                log::debug!("SenT {total_written:#x} bytes to UDP so far");
                Ok(total_written)
            }
            crate::pb::State::STATE_BEING_SHUTDOWN
            | crate::pb::State::STATE_DISCONNECTED
            | crate::pb::State::STATE_ERROR => {
                unreachable!();
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // std::net::UdpSocket does not have a flush method, so only
        // flush the TcpStream.
        let _ = self.tcp.flush();
        Ok(())
    }
}

impl crate::tunnel::IO for Client {
    /// Update's the IO's stored tunnel state.
    fn set_state(&mut self, state: crate::pb::State) {
        self.current_state = state;
    }
}

/// Implements [`Drop`] for [`Client`].
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}
