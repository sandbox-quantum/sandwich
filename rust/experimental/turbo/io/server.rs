// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Turbo transport server IO implementation.

use std::io::ErrorKind;

use crate::experimental::turbo::protocol;
use crate::experimental::turbo::support;

/// A server.
pub struct Server {
    /// The UDP socket.
    udp: std::sync::Arc<std::net::UdpSocket>,

    /// The client address.
    udp_addr: std::net::SocketAddr,

    /// The TCP socket.
    tcp: std::sync::Arc<super::FutureTCPLink>,

    /// The datagram stream.
    dg_stream: std::sync::Arc<super::DatagramStream<support::ASet<super::PartialDatagram>>>,

    /// The current tunnel state.
    current_state: crate::pb::State,

    /// The index of the last UDP packet sent.
    index_out: u8,

    /// The ConnectionID.
    pub(super) cid: protocol::ConnectionID,

    /// A weak reference to the engine that created this IO.
    engine: std::sync::Arc<super::Engine>,

    /// The packets sent by the server. This is used to buffer messages sent
    /// over UDP. In the case a packet is dropped, we resend messages using this
    /// buffer.
    server_out: std::collections::HashMap<u8, protocol::Packet>,

    /// The fragments that were requested but weren't able to
    /// be responded to yet.
    pending_fragments: std::collections::HashSet<u8>,

    /// Indicates if the tombstone has been received and processed.
    tombstone_received: bool,
}

/// Implements [`std::fmt::Debug`] for [`Server`].
impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Server[cid={:?}]", self.cid)
    }
}

/// Implements [`Server`].
impl Server {
    /// Instantiates a server using a UDP socket and a UDP address.
    pub(crate) fn new(
        udp: std::sync::Arc<std::net::UdpSocket>,
        udp_addr: std::net::SocketAddr,
        tcp: std::sync::Arc<super::FutureTCPLink>,
        cid: &protocol::ConnectionID,
        engine: std::sync::Arc<super::Engine>,
    ) -> (
        Box<Self>,
        std::sync::Arc<super::DatagramStream<support::ASet<super::PartialDatagram>>>,
    ) {
        let s = Box::new(Self {
            udp,
            udp_addr,
            tcp,
            dg_stream: super::DatagramStream::<support::ASet<super::PartialDatagram>>::default()
                .into(),
            current_state: crate::pb::State::STATE_NOT_CONNECTED,
            index_out: 1,
            cid: *cid,
            engine,
            server_out: std::collections::HashMap::new(),
            tombstone_received: false,
            pending_fragments: std::collections::HashSet::<u8>::new(),
        });
        let stream = s.dg_stream.clone();
        (s, stream)
    }
}

/// Implements [`Drop`] for [`Server`].
impl Drop for Server {
    fn drop(&mut self) {
        self.engine.deregister(self.cid);
    }
}

/// Implements [`crate::io::IO`] for [`Server`].
impl std::io::Read for Server {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_so_far = 0;
        let slice = &mut buf[..];
        log::debug!("Ask for reading {:#x} byte(s)", slice.len());
        // If the handshake is not done, read from UDP,
        // otherwise read from TCP.

        match self.current_state {
            crate::pb::State::STATE_HANDSHAKE_DONE => {
                if !self.tombstone_received {
                    self.handle_tombstone()?;
                }
                log::debug!("goto TCP");
                self.tcp.read(slice)
            }
            crate::pb::State::STATE_NOT_CONNECTED
            | crate::pb::State::STATE_CONNECTION_IN_PROGRESS
            | crate::pb::State::STATE_HANDSHAKE_IN_PROGRESS => {
                log::debug!("Reading from UDP");
                if let Ok((n, index)) = self
                    .dg_stream
                    .read(Some(std::time::Duration::from_secs(0)), slice)
                {
                    log::debug!("Got {n:#x} bytes from dgstream with index: {index:#}");
                    read_so_far += n;
                    self.pending_fragments.insert(index);
                }
                let _ = self.respond_all();
                if read_so_far > 0 {
                    log::debug!("read {read_so_far:#x} bytes so far");
                    Ok(read_so_far)
                } else {
                    Err(ErrorKind::WouldBlock.into())
                }
            }
            crate::pb::State::STATE_BEING_SHUTDOWN
            | crate::pb::State::STATE_DISCONNECTED
            | crate::pb::State::STATE_ERROR => {
                unreachable!();
            }
        }
    }
}

impl std::io::Write for Server {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut slice = buf;
        log::debug!("Ask for writing {:#x} byte(s)", slice.len());
        // If the handshake is not done, write to UDP,
        // otherwise write to TCP.
        match self.current_state {
            crate::pb::State::STATE_HANDSHAKE_DONE => {
                log::debug!("goto TCP");
                self.tcp.write(slice)
            }
            crate::pb::State::STATE_NOT_CONNECTED
            | crate::pb::State::STATE_CONNECTION_IN_PROGRESS
            | crate::pb::State::STATE_HANDSHAKE_IN_PROGRESS => {
                log::debug!("Writing {:#x} to UDP", slice.len());
                let mut total_written = 0;
                while !slice.is_empty() {
                    let n = std::cmp::min(protocol::PACKET_PAYLOAD_MAX_SIZE, slice.len());
                    let packet = protocol::Packet::new(self.cid, self.index_out, slice, n)?;
                    self.index_out += 1;
                    slice = &slice[n..];
                    total_written += n;
                    self.server_out.insert(packet.index(), packet);
                }
                let _ = self.respond_all();
                log::debug!("Sent {total_written:#x} bytes to UDP so far");
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
        self.tcp.flush()
    }
}

impl Server {
    fn respond_all(&mut self) -> std::io::Result<()> {
        // If there are no indicies, check to see if we have received any dumby fragments.
        if self.pending_fragments.is_empty() {
            let mut buf = [0u8; protocol::DATAGRAM_MAX_SIZE];
            while let Ok((n, _, dg_size)) = self.dg_stream.peek(&mut buf) {
                if n == dg_size && n == 0 {
                    // This is a request-based fragmentation dumby packet.
                    if let Ok((_, index)) = self
                        .dg_stream
                        .read(Some(std::time::Duration::from_secs(0)), &mut buf)
                    {
                        self.pending_fragments.insert(index);
                    }
                } else {
                    break;
                }
            }
        }
        let indices = self.pending_fragments.iter().copied().collect::<Vec<u8>>();
        log::debug!("Attempting to send packets: {:?}", indices);
        for index in indices {
            log::debug!("processing index: {}", index);
            if let Some(packet) = self.server_out.get(&index) {
                let p: Vec<u8> = packet.into();
                self.udp.send_to(&p[..], self.udp_addr)?;
                self.pending_fragments.remove(&index);
            } else {
                log::debug!("No packet with index: {} ready to send", index);
            }
        }
        Ok(())
    }

    fn handle_tombstone(&mut self) -> std::io::Result<()> {
        let mut buf = [0u8; 1];
        let mut retry = true;
        while retry {
            if self.tcp.read_exact(&mut buf).is_ok() {
                retry = false;
            }
        }
        let last_udp = buf[0];
        self.tombstone_received = true;
        log::debug!("Client received up to {}", last_udp);
        if last_udp < self.index_out {
            log::debug!("Resending from {} to {}", last_udp, self.index_out);
            for i in last_udp + 1..self.index_out {
                let payload = if let Some(p) = self.server_out.get(&i) {
                    p
                } else {
                    return Err(ErrorKind::WouldBlock.into());
                }
                .payload();
                self.tcp.write(payload)?;
            }
        }
        self.server_out.clear();
        Ok(())
    }
}

impl crate::tunnel::IO for Server {
    /// Update's the IO's stored tunnel state.
    fn set_state(&mut self, state: crate::pb::State) {
        self.current_state = state;
        assert!(self.current_state == state);
    }
}
