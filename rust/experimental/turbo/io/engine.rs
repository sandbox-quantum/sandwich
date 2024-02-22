// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Turbo transport server engine responsible for routing
//! UDP packets, and TCP connections to the correct server IO.

extern crate polling;

use std::io::ErrorKind;
use std::net::ToSocketAddrs;
use std::sync::atomic::Ordering;

use crate::experimental::turbo::protocol::{ConnectionID, Packet, DATAGRAM_MAX_SIZE};
#[cfg(feature = "ffi")]
use crate::ffi::io::OwnedIo;

/// A future TCP link.
pub(crate) struct FutureTCPLink {
    /// The TCP link.
    tcp: std::cell::RefCell<Option<std::net::TcpStream>>,

    /// Atomic boolean to tell if the the link is here.
    here: std::sync::atomic::AtomicBool,

    /// Fast access to here.
    fast_here: std::cell::Cell<bool>,
}

unsafe impl Sync for FutureTCPLink {}

/// Instantiates a [`FutureTCPLink`] with a [`std::net::TcpStream`].
impl From<std::net::TcpStream> for FutureTCPLink {
    fn from(tcp: std::net::TcpStream) -> Self {
        Self {
            tcp: std::cell::RefCell::new(Some(tcp)),
            here: true.into(),
            fast_here: std::cell::Cell::new(true),
        }
    }
}

/// Implements [`FutureTCPLink`].
impl FutureTCPLink {
    /// Instantiates an empty [`FutureTCPLink`].
    pub(crate) fn new() -> Self {
        Self {
            tcp: std::cell::RefCell::new(None),
            here: false.into(),
            fast_here: std::cell::Cell::new(false),
        }
    }

    /// Reads from the TCP link.
    pub(crate) fn read(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.fast_here.get() || self.here.load(Ordering::Acquire) {
            if let Some(ref mut tcp) = *self
                .tcp
                .try_borrow_mut()
                .map_err(|_| <ErrorKind as Into<std::io::Error>>::into(ErrorKind::WouldBlock))?
            {
                use std::io::Read;
                return tcp.read(buffer);
            }
        }
        Err(ErrorKind::WouldBlock.into())
    }

    /// Reads from the TCP link untill given buffer is full.
    pub(crate) fn read_exact(&self, buffer: &mut [u8]) -> std::io::Result<()> {
        if self.fast_here.get() || self.here.load(Ordering::Acquire) {
            if let Some(ref mut tcp) = *self
                .tcp
                .try_borrow_mut()
                .map_err(|_| <ErrorKind as Into<std::io::Error>>::into(ErrorKind::WouldBlock))?
            {
                use std::io::Read;
                return tcp.read_exact(buffer);
            }
        }
        Err(ErrorKind::WouldBlock.into())
    }

    /// Writes to the TCP link.
    pub(crate) fn write(&self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.fast_here.get() || self.here.load(Ordering::Acquire) {
            if let Some(ref mut tcp) = *self
                .tcp
                .try_borrow_mut()
                .map_err(|_| <ErrorKind as Into<std::io::Error>>::into(ErrorKind::WouldBlock))?
            {
                use std::io::Write;
                return tcp.write(buffer);
            }
        }
        Err(ErrorKind::WouldBlock.into())
    }

    /// Flushes underlying TCPStream.
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        if self.fast_here.get() || self.here.load(Ordering::Acquire) {
            if let Some(ref mut tcp) = *self
                .tcp
                .try_borrow_mut()
                .map_err(|_| <ErrorKind as Into<std::io::Error>>::into(ErrorKind::WouldBlock))?
            {
                use std::io::Write;
                return tcp.flush();
            }
        }
        Ok(())
    }

    /// Sets underlying TCPStream as nonblocking or not.
    pub(crate) fn set_nonblocking(&self, set_nonblocking: bool) -> std::io::Result<()> {
        if self.fast_here.get() || self.here.load(Ordering::Acquire) {
            if let Some(ref tcp) = *self
                .tcp
                .try_borrow()
                .map_err(|_| <ErrorKind as Into<std::io::Error>>::into(ErrorKind::WouldBlock))?
            {
                return tcp.set_nonblocking(set_nonblocking);
            }
        }
        Err(ErrorKind::NotConnected.into())
    }

    /// Sets the TCP link.
    fn set(&self, tcp: std::net::TcpStream) {
        self.tcp.replace(Some(tcp));
        self.here.store(true, Ordering::Release);
        self.fast_here.set(true);
    }

    /// Returns whether the TCP link is set or not.
    pub(crate) fn is_set(&self) -> bool {
        self.tcp.borrow().is_some()
    }
}

/// Implements [`Drop`] for [`FutureTCPLink`].
impl Drop for FutureTCPLink {
    fn drop(&mut self) {
        if self.fast_here.get() || self.here.load(Ordering::Acquire) {
            if let Ok(v) = self.tcp.try_borrow() {
                if let Some(ref s) = *v {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }
}

/// A server.
struct ServerHandle {
    /// The server's datagram stream.
    dg_stream: std::sync::Weak<
        super::DatagramStream<crate::experimental::turbo::support::ASet<super::PartialDatagram>>,
    >,

    /// The server's TCP link.
    tcp: std::sync::Arc<FutureTCPLink>,

    /// The server's UDP address.
    udp_addr: Option<std::net::SocketAddr>,
}

/// The Turbo transport engine.
pub(crate) struct Engine {
    /// The listening UDP socket.
    udp: std::sync::Arc<std::net::UdpSocket>,

    /// The listening TCP socket.
    tcp: std::net::TcpListener,

    /// Map of ConnectionID and ServerHandle.
    server_handles: std::sync::Mutex<std::collections::HashMap<ConnectionID, ServerHandle>>,

    /// List of Servers.
    servers: std::sync::Mutex<std::collections::VecDeque<Box<super::Server>>>,

    /// Condvar to signal when a new server is available.
    servers_cv: std::sync::Condvar,

    /// Boolean to stop the engine.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// Indicates whether ServerIOs are blocking or not.
    /// Some(Duration(0s)) == NONBLOCKING
    /// None               == BLOCKING
    duration: Option<std::time::Duration>,
}

/// Implements [`std::fmt::Debug`] for [`Engine`].
impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Engine[handles count = {:#x}, servers count = {:#x}]",
            self.server_handles
                .lock()
                .expect("poisoned map mutex")
                .len(),
            self.servers.lock().expect("poisoned servers mutex").len()
        )
    }
}

/// Turbo Transport Listener.
pub struct TurboListener {
    /// The Turbo engine.
    engine: Option<std::sync::Arc<Engine>>,

    /// The shared UDP socket.
    udp_socket: Option<std::net::UdpSocket>,

    /// The listening TCP listener.
    tcp_listener: Option<std::net::TcpListener>,

    /// The thread that handles UDP packets.
    udp_thread: Option<std::thread::JoinHandle<()>>,

    /// The thread that handles TCP connections.
    tcp_thread: Option<std::thread::JoinHandle<()>>,

    /// Indicates if listener is blocking or not.
    /// Some(Duration(0s)) == NONBLOCKING
    /// None               == BLOCKING
    duration: Option<std::time::Duration>,
}

/// Implements [`TurboListener`].
impl TurboListener {
    /// Instantiates an Engine from an IP address for UDP listening and an IP address for TCP listening.
    pub fn new(
        udp_addr: impl ToSocketAddrs,
        tcp_addr: impl ToSocketAddrs,
        is_blocking: bool,
    ) -> std::io::Result<TurboListener> {
        let udp = match udp_addr
            .to_socket_addrs()?
            .find_map(|sock_addr| std::net::UdpSocket::bind(sock_addr).ok())
        {
            Some(u) => {
                u.set_nonblocking(false)?;
                u
            }
            None => return Err(ErrorKind::AddrNotAvailable.into()),
        };

        let tcp = match tcp_addr
            .to_socket_addrs()?
            .find_map(|sock_addr| std::net::TcpListener::bind(sock_addr).ok())
        {
            Some(t) => {
                t.set_nonblocking(true)?;
                t
            }
            None => return Err(ErrorKind::AddrNotAvailable.into()),
        };
        let duration = if is_blocking {
            None
        } else {
            Some(std::time::Duration::from_secs(0))
        };
        Ok(TurboListener {
            engine: None,
            udp_socket: Some(udp),
            tcp_listener: Some(tcp),
            udp_thread: None,
            tcp_thread: None,
            duration,
        })
    }

    /// Handles new UDP clients, and UDP packet routing to already existing clients.
    fn handle_udp_clients(engine: std::sync::Arc<Engine>) {
        let mut payload = [0u8; DATAGRAM_MAX_SIZE];
        while !engine.stop.load(Ordering::Acquire) {
            let (n, addr) = match engine.udp.recv_from(&mut payload[..]) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("failed to read from udp: {e}");
                    continue;
                }
            };
            let packet = match Packet::try_from(&payload[..n]) {
                Ok(p) => p,
                Err(e) => {
                    log::error!("Invalid datagram: {e}");
                    continue;
                }
            };
            let mut map = engine.server_handles.lock().expect("poisoned map mutex");
            let cid = packet.metadata().cid();
            if map.contains_key(cid) {
                // The appropriate server IO already exists, so we just need to route this
                // packet to the appropriate server IO.
                let entry = match map.get_mut(cid) {
                    Some(v) => v,
                    None => unreachable!(),
                };
                if let Some(stream) = entry.dg_stream.upgrade() {
                    log::debug!("server handle is still here. Inserting to the map.");
                    if let Err(e) = stream.insert(packet) {
                        log::debug!("Failed to insert packet into dg_stream: {e}");
                        continue;
                    }
                } else if entry.udp_addr.is_some() {
                    log::debug!("server handle is gone. removing it from the map");
                    map.remove(cid);
                } else {
                    // TCP first, UDP second, we maye be in loopback. Create a new server IO.
                    log::debug!(
                        "TCP came first, SID={cid:?}, index={:#x}",
                        packet.metadata().index()
                    );
                    let (server, dg_stream) = super::Server::new(
                        engine.udp.clone(),
                        addr,
                        entry.tcp.clone(),
                        cid,
                        engine.clone(),
                    );
                    engine
                        .servers
                        .lock()
                        .expect("poisoned server mutex")
                        .push_back(server);
                    entry.udp_addr = Some(addr);
                    if let Err(e) = dg_stream.insert(packet) {
                        log::debug!("Failed to insert packet into dg_stream: {e}");
                        continue;
                    }
                    engine.servers_cv.notify_one();
                }
            } else {
                // We haven't received this Connection ID yet, so this is a new connection.
                // Create a new ServerIO to be queued until the listener's accept() is called.
                log::debug!(
                    "new entry, SID={cid:?}, index={:#x}",
                    packet.metadata().index()
                );
                let tcp = std::sync::Arc::new(FutureTCPLink::new());
                let (server, dg_stream) =
                    super::Server::new(engine.udp.clone(), addr, tcp.clone(), cid, engine.clone());
                engine
                    .servers
                    .lock()
                    .expect("poisoned server mutex")
                    .push_back(server);
                map.insert(
                    *cid,
                    ServerHandle {
                        dg_stream: std::sync::Arc::downgrade(&dg_stream),
                        tcp,
                        udp_addr: Some(addr),
                    },
                );
                if let Err(e) = dg_stream.insert(packet) {
                    log::debug!("Failed to insert packet into dg_stream: {e}");
                    continue;
                }
                engine.servers_cv.notify_one();
            }
        }
    }

    ///  Handles new TCP clients and associating TCP links to the appropriate server IO.
    fn handle_tcp_clients(engine: std::sync::Arc<Engine>) {
        let p = polling::Poller::new().expect("polling not supported");
        if let Err(e) = p.add_with_mode(
            &engine.tcp,
            polling::Event::readable(0),
            polling::PollMode::Oneshot,
        ) {
            log::error!("Cannot add tcp socket to poll list: {e}");
            engine.stop.store(true, Ordering::Release);
            return;
        }

        let mut events = std::vec::Vec::with_capacity(512);
        let mut tcp_clients = std::collections::HashMap::with_capacity(512);
        let mut i = 1;
        let mut cid = ConnectionID::default();
        let mut tcp_clients_to_link = std::collections::HashMap::with_capacity(512);
        while !engine.stop.load(Ordering::Acquire) {
            log::debug!("Waiting for TCP");
            events.clear();
            let n = match p.wait(&mut events, None) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("polling wait failed: {e}");
                    continue;
                }
            };
            log::debug!("poller triggered {n} events");
            for e in events[..n].iter() {
                log::debug!("poller e.key={}, e={:?}", e.key, e);
                if e.key == 0 {
                    // new client
                    let tcp = match engine.tcp.accept() {
                        Ok(v) => v.0,
                        Err(e) => {
                            log::warn!("failed to accept: {e}");
                            if let Err(e) = p.add_with_mode(
                                &engine.tcp,
                                polling::Event::readable(0),
                                polling::PollMode::Oneshot,
                            ) {
                                log::error!("polling add failed: {e}");
                                engine.stop.store(true, Ordering::Release);
                                return;
                            }
                            continue;
                        }
                    };
                    if engine.is_blocking() {
                        if let Err(e) = tcp.set_nonblocking(false) {
                            log::error!("failed to set new tcp connection as blocking: {e}");
                        }
                    } else if let Err(e) = tcp.set_nonblocking(true) {
                        log::error!("failed to set new tcp connection as non-blocking: {e}");
                    }
                    // Add to poll list until tombstone is received.
                    if let Err(e) = p.add_with_mode(
                        &tcp,
                        polling::Event::readable(i),
                        polling::PollMode::Oneshot,
                    ) {
                        log::error!("polling add failed: {e}");
                        continue;
                    }
                    log::debug!("new TCP client, i={i:#x}");
                    tcp_clients.insert(i, tcp);
                    i += 1;
                    if let Err(e) = p.add_with_mode(
                        &engine.tcp,
                        polling::Event::readable(0),
                        polling::PollMode::Oneshot,
                    ) {
                        log::error!("polling add failed: {e}");
                        continue;
                    }
                    continue;
                } else {
                    log::debug!("Event on client TCP");
                    // TCP clients contain TCP links which have not been associated with
                    // server IO structs yet.
                    let mut cli = match tcp_clients.remove(&e.key) {
                        Some(v) => v,
                        None => {
                            log::warn!("None on tcp cli map…");
                            continue;
                        }
                    };
                    if let Err(e) = p.delete(&cli) {
                        log::error!("Failed to delete cli from p: {e}");
                        continue;
                    }

                    use std::io::Read;
                    if let Ok(()) = cli.read_exact(cid.as_mut()) {
                        tcp_clients_to_link.insert(cid, cli);
                    } else {
                        log::warn!("failed to read");
                        if let Err(e) = cli.shutdown(std::net::Shutdown::Both) {
                            log::warn!("failed to shutdown tcp connection: {e}");
                        }
                        drop(cli);
                        continue;
                    }
                }
            }
            if !tcp_clients_to_link.is_empty() {
                // Link all TCP links that have we have received the tombstone for.
                let mut map = engine.server_handles.lock().expect("poisoned map mutex");
                for (cid, tcp) in tcp_clients_to_link.drain().take(1) {
                    if let std::collections::hash_map::Entry::Vacant(e) = map.entry(cid) {
                        log::debug!("new entry, SID={cid:?}, with TCP");
                        e.insert(ServerHandle {
                            dg_stream: std::sync::Weak::new(),
                            tcp: std::sync::Arc::new(tcp.into()),
                            udp_addr: None,
                        });
                    } else {
                        let entry = match map.get(&cid) {
                            Some(v) => v,
                            None => {
                                log::warn!("failed to find cid");
                                continue;
                            }
                        };
                        if entry.dg_stream.upgrade().is_some() {
                            log::debug!("server handle is still here. Setting the TCP link.");
                            entry.tcp.set(tcp);
                        } else {
                            log::debug!("server handle is gone. removing it from the map");
                            map.remove(&cid);
                            if let Err(e) = tcp.shutdown(std::net::Shutdown::Both) {
                                log::warn!("Failed to shutdown TCP: {e}");
                            }
                        }
                    }
                }
            }
            tcp_clients_to_link.clear();
        }
    }
}

/// Implements [`Drop`] for [`TurboListener`].
impl Drop for TurboListener {
    fn drop(&mut self) {
        if let Some(ref e) = self.engine {
            e.stop.store(true, Ordering::Release);
        }
    }
}

/// Implements [`crate::io::listener::Listener`] for [`TurboListener`].
impl crate::io::listener::Listener for TurboListener {
    fn listen(&mut self) -> std::io::Result<()> {
        let udp = match self.udp_socket.take() {
            Some(v) => v,
            None => return Ok(()),
        };
        let tcp = match self.tcp_listener.take() {
            Some(v) => v,
            None => return Ok(()),
        };
        let engine = std::sync::Arc::new(Engine {
            udp: std::sync::Arc::new(udp),
            tcp,
            server_handles: std::collections::HashMap::<ConnectionID, ServerHandle>::new().into(),
            servers: std::collections::VecDeque::new().into(),
            servers_cv: std::sync::Condvar::new(),
            stop: std::sync::Arc::new(false.into()),
            duration: self.duration,
        });

        let e = engine.clone();
        let udp_thread = std::thread::spawn(move || {
            TurboListener::handle_udp_clients(e);
        });

        let e = engine.clone();
        let tcp_thread = std::thread::spawn(move || {
            TurboListener::handle_tcp_clients(e);
        });
        self.engine = Some(engine);
        self.udp_thread = Some(udp_thread);
        self.tcp_thread = Some(tcp_thread);
        Ok(())
    }

    fn accept(&mut self) -> std::io::Result<Box<dyn crate::IO>> {
        if self.udp_thread.is_none() || self.tcp_thread.is_none() || self.engine.is_none() {
            Err(ErrorKind::Unsupported.into())
        } else {
            match self.engine.as_mut() {
                Some(v) => Ok(v.get_server()?),
                None => Err(ErrorKind::Unsupported.into()),
            }
        }
    }

    #[cfg(feature = "ffi")]
    fn ffi_accept_owned(&mut self) -> std::io::Result<Box<OwnedIo>> {
        if self.udp_thread.is_none() || self.tcp_thread.is_none() || self.engine.is_none() {
            Err(ErrorKind::Unsupported.into())
        } else {
            match self.engine.as_mut() {
                Some(v) => v.get_server().map(OwnedIo::from_turbo_server_boxed),
                None => Err(ErrorKind::Unsupported.into()),
            }
        }
    }

    fn close(&mut self) -> std::io::Result<()> {
        self.engine = None;
        self.udp_thread = None;
        self.tcp_thread = None;
        Ok(())
    }
}

/// Implements [`Engine`].
impl Engine {
    /// Pop a new server, return WouldBlock if no server is available.
    pub(crate) fn get_server(&self) -> std::io::Result<Box<super::Server>> {
        if self.duration.is_none() {
            let mut r = self
                .servers_cv
                .wait_while(self.servers.lock().expect("poisoned server mutex"), |s| {
                    s.is_empty()
                })
                .expect("poisoned cv server mutex");
            match r.pop_front() {
                Some(v) => Ok(v),
                None => unreachable!(),
            }
        } else {
            let mut r = self
                .servers_cv
                .wait_timeout_while(
                    self.servers.lock().expect("poisoned server mutex"),
                    std::time::Duration::from_secs(0),
                    |s| s.is_empty(),
                )
                .expect("poisoned cv server mutex");
            if r.1.timed_out() {
                Err(std::io::ErrorKind::WouldBlock.into())
            } else {
                match r.0.pop_front() {
                    Some(v) => Ok(v),
                    None => unreachable!(),
                }
            }
        }
    }

    /// Deregister a server.
    pub(crate) fn deregister(&self, cid: ConnectionID) {
        self.server_handles
            .lock()
            .expect("poisoned map mutex")
            .remove(&cid);
    }

    /// Returns whether ServerIOs that belong to this engine are blocking
    /// or not.
    pub(crate) fn is_blocking(&self) -> bool {
        self.duration.is_none()
    }
}
