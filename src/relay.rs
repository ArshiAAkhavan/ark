use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Mutex,
};

use crossbeam::{
    channel::{self, Receiver, Sender},
    select,
};

use log::{debug, info, warn};

use crate::{edns, TcpPacketSlice};

#[derive(Clone)]
struct TcpPipe {
    tx: Sender<TcpPacketSlice>,
    rx: Receiver<TcpPacketSlice>,
}

type DataWithDestination = (Vec<u8>, Ipv4Addr);

#[derive(Clone)]
struct UdpPipe {
    tx: Sender<DataWithDestination>,
    rx: Receiver<DataWithDestination>,
}

impl UdpPipe {
    fn new() -> Self {
        let (tx, rx) = channel::unbounded();
        Self { tx, rx }
    }
}
impl Default for UdpPipe {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpPipe {
    fn new() -> Self {
        let (tx, rx) = channel::unbounded();
        Self { tx, rx }
    }
}

impl Default for TcpPipe {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RelayError {
    #[error("failed to create the Udp tunnel")]
    UdpSocketFailed(#[from] io::Error),

    #[error("authentication failed")]
    TunnelAuthFailed,

    #[error("pipe is closed and unable to transfer data")]
    PipeClosed,

    #[error("IpV6 not supported")]
    IpV6NotSupported,
}

unsafe impl Sync for Relay {}
#[derive(Clone)]
pub struct Relay {
    tcp_input_pipe: TcpPipe,
    tcp_output_pipe: TcpPipe,
    udp_input_pipe: TcpPipe,
    udp_output_tx: Sender<DataWithDestination>,
}

impl Relay {
    pub fn new(udp_output_tx: Sender<DataWithDestination>) -> Relay {
        Self {
            tcp_input_pipe: Default::default(),
            tcp_output_pipe: Default::default(),
            udp_input_pipe: Default::default(),
            udp_output_tx,
        }
    }

    pub fn write(&self, packet: TcpPacketSlice) -> Result<(), RelayError> {
        self.tcp_input_pipe
            .tx
            .send(packet)
            .map_err(|_| RelayError::PipeClosed)
    }

    pub fn read(&self) -> Result<TcpPacketSlice, RelayError> {
        self.tcp_output_pipe
            .rx
            .recv()
            .map_err(|_| RelayError::PipeClosed)
    }

    pub fn run(&self) {
        loop {
            select! {
                recv(self.tcp_input_pipe.rx) -> packet => {
                    let packet = packet.map_err(|_| RelayError::PipeClosed).unwrap();

                    let buf = match edns::to_edns_packet(packet.as_bytes()){
                        Ok(buf) => buf,
                        Err(e) => {
                            warn!("malformed packet received via tunnel. ignoring..");
                            debug!("malformed packet received via tunnel: {e}");
                            continue;
                        }
                    };

                    match self.udp_output_tx.send((buf, packet.destination_ip())) {
                        Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                        _ => {}
                    };
                },
                recv(self.udp_input_pipe.rx) -> packet => {
                    let packet = packet.map_err(|_| RelayError::PipeClosed).unwrap();
                    info!("upd pipe received packet: {packet:?}");
                    self.tcp_output_pipe.tx.send(packet).map_err(|_| RelayError::PipeClosed).unwrap();
                }
            }
        }
    }
}

pub trait Tunnel: Sync + Send {
    fn run(&self);
    fn run_udp_tunnel(&self);
    fn run_udp_pipe(&self);
    fn relay(&self) -> Relay;
}

pub struct Server {
    addr_map: Mutex<HashMap<Ipv4Addr, SocketAddr>>,
    base: Mutex<Ipv4Addr>,
    relay: Relay,
    udp_tunnel: UdpSocket,
    udp_output_pipe: UdpPipe,
}

impl Server {
    pub fn bind<A: ToSocketAddrs>(local: A, gateway: Ipv4Addr) -> Result<Self, RelayError> {
        let udp_tunnel = UdpSocket::bind(local)?;

        let udp_output_pipe = UdpPipe::default();
        let server = Self {
            addr_map: Mutex::new(HashMap::new()),
            relay: Relay::new(udp_output_pipe.tx.clone()),
            base: Mutex::new(gateway),
            udp_tunnel,
            udp_output_pipe,
        };
        info!("started udp server socket");
        Ok(server)
    }

    fn allocate_new_ip(&self, addr: SocketAddr) -> Ipv4Addr {
        let mut guard = self.base.lock().unwrap();
        let mut base = guard.octets();
        base[3] += 1;
        dbg!(base);
        *guard = Ipv4Addr::new(base[0], base[1], base[2], base[3]);
        self.addr_map.lock().unwrap().insert(*guard, addr);
        *guard
    }
}
impl Tunnel for Server {
    fn run_udp_tunnel(&self) {
        let mut buf = [0; 1500];
        while let Ok((nbytes, addr)) = self.udp_tunnel.recv_from(&mut buf) {
            // client sending handshake
            if &buf[..nbytes] == "client hello".as_bytes() {
                debug!("client with addr: [{addr}] sent connection request");
                let peer_ip = self.allocate_new_ip(addr);
                match self.udp_tunnel.send_to(
                    &["server accept".as_bytes(), &peer_ip.octets()[..]].concat(),
                    addr,
                ) {
                    Err(e) => {
                        warn!("failed to initiate handshake with client");
                        debug!("failed to initiate handshake with client {e}");
                        continue;
                    }
                    _ => {}
                }
                info!("connected to proxy client");
                continue;
            }

            // client sending data
            let buf = match edns::from_edns_packet(&buf[..nbytes]) {
                Ok(buf) => buf,
                Err(e) => {
                    warn!("malformed packet received via tunnel. ignoring..");
                    debug!("malformed packet received via tunnel: {e}");
                    continue;
                }
            };
            let mut packet = [0; 1500];
            (&mut packet[..buf.len()]).copy_from_slice(&buf);
            let packet = TcpPacketSlice(packet);

            info!("received packet: {packet:?}");
            match self.relay.udp_input_pipe.tx.send(packet) {
                Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                _ => {}
            }
        }
    }
    fn run_udp_pipe(&self) {
        loop {
            let (buf, dest_ip) = match self.udp_output_pipe.rx.recv() {
                Ok(d) => d,
                Err(e) => {
                    warn!("malformed packet received via tunnel. ignoring..");
                    debug!("malformed packet received via tunnel: {e}");
                    continue;
                }
            };
            let dest = match self.dest(dest_ip) {
                Some(dest) => dest,
                None => {
                    warn!("failed to find destination for packet");
                    continue;
                }
            };
            match self.udp_tunnel.send_to(&buf, dest) {
                Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                _ => {}
            }
        }
    }

    fn run(&self) {
        self.relay.run()
    }

    fn relay(&self) -> Relay {
        self.relay.clone()
    }
}

impl Server {
    fn dest(&self, dest_ip: Ipv4Addr) -> Option<SocketAddr> {
        self.addr_map.lock().unwrap().get(&dest_ip).copied()
    }
}

pub struct Client {
    remote: SocketAddr,
    relay: Relay,
    udp_tunnel: UdpSocket,
    udp_output_pipe: UdpPipe,
}

impl Client {
    pub fn connect<A: ToSocketAddrs>(remote: A, local: A) -> Result<(Self, Ipv4Addr), RelayError> {
        let udp_output_pipe = UdpPipe::default();

        let proxy_conn = UdpSocket::bind(local)?;
        info!("started udp client socket");
        UdpSocket::connect(&proxy_conn, &remote)?;
        let remote = proxy_conn.peer_addr()?;

        let client = Self {
            remote,
            relay: Relay::new(udp_output_pipe.tx.clone()),
            udp_tunnel: proxy_conn,
            udp_output_pipe,
        };

        client.udp_tunnel.send("client hello".as_bytes())?;

        let mut buf = [0u8; 1500];
        let nbytes = client.udp_tunnel.recv(&mut buf)?;
        let auth_prefix = "server accept";
        if &buf[..auth_prefix.len()] != auth_prefix.as_bytes() {
            return Err(RelayError::TunnelAuthFailed);
        }
        let ipv4_raw = &buf[auth_prefix.len()..nbytes];
        let ip = Ipv4Addr::new(ipv4_raw[0], ipv4_raw[1], ipv4_raw[2], ipv4_raw[3]);

        info!("connected to proxy server");
        info!("allocated ip is: {ip}");
        Ok((client, ip))
    }
}
impl Tunnel for Client {
    fn run_udp_tunnel(&self) {
        let mut buf = [0; 1500];
        while let Ok(nbytes) = self.udp_tunnel.recv(&mut buf) {
            let buf = match edns::from_edns_packet(&buf[..nbytes]) {
                Ok(buf) => buf,
                Err(e) => {
                    warn!("malformed packet received via tunnel. ignoring..");
                    debug!("malformed packet received via tunnel: {e}");
                    continue;
                }
            };
            let mut packet = [0; 1500];
            (&mut packet[..buf.len()]).copy_from_slice(&buf);
            let packet = TcpPacketSlice(packet);

            info!("received packet: {packet:?}");
            match self.relay.udp_input_pipe.tx.send(packet) {
                Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                _ => {}
            }
        }
    }
    fn run_udp_pipe(&self) {
        loop {
            let (buf, dest_ip) = match self.udp_output_pipe.rx.recv() {
                Ok(d) => d,
                Err(e) => {
                    warn!("malformed packet received via tunnel. ignoring..");
                    debug!("malformed packet received via tunnel: {e}");
                    continue;
                }
            };
            let dest = match self.dest(dest_ip) {
                Some(dest) => dest,
                None => {
                    warn!("failed to find destination for packet");
                    continue;
                }
            };
            match self.udp_tunnel.send_to(&buf, dest) {
                Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                _ => {}
            }
        }
    }

    fn run(&self) {
        self.relay.run()
    }

    fn relay(&self) -> Relay {
        self.relay.clone()
    }
}

impl Client {
    fn dest(&self, _packet: Ipv4Addr) -> Option<SocketAddr> {
        Some(self.remote)
    }
}
