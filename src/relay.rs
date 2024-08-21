use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
};

use crossbeam::{
    channel::{self, Receiver, Sender},
    select,
};

use etherparse::err::packet;
use log::{debug, info, warn};

use crate::{edns, TcpPacketSlice};

#[derive(Clone)]
pub enum Mode {
    Client,
    Server,
}

struct TcpPipe {
    tx: Sender<TcpPacketSlice>,
    rx: Receiver<TcpPacketSlice>,
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
}

unsafe impl Sync for Relay {}
pub struct Relay {
    tunnel: Box<dyn Tunnel>,
    tunnel_conn: UdpSocket,
    tcp_input_pipe: TcpPipe,
    tcp_output_pipe: TcpPipe,
    udp_pipe: TcpPipe,
}

impl Relay {
    pub fn connect<A: ToSocketAddrs>(remote: A, local: A) -> Result<Relay, RelayError> {
        let proxy_conn = UdpSocket::bind(local)?;
        info!("started udp client socket");
        UdpSocket::connect(&proxy_conn, &remote)?;
        let peer = proxy_conn.peer_addr()?;

        proxy_conn.send("client hello".as_bytes())?;

        let mut buf = [0u8; 1500];
        let nbytes = proxy_conn.recv(&mut buf)?;
        if &buf[..nbytes] != "server accept".as_bytes() {
            return Err(RelayError::TunnelAuthFailed);
        }
        info!("connected to proxy server");
        Ok(Self {
            tunnel_conn: proxy_conn,
            tunnel: Box::new(Client::connect(peer)),
            tcp_input_pipe: Default::default(),
            tcp_output_pipe: Default::default(),
            udp_pipe: Default::default(),
        })
    }
}

impl Relay {
    pub fn bind<A: ToSocketAddrs>(local: A) -> Result<Relay, RelayError> {
        let tunnel_conn = UdpSocket::bind(local)?;

        info!("started udp server socket");
        let mut buf = [0u8; 1500];
        let peer_addr = loop {
            let (nbytes, addr) = tunnel_conn.recv_from(&mut buf)?;
            if &buf[..nbytes] == "client hello".as_bytes() {
                tunnel_conn.send_to("server accept".as_bytes(), addr)?;
                break addr;
            }
        };
        info!("connected to proxy client");
        Ok(Self {
            tunnel_conn,
            tunnel: Box::new(Server::bind(Ipv4Addr::new(172, 16, 0, 2), peer_addr)),
            tcp_input_pipe: Default::default(),
            tcp_output_pipe: Default::default(),
            udp_pipe: Default::default(),
        })
    }
}

impl Relay {
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

    pub fn start_upd_pipe(&self) {
        let mut buf = [0; 1500];
        while let Ok(nbytes) = self.tunnel_conn.recv(&mut buf) {
            let packet = match self.tunnel.handle_packet(&buf[..nbytes]) {
                Some(p) => p,
                None => continue,
            };
            info!("received packet: {packet:?}");
            match self.udp_pipe.tx.send(packet) {
                Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                _ => {}
            }
        }
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
                    let dest = match self.tunnel.dest(&packet){
                        Some(dest) => dest ,
                        None =>{
                            warn!("destination not found for packet");
                            debug!("destination for packet {packet:?} not found");
                            continue;
                        },
                    };
                    match self.tunnel_conn.send_to(&buf, dest){
                        Err(_) => warn!("failed to transfer data from tunnel to iface. ignoring..."),
                        _ => {}
                    };
                },
                recv(self.udp_pipe.rx) -> packet => {
                    let packet = packet.map_err(|_| RelayError::PipeClosed).unwrap();
                    info!("upd pipe received packet: {packet:?}");
                    self.tcp_output_pipe.tx.send(packet).map_err(|_| RelayError::PipeClosed).unwrap();
                }
            }
        }
    }
}

pub trait Tunnel {
    fn dest(&self, packet: &TcpPacketSlice) -> Option<SocketAddr>;
    fn handle_packet(&self, buf: &[u8]) -> Option<TcpPacketSlice>;
}

pub struct Server {
    addr: HashMap<Ipv4Addr, SocketAddr>,
}

impl Server {
    fn bind(client_id: Ipv4Addr, client_addr: SocketAddr) -> Self {
        let mut addr = HashMap::new();
        addr.insert(client_id, client_addr);
        Self { addr }
    }
}

impl Tunnel for Server {
    fn dest(&self, packet: &TcpPacketSlice) -> Option<SocketAddr> {
        self.addr.get(&packet.destination_ip()).copied()
    }

    fn handle_packet(&self, buf: &[u8]) -> Option<TcpPacketSlice> {
        let buf = match edns::from_edns_packet(buf) {
            Ok(buf) => buf,
            Err(e) => {
                warn!("malformed packet received via tunnel. ignoring..");
                debug!("malformed packet received via tunnel: {e}");
                return None;
            }
        };
        let mut packet = [0; 1500];
        (&mut packet[..buf.len()]).copy_from_slice(&buf);
        Some(TcpPacketSlice(packet))
    }
}

pub struct Client {
    remote: SocketAddr,
}

impl Client {
    fn connect(remote: SocketAddr) -> Self {
        Self { remote }
    }
}

impl Tunnel for Client {
    fn dest(&self, _packet: &TcpPacketSlice) -> Option<SocketAddr> {
        Some(self.remote)
    }

    fn handle_packet(&self, buf: &[u8]) -> Option<TcpPacketSlice> {
        let buf = match edns::from_edns_packet(buf) {
            Ok(buf) => buf,
            Err(e) => {
                warn!("malformed packet received via tunnel. ignoring..");
                debug!("malformed packet received via tunnel: {e}");
                return None;
            }
        };
        let mut packet = [0; 1500];
        (&mut packet[..buf.len()]).copy_from_slice(&buf);
        Some(TcpPacketSlice(packet))
    }
}
