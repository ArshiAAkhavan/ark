use std::{
    io,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
};

use crossbeam::{
    channel::{self, Receiver, Sender},
    select,
};

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
    tunnel_conn: UdpSocket,
    peer_addr: SocketAddr,
    tcp_input_pipe: TcpPipe,
    tcp_output_pipe: TcpPipe,
    udp_pipe: TcpPipe,
}

impl Relay {
    pub fn new<A: ToSocketAddrs>(local: A, remote: A, mode: Mode) -> Result<Self, RelayError> {
        let (proxy_conn, peer_addr) = match mode {
            Mode::Client => {
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
                (proxy_conn, peer)
            }
            Mode::Server => {
                let proxy_conn = UdpSocket::bind(local)?;

                info!("started udp server socket");
                let mut buf = [0u8; 1500];
                let peer_addr = loop {
                    let (nbytes, addr) = proxy_conn.recv_from(&mut buf)?;
                    if &buf[..nbytes] == "client hello".as_bytes() {
                        proxy_conn.send_to("server accept".as_bytes(), addr)?;
                        break addr;
                    }
                };
                info!("connected to proxy client");
                (proxy_conn, peer_addr)
            }
        };
        Ok(Self {
            tunnel_conn: proxy_conn,
            peer_addr,
            tcp_input_pipe: Default::default(),
            tcp_output_pipe: Default::default(),
            udp_pipe: Default::default(),
        })
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

    pub fn start_upd_pipe(&self) {
        let mut buf = [0; 1500];
        while let Ok(nbytes) = self.tunnel_conn.recv(&mut buf) {
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
                    match self.tunnel_conn.send_to(&buf, self.peer_addr){
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
