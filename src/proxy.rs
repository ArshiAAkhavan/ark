use std::{
    io,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
};

use crossbeam::{
    channel::{self, Receiver, Sender},
    select,
};

use log::info;

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

#[derive(Debug)]
pub enum Error {
    PipeError,
    UdpSocketError(io::Error),
}

unsafe impl Sync for Relay {}
pub struct Relay {
    proxy_conn: UdpSocket,
    peer_addr: SocketAddr,
    tcp_input_pipe: TcpPipe,
    tcp_output_pipe: TcpPipe,
    udp_pipe: TcpPipe,
}

impl Relay {
    pub fn new<A: ToSocketAddrs>(local: A, remote: A, mode: Mode) -> Result<Self, Error> {
        let (proxy_conn, peer_addr) = match mode {
            Mode::Client => {
                let proxy_conn = UdpSocket::bind(local)?;
                info!("started udp client socket");
                UdpSocket::connect(&proxy_conn, &remote)?;
                proxy_conn.send("client hello".as_bytes())?;

                let mut buf = [0u8; 1500];
                let nbytes = proxy_conn.recv(&mut buf)?;
                if &buf[..nbytes] != "server accept".as_bytes() {
                    return Err(Error::UdpSocketError(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "failed to handshake with server",
                    )));
                }
                info!("connected to proxy server");
                (
                    proxy_conn,
                    remote
                        .to_socket_addrs()?
                        .next()
                        .ok_or(Error::UdpSocketError(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "failed to handshake with server",
                        )))?,
                )
            }
            Mode::Server => {
                let proxy_conn = UdpSocket::bind(local).unwrap();
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
            proxy_conn,
            peer_addr,
            tcp_input_pipe: Default::default(),
            tcp_output_pipe: Default::default(),
            udp_pipe: Default::default(),
        })
    }

    pub fn write(&self, packet: TcpPacketSlice) -> Result<(), Error> {
        self.tcp_input_pipe
            .tx
            .send(packet)
            .map_err(|_| Error::PipeError)
    }

    pub fn read(&self) -> Result<TcpPacketSlice, Error> {
        self.tcp_output_pipe.rx.recv().map_err(|_| Error::PipeError)
    }

    pub fn start_upd_pipe(&self) {
        let mut buf = [0; 1500];
        while let Ok(nbytes) = self.proxy_conn.recv(&mut buf) {
            let buf = edns::from_edns_packet(&buf[..nbytes]).unwrap();
            let mut packet = [0; 1500];
            (&mut packet[..buf.len()]).copy_from_slice(&buf);
            let packet = TcpPacketSlice(packet);
            info!("received packet: {packet:?}");
            self.udp_pipe.tx.send(packet).unwrap();
        }
    }

    pub fn run(&self) {
        loop {
            select! {
                recv(self.tcp_input_pipe.rx) -> packet => {
                    let packet = packet.unwrap();

                    let buf = edns::to_edns_packet(packet.as_bytes()).unwrap();
                    self.proxy_conn.send_to(&buf, self.peer_addr).unwrap();
                },
                recv(self.udp_pipe.rx) -> packet => {
                    let packet = packet.unwrap();
                    info!("upd pipe received packet: {packet:?}");
                    self.tcp_output_pipe.tx.send(packet).unwrap();
                }
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::UdpSocketError(value)
    }
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::PipeError => io::Error::new(io::ErrorKind::BrokenPipe, "pipe error"),
            Error::UdpSocketError(e) => e,
        }
    }
}
