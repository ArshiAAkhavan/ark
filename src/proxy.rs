use std::net::{ToSocketAddrs, UdpSocket};

use crossbeam::{
    channel::{self, Receiver, Sender},
    select,
};

use log::info;

use crate::TcpPacketSlice;

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
    UdpSocketError,
}

unsafe impl Sync for Relay {}
pub struct Relay {
    proxy_conn: UdpSocket,
    tcp_input_pipe: TcpPipe,
    tcp_output_pipe: TcpPipe,
    udp_pipe: TcpPipe,
}

impl Relay {
    pub fn new<A: ToSocketAddrs>(server_domain: A, mode: Mode) -> Self {
        let proxy_conn = match mode {
            Mode::Client => {
                let proxy_conn = UdpSocket::bind("0.0.0.0:9090").unwrap();
                info!("started udp client socket");
                UdpSocket::connect(&proxy_conn, server_domain).unwrap();
                info!("connected to proxy server");
                proxy_conn
            }
            Mode::Server => {
                let proxy_conn = UdpSocket::bind(server_domain).unwrap();
                info!("started udp server socket");
                proxy_conn
            }
        };
        Self {
            proxy_conn,
            tcp_input_pipe: Default::default(),
            tcp_output_pipe: Default::default(),
            udp_pipe: Default::default(),
        }
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
            let mut packet = [0; 1500];
            (&mut packet[0..nbytes]).copy_from_slice(&buf[0..nbytes]);
            info!("received packet: {packet:?}");
            self.tcp_output_pipe
                .tx
                .send(TcpPacketSlice(packet))
                .unwrap();
        }
    }

    pub fn run(&self) {
        loop {
            select! {
                recv(self.tcp_input_pipe.rx) -> packet => {
                    let packet = packet.unwrap();
                    self.proxy_conn.send(&(packet.0)).unwrap();
                },
                recv(self.udp_pipe.rx) -> packet => {
                    let packet = packet.unwrap();
                    self.tcp_output_pipe.tx.send(packet).unwrap();
                }
            }
        }
    }
}
