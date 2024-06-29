mod edns;
mod relay;

use std::{fmt::Debug, net::Ipv4Addr};

pub use relay::{Mode as RelayMode, Relay, RelayError};

pub struct TcpPacketSlice([u8; 1500]);

impl TcpPacketSlice {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_packet_raw: &[u8]) -> Self {
        let mut packet = [0; 1500];

        let src_ptr = &mut packet[0..4];
        src_ptr.copy_from_slice(&src_ip.octets());

        let dst_ptr = &mut packet[4..8];
        dst_ptr.copy_from_slice(&dst_ip.octets());

        let payload_len_ptr = &mut packet[8..10];
        payload_len_ptr.copy_from_slice(&(tcp_packet_raw.len() as u16).to_be_bytes());

        let payload_ptr = &mut packet[10..tcp_packet_raw.len() + 10];
        payload_ptr.copy_from_slice(tcp_packet_raw);

        Self(packet)
    }

    pub fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[0], self.0[1], self.0[2], self.0[3])
    }
    pub fn destination_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[4], self.0[5], self.0[6], self.0[7])
    }
    pub fn packet_len(&self) -> u16 {
        u16::from_be_bytes([self.0[8], self.0[9]])
    }
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.0[10], self.0[11]])
    }
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.0[12], self.0[13]])
    }
    pub fn tcp_raw(&self) -> &[u8] {
        &self.0[10..self.packet_len() as usize + 10]
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[0..self.packet_len() as usize + 10]
    }
}

impl Debug for TcpPacketSlice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tcph =
            etherparse::TcpHeaderSlice::from_slice(&self.0[10..]).map_err(|_| std::fmt::Error)?;
        write!(
            f,
            "{}:{} -> {}:{}: len = {}",
            self.source_ip(),
            self.source_port(),
            self.destination_ip(),
            self.destination_port(),
            self.packet_len() - tcph.slice().len() as u16
        )
    }
}
