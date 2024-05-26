use etherparse::IpNumber;
use log::{info, warn};

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let iface = tun_tap::Iface::new("ark", tun_tap::Mode::Tun)?;

    let mut buff = [0u8; 1504]; // MTU + 4 byte for header
    while let Ok(nbytes) = iface.recv(&mut buff) {
        let eth_proto = u16::from_be_bytes([buff[2], buff[3]]);

        match eth_proto {
            // Ipv4
            0x800 => match etherparse::Ipv4HeaderSlice::from_slice(&buff[4..nbytes]) {
                Ok(p) => {
                    let ip_proto = p.protocol();
                    let src_ip = p.source_addr();
                    let dst_ip = p.destination_addr();
                    let ip_payload_len = p.payload_len().unwrap_or(0);
                    match ip_proto {
                        IpNumber::TCP => {
                            match etherparse::TcpHeaderSlice::from_slice(
                                &buff[4 + p.slice().len()..nbytes],
                            ) {
                                Ok(p) => {
                                    let src_port = p.source_port();
                                    let dst_port = p.destination_port();
                                    let tcp_payload_len = ip_payload_len - p.slice().len() as u16;
                                    info!(
                                        "{src_ip}:{src_port} -> {dst_ip}:{dst_port}: len = {tcp_payload_len:?}"
                                    );
                                }
                                Err(_) => warn!("sick tcp packet"),
                            }
                        }
                        IpNumber::UDP => {}
                        _ => info!("sick layer4 protocol"),
                    }
                }
                Err(_) => info!("ignoring malformed ipv4 packet"),
            },
            _ => {
                info!("ignoring other ip layer protocols")
            }
        }
    }
    Ok(())
}
