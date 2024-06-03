use std::thread;

use ark::{ProxyMode, ProxyRelay, TcpPacketSlice};
use etherparse::IpNumber;
use log::{debug, info, warn};

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let iface = tun_tap::Iface::without_packet_info("ark", tun_tap::Mode::Tun)?;

    let proxy = ProxyRelay::new("127.0.0.1:7070", ProxyMode::Client);

    thread::scope(|s| {
        s.spawn(|| proxy.start_upd_pipe());
        s.spawn(|| proxy.run());
        s.spawn(|| read_from_nic(iface, &proxy));
    });

    Ok(())
}

fn read_from_nic(iface: tun_tap::Iface, proxy: &ProxyRelay) {
    let mut buff = [0u8; 1500];
    while let Ok(nbytes) = iface.recv(&mut buff) {
        if let Ok(iph) = etherparse::Ipv4HeaderSlice::from_slice(&buff[..nbytes]) {
            let ip_proto = iph.protocol();
            let src_ip = iph.source_addr();
            let dst_ip = iph.destination_addr();
            let ip_header_end_index = iph.slice().len();
            match ip_proto {
                IpNumber::TCP => {
                    match etherparse::TcpHeaderSlice::from_slice(&buff[ip_header_end_index..nbytes])
                    {
                        Ok(_tcph) => {
                            let packet = TcpPacketSlice::new(
                                src_ip,
                                dst_ip,
                                &buff[ip_header_end_index..nbytes],
                            );
                            info!("iface: {packet:?}");
                            proxy.write(packet).unwrap();
                        }
                        Err(_) => warn!("sick tcp packet"),
                    }
                }
                _ => debug!("sick layer4 protocol {ip_proto:?}"),
            }
        }
    }
}
