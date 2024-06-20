use std::{net::Ipv4Addr, process::Command, thread};

use ark::{ProxyMode, ProxyRelay, TcpPacketSlice};
use etherparse::IpNumber;
use log::{debug, info, warn};

use clap::{Parser, ValueEnum};

#[derive(Clone, ValueEnum, Default)]
pub enum Mode {
    #[default]
    Client,
    Server,
}

impl From<Mode> for ProxyMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Client => ProxyMode::Client,
            Mode::Server => ProxyMode::Server,
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
#[clap(rename_all = "kebab_case")]
struct Opts {
    /// Address of the proxy server
    #[arg(short, long)]
    proxy_server: String,

    /// weather to run in client mode or server mode
    #[arg(short, long)]
    mode: Mode,

    /// subnet range to listen on
    #[arg(short, long)]
    subnet: String,
}

fn main() -> std::io::Result<()> {
    let opts: Opts = Opts::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let iface = setup_iface(&opts.subnet)?;
    let proxy = ProxyRelay::new(opts.proxy_server, opts.mode.into());
    let gateway_ip = opts.subnet.split("/").nth(0).unwrap();

    thread::scope(|s| {
        s.spawn(|| proxy.start_upd_pipe());
        s.spawn(|| proxy.run());
        s.spawn(|| read_from_nic(&iface, &proxy));
        s.spawn(|| write_to_nic(&iface, gateway_ip, &proxy));
    });

    Ok(())
}

fn write_to_nic(iface: &tun_tap::Iface, gateway: &str, proxy: &ProxyRelay) {
    while let Ok(packet) = proxy.read() {
        info!("writing to nic: {packet:?}");
        let iph = etherparse::Ipv4Header::new(
            packet.packet_len(),
            128,
            IpNumber::TCP,
            // packet.source_ip().octets(),
            gateway.parse::<Ipv4Addr>().unwrap().octets(),
            packet.destination_ip().octets(),
        )
        .unwrap();
        let mut buf = [0u8; 1500];
        let mut ptr = &mut buf[..];
        iph.write(&mut ptr).unwrap();
        let ptr = &mut ptr[..packet.packet_len() as usize];
        ptr.copy_from_slice(packet.raw());

        let buf = &buf[..iph.header_len() + packet.packet_len() as usize];
        info!("{buf:?}");
        iface.send(buf).unwrap();
    }
}

fn read_from_nic(iface: &tun_tap::Iface, proxy: &ProxyRelay) {
    let mut buff = [0u8; 1500];
    while let Ok(nbytes) = iface.recv(&mut buff) {
        if let Ok(iph) = etherparse::Ipv4HeaderSlice::from_slice(&buff[..nbytes]) {
            let ip_proto = iph.protocol();
            let src_ip = iph.source_addr();
            let mut dst_ip = iph.destination_addr();
            // if dst_ip == "172.30.0.14".parse::<Ipv4Addr>().unwrap() {
            // let dst_ip = "34.223.124.45".parse().unwrap();
            // }
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

fn setup_iface(subnet: &str) -> std::io::Result<tun_tap::Iface> {
    let iface = tun_tap::Iface::without_packet_info("ark-%d", tun_tap::Mode::Tun)?;

    let output = Command::new("sudo")
        .arg("ip")
        .arg("addr")
        .arg("add")
        .arg(subnet)
        .arg("dev")
        .arg(iface.name())
        .status()
        .expect("failed to execute ip addr add");

    info!("{output:?}");
    let output = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg("up")
        .arg("dev")
        .arg(iface.name())
        .status()
        .expect("failed to execute ip link");
    info!("{output:?}");
    Ok(iface)
}
