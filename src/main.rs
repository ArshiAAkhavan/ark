use std::{process::Command, thread};

use ark::{ProxyMode, ProxyRelay, TcpPacketSlice};
use etherparse::{IpNumber, TcpOptionElement};
use log::{debug, info, warn};

use clap::{Parser, ValueEnum};

#[derive(Clone, ValueEnum, Default, PartialEq)]
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
    /// Address of the remote server
    #[arg(short, long)]
    remote: Option<String>,

    /// Address to bind locally
    #[arg(short, long)]
    local: String,

    /// weather to run in client mode or server mode
    #[arg(short, long)]
    mode: Mode,

    /// subnet range to listen on
    #[arg(short, long)]
    subnet: String,
}

fn main() -> std::io::Result<()> {
    let opts = Opts::parse();
    if opts.mode == Mode::Client && opts.remote.is_none() {
        panic!("provide remote when running in client mode");
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let iface = setup_iface(&opts.subnet)?;
    let proxy = ProxyRelay::new(
        opts.local,
        opts.remote.unwrap_or_default(),
        opts.mode.into(),
    )?;

    thread::scope(|s| {
        s.spawn(|| proxy.start_upd_pipe());
        s.spawn(|| proxy.run());
        s.spawn(|| read_from_nic(&iface, &proxy));
        s.spawn(|| write_to_nic(&iface, &proxy));
    });

    Ok(())
}

fn write_to_nic(iface: &tun_tap::Iface, proxy: &ProxyRelay) {
    while let Ok(packet) = proxy.read() {
        info!("writing to nic: {packet:?}");
        let iph = etherparse::Ipv4Header::new(
            packet.packet_len(),
            128,
            IpNumber::TCP,
            packet.source_ip().octets(),
            packet.destination_ip().octets(),
        )
        .unwrap();
        let mut buf = [0u8; 1500];
        let mut ptr = &mut buf[..];
        iph.write(&mut ptr).unwrap();
        let ptr = &mut ptr[..packet.packet_len() as usize];
        ptr.copy_from_slice(packet.tcp_raw());

        let buf = &buf[..iph.header_len() + packet.packet_len() as usize];
        iface.send(buf).unwrap();
    }
}

fn read_from_nic(iface: &tun_tap::Iface, proxy: &ProxyRelay) {
    let mut buff = [0u8; 1500];
    while let Ok(nbytes) = iface.recv(&mut buff) {
        if let Ok(iph) = etherparse::Ipv4HeaderSlice::from_slice(&buff[..nbytes]) {
            let ip_proto = iph.protocol();
            let src_ip = iph.source_addr();
            let dst_ip = iph.destination_addr();
            let ip_header_end_index = iph.slice().len();
            match ip_proto {
                IpNumber::TCP => {
                    match etherparse::TcpHeader::from_slice(&buff[ip_header_end_index..nbytes]) {
                        Ok((mut tcph, _)) => {
                            let tcp_packet_size = nbytes - ip_header_end_index;
                            let mut tcp_buff = [0u8; 1500];
                            let _ = &tcp_buff[..tcp_packet_size]
                                .copy_from_slice(&buff[ip_header_end_index..nbytes]);
                            set_mss_if_any(&mut tcph);
                            let x = tcph.calc_checksum_ipv4_raw(src_ip.octets(), dst_ip.octets(), &tcp_buff[tcph.header_len()..tcp_packet_size]).unwrap();
                            tcph.checksum = x;
                            // assert_eq!(prev, tcph.header_len());
                            let mut buf = &mut tcp_buff[..];
                            tcph.write(&mut buf).unwrap();
                            let packet = TcpPacketSlice::new(
                                src_ip,
                                dst_ip,
                                &tcp_buff[..tcp_packet_size],
                                // &buff[ip_header_end_index..nbytes],
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

fn set_mss_if_any(tcph: &mut etherparse::TcpHeader) {
    let mss = tcph.options_iterator().find_map(|opt| match opt.ok()? {
        TcpOptionElement::MaximumSegmentSize(mss) => Some(mss),
        _ => None,
    });
    if mss.is_none() {
        return;
    }
    let mut new_options = Vec::new();

    for option in tcph.options_iterator() {
        let option = option.unwrap();
        match option {
            TcpOptionElement::MaximumSegmentSize(mss) => {
                info!("old mss: {mss}");
                let new_mss = std::cmp::min(mss, 1300);
                new_options.push(TcpOptionElement::MaximumSegmentSize(new_mss));
            }
            _ => new_options.push(option),
        }
    }

    tcph.set_options(&new_options)
        .map_err(|_| "Failed to set options")
        .unwrap();

    for option in tcph.options_iterator() {
        let option = option.unwrap();
        match option {
            TcpOptionElement::MaximumSegmentSize(mss) => {
                info!("new mss: {mss}");
            }
            _ => {}
        }
    }
    info!("set MSS")
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
