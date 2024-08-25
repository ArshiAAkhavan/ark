use std::{net::Ipv4Addr, process::Command, thread};

use ark::{Client, Relay, Server, TcpPacketSlice, Tunnel};
use etherparse::{IpNumber, TcpOptionElement};
use log::{debug, info, warn};

use clap::{Parser, ValueEnum};

#[derive(Clone, ValueEnum, Default, PartialEq)]
pub enum Mode {
    #[default]
    Client,
    Server,
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

    /// subnet range to listen on (server mode)
    #[arg(short, long)]
    subnet: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    if opts.mode == Mode::Client && opts.remote.is_none() {
        panic!("provide remote when running in client mode");
    }
    if opts.mode == Mode::Client && opts.subnet.is_some() {
        panic!("subnet does not work in client mode")
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let (proxy, subnet): (Box<dyn Tunnel>, String) = match opts.mode {
        Mode::Client => {
            let (relay, ip) = Client::connect(opts.remote.unwrap(), opts.local)?;
            (Box::new(relay), format!("{ip}/24"))
        }
        Mode::Server => {
            let ipv4_string = opts
                .subnet
                .clone()
                .unwrap()
                .split('/')
                .next()
                .unwrap()
                .to_owned();
            let ip: Ipv4Addr = ipv4_string.parse()?;
            (
                Box::new(Server::bind(opts.local, ip)?),
                opts.subnet.unwrap(),
            )
        }
    };
    let iface = setup_iface(&subnet)?;

    thread::scope(|s| {
        let relay1 = proxy.relay();
        let relay2 = proxy.relay();
        s.spawn(|| proxy.run_udp_pipe());
        s.spawn(|| proxy.run_udp_tunnel());
        s.spawn(|| proxy.run());
        s.spawn(|| read_from_nic(&iface, relay1));
        s.spawn(|| write_to_nic(&iface, relay2));
    });

    Ok(())
}

fn write_to_nic(iface: &tun_tap::Iface, proxy: Relay) {
    while let Ok(packet) = proxy.read() {
        info!("writing to nic: {packet:?}");
        let iph = match etherparse::Ipv4Header::new(
            packet.packet_len(),
            128,
            IpNumber::TCP,
            packet.source_ip().octets(),
            packet.destination_ip().octets(),
        ) {
            Ok(iph) => iph,
            Err(e) => {
                warn!("failed to create Ipv4 Header to write in NIC");
                debug!("{e}");
                continue;
            }
        };
        let mut buf = [0u8; 1500];
        let mut ptr = &mut buf[..];
        if let Err(e) = iph.write(&mut ptr) {
            warn!("failed to create Ipv4 Header to write in NIC");
            debug!("{e}");
            continue;
        };
        let ptr = &mut ptr[..packet.packet_len() as usize];
        ptr.copy_from_slice(packet.tcp_raw());

        let buf = &buf[..iph.header_len() + packet.packet_len() as usize];
        if let Err(e) = iface.send(buf) {
            warn!("failed to write Ipv4 Header to NIC");
            debug!("{e}");
            continue;
        }
    }
}

fn read_from_nic(iface: &tun_tap::Iface, proxy: Relay) {
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
                            tcph = match set_mss_if_any(tcph) {
                                Ok(tcph) => tcph,
                                Err(e) => {
                                    warn!("failed to set new MSS, ignoring packet...");
                                    debug!("{e}");
                                    continue;
                                }
                            };
                            let checksum = match tcph.calc_checksum_ipv4_raw(
                                src_ip.octets(),
                                dst_ip.octets(),
                                &tcp_buff[tcph.header_len()..tcp_packet_size],
                            ) {
                                Ok(c) => c,
                                Err(e) => {
                                    warn!("failed to calculate TCP checksum, ignoring packet...");
                                    debug!("{e}");
                                    continue;
                                }
                            };
                            tcph.checksum = checksum;
                            let mut buf = &mut tcp_buff[..];
                            if let Err(e) = tcph.write(&mut buf) {
                                warn!("failed to send TCP packet via proxy, ignoring packet...");
                                debug!("{e}");
                                continue;
                            }
                            let packet =
                                TcpPacketSlice::new(src_ip, dst_ip, &tcp_buff[..tcp_packet_size]);
                            info!("iface: {packet:?}");
                            if let Err(e) = proxy.write(packet) {
                                warn!("failed to send TCP packet via proxy, ignoring packet...");
                                debug!("{e}");
                                continue;
                            }
                        }
                        Err(_) => warn!("sick tcp packet"),
                    }
                }
                _ => debug!("sick layer4 protocol {ip_proto:?}"),
            }
        }
    }
}

fn set_mss_if_any(
    mut tcph: etherparse::TcpHeader,
) -> Result<etherparse::TcpHeader, Box<dyn std::error::Error>> {
    let mss = tcph.options_iterator().find_map(|opt| match opt.ok()? {
        TcpOptionElement::MaximumSegmentSize(mss) => Some(mss),
        _ => None,
    });
    if mss.is_none() {
        return Ok(tcph);
    }
    let mut new_options = Vec::new();

    for option in tcph.options_iterator() {
        let option = option?;
        match option {
            TcpOptionElement::MaximumSegmentSize(mss) => {
                let new_mss = std::cmp::min(mss, 1300);
                new_options.push(TcpOptionElement::MaximumSegmentSize(new_mss));
            }
            _ => new_options.push(option),
        }
    }

    tcph.set_options(&new_options)?;
    Ok(tcph)
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
