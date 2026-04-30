# Ark

> The art of hiding in plain sight: swap the protocol, break the balance, blend into the noise.

Ark is a layer-4 protocol-swapping VPN built for *adversarial networks*: environments where a deep-packet-inspection adversary monitors traffic patterns at every node and blocks or disrupts connections it classifies as VPN tunnels.

Instead of encrypting traffic and hoping nobody notices, Ark changes *what protocol the traffic looks like* at the transport layer. Your TCP stream is wrapped inside legitimate-looking DNS UDP packets and silently unwrapped at the exit node — transparent to applications, invisible to the traffic classifier.

---

## Table of Contents

- [The Problem: Traffic Pattern Detection](#the-problem-traffic-pattern-detection)
- [The Solution: Layer 4 Protocol Swapping](#the-solution-layer-4-protocol-swapping)
- [Building](#building)
- [Usage](#usage)
- [How It Works](#how-it-works)
  - [Encapsulation: TCP inside DNS/EDNS](#encapsulation-tcp-inside-dnsedns)
  - [MSS Clamping](#mss-clamping)
  - [The TUN Interface](#the-tun-interface)
- [Full Packet Flow](#full-packet-flow)
- [Connection Handshake](#connection-handshake)
- [Architecture](#architecture)
- [Protocol Reference](#protocol-reference)
- [Repository Layout](#repository-layout)
- [Limitations](#limitations)

---

## The Problem: Traffic Pattern Detection

In an adversarial network, a monitoring agent identifies VPN gateway nodes by checking one property: a relay node forwards every byte it receives, so its **incoming traffic equals its outgoing traffic per protocol**. That perfect per-protocol balance is the fingerprint.

A standard VPN gateway relays TCP in both directions. Counting all flows at the gateway:

```
Standard VPN — flagged because in ≈ out:

  CLIENT           VPN GATEWAY           DESTINATION
    │                    │                     │
    │─ TCP  200B ───────>│─ TCP  200B ────────>│   (request)
    │<─ TCP  2GB ────────│<─ TCP  2GB ─────────│   (response)
    │                    │                     │
               ╔══════════════════════╗
               ║  TCP in  ≈  200B+2GB ║
               ║  TCP out ≈  200B+2GB ║  <── perfectly balanced
               ╚══════════════════════╝      adversary flags this node
```

Every byte that enters the gateway on TCP exits on TCP. The adversary doesn't need to decrypt anything — the balance alone is enough to classify the node as a VPN.

---

## The Solution: Layer 4 Protocol Swapping

Ark wraps TCP packets inside DNS/EDNS UDP datagrams before they leave the client. The server unwraps them and forwards the original TCP to the destination. The gateway still relays the same data, but the per-protocol accounting is now lopsided in both directions:

```
Ark VPN — per-protocol imbalance defeats the detector:

  CLIENT           ARK GATEWAY           DESTINATION
    │                    │                     │
    │─ UDP  200B ───────>│─ TCP  200B ────────>│   (request)
    │<─ UDP   2GB ───────│<─ TCP   2GB ────────│   (response)
    │                    │                     │
               ╔═══════════════════════╗
               ║  UDP in  ≈  200B      ║  imbalanced
               ║  UDP out ≈    2GB     ║  (small queries, big answers)
               ╠═══════════════════════╣
               ║  TCP in  ≈    2GB     ║  imbalanced
               ║  TCP out ≈  200B      ║  (big fetch, small request)
               ╚═══════════════════════╝
                  looks like a DNS resolver — not a VPN
```

The gateway's traffic profile now matches a DNS caching resolver: it receives small queries over UDP and returns large payloads, while fetching content over TCP in the background. DNS is vital infrastructure that an adversary cannot block without breaking the network for everyone, making it the ideal camouflage carrier.

---

## Building

```bash
cargo build --release
```

Requires Rust 1.70+ and Linux. The binary needs `CAP_NET_ADMIN` to create TUN devices — the provided scripts handle this automatically via `setcap`.

---

## Usage

### Server

```bash
./run-server.sh --local 0.0.0.0:9091 --mode server --subnet 172.16.0.1/24
```

The script also enables IP forwarding and installs a NAT/masquerade rule so that VPN clients can reach the internet through the server:

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 172.16.0.0/24 ! -d 172.16.0.0/24 -j MASQUERADE
```

### Client

```bash
./run-client.sh --local 0.0.0.0:7070 --remote <server-ip>:9091 --mode client
```

The script sets the default route through `ark-0` so all traffic is tunneled:

```bash
ip route add default dev ark-0
```

### Flags

| Flag | Short | Description | Required by |
|------|-------|-------------|-------------|
| `--local` | `-l` | Local UDP bind address (`ip:port`) | Both |
| `--mode` | `-m` | `client` or `server` | Both |
| `--remote` | `-r` | Server address (`ip:port`) | Client |
| `--subnet` | `-s` | VPN subnet CIDR (e.g. `172.16.0.1/24`) | Server |

Set `RUST_LOG=debug` for per-packet logging.

---

## How It Works

### Encapsulation: TCP inside DNS/EDNS

Raw TCP packets are stuffed into DNS **EDNS** (Extension Mechanisms for DNS) OPT records, using custom option code `65001`. The DNS message is disguised as a legitimate A-record query — an ordinary thing for any host to send.

```
 ┌─────────────────────────────────────────────────────────┐
 │  UDP datagram (on the wire)                             │
 │  ┌───────────────────────────────────────────────────┐  │
 │  │  DNS Message                                      │  │
 │  │  ┌─────────────────────────────────────────────┐  │  │
 │  │  │  Header  ID=1, QR=Query, RD=1               │  │  │
 │  │  ├─────────────────────────────────────────────┤  │  │
 │  │  │  Question  "leader.ir."  A  IN              │  │  │
 │  │  ├─────────────────────────────────────────────┤  │  │
 │  │  │  EDNS OPT RR                                │  │  │
 │  │  │  ┌───────────────────────────────────────┐  │  │  │
 │  │  │  │  Option Code : 65001 (ARK)            │  │  │  │
 │  │  │  │  Option Data : <raw TCP packet bytes> │  │  │  │
 │  │  │  └───────────────────────────────────────┘  │  │  │
 │  │  └─────────────────────────────────────────────┘  │  │
 │  └───────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────┘
```

EDNS is fully backward-compatible with all DNS infrastructure, so these packets traverse firewalls, NAT boxes, and DNS proxies without modification.

### MSS Clamping

TCP negotiates its Maximum Segment Size during the three-way handshake. Ark intercepts SYN packets and reduces the MSS to **1300 bytes**, reserving ~200 bytes of headroom for the DNS/EDNS wrapper so every packet stays within the 1500-byte MTU.

```
  USER APP         ARK CLIENT         ARK SERVER        DESTINATION
      │                 │                  │                  │
      │ SYN MSS=1500    │                  │                  │
      │────────────────>│                  │                  │
      │                 │ SYN MSS=1300     │                  │
      │                 │ (clamped)        │                  │
      │                 │────────────────> │─ SYN MSS=1300 ──>│
      │                 │                  │<─ SYN,ACK ───────│
      │<── SYN,ACK ─────│<─────────────────│                  │
      │─── ACK ────────>│─────────────────>│── ACK ──────────>│
```

### The TUN Interface

Ark creates a virtual network interface (`ark-0`) via the Linux TUN/TAP API. Setting `ark-0` as the default route causes the kernel to hand every outbound packet to Ark's process before it reaches the real NIC — no iptables rules or application changes required.

```
  ┌──────────────────────────────────────────────────────┐
  │  Linux Kernel                                        │
  │                                                      │
  │  Application ──> TCP/IP Stack ──> ark-0 (TUN) ─────> │
  │                                        │             │
  └────────────────────────────────────────│─────────────┘
                                           │  fd read/write
                                    ┌──────▼──────┐
                                    │ ark process │
                                    │  (userspace)│
                                    └──────┬──────┘
                                           │  UDP socket
                                    ┌──────▼──────────┐
                                    │  Real NIC       │
                                    │  (eth0, wlan0…) │
                                    └─────────────────┘
```

---

## Full Packet Flow

```
CLIENT SIDE                                        SERVER SIDE
───────────────────────────────────────────────────────────────────────

  Application (curl, browser, …)
        │  TCP segment
        ▼
  Kernel routes via ark-0 TUN
        │  raw IPv4 frame
        ▼
  read_from_nic()
    ├─ parse IPv4 + TCP headers
    ├─ clamp MSS if SYN packet
    └─ build TcpPacketSlice { src_ip, dst_ip, tcp_bytes }
        │
        ▼
  Relay  (crossbeam select loop)
    └─ to_edns_packet(tcp_bytes)
       wraps TCP in DNS EDNS option 65001
        │  (edns_bytes, dst_ip)
        ▼
  Client::run_udp_pipe()
    └─ sendto(server_addr, edns_bytes)
        │
        │═══════════════ UDP over Internet ════════════════╗
                                                          ║
                                               Server::run_udp_tunnel()
                                                 ├─ recvfrom(buf)
                                                 ├─ from_edns_packet(buf)
                                                 │    extracts TCP bytes
                                                 └─ push to udp_input_pipe
                                                          │
                                                          ▼
                                               Relay  (crossbeam select loop)
                                                 └─ forward tcp_output_pipe
                                                          │
                                                          ▼
                                               write_to_nic()
                                                 ├─ reconstruct IPv4 header
                                                 └─ write to TUN ark-0
                                                          │
                                                          ▼
                                               kernel ──> real NIC ──> destination
```

The return path is symmetric: the server reads the TCP response from TUN, wraps it in EDNS, sends it back to the client over UDP.

---

## Connection Handshake

Before tunneling begins, the client obtains a VPN-internal IP from the server via a lightweight plaintext handshake:

```
  CLIENT                                        SERVER
    │                                               │
    │──── "client hello"  (raw UDP) ───────────────>│
    │                                               │ allocate next IP
    │                                               │ e.g. 172.16.0.2
    │                                               │ record IP → UDP addr
    │<─── "server accept" + [172, 16, 0, 2] ────────│
    │                                               │
    │  configure ark-0: 172.16.0.2/24               │ configure ark-0: 172.16.0.1/24
    │                                               │
    │════════ EDNS-wrapped TCP tunnel active ════════│
```

The server maintains a map of `VPN IP → client UDP address` to route responses back to the correct client. Up to 254 clients can connect simultaneously (`.2` through `.255`).

---

## Architecture

```
                     ┌───────────────────────────────────┐
                     │             Relay                 │
                     │                                   │
  TUN read ────────► │ tcp_input_pipe                    │
                     │      │                            │
                     │      ▼  (select loop)             │
                     │ to_edns_packet()                  │
                     │      │                            │
                     │      ▼                            │
                     │ udp_output_tx ────────────────────┼──► UDP socket
                     │                                   │
  UDP recv ────────► │ udp_input_pipe                    │
                     │      │                            │
                     │      ▼                            │
                     │ tcp_output_pipe ──────────────────┼──► TUN write
                     └───────────────────────────────────┘

  Server extras:
  ┌────────────────────────────────────────────────────┐
  │  addr_map : HashMap<Ipv4Addr, SocketAddr>          │
  │  base     : Ipv4Addr (incremented per new client)  │
  └────────────────────────────────────────────────────┘
```

Five scoped threads keep everything non-blocking:

| Thread | Responsibility |
|--------|----------------|
| `read_from_nic` | TUN fd → relay `tcp_input_pipe` |
| `write_to_nic` | relay `tcp_output_pipe` → TUN fd |
| `relay.run` | TCP↔EDNS conversion, crossbeam `select!` loop |
| `run_udp_tunnel` | UDP `recvfrom` → relay `udp_input_pipe` |
| `run_udp_pipe` | relay `udp_output_tx` → UDP `sendto` |

---

## Protocol Reference

| Property | Value |
|----------|-------|
| Wire transport | UDP |
| Encapsulation | DNS/EDNS OPT record (RFC 6891) |
| ARK option code | `65001` (0xFDE9) |
| DNS query name | `leader.ir.` |
| DNS query type | A |
| EDNS max payload | 4096 bytes |
| TCP MSS clamp | 1300 bytes |
| Default VPN subnet | 172.16.0.0/24 |
| Max concurrent clients | 254 |
| Packet buffer | 1500 bytes (stack-allocated) |

---

## Repository Layout

```
ark/
├── src/
│   ├── main.rs     CLI, TUN setup, thread spawning
│   ├── lib.rs      TcpPacketSlice — core packet wrapper type
│   ├── relay.rs    Relay, Server, Client, Tunnel trait
│   └── edns.rs     TCP ↔ DNS/EDNS encode/decode
├── run-server.sh   Server startup + NAT rules
├── run-client.sh   Client startup + default route
└── Cargo.toml
```

---

## Limitations

- **No encryption** — Ark conceals *traffic patterns*, not payload content. Layer it with TLS or a separate encryption tool for confidentiality.
- **No authentication** — Any client that reaches the server can connect. A pre-shared key or certificate check is not yet implemented.
- **IPv4 only** — IPv6 is not currently supported.
- **Hardcoded query name** — The DNS query name `leader.ir.` is fixed; a rotating or configurable name would improve stealth.
- **UDP-over-TCP overhead** — When tunneling UDP user traffic through the TCP tunnel, retransmission semantics are inherited from the outer TCP layer, which can cause head-of-line blocking.
