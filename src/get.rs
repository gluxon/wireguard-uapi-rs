use derive_builder::Builder;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Builder, Debug, PartialEq)]
pub struct Device {
    pub ifindex: u32,
    pub ifname: String,
    #[builder(default)]
    pub private_key: Option<[u8; 32]>,
    #[builder(default)]
    pub public_key: Option<[u8; 32]>,
    pub listen_port: u16,
    pub fwmark: u32,
    #[builder(default)]
    pub peers: Vec<Peer>,
}

#[derive(Builder, Clone, Debug, PartialEq)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    #[builder(default)]
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: u16,
    pub last_handshake_time: Duration,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[builder(default)]
    pub allowed_ips: Vec<AllowedIp>,
    pub protocol_version: u32,
}

#[derive(Builder, Clone, Debug, PartialEq)]
pub struct AllowedIp {
    pub family: u16,
    pub ipaddr: IpAddr,
    pub cidr_mask: u8,
}
