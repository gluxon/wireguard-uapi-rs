use derive_builder::Builder;
use std::net::{IpAddr, SocketAddr};
use std::{str::FromStr, time::Duration};

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
    // The public_key and allowed_ips fields are public to
    // make peer coalescing easier.
    #[builder(field(public))]
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    #[builder(default)]
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: u16,
    pub last_handshake_time: Duration,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[builder(default, field(public))]
    pub allowed_ips: Vec<AllowedIp>,
    pub protocol_version: u32,
}

#[derive(Builder, Clone, Debug, PartialEq)]
pub struct AllowedIp {
    pub family: u16,
    pub ipaddr: IpAddr,
    pub cidr_mask: u8,
}

#[derive(Debug)]
pub struct ParseAllowedIpError;

impl FromStr for AllowedIp {
    type Err = ParseAllowedIpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tokens = s.splitn(2, '/');
        let ipaddr = tokens.next().unwrap().parse().unwrap();
        let cidr_mask: u8 = tokens.next().unwrap().parse().unwrap();

        Ok(AllowedIp {
            family: match ipaddr {
                IpAddr::V4(_) => 2,
                IpAddr::V6(_) => 10,
            },
            ipaddr,
            cidr_mask,
        })
    }
}
