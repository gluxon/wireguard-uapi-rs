use derive_builder::Builder;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

#[derive(Builder, Debug, PartialEq, Eq)]
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

#[derive(Builder, Clone, Debug, PartialEq, Eq)]
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

#[derive(Builder, Clone, Debug, PartialEq, Eq)]
pub struct AllowedIp {
    pub family: u16,
    pub ipaddr: IpAddr,
    pub cidr_mask: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseAllowedIpError {
    #[error("String is missing CIDR mask: `${0}`")]
    MissingCidrMask(String),
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error(transparent)]
    InvalidCidrMask(#[from] std::num::ParseIntError),
}

impl FromStr for AllowedIp {
    type Err = ParseAllowedIpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tokens = s.splitn(2, '/');

        // The unwrap should always succeed since there's at least token.
        let ipaddr = tokens.next().unwrap().parse()?;
        let cidr_mask = tokens
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Self::Err::MissingCidrMask(s.to_string()))?
            .parse()?;

        Ok(AllowedIp {
            family: match ipaddr {
                // This code should compile on non-nix systems, so we can't use
                // libc constants directly here.
                IpAddr::V4(_) => 2,  // libc::AF_INET
                IpAddr::V6(_) => 10, // libc::AF_INET6
            },
            ipaddr,
            cidr_mask,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    #[test]
    fn parse_invalid_allowed_ip() {
        assert!(matches!(
            "".parse::<AllowedIp>(),
            Err(ParseAllowedIpError::AddrParseError(_))
        ));

        assert!(matches!(
            "10.24.24.3".parse::<AllowedIp>(),
            Err(ParseAllowedIpError::MissingCidrMask(_))
        ));

        assert!(matches!(
            "10.24.24.3/".parse::<AllowedIp>(),
            Err(ParseAllowedIpError::MissingCidrMask(_))
        ));

        assert!(matches!(
            "10.24.24.3/a".parse::<AllowedIp>(),
            Err(ParseAllowedIpError::InvalidCidrMask(_))
        ));
    }

    #[test]
    fn parse_allowed_ip_ipv4() {
        let actual = "10.24.24.3/32".parse();
        let expected = Ok(AllowedIp {
            family: 2,
            ipaddr: IpAddr::V4(Ipv4Addr::new(10, 24, 24, 3)),
            cidr_mask: 32,
        });
        assert_eq!(actual, expected);
    }

    #[test]
    fn parse_allowed_ip_ipv6() {
        let actual = "::1/128".parse();
        let expected = Ok(AllowedIp {
            family: 10,
            ipaddr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            cidr_mask: 128,
        });
        assert_eq!(actual, expected);
    }
}
