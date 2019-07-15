use crate::attr::{NlaNested, WgAllowedIpAttribute, WgDeviceAttribute, WgPeerAttribute};
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::IpAddr;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum WgDeviceF {
    ReplacePeers = 1,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum WgPeerF {
    RemoveMe = 1,
    ReplaceAllowedIps = 2,
}

#[derive(Debug)]
pub struct Device<'a> {
    ifindex: Option<u32>,
    ifname: Option<Cow<'a, str>>,
    /// 0 or WGDEVICE_F_REPLACE_PEERS if all current peers should be removed prior to adding the
    // list below.
    pub flags: Vec<WgDeviceF>,
    /// all zeros to remove
    pub private_key: Option<&'a [u8; 32]>,
    /// 0 to choose randomly
    pub listen_port: Option<u16>,
    /// 0 to disable
    pub fwmark: Option<u32>,
    pub peers: Vec<Peer<'a>>,
}

impl<'a> Device<'a> {
    pub fn from_ifname<T: Into<Cow<'a, str>>>(ifname: T) -> Self {
        Self {
            ifindex: None,
            ifname: Some(ifname.into()),
            flags: vec![],
            private_key: None,
            listen_port: None,
            fwmark: None,
            peers: vec![],
        }
    }

    pub fn from_ifindex(ifindex: u32) -> Self {
        Self {
            ifindex: Some(ifindex),
            ifname: None,
            flags: vec![],
            private_key: None,
            listen_port: None,
            fwmark: None,
            peers: vec![],
        }
    }

    pub fn flags(mut self, flags: Vec<WgDeviceF>) -> Self {
        self.flags = flags;
        self
    }

    pub fn private_key(mut self, private_key: &'a [u8; 32]) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn listen_port(mut self, listen_port: u16) -> Self {
        self.listen_port = Some(listen_port);
        self
    }

    pub fn fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }

    pub fn peers(mut self, peers: Vec<Peer<'a>>) -> Self {
        self.peers = peers;
        self
    }
}

impl<'a> TryFrom<&Device<'a>> for Vec<Nlattr<WgDeviceAttribute, Vec<u8>>> {
    type Error = SerError;

    fn try_from(device: &Device) -> Result<Self, Self::Error> {
        let mut attrs = vec![];

        if let Some(ifindex) = device.ifindex {
            attrs.push(Nlattr::new(
                None,
                WgDeviceAttribute::Ifindex,
                ifindex,
            )?);
        }

        if let Some(ifname) = &device.ifname {
            attrs.push(Nlattr::new(
                None,
                WgDeviceAttribute::Ifname,
                ifname.as_ref(),
            )?);
        }

        if device.flags.len() > 0 {
            let mut unique = device.flags.clone();
            unique.dedup();

            attrs.push(Nlattr::new(
                None,
                WgDeviceAttribute::Flags,
                unique.drain(..).map(|flag| flag as u32).sum::<u32>(),
            )?);
        }

        if let Some(private_key) = device.private_key {
            attrs.push(Nlattr::new(
                None,
                WgDeviceAttribute::PrivateKey,
                &private_key[..],
            )?);
        }

        if let Some(listen_port) = device.listen_port {
            attrs.push(Nlattr::new(
                Some(6),
                WgDeviceAttribute::ListenPort,
                // neli 0.3.1 does not pad. Add 2 bytes to meet required 4 byte boundary.
                [listen_port.to_ne_bytes(), [0u8; 2]].concat(),
            )?);
        }

        if let Some(fwmark) = device.fwmark {
            attrs.push(Nlattr::new(
                None,
                WgDeviceAttribute::Fwmark,
                fwmark,
            )?);
        }

        if device.peers.len() > 0 {
            let mut nested = Nlattr::new::<Vec<u8>>(None, WgDeviceAttribute::Peers, vec![])?;
            for peer in device.peers.iter() {
                nested.add_nested_attribute(&peer.try_into()?)?;
            }

            attrs.push(nested);
        }

        Ok(attrs)
    }
}

#[derive(Debug)]
pub struct Peer<'a> {
    pub public_key: &'a [u8; 32],
    pub flags: Vec<WgPeerF>,
    /// all zeros to remove
    pub preshared_key: Option<&'a [u8; 32]>,
    pub endpoint: Option<&'a SocketAddr>,
    /// 0 to disable
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<AllowedIp<'a>>,
    /// should not be set or used at all by most users of this API, as the most recent protocol
    /// will be used when this is unset. Otherwise, must be set to 1.
    pub protocol_version: Option<u32>,
}

impl<'a> Peer<'a> {
    pub fn from_public_key(public_key: &'a [u8; 32]) -> Self {
        Self {
            public_key,
            flags: vec![],
            preshared_key: None,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ips: vec![],
            protocol_version: None,
        }
    }

    pub fn flags(mut self, flags: Vec<WgPeerF>) -> Self {
        self.flags = flags;
        self
    }

    pub fn preshared_key(mut self, preshared_key: &'a [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    pub fn endpoint(mut self, endpoint: &'a SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn persistent_keepalive_interval(mut self, persistent_keepalive_interval: u16) -> Self {
        self.persistent_keepalive_interval = Some(persistent_keepalive_interval);
        self
    }

    pub fn allowed_ips(mut self, allowed_ips: Vec<AllowedIp<'a>>) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    pub fn protocol_version(mut self, protocol_version: u32) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }
}

impl<'a> TryFrom<&Peer<'a>> for Nlattr<NlaNested, Vec<u8>> {
    type Error = SerError;

    fn try_from(peer: &Peer) -> Result<Self, Self::Error> {
        let mut nested = Nlattr::new::<Vec<u8>>(None, NlaNested::Unspec, vec![])?;

        let public_key = Nlattr::new(None, WgPeerAttribute::PublicKey, peer.public_key.to_vec())?;
        nested.add_nested_attribute(&public_key)?;

        if peer.flags.len() > 0 {
            let mut unique = peer.flags.clone();
            unique.dedup();

            nested.add_nested_attribute(&Nlattr::new(
                None,
                WgPeerAttribute::Flags,
                unique.drain(..).map(|flag| flag as u32).sum::<u32>(),
            )?)?;
        }

        if let Some(preshared_key) = peer.preshared_key {
            nested.add_nested_attribute(&Nlattr::new(
                None,
                WgPeerAttribute::PresharedKey,
                &preshared_key[..],
            )?)?;
        }

        if let Some(endpoint) = peer.endpoint {
            // Using the serialize trait from serde might be easier.
            let mut payload: Vec<u8> = vec![];

            let family = match endpoint {
                SocketAddr::V4(_) => (libc::AF_INET as u16).to_ne_bytes(),
                SocketAddr::V6(_) => (libc::AF_INET6 as u16).to_ne_bytes(),
            };
            let port = endpoint.port().to_be_bytes();

            payload.extend(family.iter());
            payload.extend(port.iter());

            match endpoint {
                SocketAddr::V4(addr) => {
                    payload.extend(addr.ip().octets().iter());
                    payload.extend([0u8; 8].iter());
                }
                SocketAddr::V6(addr) => {
                    payload.extend(addr.flowinfo().to_ne_bytes().iter());
                    payload.extend(addr.ip().octets().iter());
                    payload.extend(addr.scope_id().to_ne_bytes().iter());
                }
            };

            nested.add_nested_attribute(&Nlattr::new(None, WgPeerAttribute::Endpoint, payload)?)?;
        }

        if let Some(persistent_keepalive_interval) = peer.persistent_keepalive_interval {
            nested.add_nested_attribute(&Nlattr::new(
                Some(6),
                WgPeerAttribute::PersistentKeepaliveInterval,
                // neli 0.3.1 does not pad. Add 2 bytes to meet required 4 byte boundary.
                [persistent_keepalive_interval.to_ne_bytes(), [0u8; 2]].concat(),
            )?)?;
        }

        if peer.allowed_ips.len() > 0 {
            let mut allowed_ips_attribute = Nlattr::new::<Vec<u8>>(
                None,
                WgPeerAttribute::AllowedIps,
                vec![],
            )?;
            for allowed_ip in peer.allowed_ips.iter() {
                allowed_ips_attribute.add_nested_attribute(&allowed_ip.try_into()?)?;
            }

            nested.add_nested_attribute(&allowed_ips_attribute)?;
        }

        if let Some(protocol_version) = peer.protocol_version {
            nested.add_nested_attribute(&Nlattr::new(
                None,
                WgPeerAttribute::ProtocolVersion,
                protocol_version,
            )?)?;
        }

        Ok(nested)
    }
}

#[derive(Debug)]
pub struct AllowedIp<'a> {
    pub ipaddr: &'a IpAddr,
    pub cidr_mask: Option<u8>,
}

impl<'a> AllowedIp<'a> {
    pub fn from_ipaddr(ipaddr: &'a IpAddr) -> Self {
        Self {
            ipaddr,
            cidr_mask: None,
        }
    }
}

impl<'a> TryFrom<&AllowedIp<'a>> for Nlattr<NlaNested, Vec<u8>> {
    type Error = SerError;

    fn try_from(allowed_ip: &AllowedIp) -> Result<Self, Self::Error> {
        let mut nested = Nlattr::new::<Vec<u8>>(None, NlaNested::Unspec, vec![])?;

        let family = match allowed_ip.ipaddr {
            IpAddr::V4(_) => libc::AF_INET as u16,
            IpAddr::V6(_) => libc::AF_INET6 as u16,
        };
        nested.add_nested_attribute(&Nlattr::new(
            None,
            WgAllowedIpAttribute::Family,
            // neli 0.3.1 does not pad. Add 2 bytes to meet required 4 byte boundary.
            [family.to_ne_bytes(), [0u8; 2]].concat(),
        )?)?;

        let ipaddr = match allowed_ip.ipaddr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        nested.add_nested_attribute(&Nlattr::new(
            None,
            WgAllowedIpAttribute::IpAddr,
            ipaddr,
        )?)?;

        let cidr_mask = allowed_ip.cidr_mask.unwrap_or(match allowed_ip.ipaddr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        });
        nested.add_nested_attribute(&Nlattr::new(
            Some(5),
            WgAllowedIpAttribute::CidrMask,
            // neli 0.3.1 does not pad. Add 3 bytes to meet required 4 byte boundary.
            [&cidr_mask.to_ne_bytes()[..], &[0u8; 3][..]].concat(),
        )?)?;

        Ok(nested)
    }
}
