use crate::attr::{NlaNested, WgPeerAttribute};
use crate::set::AllowedIp;
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum WgPeerF {
    RemoveMe = 1,
    ReplaceAllowedIps = 2,
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

        if !peer.flags.is_empty() {
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

        if !peer.allowed_ips.is_empty() {
            let mut allowed_ips_attribute =
                Nlattr::new::<Vec<u8>>(None, WgPeerAttribute::AllowedIps, vec![])?;
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
