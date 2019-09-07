use crate::attr::{NlaNested, WgPeerAttribute};
use crate::set::AllowedIp;
use crate::set::Peer;
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::SocketAddr;

pub enum PeerFragment<'a> {
    First(&'a Peer<'a>),
    Following(&'a PeerFragmentFollowing<'a>),
}

pub struct PeerFragmentFollowing<'a> {
    pub public_key: &'a [u8; 32],
    pub allowed_ips: Vec<AllowedIp<'a>>,
}

fn create_allowed_ips_attr(
    allowed_ips: &Vec<AllowedIp>,
) -> Result<Nlattr<WgPeerAttribute, Vec<u8>>, SerError> {
    let mut allowed_ips_attribute =
        Nlattr::new::<Vec<u8>>(None, WgPeerAttribute::AllowedIps, vec![])?;
    for allowed_ip in allowed_ips.iter() {
        allowed_ips_attribute.add_nested_attribute(&allowed_ip.try_into()?)?;
    }
    Ok(allowed_ips_attribute)
}

fn try_from_first(peer: &Peer) -> Result<Nlattr<NlaNested, Vec<u8>>, SerError> {
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
        nested.add_nested_attribute(&create_allowed_ips_attr(&peer.allowed_ips)?)?;
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

fn try_from_following(
    following: &PeerFragmentFollowing,
) -> Result<Nlattr<NlaNested, Vec<u8>>, SerError> {
    let mut nested = Nlattr::new::<Vec<u8>>(None, NlaNested::Unspec, vec![])?;

    let public_key = Nlattr::new(
        None,
        WgPeerAttribute::PublicKey,
        following.public_key.to_vec(),
    )?;
    nested.add_nested_attribute(&public_key)?;

    if !following.allowed_ips.is_empty() {
        nested.add_nested_attribute(&create_allowed_ips_attr(&following.allowed_ips)?)?;
    }

    Ok(nested)
}

impl<'a> TryFrom<&PeerFragment<'a>> for Nlattr<NlaNested, Vec<u8>> {
    type Error = SerError;

    fn try_from(fragment: &PeerFragment) -> Result<Self, Self::Error> {
        match fragment {
            PeerFragment::First(first) => try_from_first(first),
            PeerFragment::Following(following) => try_from_following(following),
        }
    }
}
