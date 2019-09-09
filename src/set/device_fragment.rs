use super::Fragment;
use crate::attr::WgDeviceAttribute;
use crate::set::{Device, Peer, PeerFragment};
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Debug)]
pub enum DeviceFragment<'a> {
    First(&'a mut Device<'a>),
    Following(&'a mut DeviceFragmentFollowing<'a>),
}

#[derive(Debug)]
pub struct DeviceFragmentFollowing<'a> {
    pub ifindex: Option<u32>,
    pub ifname: Option<Cow<'a, str>>,
    pub peers: Vec<Peer<'a>>,
}

impl<'a> DeviceFragment<'a> {
    pub fn add_peer(&mut self, peer: Peer<'a>) {
        match self {
            DeviceFragment::First(ref mut first) => first.peers.push(peer),
            DeviceFragment::Following(ref mut following) => following.peers.push(peer),
        };
    }
}

impl<'a> DeviceFragmentFollowing<'a> {
    pub fn add_peer(&mut self, peer: Peer<'a>) {
        self.peers.push(peer);
    }
}

fn create_peers_attr(peers: &Vec<Peer>) -> Result<Nlattr<WgDeviceAttribute, Vec<u8>>, SerError> {
    let mut nested = Nlattr::new::<Vec<u8>>(None, WgDeviceAttribute::Peers, vec![])?;
    for peer in peers.iter() {
        let attr = (&PeerFragment::First(&peer)).try_into()?;
        nested.add_nested_attribute(&attr)?;
    }
    Ok(nested)
}

fn try_from_first(device: &Device) -> Result<Vec<Nlattr<WgDeviceAttribute, Vec<u8>>>, SerError> {
    let mut attrs = vec![];

    if let Some(ifindex) = device.ifindex {
        attrs.push(Nlattr::new(None, WgDeviceAttribute::Ifindex, ifindex)?);
    }

    if let Some(ifname) = &device.ifname {
        attrs.push(Nlattr::new(
            None,
            WgDeviceAttribute::Ifname,
            ifname.as_ref(),
        )?);
    }

    if !device.flags.is_empty() {
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
        attrs.push(Nlattr::new(None, WgDeviceAttribute::Fwmark, fwmark)?);
    }

    if !device.peers.is_empty() {
        attrs.push(create_peers_attr(&device.peers)?);
    }

    Ok(attrs)
}

fn try_from_following(
    following: &DeviceFragmentFollowing,
) -> Result<Vec<Nlattr<WgDeviceAttribute, Vec<u8>>>, SerError> {
    let mut attrs = vec![];

    if let Some(ifindex) = following.ifindex {
        attrs.push(Nlattr::new(None, WgDeviceAttribute::Ifindex, ifindex)?);
    }

    if let Some(ifname) = &following.ifname {
        attrs.push(Nlattr::new(
            None,
            WgDeviceAttribute::Ifname,
            ifname.as_ref(),
        )?);
    }

    if !following.peers.is_empty() {
        attrs.push(create_peers_attr(&following.peers)?);
    }

    Ok(attrs)
}

impl<'a> TryFrom<&DeviceFragment<'a>> for Vec<Nlattr<WgDeviceAttribute, Vec<u8>>> {
    type Error = SerError;

    fn try_from(fragment: &DeviceFragment) -> Result<Self, Self::Error> {
        match fragment {
            DeviceFragment::First(first) => try_from_first(first),
            DeviceFragment::Following(following) => try_from_following(following),
        }
    }
}
