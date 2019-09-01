use crate::attr::WgDeviceAttribute;
use crate::set::Peer;
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum WgDeviceF {
    ReplacePeers = 1,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceInterface<'a> {
    Index(u32),
    Name(Cow<'a, str>),
}

impl<'a> TryFrom<&DeviceInterface<'a>> for Nlattr<WgDeviceAttribute, Vec<u8>> {
    type Error = SerError;

    fn try_from(interface: &DeviceInterface) -> Result<Self, Self::Error> {
        let attr = match interface {
            &DeviceInterface::Index(ifindex) => {
                Nlattr::new(None, WgDeviceAttribute::Ifindex, ifindex)?
            }
            DeviceInterface::Name(ifname) => {
                Nlattr::new(None, WgDeviceAttribute::Ifname, ifname.as_ref())?
            }
        };
        Ok(attr)
    }
}

#[derive(Debug)]
pub struct Device<'a> {
    pub interface: DeviceInterface<'a>,
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
            interface: DeviceInterface::Name(ifname.into()),
            flags: vec![],
            private_key: None,
            listen_port: None,
            fwmark: None,
            peers: vec![],
        }
    }

    pub fn from_ifindex(ifindex: u32) -> Self {
        Self {
            interface: DeviceInterface::Index(ifindex),
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

        attrs.push((&device.interface).try_into()?);

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
            let mut nested = Nlattr::new::<Vec<u8>>(None, WgDeviceAttribute::Peers, vec![])?;
            for peer in device.peers.iter() {
                nested.add_nested_attribute(&peer.try_into()?)?;
            }

            attrs.push(nested);
        }

        Ok(attrs)
    }
}
