use crate::linux::attr::WgDeviceAttribute;
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::borrow::Cow;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq)]
pub enum DeviceInterface<'a> {
    Index(u32),
    Name(Cow<'a, str>),
}

impl<'a> DeviceInterface<'a> {
    pub fn from_index(index: u32) -> Self {
        DeviceInterface::Index(index)
    }

    pub fn from_name<T: Into<Cow<'a, str>>>(name: T) -> Self {
        DeviceInterface::Name(name.into())
    }
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
