use crate::linux::attr::WgDeviceAttribute;
use crate::linux::consts::NLA_NETWORK_ORDER;
use neli::{err::NlError, genl::Nlattr, types::Buffer};
use std::borrow::Cow;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq)]
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

impl<'a> TryFrom<&DeviceInterface<'a>> for Nlattr<WgDeviceAttribute, Buffer> {
    type Error = NlError;

    fn try_from(interface: &DeviceInterface) -> Result<Self, Self::Error> {
        let attr = match interface {
            &DeviceInterface::Index(ifindex) => Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgDeviceAttribute::Ifindex,
                ifindex,
            )?,
            DeviceInterface::Name(ifname) => Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgDeviceAttribute::Ifname,
                ifname.as_ref(),
            )?,
        };
        Ok(attr)
    }
}
