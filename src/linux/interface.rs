use crate::linux::attr::WgDeviceAttribute;
use std::borrow::Cow;

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

impl<'a> From<&DeviceInterface<'a>> for WgDeviceAttribute {
    fn from(interface: &DeviceInterface) -> Self {
        return match interface {
            &DeviceInterface::Index(ifindex) => WgDeviceAttribute::Ifindex(ifindex),
            DeviceInterface::Name(ifname) => WgDeviceAttribute::Ifname(ifname.to_string()),
        };
    }
}
