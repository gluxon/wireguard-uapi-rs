use super::list_device_names_utils;
use super::{link_message, WireGuardDeviceLinkOperation};
use crate::err::{ConnectError, LinkDeviceError, ListDevicesError};
use list_device_names_utils::PotentialWireGuardDeviceName;
use neli::{
    consts::{
        genl::{CtrlAttr, CtrlCmd},
        nl::{NlTypeWrapper, Nlmsg},
        socket::NlFamily,
    },
    genl::Genlmsghdr,
    rtnl::Ifinfomsg,
    socket::NlSocketHandle,
};
use std::convert::TryFrom;

pub struct RouteSocket {
    sock: NlSocketHandle,
}

impl RouteSocket {
    pub fn connect() -> Result<Self, ConnectError> {
        let sock = NlSocketHandle::new(NlFamily::Route)?;

        // Autoselect a PID
        let pid = None;
        let groups = &[];
        sock.bind(pid, groups)?;

        Ok(Self { sock })
    }

    pub fn add_device(&mut self, ifname: &str) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceLinkOperation::Add;

        self.sock.send(link_message(ifname, operation)?)?;
        self.sock.recv::<Nlmsg, Genlmsghdr<CtrlCmd, CtrlAttr>>()?;

        Ok(())
    }

    pub fn del_device(&mut self, ifname: &str) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceLinkOperation::Delete;

        self.sock.send(link_message(ifname, operation)?)?;
        self.sock.recv::<Nlmsg, Genlmsghdr<CtrlCmd, CtrlAttr>>()?;

        Ok(())
    }

    /// Retrieves all interface names that have the string "wireguard" as an
    /// [IFLA_INFO_KIND](libc::IFLA_INFO_KIND) value.
    pub fn list_device_names(&mut self) -> Result<Vec<String>, ListDevicesError> {
        self.sock
            .send(list_device_names_utils::get_list_device_names_msg())?;

        let mut iter = self.sock.iter::<Ifinfomsg>(false);

        let mut result_names = vec![];

        while let Some(Ok(response)) = iter.next() {
            match response.nl_type {
                NlTypeWrapper::Nlmsg(Nlmsg::Error) => return Err(ListDevicesError::Unknown),
                NlTypeWrapper::Nlmsg(Nlmsg::Done) => break,
                _ => (),
            }

            let PotentialWireGuardDeviceName {
                is_wireguard,
                ifname,
            } = PotentialWireGuardDeviceName::try_from(response)?;

            if is_wireguard {
                if let Some(ifname) = ifname {
                    result_names.push(ifname);
                }
            }
        }

        Ok(result_names)
    }
}
