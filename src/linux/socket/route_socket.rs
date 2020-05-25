use super::list_device_names_utils;
use super::{link_message, WireGuardDeviceLinkOperation};
use crate::linux::err::{ConnectError, LinkDeviceError, ListDevicesError};
use list_device_names_utils::PotentialWireGuardDeviceName;
use neli::consts::{Ifla, NlFamily, Nlmsg};
use neli::rtnl::Ifinfomsg;
use neli::socket::NlSocket;

pub struct RouteSocket {
    sock: NlSocket,
}

impl RouteSocket {
    pub fn connect() -> Result<Self, ConnectError> {
        let track_seq = true;
        let mut sock = NlSocket::new(NlFamily::Route, track_seq)?;

        // Autoselect a PID
        let pid = None;
        let groups = None;
        sock.bind(pid, groups)?;

        Ok(Self { sock })
    }

    pub fn add_device(&mut self, ifname: &str) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceLinkOperation::Add;
        self.sock.send_nl(link_message(ifname, operation)?)?;
        self.sock.recv_ack()?;
        Ok(())
    }

    pub fn del_device(&mut self, ifname: &str) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceLinkOperation::Delete;
        self.sock.send_nl(link_message(ifname, operation)?)?;
        self.sock.recv_ack()?;
        Ok(())
    }

    /// Retrieves all interface names that have the string "wireguard" as an
    /// [IFLA_INFO_KIND](libc::IFLA_INFO_KIND) value.
    pub fn list_device_names(&mut self) -> Result<Vec<String>, ListDevicesError> {
        self.sock
            .send_nl(list_device_names_utils::get_list_device_names_msg())?;

        let mut iter = self.sock.iter::<Nlmsg, Ifinfomsg<Ifla>>();

        let mut result_names = vec![];

        while let Some(Ok(response)) = iter.next() {
            match response.nl_type {
                Nlmsg::Error => return Err(ListDevicesError::Unknown),
                Nlmsg::Done => break,
                _ => (),
            };

            let PotentialWireGuardDeviceName {
                is_wireguard,
                ifname,
            } = list_device_names_utils::parse_ifinfomsg(response)?;

            if is_wireguard {
                if let Some(ifname) = ifname {
                    result_names.push(ifname);
                }
            }
        }

        Ok(result_names)
    }
}
