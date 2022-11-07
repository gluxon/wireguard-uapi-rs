use crate::get;
use crate::linux::attr::WgDeviceAttribute;
use crate::linux::cmd::WgCmd;
use crate::linux::consts::NLA_NETWORK_ORDER;
use crate::linux::consts::{WG_GENL_NAME, WG_GENL_VERSION};
use crate::linux::err::{ConnectError, GetDeviceError, SetDeviceError};
use crate::linux::set;
use crate::linux::set::create_set_device_messages;
use crate::linux::socket::parse::*;
use crate::linux::socket::NlWgMsgType;
use crate::linux::DeviceInterface;
use libc::IFNAMSIZ;
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags, Nlmsg},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::GenlBuffer,
};
use std::convert::TryFrom;

pub struct WgSocket {
    sock: NlSocketHandle,
    family_id: NlWgMsgType,
}

impl WgSocket {
    pub fn connect() -> Result<Self, ConnectError> {
        let family_id = {
            NlSocketHandle::new(NlFamily::Generic)?
                .resolve_genl_family(WG_GENL_NAME)
                .map_err(ConnectError::ResolveFamilyError)?
        };

        // Autoselect a PID
        let pid = None;
        let groups = &[];
        let wgsock = NlSocketHandle::connect(NlFamily::Generic, pid, groups)?;

        Ok(Self {
            sock: wgsock,
            family_id,
        })
    }

    pub fn get_device(
        &mut self,
        interface: DeviceInterface,
    ) -> Result<get::Device, GetDeviceError> {
        let attr = match interface {
            DeviceInterface::Name(name) => {
                Some(name.len())
                    .filter(|&len| 0 < len && len < IFNAMSIZ)
                    .ok_or(GetDeviceError::InvalidInterfaceName)?;
                Nlattr::new(
                    false,
                    NLA_NETWORK_ORDER,
                    WgDeviceAttribute::Ifname,
                    name.as_ref(),
                )?
            }
            DeviceInterface::Index(index) => {
                Nlattr::new(false, NLA_NETWORK_ORDER, WgDeviceAttribute::Ifindex, index)?
            }
        };
        let genlhdr = {
            let cmd = WgCmd::GetDevice;
            let version = WG_GENL_VERSION;
            let mut attrs = GenlBuffer::new();

            attrs.push(attr);
            Genlmsghdr::new(cmd, version, attrs)
        };
        let nlhdr = {
            let size = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(genlhdr);
            Nlmsghdr::new(size, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(nlhdr)?;

        let mut iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<WgCmd, WgDeviceAttribute>>(false);

        let mut device = None;
        while let Some(Ok(response)) = iter.next() {
            match response.nl_type {
                Nlmsg::Error => return Err(GetDeviceError::AccessError),
                Nlmsg::Done => break,
                _ => (),
            };

            let handle = response.get_payload()?.get_attr_handle();
            device = Some(match device {
                Some(device) => extend_device(device, handle)?,
                None => get::Device::try_from(handle)?,
            });
        }

        device.ok_or(GetDeviceError::AccessError)
    }

    /// This assumes that the device interface has already been created. Otherwise an error will
    /// be returned. You can create a new device interface with
    /// [`RouteSocket::add_device`](./struct.RouteSocket.html#add_device.v).
    ///
    /// The peers in this device won't be reachable at their allowed IPs until they're added to the
    /// newly created device interface through a Netlink Route message. This library doesn't have
    /// built-in way to do that right now. Here's how it would be done with the `ip` command:
    ///
    ///
    /// ```sh
    ///  sudo ip -4 route add 127.3.1.1/32 dev wgtest0
    /// ```
    pub fn set_device(&mut self, device: set::Device) -> Result<(), SetDeviceError> {
        for nl_message in create_set_device_messages(device, self.family_id)? {
            self.sock.send(nl_message)?;
            self.sock.recv()?;
        }

        Ok(())
    }
}
