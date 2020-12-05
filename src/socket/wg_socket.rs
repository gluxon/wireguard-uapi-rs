use crate::attr::WgDeviceAttribute;
use crate::cmd::WgCmd;
use crate::consts::{WG_GENL_NAME, WG_GENL_VERSION};
use crate::err::{ConnectError, GetDeviceError, SetDeviceError};
use crate::get;
use crate::set;
use crate::set::create_set_device_messages;
use crate::socket::parse::*;
use crate::socket::NlWgMsgType;
use crate::DeviceInterface;
use libc::IFNAMSIZ;
use neli::consts::{NlFamily, NlmF, Nlmsg};
use neli::genl::Genlmsghdr;
use neli::nl::Nlmsghdr;
use neli::nlattr::Nlattr;
use neli::socket::NlSocket;
use neli::Nl;
use neli::StreamWriteBuffer;

pub struct WgSocket {
    sock: NlSocket,
    family_id: NlWgMsgType,
}

impl WgSocket {
    pub fn connect() -> Result<Self, ConnectError> {
        let family_id = {
            NlSocket::new(NlFamily::Generic, true)?
                .resolve_genl_family(WG_GENL_NAME)
                .map_err(ConnectError::ResolveFamilyError)?
        };

        let track_seq = true;
        let mut wgsock = NlSocket::new(NlFamily::Generic, track_seq)?;

        // Autoselect a PID
        let pid = None;
        let groups = None;
        wgsock.bind(pid, groups)?;

        Ok(Self {
            sock: wgsock,
            family_id,
        })
    }

    pub fn get_device(
        &mut self,
        interface: DeviceInterface,
    ) -> Result<get::Device, GetDeviceError> {
        let mut mem = StreamWriteBuffer::new_growable(None);
        let attr = match interface {
            DeviceInterface::Name(name) => {
                Some(name.len())
                    .filter(|&len| 0 < len && len < IFNAMSIZ)
                    .ok_or(GetDeviceError::InvalidInterfaceName)?;
                name.as_ref().serialize(&mut mem)?;
                Nlattr::new(None, WgDeviceAttribute::Ifname, mem.as_ref())?
            }
            DeviceInterface::Index(index) => {
                index.serialize(&mut mem)?;
                Nlattr::new(None, WgDeviceAttribute::Ifindex, mem.as_ref())?
            }
        };
        let genlhdr = {
            let cmd = WgCmd::GetDevice;
            let version = WG_GENL_VERSION;
            let attrs = vec![attr];
            Genlmsghdr::new(cmd, version, attrs)?
        };
        let nlhdr = {
            let size = None;
            let nl_type = self.family_id;
            let flags = vec![NlmF::Request, NlmF::Ack, NlmF::Dump];
            let seq = None;
            let pid = None;
            let payload = genlhdr;
            Nlmsghdr::new(size, nl_type, flags, seq, pid, payload)
        };

        self.sock.send_nl(nlhdr)?;

        let mut iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<WgCmd, WgDeviceAttribute>>();

        let mut device = None;
        while let Some(Ok(response)) = iter.next() {
            match response.nl_type {
                Nlmsg::Error => return Err(GetDeviceError::AccessError),
                Nlmsg::Done => break,
                _ => (),
            };

            let handle = response.nl_payload.get_attr_handle();
            device = Some(match device {
                Some(device) => extend_device(device, handle)?,
                None => parse_device(handle)?,
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
            self.sock.send_nl(nl_message)?;
            self.sock.recv_ack()?;
        }

        Ok(())
    }
}
