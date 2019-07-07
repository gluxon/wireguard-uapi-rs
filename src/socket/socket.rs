use crate::attr::WgDeviceAttribute;
use crate::cmd::WgCmd;
use crate::consts::{WG_GENL_NAME, WG_GENL_VERSION};
use crate::err::{ConnectError, GetDeviceError, SetDeviceError};
use crate::get;
use crate::set;
use crate::socket::parse::*;
use crate::socket::NlWgMsgType;
use libc::{IFNAMSIZ};
use neli::Nl;
use neli::consts::{NlFamily, Nlmsg, NlmF};
use neli::genl::Genlmsghdr;
use neli::nlattr::Nlattr;
use neli::nl::Nlmsghdr;
use neli::socket::NlSocket;
use neli::StreamWriteBuffer;
use std::convert::TryInto;

pub struct Socket {
    sock: NlSocket,
    family_id: NlWgMsgType,
}

pub enum GetDeviceArg<'a> {
    Ifindex(u32),
    Ifname(&'a str),
}

impl Socket {
    pub fn connect() -> Result<Self, ConnectError> {
        let family_id = {
            NlSocket::new(NlFamily::Generic, true)?
                .resolve_genl_family(WG_GENL_NAME)
                .map_err(|err| ConnectError::ResolveFamilyError(err))?
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

    pub fn get_device(&mut self, interface: GetDeviceArg) -> Result<get::Device, GetDeviceError> {
        let mut mem = StreamWriteBuffer::new_growable(None);
        let attr = match interface {
            GetDeviceArg::Ifname(name) => {
                Some(name.len())
                    .filter(|&len| 0 < len && len < IFNAMSIZ)
                    .ok_or_else(|| GetDeviceError::InvalidInterfaceName)?;
                name.serialize(&mut mem)?;
                Nlattr::new(None, WgDeviceAttribute::Ifname, mem.as_ref())?
            }
            GetDeviceArg::Ifindex(index) => {
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

        // In the future, neli will return multiple Netlink messages. We have to go through each
        // message and coalesce peers in the way described by the WireGuard UAPI when this change
        // happens. For now, parsing is broken if the entire response doesn't fit in a single
        // payload.
        //
        // See: https://github.com/jbaublitz/neli/issues/15

        let mut iter = self.sock.iter::<Nlmsg, Genlmsghdr<WgCmd, WgDeviceAttribute>>();
        while let Some(Ok(response)) = iter.next() {
            println!("{:#?}", response);
            match response.nl_type {
                Nlmsg::Error => return Err(GetDeviceError::AccessError),
                Nlmsg::Done => break,
                _ => (),
            };

            let handle = response.nl_payload.get_attr_handle();
            return Ok(parse_device(handle)?);
        }

        Err(GetDeviceError::AccessError)
    }

    pub fn set_device(&mut self, device: set::Device) -> Result<(), SetDeviceError> {
        let genlhdr = {
            let cmd = WgCmd::SetDevice;
            let version = WG_GENL_VERSION;
            let attrs = (&device).try_into()?;
            Genlmsghdr::new(cmd, version, attrs)?
        };
        let nlhdr = {
            let size = None;
            let nl_type = self.family_id;
            let flags = vec![NlmF::Request, NlmF::Ack];
            let seq = None;
            let pid = None;
            let payload = genlhdr;
            Nlmsghdr::new(size, nl_type, flags, seq, pid, payload)
        };

        self.sock.send_nl(nlhdr)?;
        self.sock.recv_ack()?;

        Ok(())
    }
}
