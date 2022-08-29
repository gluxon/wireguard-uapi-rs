use crate::err::ListDevicesError;
use neli::attr::Attribute;
use neli::rtnl::Rtattr;
use neli::{
    consts::{
        nl::{NlTypeWrapper, NlmF, NlmFFlags},
        rtnl::{Arphrd, Iff, IffFlags, Ifla, IflaInfo, Rtm},
    },
    nl::{NlPayload, Nlmsghdr},
    rtnl::Ifinfomsg,
    types::RtBuffer,
};
use std::convert::TryFrom;

pub fn get_list_device_names_msg() -> Nlmsghdr<Rtm, Ifinfomsg> {
    let infomsg = {
        let ifi_family =
            neli::consts::rtnl::RtAddrFamily::UnrecognizedVariant(libc::AF_UNSPEC as u8);
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = IffFlags::empty();
        let rtattrs = RtBuffer::new();
        let ifi_change = IffFlags::new(&[Iff::Up]);

        Ifinfomsg::new(
            ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change, rtattrs,
        )
    };

    let len = None;
    let nl_type = Rtm::Getlink;
    let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack, NlmF::Dump]);
    let seq = None;
    let pid = None;
    let payload = infomsg;
    Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(payload))
}

pub struct PotentialWireGuardDeviceName {
    pub ifname: Option<String>,
    pub is_wireguard: bool,
}

impl TryFrom<Nlmsghdr<NlTypeWrapper, Ifinfomsg>> for PotentialWireGuardDeviceName {
    type Error = ListDevicesError;

    fn try_from(response: Nlmsghdr<NlTypeWrapper, Ifinfomsg>) -> Result<Self, Self::Error> {
        let mut is_wireguard = false;
        let mut ifname: Option<String> = None;

        let handle = response.get_payload()?.rtattrs.get_attr_handle();

        for attr in handle.get_attrs() {
            match attr.rta_type {
                Ifla::Linkinfo => {
                    for info_kind in attr
                        .get_attr_handle()?
                        .iter()
                        .filter(|attr: &&Rtattr<IflaInfo, _>| attr.rta_type == IflaInfo::Kind)
                    {
                        is_wireguard |= info_kind.get_payload_as::<String>()?
                            == crate::linux::consts::WG_GENL_NAME;
                    }
                }
                Ifla::Ifname => {
                    ifname = Some(attr.get_payload_as::<String>()?);
                }
                _ => {}
            }
        }

        Ok(PotentialWireGuardDeviceName {
            ifname,
            is_wireguard,
        })
    }
}
