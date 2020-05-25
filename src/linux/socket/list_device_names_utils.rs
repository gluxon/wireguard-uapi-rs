use super::parse::parse_nla_nul_string;
use crate::linux::err::ListDevicesError;
use neli::consts::{Arphrd, Ifla, NlmF, Nlmsg, Rtm};
use neli::nl::Nlmsghdr;
use neli::rtnl::Ifinfomsg;
use neli::rtnl::Rtattr;
use neli::{Nl, StreamReadBuffer};

pub fn get_list_device_names_msg() -> Nlmsghdr<Rtm, Ifinfomsg<Ifla>> {
    let infomsg = {
        let ifi_family =
            neli::consts::rtnl::RtAddrFamily::UnrecognizedVariant(libc::AF_UNSPEC as u8);
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = vec![];
        let rtattrs: Vec<Rtattr<Ifla, Vec<u8>>> = vec![];
        Ifinfomsg::new(ifi_family, ifi_type, ifi_index, ifi_flags, rtattrs)
    };

    let len = None;
    let nl_type = Rtm::Getlink;
    let flags = vec![NlmF::Request, NlmF::Ack, NlmF::Dump];
    let seq = None;
    let pid = None;
    let payload = infomsg;
    Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
}

pub struct PotentialWireGuardDeviceName {
    pub ifname: Option<String>,
    pub is_wireguard: bool,
}

pub fn parse_ifinfomsg(
    response: Nlmsghdr<Nlmsg, Ifinfomsg<Ifla>>,
) -> Result<PotentialWireGuardDeviceName, ListDevicesError> {
    let mut is_wireguard = false;
    let mut ifname: Option<String> = None;

    for attr in response.nl_payload.rtattrs {
        match attr.rta_type {
            Ifla::UnrecognizedVariant(libc::IFLA_LINKINFO) => {
                let mut buf = StreamReadBuffer::new(&attr.rta_payload);
                let linkinfo = Rtattr::<u16, Vec<u8>>::deserialize(&mut buf)?;

                if linkinfo.rta_type == libc::IFLA_INFO_KIND {
                    let info_kind = parse_nla_nul_string(&linkinfo.rta_payload)?;
                    if info_kind == crate::linux::consts::WG_GENL_NAME {
                        is_wireguard = true;
                    }
                }
            }
            Ifla::Ifname => {
                ifname = Some(parse_nla_nul_string(&attr.rta_payload)?);
            }
            _ => {}
        };
    }

    Ok(PotentialWireGuardDeviceName {
        ifname,
        is_wireguard,
    })
}
