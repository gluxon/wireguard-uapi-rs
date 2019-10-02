use crate::consts::WG_GENL_NAME;
use neli::consts::{Arphrd, Ifla, NlmF, Rtm};
use neli::err::SerError;
use neli::nl::Nlmsghdr;
use neli::nlattr::Nlattr;
use neli::rtnl::Ifinfomsg;
use neli::rtnl::Rtattr;
use neli::Nl;
use neli::StreamWriteBuffer;

const RTATTR_HEADER_LEN: libc::c_ushort = 4;

// https://github.com/torvalds/linux/blob/54ecb8f7/include/uapi/linux/if_link.h#L133
const IFLA_LINKINFO: libc::c_ushort = 18;

// https://github.com/torvalds/linux/blob/54ecb8f7/include/uapi/linux/if_link.h#L356
const IFLA_INFO_KIND: libc::c_ushort = 1;

pub enum WireGuardDeviceLinkOperation {
    Add,
    Delete,
}

fn create_rtattr(rta_type: Ifla, rta_payload: Vec<u8>) -> Rtattr<Ifla, Vec<u8>> {
    let mut rtattr = Rtattr {
        rta_len: 0,
        rta_type,
        rta_payload,
    };
    // neli doesn't provide a nice way to automatically set this for rtattr (it does for nlattr),
    // so we'll do some small math ourselves.
    rtattr.rta_len = rtattr.payload_size() as libc::c_ushort + RTATTR_HEADER_LEN;
    rtattr
}

pub fn link_message(
    ifname: &str,
    link_operation: WireGuardDeviceLinkOperation,
) -> Result<Nlmsghdr<Rtm, Ifinfomsg<Ifla>>, SerError> {
    let ifname = create_rtattr(Ifla::Ifname, ifname.as_bytes().to_vec());

    let link = {
        let rta_type = Ifla::UnrecognizedVariant(IFLA_LINKINFO);
        let payload = {
            // The Rtattr struct doesn't have a add_nested_attribute field like Nlattr. To work
            // around this, we can create a Nlattr and manually serialize it to a byte vector.
            let mut payload = StreamWriteBuffer::new_growable(None);
            let rtattr =
                Nlattr::new::<Vec<u8>>(None, IFLA_INFO_KIND, WG_GENL_NAME.as_bytes().to_vec())?;
            rtattr.serialize(&mut payload)?;
            payload.as_ref().to_vec()
        };
        create_rtattr(rta_type, payload)
    };

    let infomsg = {
        let ifi_family =
            neli::consts::rtnl::RtAddrFamily::UnrecognizedVariant(libc::AF_UNSPEC as u8);
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = vec![];
        let rtattrs = vec![ifname, link];
        Ifinfomsg::new(ifi_family, ifi_type, ifi_index, ifi_flags, rtattrs)
    };

    let nlmsg = {
        let len = None;
        let nl_type = match link_operation {
            WireGuardDeviceLinkOperation::Add => Rtm::Newlink,
            WireGuardDeviceLinkOperation::Delete => Rtm::Dellink,
        };
        let flags = match link_operation {
            WireGuardDeviceLinkOperation::Add => {
                vec![NlmF::Request, NlmF::Ack, NlmF::Create, NlmF::Excl]
            }
            WireGuardDeviceLinkOperation::Delete => vec![NlmF::Request, NlmF::Ack],
        };
        let seq = None;
        let pid = None;
        let payload = infomsg;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };

    Ok(nlmsg)
}
