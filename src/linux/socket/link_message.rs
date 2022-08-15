use crate::linux::consts::WG_GENL_NAME;
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{Arphrd, Iff, IffFlags, Ifla, IflaInfo, RtAddrFamily, Rtm},
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifinfomsg, Rtattr},
    types::{Buffer, RtBuffer},
};

pub enum WireGuardDeviceLinkOperation {
    Add,
    Delete,
}

pub fn link_message(
    ifname: &str,
    link_operation: WireGuardDeviceLinkOperation,
) -> Result<Nlmsghdr<Rtm, Ifinfomsg>, NlError> {
    let ifname = Rtattr::new(None, Ifla::Ifname, Buffer::from(ifname.as_bytes()))?;
    let link = {
        let mut attrs = RtBuffer::new();

        attrs.push(Rtattr::new(
            None,
            IflaInfo::Kind,
            WG_GENL_NAME.as_bytes().to_vec(),
        )?);

        Rtattr::new(None, Ifla::Linkinfo, attrs)?
    };
    let infomsg = {
        let ifi_family = RtAddrFamily::Unspecified;
        // Arphrd::Netrom corresponds to 0. Not sure why 0 is necessary here but this is what the
        // embedded C library does.
        let ifi_type = Arphrd::Netrom;
        let ifi_index = 0;
        let ifi_flags = IffFlags::empty();
        let ifi_change = IffFlags::new(&[Iff::Up]);
        let rtattrs = {
            let mut buffer = RtBuffer::new();
            buffer.push(ifname);
            buffer.push(link);
            buffer
        };

        Ifinfomsg::new(
            ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change, rtattrs,
        )
    };

    let nlmsg = {
        let len = None;
        let nl_type = match link_operation {
            WireGuardDeviceLinkOperation::Add => Rtm::Newlink,
            WireGuardDeviceLinkOperation::Delete => Rtm::Dellink,
        };
        let flags = match link_operation {
            WireGuardDeviceLinkOperation::Add => {
                NlmFFlags::new(&[NlmF::Request, NlmF::Ack, NlmF::Create, NlmF::Excl])
            }
            WireGuardDeviceLinkOperation::Delete => NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        };
        let seq = None;
        let pid = None;
        let payload = NlPayload::Payload(infomsg);
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };

    Ok(nlmsg)
}
