use crate::attr::{NlaNested, WgAllowedIpAttribute};
use neli::err::SerError;
use neli::nlattr::Nlattr;
use std::convert::TryFrom;
use std::net::IpAddr;

#[derive(Debug)]
pub struct AllowedIp<'a> {
    pub ipaddr: &'a IpAddr,
    pub cidr_mask: Option<u8>,
}

impl<'a> AllowedIp<'a> {
    pub fn from_ipaddr(ipaddr: &'a IpAddr) -> Self {
        Self {
            ipaddr,
            cidr_mask: None,
        }
    }
}

impl<'a> TryFrom<&AllowedIp<'a>> for Nlattr<NlaNested, Vec<u8>> {
    type Error = SerError;

    fn try_from(allowed_ip: &AllowedIp) -> Result<Self, Self::Error> {
        let mut nested = Nlattr::new::<Vec<u8>>(None, NlaNested::Unspec, vec![])?;

        let family = match allowed_ip.ipaddr {
            IpAddr::V4(_) => libc::AF_INET as u16,
            IpAddr::V6(_) => libc::AF_INET6 as u16,
        };
        nested.add_nested_attribute(&Nlattr::new(
            None,
            WgAllowedIpAttribute::Family,
            &family.to_ne_bytes()[..],
        )?)?;

        let ipaddr = match allowed_ip.ipaddr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        nested.add_nested_attribute(&Nlattr::new(None, WgAllowedIpAttribute::IpAddr, ipaddr)?)?;

        let cidr_mask = allowed_ip.cidr_mask.unwrap_or(match allowed_ip.ipaddr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        });
        nested.add_nested_attribute(&Nlattr::new(
            None,
            WgAllowedIpAttribute::CidrMask,
            &cidr_mask.to_ne_bytes()[..],
        )?)?;

        Ok(nested)
    }
}
