use crate::attr::{NlaNested, WgAllowedIpAttribute, WgDeviceAttribute, WgPeerAttribute};
use crate::err::{ParseAttributeError, ParseDeviceError, ParseIpAddrError, ParseSockAddrError};
use crate::get::{AllowedIp, AllowedIpBuilder, Device, DeviceBuilder, Peer, PeerBuilder};
use libc::{in6_addr, in_addr, AF_INET, AF_INET6};
use neli::err::NlError;
use neli::nlattr::{AttrHandle, NlAttrHdr};
use neli::Nl;
use std::convert::TryFrom;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

fn parse_nla_nested<T: Nl + Into<u16> + From<u16> + std::cmp::PartialEq>(
    mut handle: AttrHandle<T>,
) -> Result<Vec<NlAttrHdr<T>>, NlError> {
    // The neli library provides a .iter method on handles that have been parsed. Unfortunately
    // this is just a Vec reference slice and doesn't provide ownership. The workaround below moves
    // the internal vector within the handle and returns it.
    handle.parse_nested_attributes()?;
    match handle {
        AttrHandle::Parsed(attrs) => Ok(attrs),
        // This case will never happen (as of neli 0.3.1). Calling parse_nested_attributes above
        // should change the handle above into the Parsed enum kind.
        _ => panic!("Unable to parse nested attributes."),
    }
}

pub fn parse_device(handle: AttrHandle<WgDeviceAttribute>) -> Result<Device, ParseDeviceError> {
    let mut device_builder = DeviceBuilder::default();

    for attr in parse_nla_nested(handle)? {
        match attr.nla_type {
            WgDeviceAttribute::Unspec => {
                // The embeddable-wg-library example ignores unspec, so we'll do the same.
            }
            WgDeviceAttribute::Ifindex => {
                device_builder.ifindex(parse_nla_u32(&attr.payload)?);
            }
            WgDeviceAttribute::Ifname => {
                device_builder.ifname(parse_nla_nul_string(attr.payload)?);
            }
            WgDeviceAttribute::PrivateKey => {
                device_builder.private_key(Some(parse_device_key(&attr.payload)?));
            }
            WgDeviceAttribute::PublicKey => {
                device_builder.public_key(Some(parse_device_key(&attr.payload)?));
            }
            WgDeviceAttribute::ListenPort => {
                device_builder.listen_port(parse_nla_u16(&attr.payload)?);
            }
            WgDeviceAttribute::Fwmark => {
                device_builder.fwmark(parse_nla_u32(&attr.payload)?);
            }
            WgDeviceAttribute::Peers => {
                let handle = attr.get_attr_handle::<NlaNested>();
                device_builder.peers(parse_peers(handle)?);
            }
            WgDeviceAttribute::Flags => {
                // This attribute is for set_device. Ignore it for get_device.
            }
            WgDeviceAttribute::UnrecognizedVariant(i) => {
                return Err(ParseDeviceError::UnknownDeviceAttributeError { id: i })
            }
        }
    }

    Ok(device_builder.build()?)
}

pub fn parse_peers(handle: AttrHandle<NlaNested>) -> Result<Vec<Peer>, ParseDeviceError> {
    let mut peers = vec![];

    for peer in parse_nla_nested(handle)? {
        let handle = peer.get_attr_handle::<WgPeerAttribute>();
        peers.push(parse_peer(handle)?);
    }

    Ok(peers)
}

pub fn parse_peer(handle: AttrHandle<WgPeerAttribute>) -> Result<Peer, ParseDeviceError> {
    let mut peer_builder = PeerBuilder::default();

    for attr in parse_nla_nested(handle)? {
        match attr.nla_type {
            WgPeerAttribute::Unspec => {}
            WgPeerAttribute::Flags => {}
            WgPeerAttribute::PublicKey => {
                peer_builder.public_key(parse_device_key(&attr.payload)?);
            }
            WgPeerAttribute::PresharedKey => {
                peer_builder.preshared_key(parse_device_key(&attr.payload)?);
            }
            WgPeerAttribute::Endpoint => {
                peer_builder.endpoint(Some(parse_sockaddr_in(&attr.payload)?));
            }
            WgPeerAttribute::PersistentKeepaliveInterval => {
                peer_builder.persistent_keepalive_interval(parse_nla_u16(&attr.payload)?);
            }
            WgPeerAttribute::LastHandshakeTime => {
                peer_builder.last_handshake_time(parse_last_handshake_time(&attr.payload)?);
            }
            WgPeerAttribute::RxBytes => {
                peer_builder.rx_bytes(parse_nla_u64(&attr.payload)?);
            }
            WgPeerAttribute::TxBytes => {
                peer_builder.tx_bytes(parse_nla_u64(&attr.payload)?);
            }
            WgPeerAttribute::AllowedIps => {
                peer_builder.allowed_ips(parse_allowedips(attr)?);
            }
            WgPeerAttribute::ProtocolVersion => {
                peer_builder.protocol_version(parse_nla_u32(&attr.payload)?);
            }
            WgPeerAttribute::UnrecognizedVariant(i) => {
                return Err(ParseDeviceError::UnknownPeerAttributeError { id: i })
            }
        }
    }

    Ok(peer_builder.build()?)
}

pub fn parse_allowedips(
    attr: NlAttrHdr<WgPeerAttribute>,
) -> Result<Vec<AllowedIp>, ParseDeviceError> {
    let mut allowed_ips = vec![];

    let handle = attr.get_attr_handle::<NlaNested>();
    for allowed_ip in parse_nla_nested(handle)? {
        allowed_ips.push(parse_allowedip(allowed_ip)?)
    }

    Ok(allowed_ips)
}

pub fn parse_allowedip(attr: NlAttrHdr<NlaNested>) -> Result<AllowedIp, ParseDeviceError> {
    let mut allowed_ip_builder = AllowedIpBuilder::default();

    let handle = attr.get_attr_handle::<WgAllowedIpAttribute>();
    for attr in parse_nla_nested(handle)? {
        let payload = &attr.payload;
        match attr.nla_type {
            WgAllowedIpAttribute::Unspec => {}
            WgAllowedIpAttribute::Family => {
                allowed_ip_builder.family(parse_nla_u16(payload)?);
            }
            WgAllowedIpAttribute::IpAddr => {
                let addr = match payload.len() {
                    len if len == size_of::<in_addr>() => IpAddr::V4(parse_in_addr(payload)?),
                    len if len == size_of::<in6_addr>() => IpAddr::V6(parse_in6_addr(payload)?),
                    len => {
                        return Err(ParseIpAddrError::InvalidIpAddrLengthError { found: len })
                            .map_err(ParseAttributeError::from)
                            .map_err(ParseDeviceError::from)
                    }
                };
                allowed_ip_builder.ipaddr(addr);
            }
            WgAllowedIpAttribute::CidrMask => {
                allowed_ip_builder.cidr_mask(parse_nla_u8(payload)?);
            }
            WgAllowedIpAttribute::UnrecognizedVariant(i) => {
                return Err(ParseDeviceError::UnknownAllowedIpAttributeError { id: i })
            }
        }
    }

    Ok(allowed_ip_builder.build()?)
}

macro_rules! create_parse_nla_int {
    ($func_name: ident, $int_type: ident, $bytes: expr) => {
        pub fn $func_name(buf: &[u8]) -> Result<$int_type, ParseAttributeError> {
            Some(buf.len())
                .filter(|&len| len == $bytes)
                .ok_or_else(|| ParseAttributeError::StaticLengthError {
                    expected: $bytes,
                    found: buf.len(),
                })?;

            let mut arr = [0u8; $bytes];
            arr.copy_from_slice(&buf);
            Ok($int_type::from_ne_bytes(arr))
        }
    };
}

create_parse_nla_int!(parse_nla_u8, u8, size_of::<u8>());
create_parse_nla_int!(parse_nla_u16, u16, size_of::<u16>());
create_parse_nla_int!(parse_nla_u32, u32, size_of::<u32>());
create_parse_nla_int!(parse_nla_u64, u64, size_of::<u64>());
create_parse_nla_int!(parse_nla_i64, i64, size_of::<i64>());

pub fn parse_nla_u16_be(buf: &[u8]) -> Result<u16, ParseAttributeError> {
    Some(buf.len()).filter(|&len| len == 2).ok_or_else(|| {
        ParseAttributeError::StaticLengthError {
            expected: 2,
            found: buf.len(),
        }
    })?;

    let mut arr = [0u8; 2];
    arr.copy_from_slice(&buf);
    Ok(u16::from_be_bytes(arr))
}

pub fn parse_nla_nul_string(mut payload: Vec<u8>) -> Result<String, ParseAttributeError> {
    // Although payload is a known length, a null-terminated C string is still
    // sent over netlink. We should check that this was the case before dropping
    // the last character (which should be null).
    payload
        .pop()
        .filter(|char| char == &0)
        .ok_or(ParseAttributeError::InvalidCStringError)?;

    Ok(String::from_utf8(payload)?)
}

pub fn parse_device_key(buf: &[u8]) -> Result<[u8; 32], ParseAttributeError> {
    Some(buf.len()).filter(|&len| len == 32).ok_or_else(|| {
        ParseAttributeError::StaticLengthError {
            expected: 32,
            found: buf.len(),
        }
    })?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&buf);
    Ok(key)
}

pub fn parse_sockaddr_in(buf: &[u8]) -> Result<SocketAddr, ParseAttributeError> {
    let family = parse_nla_u16(&buf[0..2])?;

    // The port bytes are always in network byte order (or big endian) according to man 7 ip.
    let port = parse_nla_u16_be(&buf[2..4])?;

    let addr = match libc::c_int::from(family) {
        AF_INET => IpAddr::V4(parse_in_addr(&buf[4..8])?),
        AF_INET6 => IpAddr::V6(parse_in6_addr(&buf[8..24])?),
        id => return Err(ParseSockAddrError::UnrecognizedAddressFamilyError { id }.into()),
    };

    Ok(SocketAddr::new(addr, port))
}

pub fn parse_last_handshake_time(buf: &[u8]) -> Result<Duration, ParseAttributeError> {
    Some(buf.len()).filter(|&len| len == 16).ok_or_else(|| {
        ParseAttributeError::StaticLengthError {
            expected: 16,
            found: buf.len(),
        }
    })?;

    // WireGuard uses __kernel__timespec for last handshake time.
    // https://git.zx2c4.com/WireGuard/commit/?id=c870c7af53f44a37814dfc76ceb8ad88e290fcd8
    //
    // The following try_from calls should only fail if negative values are returned. Otherwise a
    // positive valued i64 will fit in a u32 and u64.
    let secs = parse_nla_i64(&buf[0..8])?;
    let secs = u64::try_from(secs)?;
    let nanos = parse_nla_i64(&buf[8..16])?;
    let nanos = u32::try_from(nanos)?;

    Ok(Duration::new(secs, nanos))
}

pub fn parse_in_addr(buf: &[u8]) -> Result<Ipv4Addr, ParseAttributeError> {
    // https://linux.die.net/man/7/ip
    Some(buf.len()).filter(|&len| len == 4).ok_or_else(|| {
        ParseAttributeError::StaticLengthError {
            expected: 4,
            found: buf.len(),
        }
    })?;
    Ok(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
}

pub fn parse_in6_addr(buf: &[u8]) -> Result<Ipv6Addr, ParseAttributeError> {
    // http://man7.org/linux/man-pages/man7/ipv6.7.html
    Some(buf.len()).filter(|&len| len == 16).ok_or_else(|| {
        ParseAttributeError::StaticLengthError {
            expected: 16,
            found: buf.len(),
        }
    })?;
    let a = parse_nla_u16_be(&buf[0..2])?;
    let b = parse_nla_u16_be(&buf[2..4])?;
    let c = parse_nla_u16_be(&buf[4..6])?;
    let d = parse_nla_u16_be(&buf[6..8])?;
    let e = parse_nla_u16_be(&buf[8..10])?;
    let f = parse_nla_u16_be(&buf[10..12])?;
    let g = parse_nla_u16_be(&buf[12..14])?;
    let h = parse_nla_u16_be(&buf[14..16])?;
    Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use failure;
    use neli::nlattr::AttrHandle;

    #[test]
    fn parse_device_example_from_man_page() -> Result<(), failure::Error> {
        // This payload comes from the configuration example in "man wg", but with the third peer
        // removed since it specifies an invalid endpoint.
        let payload = vec![
            6, 0, 6, 0, 108, 202, 0, 0, 8, 0, 7, 0, 0, 0, 0, 0, 8, 0, 1, 0, 6, 0, 0, 0, 9, 0, 2, 0,
            116, 101, 115, 116, 0, 0, 0, 0, 36, 0, 3, 0, 200, 9, 243, 229, 49, 126, 149, 117, 201,
            181, 237, 120, 182, 56, 183, 206, 83, 13, 171, 232, 93, 218, 182, 20, 34, 2, 65, 128,
            29, 223, 6, 105, 36, 0, 4, 0, 28, 136, 40, 247, 19, 115, 36, 197, 139, 40, 4, 146, 134,
            36, 234, 35, 38, 241, 103, 69, 55, 192, 98, 226, 81, 226, 117, 60, 167, 252, 202, 76,
            192, 1, 8, 0, 216, 0, 0, 0, 36, 0, 1, 0, 197, 50, 1, 3, 154, 219, 161, 75, 231, 31,
            136, 109, 161, 216, 219, 233, 238, 189, 237, 8, 203, 17, 27, 117, 52, 0, 120, 153, 154,
            169, 240, 56, 36, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 6, 0, 5, 0, 0, 0, 0, 0, 12, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 7, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 8, 0, 10, 0, 1, 0, 0, 0, 20, 0, 4, 0, 2, 0, 4, 210, 192, 95, 5,
            67, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 9, 0, 28, 0, 0, 0, 5, 0, 3, 0, 32, 0, 0, 0, 6, 0, 1,
            0, 2, 0, 0, 0, 8, 0, 2, 0, 10, 192, 122, 3, 28, 0, 0, 0, 5, 0, 3, 0, 24, 0, 0, 0, 6, 0,
            1, 0, 2, 0, 0, 0, 8, 0, 2, 0, 10, 192, 124, 0, 228, 0, 0, 0, 36, 0, 1, 0, 78, 179, 47,
            74, 131, 248, 141, 132, 37, 99, 164, 72, 204, 24, 27, 178, 196, 42, 99, 123, 241, 35,
            99, 226, 251, 46, 245, 148, 229, 150, 93, 125, 36, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 6, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5, 0, 0, 0, 0, 0, 12, 0, 8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 12, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 10, 0, 1, 0, 0, 0, 32, 0, 4,
            0, 10, 0, 9, 164, 0, 0, 0, 0, 38, 7, 83, 0, 0, 96, 6, 176, 0, 0, 0, 0, 192, 95, 5, 67,
            0, 0, 0, 0, 60, 0, 9, 0, 28, 0, 0, 0, 5, 0, 3, 0, 32, 0, 0, 0, 6, 0, 1, 0, 2, 0, 0, 0,
            8, 0, 2, 0, 10, 192, 122, 4, 28, 0, 0, 0, 5, 0, 3, 0, 16, 0, 0, 0, 6, 0, 1, 0, 2, 0, 0,
            0, 8, 0, 2, 0, 192, 168, 0, 0, 20, 0, 0, 0, 3, 0, 2, 0, 0, 0, 0, 0, 250, 117, 199, 159,
            0, 0, 0, 0,
        ];
        let device = parse_device(AttrHandle::Bin(&payload))?;

        assert_eq!(
            device,
            Device {
                ifindex: 6,
                ifname: "test".to_string(),
                private_key: Some(parse_device_key(&base64::decode(
                    "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
                )?)?),
                public_key: Some(parse_device_key(&base64::decode(
                    "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
                )?)?),
                listen_port: 51820,
                fwmark: 0,
                peers: vec![
                    Peer {
                        public_key: parse_device_key(&base64::decode(
                            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg"
                        )?)?,
                        preshared_key: [0u8; 32],
                        endpoint: Some("192.95.5.67:1234".parse()?),
                        persistent_keepalive_interval: 0,
                        last_handshake_time: Duration::new(0, 0),
                        rx_bytes: 0,
                        tx_bytes: 0,
                        allowed_ips: vec![
                            AllowedIp {
                                family: libc::AF_INET as u16,
                                ipaddr: "10.192.122.3".parse()?,
                                cidr_mask: 32
                            },
                            AllowedIp {
                                family: libc::AF_INET as u16,
                                ipaddr: "10.192.124.0".parse()?,
                                cidr_mask: 24
                            }
                        ],
                        protocol_version: 1,
                    },
                    Peer {
                        public_key: parse_device_key(&base64::decode(
                            "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
                        )?)?,
                        preshared_key: [0u8; 32],
                        endpoint: Some("[2607:5300:60:6b0::c05f:543]:2468".parse()?),
                        persistent_keepalive_interval: 0,
                        last_handshake_time: Duration::new(0, 0),
                        rx_bytes: 0,
                        tx_bytes: 0,
                        allowed_ips: vec![
                            AllowedIp {
                                family: libc::AF_INET as u16,
                                ipaddr: "10.192.122.4".parse()?,
                                cidr_mask: 32
                            },
                            AllowedIp {
                                family: libc::AF_INET as u16,
                                ipaddr: "192.168.0.0".parse()?,
                                cidr_mask: 16
                            }
                        ],
                        protocol_version: 1,
                    }
                ]
            }
        );

        Ok(())
    }
}
