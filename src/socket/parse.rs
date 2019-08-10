use crate::attr::{NlaNested, WgAllowedIpAttribute, WgDeviceAttribute, WgPeerAttribute};
use crate::err::{ParseAttributeError, ParseDeviceError, ParseIpAddrError, ParseSockAddrError};
use crate::get::{AllowedIp, AllowedIpBuilder, Device, DeviceBuilder, Peer, PeerBuilder};
use libc::{in6_addr, in_addr, AF_INET, AF_INET6};
use neli::nlattr::AttrHandle;
use neli::nlattr::Nlattr;
use std::convert::TryFrom;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub fn parse_device(handle: AttrHandle<WgDeviceAttribute>) -> Result<Device, ParseDeviceError> {
    let mut device_builder = DeviceBuilder::default();

    for attr in handle.iter() {
        match attr.nla_type {
            WgDeviceAttribute::Unspec => {
                // The embeddable-wg-library example ignores unspec, so we'll do the same.
            }
            WgDeviceAttribute::Ifindex => {
                device_builder.ifindex(parse_nla_u32(&attr.payload)?);
            }
            WgDeviceAttribute::Ifname => {
                device_builder.ifname(parse_nla_nul_string(&attr.payload)?);
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
                let handle = attr.get_nested_attributes::<NlaNested>()?;
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

pub fn extend_device(
    mut device: Device,
    handle: AttrHandle<WgDeviceAttribute>,
) -> Result<Device, ParseDeviceError> {
    let next_peers = {
        let peers_attr = handle.get_attribute(WgDeviceAttribute::Peers).unwrap();
        let handle = peers_attr.get_nested_attributes::<NlaNested>()?;

        handle
            .iter()
            .map(Nlattr::<NlaNested, Vec<u8>>::get_nested_attributes::<WgPeerAttribute>)
            .map(|handle| {
                handle
                    .map_err(|err| err.into())
                    .and_then(parse_peer_builder)
            })
            .collect::<Result<Vec<PeerBuilder>, _>>()?
    };

    for next_peer in next_peers {
        let matching_last_peer = device
            .peers
            .last_mut()
            .filter(|last_peer| Some(last_peer.public_key) == next_peer.public_key);

        match matching_last_peer {
            Some(matching_last_peer) => matching_last_peer
                .allowed_ips
                .append(&mut next_peer.allowed_ips.unwrap_or(vec![])),
            None => device.peers.push(next_peer.build()?),
        }
    }

    Ok(device)
}

pub fn parse_peers(handle: AttrHandle<NlaNested>) -> Result<Vec<Peer>, ParseDeviceError> {
    let mut peers = vec![];

    for peer in handle.iter() {
        let handle = peer.get_nested_attributes::<WgPeerAttribute>()?;
        peers.push(parse_peer(handle)?);
    }

    Ok(peers)
}

pub fn parse_peer_builder(
    handle: AttrHandle<WgPeerAttribute>,
) -> Result<PeerBuilder, ParseDeviceError> {
    let mut peer_builder = PeerBuilder::default();

    for attr in handle.iter() {
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
                let handle = attr.get_nested_attributes::<NlaNested>()?;
                peer_builder.allowed_ips(parse_allowedips(handle)?);
            }
            WgPeerAttribute::ProtocolVersion => {
                peer_builder.protocol_version(parse_nla_u32(&attr.payload)?);
            }
            WgPeerAttribute::UnrecognizedVariant(i) => {
                return Err(ParseDeviceError::UnknownPeerAttributeError { id: i })
            }
        }
    }

    Ok(peer_builder)
}

pub fn parse_peer(handle: AttrHandle<WgPeerAttribute>) -> Result<Peer, ParseDeviceError> {
    let peer_builder = parse_peer_builder(handle)?;
    Ok(peer_builder.build()?)
}

pub fn parse_allowedips(handle: AttrHandle<NlaNested>) -> Result<Vec<AllowedIp>, ParseDeviceError> {
    let mut allowed_ips = vec![];

    for allowed_ip in handle.iter() {
        let handle = allowed_ip.get_nested_attributes::<WgAllowedIpAttribute>()?;
        allowed_ips.push(parse_allowedip(handle)?);
    }

    Ok(allowed_ips)
}

pub fn parse_allowedip(
    handle: AttrHandle<WgAllowedIpAttribute>,
) -> Result<AllowedIp, ParseDeviceError> {
    let mut allowed_ip_builder = AllowedIpBuilder::default();

    for attr in handle.iter() {
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

pub fn parse_nla_nul_string(payload: &[u8]) -> Result<String, ParseAttributeError> {
    // Although payload is a known length, a null-terminated C string is still
    // sent over netlink. We should check that this was the case before dropping
    // the last character (which should be null).
    let mut payload = payload.to_vec();

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
    use crate::cmd::WgCmd;
    use base64;
    use buffering::copy::StreamReadBuffer;
    use failure;
    use neli::err::DeError;
    use neli::genl::Genlmsghdr;
    use neli::Nl;

    fn create_test_genlmsghdr(
        payload: &[u8],
    ) -> Result<Genlmsghdr<WgCmd, WgDeviceAttribute>, DeError> {
        let mut mem = StreamReadBuffer::new(payload);
        mem.set_size_hint(payload.size());
        Genlmsghdr::deserialize(&mut mem)
    }

    #[test]
    fn parse_device_example_from_man_page() -> Result<(), failure::Error> {
        // This payload comes from the configuration example in "man wg", but with the third peer
        // removed since it specifies an invalid endpoint.
        let payload = vec![
            1, 1, 0, 0, 6, 0, 6, 0, 108, 202, 0, 0, 8, 0, 7, 0, 0, 0, 0, 0, 8, 0, 1, 0, 6, 0, 0, 0,
            9, 0, 2, 0, 116, 101, 115, 116, 0, 0, 0, 0, 36, 0, 3, 0, 200, 9, 243, 229, 49, 126,
            149, 117, 201, 181, 237, 120, 182, 56, 183, 206, 83, 13, 171, 232, 93, 218, 182, 20,
            34, 2, 65, 128, 29, 223, 6, 105, 36, 0, 4, 0, 28, 136, 40, 247, 19, 115, 36, 197, 139,
            40, 4, 146, 134, 36, 234, 35, 38, 241, 103, 69, 55, 192, 98, 226, 81, 226, 117, 60,
            167, 252, 202, 76, 192, 1, 8, 0, 216, 0, 0, 0, 36, 0, 1, 0, 197, 50, 1, 3, 154, 219,
            161, 75, 231, 31, 136, 109, 161, 216, 219, 233, 238, 189, 237, 8, 203, 17, 27, 117, 52,
            0, 120, 153, 154, 169, 240, 56, 36, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5, 0, 0, 0, 0, 0, 12, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            12, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 10, 0, 1, 0, 0, 0, 20, 0, 4, 0, 2, 0, 4,
            210, 192, 95, 5, 67, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 9, 0, 28, 0, 0, 0, 5, 0, 3, 0, 32,
            0, 0, 0, 6, 0, 1, 0, 2, 0, 0, 0, 8, 0, 2, 0, 10, 192, 122, 3, 28, 0, 0, 0, 5, 0, 3, 0,
            24, 0, 0, 0, 6, 0, 1, 0, 2, 0, 0, 0, 8, 0, 2, 0, 10, 192, 124, 0, 228, 0, 0, 0, 36, 0,
            1, 0, 78, 179, 47, 74, 131, 248, 141, 132, 37, 99, 164, 72, 204, 24, 27, 178, 196, 42,
            99, 123, 241, 35, 99, 226, 251, 46, 245, 148, 229, 150, 93, 125, 36, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            20, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5, 0, 0, 0, 0, 0,
            12, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 10, 0,
            1, 0, 0, 0, 32, 0, 4, 0, 10, 0, 9, 164, 0, 0, 0, 0, 38, 7, 83, 0, 0, 96, 6, 176, 0, 0,
            0, 0, 192, 95, 5, 67, 0, 0, 0, 0, 60, 0, 9, 0, 28, 0, 0, 0, 5, 0, 3, 0, 32, 0, 0, 0, 6,
            0, 1, 0, 2, 0, 0, 0, 8, 0, 2, 0, 10, 192, 122, 4, 28, 0, 0, 0, 5, 0, 3, 0, 16, 0, 0, 0,
            6, 0, 1, 0, 2, 0, 0, 0, 8, 0, 2, 0, 192, 168, 0, 0, 20, 0, 0, 0, 3, 0, 2, 0, 0, 0, 0,
            0, 250, 117, 199, 159, 0, 0, 0, 0,
        ];
        let genlmsghdr = create_test_genlmsghdr(&payload)?;
        let device = parse_device(genlmsghdr.get_attr_handle())?;

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

    #[test]
    fn parse_device_with_large_peer() -> Result<(), failure::Error> {
        let first_payload = [
            0, 1, 0, 0, 6, 0, 6, 0, 108, 202, 0, 0, 8, 0, 7, 0, 0, 0, 0, 0, 8, 0, 1, 0, 6, 0, 0, 0,
            9, 0, 2, 0, 116, 101, 115, 116, 0, 0, 0, 0, 36, 0, 3, 0, 200, 9, 243, 229, 49, 126,
            149, 117, 201, 181, 237, 120, 182, 56, 183, 206, 83, 13, 171, 232, 93, 218, 182, 20,
            34, 2, 65, 128, 29, 223, 6, 105, 36, 0, 4, 0, 28, 136, 40, 247, 19, 115, 36, 197, 139,
            40, 4, 146, 134, 36, 234, 35, 38, 241, 103, 69, 55, 192, 98, 226, 81, 226, 117, 60,
            167, 252, 202, 76, 60, 14, 8, 0, 56, 14, 0, 0, 36, 0, 1, 0, 197, 50, 1, 3, 154, 219,
            161, 75, 231, 31, 136, 109, 161, 216, 219, 233, 238, 189, 237, 8, 203, 17, 27, 117, 52,
            0, 120, 153, 154, 169, 240, 56, 36, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5, 0, 0, 0, 0, 0, 12, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            12, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 10, 0, 1, 0, 0, 0, 20, 0, 4, 0, 2, 0, 4,
            210, 192, 95, 5, 67, 0, 0, 0, 0, 0, 0, 0, 0, 156, 13, 9, 0, 40, 0, 0, 0, 5, 0, 3, 0,
            128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0,
            0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            3, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 40, 0,
            0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 8, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 10, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 15, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 17, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 19, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 24, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 26, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 28, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 33, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 35, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 37, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 38, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 42, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 44, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 46, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 51, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 53, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 55, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 60, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 62, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 64, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 67, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 69, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 70, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 71, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 73, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 78, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 80, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 81, 40, 0, 0, 0, 5, 0, 3, 0, 128,
            0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 82, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1,
            0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 86, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 87,
        ];
        let second_payload = [
            0, 1, 0, 0, 6, 0, 6, 0, 108, 202, 0, 0, 8, 0, 7, 0, 0, 0, 0, 0, 8, 0, 1, 0, 6, 0, 0, 0,
            9, 0, 2, 0, 116, 101, 115, 116, 0, 0, 0, 0, 36, 0, 3, 0, 200, 9, 243, 229, 49, 126,
            149, 117, 201, 181, 237, 120, 182, 56, 183, 206, 83, 13, 171, 232, 93, 218, 182, 20,
            34, 2, 65, 128, 29, 223, 6, 105, 36, 0, 4, 0, 28, 136, 40, 247, 19, 115, 36, 197, 139,
            40, 4, 146, 134, 36, 234, 35, 38, 241, 103, 69, 55, 192, 98, 226, 81, 226, 117, 60,
            167, 252, 202, 76, 8, 10, 8, 0, 4, 10, 0, 0, 36, 0, 1, 0, 197, 50, 1, 3, 154, 219, 161,
            75, 231, 31, 136, 109, 161, 216, 219, 233, 238, 189, 237, 8, 203, 17, 27, 117, 52, 0,
            120, 153, 154, 169, 240, 56, 220, 9, 9, 0, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 40, 0,
            0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 89, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10,
            0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 40, 0, 0, 0, 5,
            0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 91, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0,
            20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 92, 40, 0, 0, 0, 5, 0, 3, 0,
            128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 93, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 94, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0,
            0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            95, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 40, 0,
            0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 98, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10,
            0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 40, 0, 0, 0, 5,
            0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 100, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0,
            20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 40, 0, 0, 0, 5, 0, 3, 0,
            128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 102, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 103, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0,
            0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 104, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 105, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 106,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 107, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 40,
            0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 109, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0,
            10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 111, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 113, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 40, 0, 0, 0, 5, 0, 3, 0,
            128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 115, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 116, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0,
            0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 117, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 118, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 121, 40,
            0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 122, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0,
            10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 124, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 125, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 126, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 40, 0, 0, 0, 5, 0, 3, 0,
            128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 128, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0,
            0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 130, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 132,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 134, 40,
            0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 135, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0,
            10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 137, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0,
            0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 138, 40, 0, 0, 0, 5, 0,
            3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 139, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 40, 0, 0, 0, 5, 0, 3, 0,
            128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 141, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 142, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0,
            0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 143, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0,
            6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 145,
            40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 146, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0,
            1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 147, 40,
            0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 40, 0, 0, 0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0,
            10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 149, 40, 0, 0,
            0, 5, 0, 3, 0, 128, 0, 0, 0, 6, 0, 1, 0, 10, 0, 0, 0, 20, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 150,
        ];

        let genlmsghdr = create_test_genlmsghdr(&first_payload)?;
        let device = parse_device(genlmsghdr.get_attr_handle())?;

        let genlmsghdr = create_test_genlmsghdr(&second_payload)?;
        let device = extend_device(device, genlmsghdr.get_attr_handle())?;

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
                peers: vec![Peer {
                    public_key: parse_device_key(&base64::decode(
                        "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
                    )?)?,
                    preshared_key: [0u8; 32],
                    endpoint: Some("192.95.5.67:1234".parse()?),
                    persistent_keepalive_interval: 0,
                    last_handshake_time: Duration::new(0, 0),
                    rx_bytes: 0,
                    tx_bytes: 0,
                    allowed_ips: (1..=150)
                        .step_by(1)
                        .map(|h| AllowedIp {
                            family: libc::AF_INET6 as u16,
                            ipaddr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, h)),
                            cidr_mask: 128,
                        })
                        .collect(),
                    protocol_version: 1,
                }]
            }
        );

        Ok(())
    }
}
