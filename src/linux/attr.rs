use neli::consts::genl::NlAttrType;
use neli::neli_enum;
use std::fmt;

// As of neli 0.4.3, the NLA_F_NESTED flag needs to be added to newly created
// attribute types and the NLA_TYPE_MASK mask needs to be applied to read types.
// A future version of neli should do this automatically. At that point the
// below consts can be deleted.
pub(crate) const NLA_F_NESTED: u16 = libc::NLA_F_NESTED as u16;
pub(crate) const NLA_TYPE_MASK: u16 = libc::NLA_TYPE_MASK as u16;

macro_rules! impl_bit_ops_for_nla {
    ($name:ident) => {
        impl std::ops::BitOr<u16> for $name {
            type Output = Self;

            fn bitor(self, rhs: u16) -> Self {
                Self::from(u16::from(self) | rhs)
            }
        }

        impl std::ops::BitAnd<u16> for $name {
            type Output = Self;

            fn bitand(self, rhs: u16) -> Self {
                Self::from(u16::from(self) & rhs)
            }
        }
    };
}

#[neli_enum(serialized_type = "u16")]
pub enum NlaNested {
    Unspec = 0,
    // neli requires 1 non-zero argument even though WireGuard
    // does not use it.
    Unused = 1,
}

impl NlAttrType for NlaNested {}

impl_bit_ops_for_nla!(NlaNested);

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L147
#[neli_enum(serialized_type = "u16")]
pub enum WgDeviceAttribute {
    Unspec = 0,
    Ifindex = 1,
    Ifname = 2,
    PrivateKey = 3,
    PublicKey = 4,
    Flags = 5,
    ListenPort = 6,
    Fwmark = 7,
    Peers = 8,
}

impl NlAttrType for WgDeviceAttribute {}

impl fmt::Display for WgDeviceAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl_bit_ops_for_nla!(WgDeviceAttribute);

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L165
#[neli_enum(serialized_type = "u16")]
pub enum WgPeerAttribute {
    Unspec = 0,
    PublicKey = 1,
    PresharedKey = 2,
    Flags = 3,
    Endpoint = 4,
    PersistentKeepaliveInterval = 5,
    LastHandshakeTime = 6,
    RxBytes = 7,
    TxBytes = 8,
    AllowedIps = 9,
    ProtocolVersion = 10,
}

impl NlAttrType for WgPeerAttribute {}

impl fmt::Display for WgPeerAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl_bit_ops_for_nla!(WgPeerAttribute);

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L181
#[neli_enum(serialized_type = "u16")]
pub enum WgAllowedIpAttribute {
    Unspec = 0,
    Family = 1,
    IpAddr = 2,
    CidrMask = 3,
}

impl NlAttrType for WgAllowedIpAttribute {}
