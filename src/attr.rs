use neli::consts::NlAttrType;
use neli::{impl_var, impl_var_base, impl_var_trait};
use std::fmt;

impl_var_trait!(
    NlaNested, u16, NlAttrType,
    Unspec => 0,
    // neli requires 1 non-zero argument even though WireGuard
    // does not use it.
    Unused => 1
);

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L147
impl_var_trait!(
    WgDeviceAttribute, u16, NlAttrType,
    Unspec => 0,
    Ifindex => 1,
    Ifname => 2,
    PrivateKey => 3,
    PublicKey => 4,
    Flags => 5,
    ListenPort => 6,
    Fwmark => 7,
    Peers => 8
);

impl fmt::Display for WgDeviceAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L165
impl_var_trait!(
    WgPeerAttribute, u16, NlAttrType,
    Unspec => 0,
    PublicKey => 1,
    PresharedKey => 2,
    Flags => 3,
    Endpoint => 4,
    PersistentKeepaliveInterval => 5,
    LastHandshakeTime => 6,
    RxBytes => 7,
    TxBytes => 8,
    AllowedIps => 9,
    ProtocolVersion => 10
);

impl fmt::Display for WgPeerAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L181
impl_var_trait!(
    WgAllowedIpAttribute, u16, NlAttrType,
    Unspec => 0,
    Family => 1,
    IpAddr => 2,
    CidrMask => 3
);
