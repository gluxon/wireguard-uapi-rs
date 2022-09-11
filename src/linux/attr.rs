use nldl::attr::Nested;
use nldl::attr::UnknownAttribute;
use std::fmt;

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L147
#[derive(Debug, PartialEq, nldl::attr::Serialize, nldl::attr::Deserialize)]
pub enum WgDeviceAttribute {
    #[nla_type(0)]
    Unspec,
    #[nla_type(1)]
    Ifindex(u32),
    #[nla_type(2)]
    Ifname(String),
    #[nla_type(3)]
    PrivateKey(Vec<u8>), // TODO: Make this a [u8; 32] wrapper type.
    #[nla_type(4)]
    PublicKey(Vec<u8>), // TODO: Make this a [u8; 32] wrapper type.
    #[nla_type(5)]
    Flags(u32),
    #[nla_type(6)]
    ListenPort(u16),
    #[nla_type(7)]
    Fwmark(u32),
    #[nla_type(8)]
    Peers(Vec<Nested<WgPeerAttribute>>),
    #[nla_type(_)]
    Unknown(UnknownAttribute),
}

impl fmt::Display for WgDeviceAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L165
#[derive(Debug, PartialEq, nldl::attr::Serialize, nldl::attr::Deserialize)]
pub enum WgPeerAttribute {
    #[nla_type(0)]
    Unspec,
    #[nla_type(1)]
    PublicKey(Vec<u8>),
    #[nla_type(2)]
    PresharedKey(Vec<u8>),
    #[nla_type(3)]
    Flags(u32),
    #[nla_type(4)]
    Endpoint(Vec<u8>), // TODO: Set this to SocketAddr
    #[nla_type(5)]
    PersistentKeepaliveInterval(u16),
    #[nla_type(6)]
    LastHandshakeTime(Vec<u8>),
    #[nla_type(7)]
    RxBytes(u64),
    #[nla_type(8)]
    TxBytes(u64),
    #[nla_type(9)]
    AllowedIps(Vec<Nested<WgAllowedIpAttribute>>),
    #[nla_type(10)]
    ProtocolVersion(u32),
    #[nla_type(_)]
    Unknown(UnknownAttribute),
}

impl fmt::Display for WgPeerAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L181
#[derive(Debug, PartialEq, nldl::attr::Serialize, nldl::attr::Deserialize)]
pub enum WgAllowedIpAttribute {
    #[nla_type(0)]
    Unspec,
    #[nla_type(1)]
    Family(u16),
    #[nla_type(2)]
    IpAddr(Vec<u8>), // TODO
    #[nla_type(3)]
    CidrMask(u8),
    #[nla_type(_)]
    Unknown(UnknownAttribute),
}
