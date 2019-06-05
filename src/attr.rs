use std::fmt;

impl_var!(NlaNested, u16,
    Unspec => 0,
);

// https://github.com/WireGuard/WireGuard/blob/62b335b56cc99312ccedfa571500fbef3756a623/src/uapi/wireguard.h#L147
impl_var!(WgDeviceAttribute, u16,
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
impl_var!(WgPeerAttribute, u16,
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
impl_var!(WgAllowedIpAttribute, u16,
    Unspec => 0,
    Family => 1,
    IpAddr => 2,
    CidrMask => 3
);
