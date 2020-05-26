use std::fmt::Debug;
use std::str::FromStr;

pub(crate) struct ParseKeyError {
    pub unknown_key: String,
}

#[derive(Debug)]
pub(crate) enum GetKey {
    PrivateKey,
    ListenPort,
    PublicKey,
    PresharedKey,
    Endpoint,
    PersistentKeepaliveInterval,
    AllowedIp,
    RxBytes,
    TxBytes,
    LastHandshakeTimeSec,
    LastHandshakeTimeNsec,
    ProtocolVersion,
    Errno,
}

impl FromStr for GetKey {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "private_key" => Ok(Self::PrivateKey),
            "listen_port" => Ok(Self::ListenPort),
            "public_key" => Ok(Self::PublicKey),
            "preshared_key" => Ok(Self::PresharedKey),
            "endpoint" => Ok(Self::Endpoint),
            "persistent_keepalive_interval" => Ok(Self::PersistentKeepaliveInterval),
            "allowed_ip" => Ok(Self::AllowedIp),
            "rx_bytes" => Ok(Self::RxBytes),
            "tx_bytes" => Ok(Self::TxBytes),
            "last_handshake_time_sec" => Ok(Self::LastHandshakeTimeSec),
            "last_handshake_time_nsec" => Ok(Self::LastHandshakeTimeNsec),
            "protocol_version" => Ok(Self::ProtocolVersion),
            "errno" => Ok(Self::Errno),
            _ => Err(Self::Err {
                unknown_key: s.to_string(),
            }),
        }
    }
}

pub(crate) enum SetKey {
    PrivateKey,
    ListenPort,
    Fwmark,
    ReplacePeers,
    PublicKey,
    Remove,
    UpdateOnly,
    PresharedKey,
    Endpoint,
    PersistentKeepaliveInterval,
    ReplaceAllowedIps,
    AllowedIp,
    ProtocolVersion,
}

impl From<SetKey> for &'static str {
    fn from(set_key: SetKey) -> &'static str {
        match set_key {
            SetKey::PrivateKey => "private_key",
            SetKey::ListenPort => "listen_port",
            SetKey::Fwmark => "fwmark",
            SetKey::ReplacePeers => "replace_peers",
            SetKey::PublicKey => "public_key",
            SetKey::Remove => "remove",
            SetKey::UpdateOnly => "update_only",
            SetKey::PresharedKey => "preshared_key",
            SetKey::Endpoint => "endpoint",
            SetKey::PersistentKeepaliveInterval => "persistent_keepalive_interval",
            SetKey::ReplaceAllowedIps => "replace_allowed_ips",
            SetKey::AllowedIp => "allowed_ip",
            SetKey::ProtocolVersion => "protocol_version",
        }
    }
}
