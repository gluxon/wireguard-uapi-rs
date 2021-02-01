use std::fmt::Debug;
use std::fmt::Display;
use std::str::FromStr;

pub struct ParseKeyError {
    pub unknown_key: String,
}

#[derive(Debug)]
pub enum GetKey {
    PrivateKey,
    ListenPort,
    Fwmark,
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
            "fwmark" => Ok(Self::Fwmark),
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

impl Display for GetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetKey::PrivateKey => f.write_str("private_key"),
            GetKey::ListenPort => f.write_str("listen_port"),
            GetKey::Fwmark => f.write_str("fw_mark"),
            GetKey::PublicKey => f.write_str("public_key"),
            GetKey::PresharedKey => f.write_str("preshared_key"),
            GetKey::Endpoint => f.write_str("endpoint"),
            GetKey::PersistentKeepaliveInterval => f.write_str("persistent_keepalive_interval"),
            GetKey::AllowedIp => f.write_str("allowed_ip"),
            GetKey::RxBytes => f.write_str("rx_bytes"),
            GetKey::TxBytes => f.write_str("tx_bytes"),
            GetKey::LastHandshakeTimeSec => f.write_str("last_handshake_time_sec"),
            GetKey::LastHandshakeTimeNsec => f.write_str("last_handshake_time_nsec"),
            GetKey::ProtocolVersion => f.write_str("protocol_version"),
            GetKey::Errno => f.write_str("errno"),
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
}

impl From<&SetKey> for &'static str {
    fn from(set_key: &SetKey) -> &'static str {
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
        }
    }
}

impl Display for SetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = self.into();
        f.write_str(s)
    }
}
