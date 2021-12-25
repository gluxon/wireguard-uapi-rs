use super::state::{ParsePeerState, ParseState};
use crate::get;
use crate::get::{DeviceBuilderError, ParseAllowedIpError, PeerBuilderError};
use crate::xplatform::protocol::{GetKey, ParseKeyError};
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::{str::FromStr, time::Duration};
use take_until::TakeUntilExt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseGetResponseError {
    #[error("Failed to read line from socket: `{0}`")]
    ReadLineIoError(#[source] std::io::Error),

    #[error("Received non-zero error number in response: `{0}`")]
    ServerError(String),
    #[error("Received incomplete response")]
    IncompleteResponse,
    #[error("Received empty response")]
    EmptyResponse,
    #[error("Get responses require an empty line. None found.")]
    MissingEndOfResponseNewline,

    #[error("Encountered unknown key `{0}`")]
    UnknownKey(String),
    #[error("Missing value for key `{0}`")]
    MissingValueForKey(GetKey),

    #[error("{0}")]
    InternalBuildGetDeviceError(DeviceBuilderError),
    #[error("{0}")]
    InternalBuildGetPeerError(PeerBuilderError),

    #[error("Invalid private_key")]
    InvalidPrivateKey,
    #[error("Invalid public_key: `{0}`")]
    InvalidPublicKey(String),
    #[error("Invalid preshared_key: `{0}`")]
    InvalidPresharedKey(String),
    #[error("{0}")]
    InvalidListenPort(#[source] ParseIntError),
    #[error("{0}")]
    InvalidFwmark(#[source] ParseIntError),
    #[error("{0}")]
    InvalidEndpoint(#[source] AddrParseError),
    #[error("{0}")]
    InvalidPersistentKeepaliveInterval(#[source] ParseIntError),
    #[error(transparent)]
    InvalidAllowedIp(#[from] ParseAllowedIpError),
    #[error("{0}")]
    InvalidRxBytes(#[source] ParseIntError),
    #[error("{0}")]
    InvalidTxBytes(#[source] ParseIntError),
    #[error("{0}")]
    InvalidLastHandhsakeTimeSec(#[source] ParseIntError),
    #[error("{0}")]
    InvalidLastHandhsakeTimeNsec(#[source] ParseIntError),
    #[error("{0}")]
    InvalidProtocolVersion(#[source] ParseIntError),

    // Invalid parser state transition errors
    #[error("Expected `private_key=...` or `listen_port=...`. Observed key: `{0}`")]
    InvalidStartOfResponse(GetKey),
    #[error("private_key was ambiguously specified twice in response.")]
    AmbiguousPrivateKey,
    #[error("Observed peer-level key `{0}` before public_key was specified")]
    PeerLevelKeyBeforePublicKey(GetKey),
    #[error("Observed interface-level key `{0}` after a peer-level key")]
    InterfaceLevelKeyAfterPeerLevelKey(GetKey),
    #[error("Observed key after end of response")]
    DataAfterEndOfResponse(GetKey),
}

impl From<ParseKeyError> for ParseGetResponseError {
    fn from(err: ParseKeyError) -> Self {
        Self::UnknownKey(err.unknown_key)
    }
}

pub(crate) fn parse(
    lines: impl Iterator<Item = Result<String, std::io::Error>>,
) -> Result<get::Device, ParseGetResponseError> {
    let initial_state = {
        let mut device_builder = get::DeviceBuilder::default();
        device_builder.ifindex(0);
        device_builder.ifname("".to_string());
        device_builder.fwmark(0);
        ParseState::Initial(device_builder)
    };
    let parse_state = lines
        // WireGuard xplatform implementations signify the end of a response
        // with an empty newline. Stop reading beyond this point to avoid
        // hanging.
        //
        // The rust standard library may include take_until in the future.
        // https://github.com/rust-lang/rust/issues/62208
        .take_until(|result| matches!(result.as_ref().map(String::as_str), Ok("")))
        .try_fold(initial_state, process_line)?;

    match parse_state {
        ParseState::Initial(_) => Err(ParseGetResponseError::EmptyResponse),
        ParseState::InterfaceLevelKeys(_) | ParseState::PeerLevelKeys(_) => {
            Err(ParseGetResponseError::MissingEndOfResponseNewline)
        }
        ParseState::Finish(device) => Ok(device),
    }
}

fn process_line(
    state: ParseState,
    line: std::io::Result<String>,
) -> Result<ParseState, ParseGetResponseError> {
    type ParseErr = ParseGetResponseError;

    let line = line.map_err(ParseErr::ReadLineIoError)?;

    // An empty line signifies the end of a "get" response.
    if line.is_empty() {
        return match state {
            ParseState::Initial(_) => Err(ParseGetResponseError::IncompleteResponse),
            ParseState::InterfaceLevelKeys(device_builder) => device_builder
                .build()
                .map_err(ParseGetResponseError::InternalBuildGetDeviceError)
                .map(ParseState::Finish),
            ParseState::PeerLevelKeys(state) => Ok(ParseState::Finish(state.coalesce())),
            ParseState::Finish(device) => Ok(ParseState::Finish(device)),
        };
    }

    let (key, raw_val) = {
        let mut tokens = line.trim().splitn(2, '=');

        // The first token should always exist.
        let raw_key = tokens.next().unwrap();
        let key = GetKey::from_str(raw_key)?;

        let raw_val = match tokens.next() {
            Some(val) => val,
            None => return Err(ParseErr::MissingValueForKey(key)),
        };

        (key, raw_val)
    };

    match state {
        ParseState::Initial(mut device_builder) => match key {
            GetKey::PrivateKey => {
                let private_key: [u8; 32] = hex::decode(raw_val)
                    .ok()
                    .and_then(|buf| parse_device_key(&buf))
                    .ok_or(ParseErr::InvalidPrivateKey)?;
                device_builder.private_key(Some(private_key));
                Ok(ParseState::InterfaceLevelKeys(device_builder))
            }
            GetKey::ListenPort => {
                let listen_port = raw_val.parse().map_err(ParseErr::InvalidListenPort)?;
                device_builder.listen_port(listen_port);
                Ok(ParseState::InterfaceLevelKeys(device_builder))
            }
            GetKey::Errno => match raw_val {
                "0" => Ok(ParseState::Initial(device_builder)),
                _ => Err(ParseErr::ServerError(raw_val.to_string())),
            },
            _ => Err(ParseErr::InvalidStartOfResponse(key)),
        },

        ParseState::InterfaceLevelKeys(mut device_builder) => match key {
            GetKey::PrivateKey => Err(ParseErr::AmbiguousPrivateKey),
            GetKey::ListenPort => {
                let listen_port = raw_val.parse().map_err(ParseErr::InvalidListenPort)?;
                device_builder.listen_port(listen_port);
                Ok(ParseState::InterfaceLevelKeys(device_builder))
            }
            GetKey::Fwmark => {
                let fwmark = raw_val.parse().map_err(ParseErr::InvalidFwmark)?;
                device_builder.fwmark(fwmark);
                Ok(ParseState::InterfaceLevelKeys(device_builder))
            }

            // A public_key entry specifies the start of a new peer block.
            // Transition the parser state to receive peer-level keys.
            GetKey::PublicKey => {
                let mut peer_builder = get::PeerBuilder::default();
                let public_key = hex::decode(raw_val)
                    .ok()
                    .and_then(|buf| parse_device_key(&buf))
                    .ok_or_else(|| ParseErr::InvalidPublicKey(raw_val.to_string()))?;
                peer_builder.public_key(public_key);
                peer_builder.preshared_key([0u8; 32]);
                peer_builder.persistent_keepalive_interval(0);
                peer_builder.tx_bytes(0);
                peer_builder.rx_bytes(0);
                peer_builder.protocol_version(1);
                Ok(ParseState::PeerLevelKeys(Box::new(ParsePeerState {
                    device_builder,
                    peers: vec![],
                    peer_builder,
                    allowed_ips: vec![],
                    last_handshake_time_sec: None,
                    last_handshake_time_nsec: None,
                })))
            }

            GetKey::PresharedKey
            | GetKey::Endpoint
            | GetKey::PersistentKeepaliveInterval
            | GetKey::AllowedIp
            | GetKey::RxBytes
            | GetKey::TxBytes
            | GetKey::LastHandshakeTimeSec
            | GetKey::LastHandshakeTimeNsec
            | GetKey::ProtocolVersion => Err(ParseErr::PeerLevelKeyBeforePublicKey(key)),

            GetKey::Errno => match raw_val {
                "0" => Ok(ParseState::InterfaceLevelKeys(device_builder)),
                _ => Err(ParseErr::ServerError(raw_val.to_string())),
            },
        },

        ParseState::PeerLevelKeys(mut state) => match key {
            GetKey::PrivateKey | GetKey::ListenPort | GetKey::Fwmark => {
                Err(ParseErr::InterfaceLevelKeyAfterPeerLevelKey(key))
            }

            GetKey::PublicKey => {
                state.peer_builder.allowed_ips(state.allowed_ips);
                let last_handshake_time = Duration::new(
                    state.last_handshake_time_sec.unwrap_or(0),
                    state.last_handshake_time_nsec.unwrap_or(0),
                );
                state.peer_builder.last_handshake_time(last_handshake_time);
                let peer = state
                    .peer_builder
                    .build()
                    .map_err(ParseErr::InternalBuildGetPeerError)?;
                state.peers.push(peer);

                state.peer_builder = get::PeerBuilder::default();
                let public_key = hex::decode(raw_val)
                    .ok()
                    .and_then(|buf| parse_device_key(&buf))
                    .ok_or_else(|| ParseErr::InvalidPublicKey(raw_val.to_string()))?;
                state.peer_builder.public_key(public_key);
                state.peer_builder.preshared_key([0u8; 32]);
                state.peer_builder.persistent_keepalive_interval(0);
                state.peer_builder.tx_bytes(0);
                state.peer_builder.rx_bytes(0);
                state.peer_builder.protocol_version(1);
                state.allowed_ips = vec![];

                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::PresharedKey => {
                let preshared_key = hex::decode(raw_val)
                    .ok()
                    .and_then(|buf| parse_device_key(&buf))
                    .ok_or_else(|| ParseErr::InvalidPresharedKey(raw_val.to_string()))?;
                state.peer_builder.preshared_key(preshared_key);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::Endpoint => {
                let endpoint = raw_val.parse().map_err(ParseErr::InvalidEndpoint)?;
                state.peer_builder.endpoint(Some(endpoint));
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::PersistentKeepaliveInterval => {
                let interval = raw_val
                    .parse()
                    .map_err(ParseErr::InvalidPersistentKeepaliveInterval)?;
                state.peer_builder.persistent_keepalive_interval(interval);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::AllowedIp => {
                let allowed_ip: get::AllowedIp = raw_val.parse()?;
                state.allowed_ips.push(allowed_ip);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::RxBytes => {
                let rx_bytes = raw_val.parse().map_err(ParseErr::InvalidRxBytes)?;
                state.peer_builder.rx_bytes(rx_bytes);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::TxBytes => {
                let tx_bytes = raw_val.parse().map_err(ParseErr::InvalidTxBytes)?;
                state.peer_builder.tx_bytes(tx_bytes);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::LastHandshakeTimeSec => {
                let sec = raw_val
                    .parse()
                    .map_err(ParseErr::InvalidLastHandhsakeTimeSec)?;
                state.last_handshake_time_sec = Some(sec);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::LastHandshakeTimeNsec => {
                let nsec = raw_val
                    .parse()
                    .map_err(ParseErr::InvalidLastHandhsakeTimeNsec)?;
                state.last_handshake_time_nsec = Some(nsec);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::ProtocolVersion => {
                let protocol_version = raw_val.parse().map_err(ParseErr::InvalidProtocolVersion)?;
                state.peer_builder.protocol_version(protocol_version);
                Ok(ParseState::PeerLevelKeys(state))
            }
            GetKey::Errno => match raw_val {
                "0" => Ok(ParseState::PeerLevelKeys(state)),
                _ => Err(ParseErr::ServerError(raw_val.to_string())),
            },
        },

        ParseState::Finish(_) => Err(ParseErr::DataAfterEndOfResponse(key)),
    }
}

// TODO: Get this from a shared util
pub fn parse_device_key(buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != 32 {
        return None;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(buf);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_device_key};
    use crate::get;
    use std::time::Duration;

    #[test]
    fn parse_basic() -> anyhow::Result<()> {
        let response = "\
            private_key=18aa10c05a531f5c537a18426b376387fc2cbd701ae1b9b4271e327aaade9d4f\n\
            listen_port=56137\n\
            public_key=913ea0e20e28c12b5c5f5a858b93a05e686dc3ce524e16f3143bbb1023679751\n\
            preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n\
            protocol_version=1\n\
            endpoint=192.168.64.73:51820\n\
            last_handshake_time_sec=1590459201\n\
            last_handshake_time_nsec=283546000\n\
            tx_bytes=824\n\
            rx_bytes=696\n\
            persistent_keepalive_interval=110\n\
            allowed_ip=10.24.24.3/32\n\
            errno=0\n\
            \n";
        let expected = get::Device {
            ifindex: 0,
            ifname: "".to_string(),
            private_key: parse_device_key(&base64::decode(
                "GKoQwFpTH1xTehhCazdjh/wsvXAa4bm0Jx4yeqrenU8=",
            )?),
            public_key: None,
            listen_port: 56137,
            fwmark: 0,
            peers: vec![get::Peer {
                public_key: parse_device_key(&base64::decode(
                    "kT6g4g4owStcX1qFi5OgXmhtw85SThbzFDu7ECNnl1E=",
                )?)
                .unwrap(),
                preshared_key: [0u8; 32],
                endpoint: Some("192.168.64.73:51820".parse()?),
                last_handshake_time: Duration::new(1_590_459_201, 283_546_000),
                tx_bytes: 824,
                rx_bytes: 696,
                persistent_keepalive_interval: 110,
                allowed_ips: vec![get::AllowedIp {
                    family: 2,
                    ipaddr: "10.24.24.3".parse()?,
                    cidr_mask: 32,
                }],
                protocol_version: 1,
            }],
        };

        let actual = parse(response.lines().map(String::from).map(Ok))?;
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn parse_device_with_no_peers() -> anyhow::Result<()> {
        let response = "\
            private_key=18aa10c05a531f5c537a18426b376387fc2cbd701ae1b9b4271e327aaade9d4f\n\
            listen_port=56137\n\
            errno=0\n\
            \n";
        let expected = get::Device {
            ifindex: 0,
            ifname: "".to_string(),
            private_key: parse_device_key(&base64::decode(
                "GKoQwFpTH1xTehhCazdjh/wsvXAa4bm0Jx4yeqrenU8=",
            )?),
            public_key: None,
            listen_port: 56137,
            fwmark: 0,
            peers: vec![],
        };

        let actual = parse(response.lines().map(String::from).map(Ok))?;
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn parse_website_example() -> anyhow::Result<()> {
        // The scope ID of an endpoint had to be removed since Rust's default SocketAddrV6 parser
        // didn't recognize it. We'll have to see if any existing crates can parse this or write
        // something manually.
        let response = "\
            private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\n\
            listen_port=12912\n\
            public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33\n\
            preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52\n\
            allowed_ip=192.168.4.4/32\n\
            endpoint=[abcd:23::33]:51820\n\
            public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376\n\
            tx_bytes=38333\n\
            rx_bytes=2224\n\
            allowed_ip=192.168.4.6/32\n\
            persistent_keepalive_interval=111\n\
            endpoint=182.122.22.19:3233\n\
            public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\n\
            endpoint=5.152.198.39:51820\n\
            allowed_ip=192.168.4.10/32\n\
            allowed_ip=192.168.4.11/32\n\
            tx_bytes=1212111\n\
            rx_bytes=1929999999\n\
            protocol_version=1\n\
            errno=0\n\
            \n";

        let expected = get::Device {
            ifindex: 0,
            ifname: "".to_string(),
            private_key: parse_device_key(&base64::decode(
                "6EtabScXwQA6E7QxVwNT26ypFGzxUMX4V1aA/rpSAno=",
            )?),
            public_key: None,
            listen_port: 12912,
            fwmark: 0,
            peers: vec![
                get::Peer {
                    public_key: parse_device_key(&base64::decode(
                        "uFmW/sycfx/G0lcqdu2hHVm80gvo5UOxXOS9hajnWjM=",
                    )?)
                    .unwrap(),
                    preshared_key: parse_device_key(&base64::decode(
                        "GIUVCT6VL18i6GXO8wEucvi18LWYrAMJ1drM47cPz1I=",
                    )?)
                    .unwrap(),
                    endpoint: Some("[abcd:23::33]:51820".parse()?),
                    last_handshake_time: Duration::new(0, 0),
                    tx_bytes: 0,
                    rx_bytes: 0,
                    persistent_keepalive_interval: 0,
                    allowed_ips: vec![get::AllowedIp {
                        family: 2,
                        ipaddr: "192.168.4.4".parse()?,
                        cidr_mask: 32,
                    }],
                    protocol_version: 1,
                },
                get::Peer {
                    public_key: parse_device_key(&base64::decode(
                        "WEAuaVuhdyscyTCXVfBDJR6nf9zxD75jmJzrfhkyE3Y=",
                    )?)
                    .unwrap(),
                    preshared_key: [0u8; 32],
                    endpoint: Some("182.122.22.19:3233".parse()?),
                    last_handshake_time: Duration::new(0, 0),
                    tx_bytes: 38333,
                    rx_bytes: 2224,
                    persistent_keepalive_interval: 111,
                    allowed_ips: vec![get::AllowedIp {
                        family: 2,
                        ipaddr: "192.168.4.6".parse()?,
                        cidr_mask: 32,
                    }],
                    protocol_version: 1,
                },
                get::Peer {
                    public_key: parse_device_key(&base64::decode(
                        "Zi4U/VlFVvUiYEcDNANRJYkDtk81VTdj8ZQmqypRXFg=",
                    )?)
                    .unwrap(),
                    preshared_key: [0u8; 32],
                    endpoint: Some("5.152.198.39:51820".parse()?),
                    last_handshake_time: Duration::new(0, 0),
                    tx_bytes: 1_212_111,
                    rx_bytes: 1_929_999_999,
                    persistent_keepalive_interval: 0,
                    allowed_ips: vec![
                        get::AllowedIp {
                            family: 2,
                            ipaddr: "192.168.4.10".parse()?,
                            cidr_mask: 32,
                        },
                        get::AllowedIp {
                            family: 2,
                            ipaddr: "192.168.4.11".parse()?,
                            cidr_mask: 32,
                        },
                    ],
                    protocol_version: 1,
                },
            ],
        };

        let actual = parse(response.lines().map(String::from).map(Ok))?;
        assert_eq!(actual, expected);

        Ok(())
    }
}
