use super::state::{ParsePeerState, ParseState};
use crate::get;
use crate::userspace::protocol::{GetKey, ParseKeyError};
use std::{str::FromStr, time::Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseGetResponseError {
    #[error("Encountered unknown key `{0}`")]
    UnknownKey(String),

    #[error("Received incomplete response")]
    IncompleteResponse,
}

impl From<ParseKeyError> for ParseGetResponseError {
    fn from(err: ParseKeyError) -> Self {
        Self::UnknownKey(err.unknown_key)
    }
}

pub(crate) fn parse(response: &str) -> Result<get::Device, ParseGetResponseError> {
    let initial_state = {
        let mut device_builder = get::DeviceBuilder::default();
        device_builder.ifindex(0);
        device_builder.ifname("".to_string());
        device_builder.fwmark(0);
        ParseState::Initial(device_builder)
    };
    let parse_state = response.lines().try_fold(initial_state, process_line)?;

    match parse_state {
        ParseState::Finish(device) => Ok(device),
        _ => Err(ParseGetResponseError::IncompleteResponse),
    }
}

fn process_line(state: ParseState, line: &str) -> Result<ParseState, ParseGetResponseError> {
    if line == "" {
        return Ok(state);
    }

    let mut splitter = line.splitn(2, '=');
    let raw_key = splitter.next().unwrap();
    let raw_val = splitter.next().unwrap();

    let key = GetKey::from_str(raw_key)?;

    Ok(match (key, state) {
        (GetKey::PrivateKey, ParseState::Initial(mut device_builder)) => {
            let private_key = hex::decode(raw_val)
                .ok()
                .map(|buf| parse_device_key(&buf))
                .unwrap();
            device_builder.private_key(private_key);
            ParseState::InterfaceLevelKeys(device_builder)
        }
        (GetKey::ListenPort, ParseState::InterfaceLevelKeys(mut device_builder)) => {
            device_builder.listen_port(raw_val.parse().unwrap());
            ParseState::InterfaceLevelKeys(device_builder)
        }
        (GetKey::PublicKey, ParseState::InterfaceLevelKeys(device_builder)) => {
            let mut peer_builder = get::PeerBuilder::default();
            let public_key = hex::decode(raw_val)
                .ok()
                .and_then(|buf| parse_device_key(&buf))
                .unwrap();
            peer_builder.public_key(public_key);
            peer_builder.preshared_key([0u8; 32]);
            peer_builder.persistent_keepalive_interval(0);
            peer_builder.tx_bytes(0);
            peer_builder.rx_bytes(0);
            peer_builder.protocol_version(1);
            ParseState::PeerLevelKeys(ParsePeerState {
                device_builder,
                peers: vec![],
                peer_builder,
                allowed_ips: vec![],
                last_handshake_time_sec: None,
                last_handshake_time_nsec: None,
            })
        }
        (GetKey::PublicKey, ParseState::PeerLevelKeys(mut state)) => {
            state.peer_builder.allowed_ips(state.allowed_ips);
            let last_handshake_time = Duration::new(
                state.last_handshake_time_sec.unwrap_or(0),
                state.last_handshake_time_nsec.unwrap_or(0),
            );
            state.peer_builder.last_handshake_time(last_handshake_time);
            state.peers.push(state.peer_builder.build().unwrap());

            state.peer_builder = get::PeerBuilder::default();
            let public_key = hex::decode(raw_val)
                .ok()
                .and_then(|buf| parse_device_key(&buf))
                .unwrap();
            state.peer_builder.public_key(public_key);
            state.peer_builder.preshared_key([0u8; 32]);
            state.peer_builder.persistent_keepalive_interval(0);
            state.peer_builder.tx_bytes(0);
            state.peer_builder.rx_bytes(0);
            state.peer_builder.protocol_version(1);
            state.allowed_ips = vec![];

            ParseState::PeerLevelKeys(state)
        }
        (GetKey::PresharedKey, ParseState::PeerLevelKeys(mut state)) => {
            let preshared_key = hex::decode(raw_val)
                .ok()
                .and_then(|buf| parse_device_key(&buf))
                .unwrap();
            state.peer_builder.preshared_key(preshared_key);
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::Endpoint, ParseState::PeerLevelKeys(mut state)) => {
            state.peer_builder.endpoint(Some(raw_val.parse().unwrap()));
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::PersistentKeepaliveInterval, ParseState::PeerLevelKeys(mut state)) => {
            state
                .peer_builder
                .persistent_keepalive_interval(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::AllowedIp, ParseState::PeerLevelKeys(mut state)) => {
            state.allowed_ips.push(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::RxBytes, ParseState::PeerLevelKeys(mut state)) => {
            state.peer_builder.rx_bytes(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::TxBytes, ParseState::PeerLevelKeys(mut state)) => {
            state.peer_builder.tx_bytes(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::LastHandshakeTimeSec, ParseState::PeerLevelKeys(mut state)) => {
            state.last_handshake_time_sec = Some(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::LastHandshakeTimeNsec, ParseState::PeerLevelKeys(mut state)) => {
            state.last_handshake_time_nsec = Some(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::ProtocolVersion, ParseState::PeerLevelKeys(mut state)) => {
            state
                .peer_builder
                .protocol_version(raw_val.parse().unwrap());
            ParseState::PeerLevelKeys(state)
        }
        (GetKey::Errno, ParseState::PeerLevelKeys(state)) => ParseState::Finish(state.coalesce()),

        (_, _) => panic!("invalid transition"),
    })
}

// TODO: Get this from a shared util
pub fn parse_device_key(buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != 32 {
        return None;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&buf);
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
                last_handshake_time: Duration::new(1590459201, 283546000),
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

        let actual = parse(&response)?;
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
                    tx_bytes: 1212111,
                    rx_bytes: 1929999999,
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

        let actual = parse(&response)?;
        assert_eq!(actual, expected);

        Ok(())
    }
}
