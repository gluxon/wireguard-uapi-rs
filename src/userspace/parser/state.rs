use crate::get;
use std::time::Duration;

pub enum ParseState {
    Initial(get::DeviceBuilder),
    InterfaceLevelKeys(get::DeviceBuilder),
    PeerLevelKeys(ParsePeerState),
    Finish(get::Device),
}

pub struct ParsePeerState {
    pub device_builder: get::DeviceBuilder,
    pub peers: Vec<get::Peer>,
    pub peer_builder: get::PeerBuilder,
    pub allowed_ips: Vec<get::AllowedIp>,
    pub last_handshake_time_sec: Option<u64>,
    pub last_handshake_time_nsec: Option<u32>,
}

impl ParsePeerState {
    pub fn coalesce(mut self) -> get::Device {
        let last_handshake_time = Duration::new(
            self.last_handshake_time_sec.unwrap_or(0),
            self.last_handshake_time_nsec.unwrap_or(0),
        );
        self.peer_builder.last_handshake_time(last_handshake_time);
        self.peer_builder.allowed_ips(self.allowed_ips);
        self.peers.push(self.peer_builder.build().unwrap());
        self.device_builder.peers(self.peers);
        self.device_builder.build().unwrap()
    }
}
