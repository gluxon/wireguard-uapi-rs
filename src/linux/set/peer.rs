use crate::linux::set::AllowedIp;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum WgPeerF {
    RemoveMe = 1,
    ReplaceAllowedIps = 2,
}

#[derive(Debug)]
pub struct Peer<'a> {
    pub public_key: &'a [u8; 32],
    pub flags: Vec<WgPeerF>,
    /// all zeros to remove
    pub preshared_key: Option<&'a [u8; 32]>,
    pub endpoint: Option<&'a SocketAddr>,
    /// 0 to disable
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<AllowedIp<'a>>,
    /// should not be set or used at all by most users of this API, as the most recent protocol
    /// will be used when this is unset. Otherwise, must be set to 1.
    pub protocol_version: Option<u32>,
}

impl<'a> Peer<'a> {
    pub fn from_public_key(public_key: &'a [u8; 32]) -> Self {
        Self {
            public_key,
            flags: vec![],
            preshared_key: None,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ips: vec![],
            protocol_version: None,
        }
    }

    pub fn flags(mut self, flags: Vec<WgPeerF>) -> Self {
        self.flags = flags;
        self
    }

    pub fn preshared_key(mut self, preshared_key: &'a [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    pub fn endpoint(mut self, endpoint: &'a SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn persistent_keepalive_interval(mut self, persistent_keepalive_interval: u16) -> Self {
        self.persistent_keepalive_interval = Some(persistent_keepalive_interval);
        self
    }

    pub fn allowed_ips(mut self, allowed_ips: Vec<AllowedIp<'a>>) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    pub fn protocol_version(mut self, protocol_version: u32) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }
}
