mod allowed_ip;
pub use allowed_ip::AllowedIp;
mod device;
pub use device::{Device, WgDeviceF};
mod device_fragment;
pub(crate) use device_fragment::DeviceFragment;
mod peer;
pub use peer::{Peer, WgPeerF};
mod peer_fragment;
pub(crate) use peer_fragment::PeerFragment;
mod split_into_fragments;
pub(crate) use split_into_fragments::split_into_fragments;

pub(crate) trait Fragment {
    fn packet_size(&self) -> u16;
}
