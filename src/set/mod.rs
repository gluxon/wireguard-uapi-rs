mod allowed_ip;
pub use allowed_ip::AllowedIp;
mod device;
pub use device::{Device, DeviceInterface, WgDeviceF};
mod peer;
pub use peer::{Peer, WgPeerF};
