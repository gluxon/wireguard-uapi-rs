use super::{Device, DeviceFragment, Peer, PeerFragment};
use std::mem::swap;

pub const NETLINK_PACKET_LIMIT: u16 = 65 * 1000;

pub fn split_into_fragments<'a>(device: &'a mut Device) -> Vec<DeviceFragment<'a>> {
    let fragments: Vec<DeviceFragment> = vec![];

    // Move the peers from the device payload. We'll loop through each one
    // and add them into different fragments as they fit.
    let mut peers = vec![];
    swap(&mut peers, &mut device.peers);

    // let mut current_fragment: DeviceFragment = DeviceFragment::First(device);

    for peer in peers {
        // current_fragment.add_peer(peer);
    }

    fragments
}
