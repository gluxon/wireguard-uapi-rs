use super::{AllowedIp, Device, Peer};
use crate::linux::attr::NLA_F_NESTED;
use crate::linux::attr::{NlaNested, WgDeviceAttribute, WgPeerAttribute};
use crate::linux::cmd::WgCmd;
use crate::linux::consts::NLA_NETWORK_ORDER;
use crate::linux::consts::WG_GENL_VERSION;
use crate::linux::socket::NlWgMsgType;
use crate::linux::DeviceInterface;
use neli::{
    consts::nl::{NlmF, NlmFFlags},
    err::NlError,
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    types::{Buffer, GenlBuffer},
    Size,
};
use std::convert::TryInto;
use std::net::SocketAddr;

// TODO: Remove these constants and use something from libc.
const NETLINK_HEADER_SIZE: usize = 16;
const GENL_HEADER_SIZE: usize = 4;
const NETLINK_MSG_LIMIT: usize = 65_536; // 2^16

type NlWgMessage = Nlmsghdr<NlWgMsgType, Genlmsghdr<WgCmd, WgDeviceAttribute>>;

/// A struct containing information necessary to build a set_device message fragment. It keeps
/// track of an initial bag of partial_device but keeps peers separate until they're ready to be
// added in.
struct IncubatingDeviceFragment {
    partial_device: GenlBuffer<WgDeviceAttribute, Buffer>,
    peers: Nlattr<WgDeviceAttribute, Buffer>,
}

impl IncubatingDeviceFragment {
    fn split_off_peers(device: Device<'_>) -> Result<(Self, Vec<Peer<'_>>), NlError> {
        let incubating_device = IncubatingDeviceFragment {
            partial_device: {
                let mut attrs = GenlBuffer::new();

                let interface_attr: Nlattr<WgDeviceAttribute, Buffer> =
                    (&device.interface).try_into()?;
                attrs.push(interface_attr);

                if !device.flags.is_empty() {
                    let mut unique = device.flags.clone();
                    unique.dedup();

                    attrs.push(Nlattr::new(
                        false,
                        NLA_NETWORK_ORDER,
                        WgDeviceAttribute::Flags,
                        unique.drain(..).map(|flag| flag as u32).sum::<u32>(),
                    )?);
                }

                if let Some(private_key) = device.private_key {
                    attrs.push(Nlattr::new(
                        false,
                        NLA_NETWORK_ORDER,
                        WgDeviceAttribute::PrivateKey,
                        &private_key[..],
                    )?);
                }

                if let Some(listen_port) = device.listen_port {
                    attrs.push(Nlattr::new(
                        false,
                        NLA_NETWORK_ORDER,
                        WgDeviceAttribute::ListenPort,
                        &listen_port.to_ne_bytes()[..],
                    )?);
                }

                if let Some(fwmark) = device.fwmark {
                    attrs.push(Nlattr::new(
                        false,
                        NLA_NETWORK_ORDER,
                        WgDeviceAttribute::Fwmark,
                        fwmark,
                    )?);
                }

                // This covers all attributes except peers. Avoid parsing peers here purposefully
                // since they may not all fit into the first device message.

                attrs
            },
            peers: Nlattr::new::<Vec<u8>>(
                false,
                NLA_NETWORK_ORDER,
                WgDeviceAttribute::Peers | NLA_F_NESTED,
                vec![],
            )?,
        };

        Ok((incubating_device, device.peers))
    }

    fn from_interface(interface: &DeviceInterface) -> Result<Self, NlError> {
        let partial_device = {
            let mut buffer = GenlBuffer::new();
            buffer.push(interface.try_into()?);
            buffer
        };

        Ok(Self {
            partial_device,
            peers: Nlattr::new::<Vec<u8>>(
                false,
                NLA_NETWORK_ORDER,
                WgDeviceAttribute::Peers | NLA_F_NESTED,
                vec![],
            )?,
        })
    }

    fn incubating_size(&self) -> usize {
        let attrs_size: usize = self
            .partial_device
            .iter()
            .map(|attr| attr.padded_size())
            .sum();

        NETLINK_HEADER_SIZE + GENL_HEADER_SIZE + attrs_size + self.peers.padded_size()
    }

    fn finalize(self, family_id: NlWgMsgType) -> Result<NlWgMessage, NlError> {
        let mut device_attrs = self.partial_device;

        // TODO: Condition this behavior on whether peers have ever been added.
        if self.peers.unpadded_size() > GENL_HEADER_SIZE {
            device_attrs.push(self.peers);
        }

        let genlhdr = {
            let cmd = WgCmd::SetDevice;
            let version = WG_GENL_VERSION;
            Genlmsghdr::new(cmd, version, device_attrs)
        };
        let nlhdr: NlWgMessage = {
            let size = None;
            let nl_type = family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(genlhdr);
            Nlmsghdr::new(size, nl_type, flags, seq, pid, payload)
        };

        Ok(nlhdr)
    }
}

struct IncubatingPeerFragment {
    pub partial_peer: Nlattr<NlaNested, Buffer>,
    pub allowed_ips: Nlattr<WgPeerAttribute, Buffer>,
}

impl IncubatingPeerFragment {
    fn split_off_allowed_ips(peer: Peer<'_>) -> Result<(Self, Vec<AllowedIp<'_>>), NlError> {
        let mut partial_peer = Nlattr::new::<Vec<u8>>(
            false,
            NLA_NETWORK_ORDER,
            NlaNested::Unspec | NLA_F_NESTED,
            vec![],
        )?;

        let public_key = Nlattr::new(
            false,
            NLA_NETWORK_ORDER,
            WgPeerAttribute::PublicKey,
            peer.public_key.to_vec(),
        )?;
        partial_peer.add_nested_attribute(&public_key)?;

        if !peer.flags.is_empty() {
            let mut unique = peer.flags.clone();
            unique.dedup();

            partial_peer.add_nested_attribute(&Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgPeerAttribute::Flags,
                unique.drain(..).map(|flag| flag as u32).sum::<u32>(),
            )?)?;
        }

        if let Some(preshared_key) = peer.preshared_key {
            partial_peer.add_nested_attribute(&Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgPeerAttribute::PresharedKey,
                &preshared_key[..],
            )?)?;
        }

        if let Some(endpoint) = peer.endpoint {
            // Using the serialize trait from serde might be easier.
            let mut payload: Vec<u8> = vec![];

            let family = match endpoint {
                SocketAddr::V4(_) => (libc::AF_INET as u16).to_ne_bytes(),
                SocketAddr::V6(_) => (libc::AF_INET6 as u16).to_ne_bytes(),
            };
            let port = endpoint.port().to_be_bytes();

            payload.extend(family.iter());
            payload.extend(port.iter());

            match endpoint {
                SocketAddr::V4(addr) => {
                    payload.extend(addr.ip().octets().iter());
                    payload.extend([0u8; 8].iter());
                }
                SocketAddr::V6(addr) => {
                    payload.extend(addr.flowinfo().to_ne_bytes().iter());
                    payload.extend(addr.ip().octets().iter());
                    payload.extend(addr.scope_id().to_ne_bytes().iter());
                }
            };

            partial_peer.add_nested_attribute(&Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgPeerAttribute::Endpoint,
                payload,
            )?)?;
        }

        if let Some(persistent_keepalive_interval) = peer.persistent_keepalive_interval {
            partial_peer.add_nested_attribute(&Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgPeerAttribute::PersistentKeepaliveInterval,
                &persistent_keepalive_interval.to_ne_bytes()[..],
            )?)?;
        }

        if let Some(protocol_version) = peer.protocol_version {
            partial_peer.add_nested_attribute(&Nlattr::new(
                false,
                NLA_NETWORK_ORDER,
                WgPeerAttribute::ProtocolVersion,
                protocol_version,
            )?)?;
        }

        // This covers all attributes except allowed ips. Avoid parsing allowed ips here
        // purposefully since they may not all fit into the current device message.

        let incubating_peer_fragment = IncubatingPeerFragment {
            partial_peer,
            allowed_ips: Nlattr::new::<Vec<u8>>(
                false,
                NLA_NETWORK_ORDER,
                WgPeerAttribute::AllowedIps | NLA_F_NESTED,
                vec![],
            )?,
        };

        Ok((incubating_peer_fragment, peer.allowed_ips))
    }

    fn from_public_key(public_key: &[u8; 32]) -> Result<Self, NlError> {
        let mut partial_peer =
            Nlattr::new::<Vec<u8>>(false, false, NlaNested::Unspec | NLA_F_NESTED, vec![])?;
        let allowed_ips = Nlattr::new::<Vec<u8>>(
            false,
            NLA_NETWORK_ORDER,
            WgPeerAttribute::AllowedIps | NLA_F_NESTED,
            vec![],
        )?;

        let public_key = Nlattr::new(
            false,
            NLA_NETWORK_ORDER,
            WgPeerAttribute::PublicKey,
            public_key.to_vec(),
        )?;
        partial_peer.add_nested_attribute(&public_key)?;

        Ok(IncubatingPeerFragment {
            partial_peer,
            allowed_ips,
        })
    }

    fn incubating_size(&self) -> usize {
        self.partial_peer.padded_size() + self.allowed_ips.padded_size()
    }

    fn finalize(self) -> Result<Nlattr<NlaNested, Buffer>, NlError> {
        let mut partial_peer = self.partial_peer;
        if self.allowed_ips.padded_size() > GENL_HEADER_SIZE {
            partial_peer.add_nested_attribute(&self.allowed_ips)?;
        }
        Ok(partial_peer)
    }
}

pub fn create_set_device_messages(
    device: Device,
    family_id: NlWgMsgType,
) -> Result<Vec<NlWgMessage>, NlError> {
    let mut messages = vec![];

    // All the device fragments we generate here will have the same interface. Before moving the
    // original device into split_off_peers, copy the interface so we can continue to build new
    // fragments from it.
    let interface = device.interface.clone();
    let (mut incubating_device_fragment, peers_to_add) =
        IncubatingDeviceFragment::split_off_peers(device)?;

    for peer in peers_to_add {
        let public_key = peer.public_key;
        let (mut incubating_peer_fragment, allowed_ips_to_add) =
            IncubatingPeerFragment::split_off_allowed_ips(peer)?;

        let next_size = incubating_device_fragment.incubating_size()
            + incubating_peer_fragment.incubating_size();
        if next_size > NETLINK_MSG_LIMIT {
            let device_message = incubating_device_fragment.finalize(family_id)?;
            messages.push(device_message);
            incubating_device_fragment = IncubatingDeviceFragment::from_interface(&interface)?;
        }

        for allowed_ip in allowed_ips_to_add {
            let allowed_ip_attr: Nlattr<NlaNested, Buffer> = (&allowed_ip).try_into()?;

            let next_size = incubating_device_fragment.incubating_size()
                + incubating_peer_fragment.incubating_size()
                + allowed_ip_attr.padded_size();
            if next_size > NETLINK_MSG_LIMIT {
                let peer_fragment = incubating_peer_fragment.finalize()?;
                incubating_device_fragment
                    .peers
                    .add_nested_attribute(&peer_fragment)?;

                let device_message = incubating_device_fragment.finalize(family_id)?;
                messages.push(device_message);

                incubating_device_fragment = IncubatingDeviceFragment::from_interface(&interface)?;
                incubating_peer_fragment = IncubatingPeerFragment::from_public_key(public_key)?;
            }

            incubating_peer_fragment
                .allowed_ips
                .add_nested_attribute(&allowed_ip_attr)?;
        }

        let peer_attr = incubating_peer_fragment.finalize()?;
        incubating_device_fragment
            .peers
            .add_nested_attribute(&peer_attr)?;
    }

    let device_message = incubating_device_fragment.finalize(family_id)?;
    messages.push(device_message);

    Ok(messages)
}
