// wireguard.h netlink uapi
pub const WG_GENL_NAME: &str = "wireguard";
pub const WG_GENL_VERSION: u8 = 1;

/// Never create Netlink attributes with network byte order. Communication with
/// the WireGuard kernel module is expected to be use native endian.
pub(crate) const NLA_NETWORK_ORDER: bool = false;
