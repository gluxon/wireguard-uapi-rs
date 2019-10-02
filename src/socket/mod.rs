mod socket;
pub use socket::Socket;

pub(crate) mod parse;

pub(crate) type NlWgMsgType = u16;

pub(crate) mod link_message;
pub(crate) use link_message::{link_message, WireGuardDeviceLinkOperation};
