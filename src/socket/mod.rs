mod route_socket;
pub use route_socket::RouteSocket;

mod wg_socket;
pub use wg_socket::WgSocket;

pub(crate) mod parse;

pub(crate) type NlWgMsgType = u16;

pub(crate) mod link_message;
pub(crate) use link_message::{link_message, WireGuardDeviceLinkOperation};
