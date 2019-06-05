mod socket;
pub use socket::{GetDeviceArg, Socket};

pub(crate) mod parse;

pub(crate) type NlWgMsgType = u16;
