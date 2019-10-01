mod attr;
mod cmd;
mod consts;
pub mod err;
pub mod get;
mod interface;
pub mod set;
mod socket;

pub use interface::DeviceInterface;
pub use socket::Socket;
