mod attr;
mod cmd;
mod consts;
pub mod err;
mod interface;
pub mod set;
mod socket;

pub use interface::DeviceInterface;
pub use socket::{RouteSocket, WgSocket};
