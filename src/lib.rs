#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{err, set, DeviceInterface, RouteSocket, WgSocket};

pub mod get;

#[cfg(feature = "userspace")]
pub mod userspace;
