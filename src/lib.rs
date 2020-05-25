#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{err, get, set, DeviceInterface, RouteSocket, WgSocket};
