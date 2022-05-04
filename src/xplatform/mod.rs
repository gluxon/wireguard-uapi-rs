//! Cross-Platform Userspace Client
//!
//! This module implements the cross-platform userspace protocol defined at
//! [wireguard.com/xplatform]. It is disabled by default, and guarded behind the
//! `xplatform` feature flag.
//!
//! Similar to the Linux-specific client, structs are organized into
//! [`set`][crate::xplatform::set] and [`get`][crate::get] modules. The
//! [`get`][crate::get] module for the cross-platform client is shared with the
//! Linux-specific client since the typings are compatible.
//!
//! This module does not provide any way to create and destroy WireGuard
//! interfaces. That functionality is not part of the cross-platform protocol
//! specification. In general you will have to shell out to the command line. See
//! the [*Interface* section of the official docs][xplatform-interface] for an
//! example.
//!
//! [wireguard.com/xplatform]: https://www.wireguard.com/xplatform
//! [xplatform-interface]: https://www.wireguard.com/xplatform/#interface

mod client;
pub mod error;
pub mod parser;
mod protocol;
pub mod set;

#[cfg(unix)]
pub use client::Client;
