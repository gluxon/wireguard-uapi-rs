# wireguard-uapi-rs

[![Build Status](https://github.com/gluxon/wireguard-uapi-rs/workflows/Rust/badge.svg?branch=develop)](https://github.com/gluxon/wireguard-uapi-rs/actions?query=workflow%3ARust)
[![Crates version](https://img.shields.io/crates/v/wireguard-uapi.svg)](https://crates.io/crates/wireguard-uapi)
[![docs.rs](https://docs.rs/wireguard-uapi/badge.svg?version=0.2.0)](https://docs.rs/wireguard-uapi)
![MIT](https://img.shields.io/github/license/gluxon/wireguard-uapi-rs)

This library implements the [WireGuard Netlink API](https://git.zx2c4.com/WireGuard/tree/src/uapi/wireguard.h) in Rust for Linux.

- If you're just reading a WireGuard device interface, this library fully supports that functionality.
- If you're creating new WireGuard device interfaces, this library has partial support. Creating and deleting device interfaces is possible, but there's no ability at the moment for adding IP addresses to those devices.

Here's a quick example.

```rust
use failure;
use wireguard_uapi::{DeviceInterface, WgSocket};

fn main() -> Result<(), failure::Error> {
  let mut wg = WgSocket::connect()?;
  let device = wg.get_device(DeviceInterface::from_name("wgtest0"))?;

  print_device(&device);
  Ok(())
}
```

## Permissions

Compiled binaries need the `CAP_NET_ADMIN` capability to read network interfaces. If you're getting an access error while using this library, make sure the compiled executable has that permission. If you trust your compiled binary, one way to grant it is:

```sh
sudo setcap CAP_NET_ADMIN=+eip ./my-compiled-binary
```

## Disclaimer

This isn't an official WireGuard product. (Although I'm interested in making it so.)

Feel free to file bugs.
