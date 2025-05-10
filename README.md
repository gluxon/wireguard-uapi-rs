# wireguard-uapi-rs

[![Build Status](https://github.com/gluxon/wireguard-uapi-rs/workflows/Rust/badge.svg?branch=main)](https://github.com/gluxon/wireguard-uapi-rs/actions/workflows/rust.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/gluxon/wireguard-uapi-rs/branch/develop/graph/badge.svg)](https://codecov.io/gh/gluxon/wireguard-uapi-rs)
[![Crates version](https://img.shields.io/crates/v/wireguard-uapi.svg)](https://crates.io/crates/wireguard-uapi)
[![docs.rs](https://docs.rs/wireguard-uapi/badge.svg)](https://docs.rs/wireguard-uapi)
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

## Developing

Similar to the above, the compiled test binaries need permission to interface with the kernel. The easiest way to do this (that the author is aware of) is to run the tests with `sudo`.

```toml
# .cargo/config.toml

[target.x86_64-unknown-linux-gnu]
runner = "sudo"

[target.aarch64-unknown-linux-gnu]
runner = "sudo"
```

## Disclaimer

This isn't an official WireGuard product. (Although I'm interested in making it so.)

Feel free to file bugs.
