# wireguard-uapi-rs

[![Build Status](https://travis-ci.org/gluxon/wireguard-uapi-rs.svg?branch=master)](https://travis-ci.org/gluxon/wireguard-uapi-rs)
[![Crates version](https://img.shields.io/crates/v/wireguard-uapi.svg)](https://crates.io/crates/wireguard-uapi)
[![docs.rs](https://docs.rs/wireguard-uapi/badge.svg?version=0.2.0)](https://docs.rs/wireguard-uapi)
![MIT](https://img.shields.io/github/license/gluxon/wireguard-uapi-rs)

This library is a work in progress. At the moment this library just talks to the WireGuard dynamic kernel module.

- If you're just reading a WireGuard device interface, this library fully supports that functionality.
- If you're creating new WireGuard device interfaces, this library currently has partial support. Configured peers won't be reachable at their allowed IPs for now. Doing so involves some [Netlink Route](https://www.infradead.org/~tgr/libnl/doc/route.html) communication, which is being worked on.

Checkout the examples folder for more guidance.

Feel free to file bugs.

DISCLAIMER: This isn't an official WireGuard product. (Although I'm interested in making it so.)
