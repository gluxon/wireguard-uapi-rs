#[cfg(target_os = "linux")]
use wireguard_uapi::set;
#[cfg(target_os = "linux")]
use wireguard_uapi::WgSocket;

#[cfg(target_os = "linux")]
#[test]
// WireGuard returns an ENODEV (no device error) when you attempt to update a
// WireGuard device that hasn't been created yet.
//
// Instead of properly reporting this error, the library currently swallows it
// and reports "No ack received". Adding this test now to record what currently
// happens and comment on the ideal future state.
//
// See https://github.com/gluxon/wireguard-uapi-rs/issues/28
fn missing_device_returns_sensible_error() -> anyhow::Result<()> {
    let mut wg = WgSocket::connect()?;
    let ifname = "wg404";

    let set_device_args = set::Device::from_ifname(ifname)
        .flags(vec![set::WgDeviceF::ReplacePeers])
        .peers(vec![]);
    let set_device_result = wg.set_device(set_device_args);

    let existing_err_message = set_device_result.unwrap_err().to_string();

    // TODO: Ensure this library returns more sensible errors. Update the "No
    // ack received" string below to "No device found by interface name or
    // public key".
    // As of neli 0.5.3 the library returns ENODEV instead of “No ack
    // received”.
    assert_eq!(
        existing_err_message,
        "Error response received from netlink: Unknown error -19 (os error -19)"
    );

    Ok(())
}
