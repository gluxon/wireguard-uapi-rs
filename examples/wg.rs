use colored::*;
use wireguard_uapi::get::{AllowedIp, Device, Peer};

fn main() -> anyhow::Result<()> {
    let device_names = wireguard_uapi::RouteSocket::connect()?.list_device_names()?;

    let mut wg = wireguard_uapi::WgSocket::connect()?;
    for device_name in &device_names {
        let device = wg.get_device(wireguard_uapi::DeviceInterface::from_name(device_name))?;
        print_device(&device);

        if Some(device_name) != device_names.last() {
            println!();
        }
    }

    Ok(())
}

fn print_device(device: &Device) {
    println!("{}: {}", "interface".green(), device.ifname.green());
    if let Some(public_key) = &device.public_key {
        println!(
            "  {}: {}",
            "public key".black().bold(),
            base64::encode(public_key)
        );
    }

    if device.listen_port != 0 {
        println!("  {}: {}", "listen port".black().bold(), device.listen_port);
    }

    for peer in &device.peers {
        println!();
        print_peer(&peer);
    }
}

fn print_peer(peer: &Peer) {
    println!(
        "{}: {}",
        "peer".yellow(),
        base64::encode(&peer.public_key).yellow()
    );
    if let Some(endpoint) = peer.endpoint {
        println!("  {}: {}", "endpoint".black().bold(), endpoint);
    }

    print!("  {}: ", "allowed ips".black().bold());
    for (i, allowed_ip) in peer.allowed_ips.iter().enumerate() {
        print_allowed_ip(allowed_ip);
        if i < peer.allowed_ips.len() - 1 {
            print!(", ");
        }
    }
    println!();
}

fn print_allowed_ip(allowed_ip: &AllowedIp) {
    print!(
        "{}{}{}",
        allowed_ip.ipaddr,
        "/".cyan(),
        allowed_ip.cidr_mask
    );
}
