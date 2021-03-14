#[cfg(target_os = "macos")]
#[cfg(feature = "xplatform")]
mod tests {
    use anyhow::anyhow;
    use std::fs::Permissions;
    use std::io::Read;
    use std::os::unix::prelude::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::NamedTempFile;

    const MACOS_WG_SOCK_DIR: &str = "/var/run/wireguard";

    fn create_random_interface_for_testing() -> anyhow::Result<PathBuf> {
        std::fs::create_dir_all(MACOS_WG_SOCK_DIR)?;

        let mut ifname_output_file = NamedTempFile::new()?;
        std::fs::set_permissions(ifname_output_file.path(), Permissions::from_mode(0o777))?;

        // On macOS, "wireguard-go utun" creates a new utunX.sock file in the
        // /var/run/wireguard folder.
        // https://github.com/WireGuard/wireguard-go#macos
        let wireguard_go_status = Command::new("wireguard-go")
            .args(&["utun"])
            .env("WG_TUN_NAME_FILE", ifname_output_file.path().as_os_str())
            .status()?;
        if !wireguard_go_status.success() {
            return Err(anyhow!(
            "The command \"wireguard-go utun\" failed with exit code {}. This test may need to run with sudo to create new interfaces.",
            wireguard_go_status
        ));
        }

        let sock_path = {
            let mut buffer = String::new();
            ifname_output_file.read_to_string(&mut buffer)?;
            let ifname = buffer.trim();
            assert!(!ifname.is_empty());
            PathBuf::from(MACOS_WG_SOCK_DIR).join(format!("{}.sock", ifname))
        };

        // There appears to be a short duration after wireguard-go returns where the
        // interface hasn't been created yet.
        std::thread::sleep(std::time::Duration::from_millis(100));

        Ok(sock_path)
    }

    // https://github.com/jedisct1/libsodium/blob/3de0b3cdad90bbe0c44393fb0a264e9af6d76724/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L91-L93
    fn curve25519_clamp(key: [u8; 32]) -> [u8; 32] {
        let mut key = key;
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
        key
    }

    #[test]
    fn empty() -> anyhow::Result<()> {
        let socket = create_random_interface_for_testing()?;
        let client = wireguard_uapi::xplatform::Client::create(socket);

        let interface = client.get()?;
        assert_eq!(interface.private_key, None);
        Ok(())
    }

    #[test]
    fn simple() -> anyhow::Result<()> {
        use wireguard_uapi::xplatform::set;

        let socket = create_random_interface_for_testing()?;
        let client = wireguard_uapi::xplatform::Client::create(socket);

        let interface = client.get()?;
        assert_eq!(interface.private_key, None);

        let private_key = curve25519_clamp(rand::random());
        client.set(set::Device {
            private_key: Some(private_key),
            ..Default::default()
        })?;
        let interface = client.get()?;
        assert_eq!(interface.private_key, Some(private_key));

        Ok(())
    }
}
