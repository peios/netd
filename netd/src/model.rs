//! What the kernel says the network is, and how netd names interfaces.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

/// The routing protocol number netd stamps on routes it owns. Values above
/// `RTPROT_STATIC` are for userspace to claim; 200 is ours. The reconciler
/// touches no route carrying any other protocol.
pub const RTPROT_NETD: u8 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mac: Option<[u8; 6]>,
    pub up: bool,
    /// `IFF_LOWER_UP`: the physical layer sees a peer.
    pub carrier: bool,
    pub loopback: bool,
    pub mtu: u32,
    /// `ARPHRD_*`.
    pub link_type: u16,
    /// For bookkeeping and matching: the `Type` match key.
    pub kind: LinkKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Loopback,
    Ether,
    Wireless,
    Other,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Loopback => "loopback",
            LinkKind::Ether => "ether",
            LinkKind::Wireless => "wlan",
            LinkKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    pub index: u32,
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Route {
    pub index: u32,
    pub destination: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub metric: u32,
    pub protocol: u8,
}

impl Route {
    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }
}

/// A snapshot of kernel network state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    pub links: BTreeMap<u32, Link>,
    pub addresses: Vec<Address>,
    pub routes: Vec<Route>,
}

impl Observed {
    pub fn addresses_of(&self, index: u32) -> impl Iterator<Item = &Address> {
        self.addresses.iter().filter(move |a| a.index == index)
    }

    pub fn routes_of(&self, index: u32) -> impl Iterator<Item = &Route> {
        self.routes.iter().filter(move |r| r.index == index)
    }
}

/// Hardware identity read from sysfs: what stays the same when the name does
/// not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    /// e.g. `pci-0000:00:03.0`, or empty for virtual devices.
    pub path: String,
    /// e.g. `virtio_net`.
    pub driver: String,
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// The interface id: a UUID-shaped digest of bus path and MAC.
///
/// Same card in the same slot gives the same id on every boot, whatever the
/// kernel called it. A virtual device has no bus path, so its id follows its
/// MAC alone (and a MAC-less one its name, which is all it has).
pub fn interface_id(identity: &Identity, mac: Option<&[u8; 6]>, name: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(b"peios-netd-ifid|");
    if !identity.path.is_empty() {
        h.update(identity.path.as_bytes());
    }
    h.update(b"|");
    match mac {
        Some(m) => h.update(m),
        None => h.update(name.as_bytes()),
    }
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    // UUID version 5 (SHA-1 name-based), RFC 4122 variant.
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Read a link's hardware identity from sysfs.
pub fn read_identity(name: &str) -> Identity {
    let device = std::path::PathBuf::from(format!("/sys/class/net/{name}/device"));
    let path = std::fs::canonicalize(&device)
        .ok()
        .and_then(|p| {
            // /sys/devices/pci0000:00/0000:00:03.0 -> pci-0000:00:03.0
            let leaf = p.file_name()?.to_str()?.to_owned();
            let bus = p
                .parent()?
                .file_name()?
                .to_str()?
                .trim_end_matches(|c: char| c.is_ascii_digit() || c == ':')
                .to_owned();
            Some(match bus.as_str() {
                "" => leaf,
                b => format!("{b}-{leaf}"),
            })
        })
        .unwrap_or_default();
    let driver = std::fs::read_link(device.join("driver"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_default();
    Identity { path, driver }
}

/// Whether sysfs says this link is wireless.
pub fn is_wireless(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists()
        || std::path::Path::new(&format!("/sys/class/net/{name}/phy80211")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_distinct() {
        let id = Identity { path: "pci-0000:00:03.0".into(), driver: "virtio_net".into() };
        let mac = [0x52, 0x54, 0, 1, 2, 3];
        let a = interface_id(&id, Some(&mac), "eth0");
        let b = interface_id(&id, Some(&mac), "enp0s3");
        assert_eq!(a, b, "a rename does not change the id");
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "5");
        let other = interface_id(&id, Some(&[0x52, 0x54, 0, 1, 2, 4]), "eth0");
        assert_ne!(a, other);
    }

    #[test]
    fn macs_format() {
        assert_eq!(format_mac(&[0x52, 0x54, 0, 0xab, 0xcd, 0xef]), "52:54:00:ab:cd:ef");
    }
}
