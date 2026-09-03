//! Networks: the thing on the other side of an interface.
//!
//! netd has to say "this is the same network as last time" with nothing on
//! the wire that says so. First version of the identity (PEI-598, the
//! interface configuration surface): a wired network is the DHCP server
//! that answered plus the subnet it handed out; an IPv6-only network is the
//! router that advertised plus its first prefix. Every signal is recorded
//! on the record's `Status` key so a later proof — an authenticated peer,
//! a known certificate — can replace the guess without changing the key.
//!
//! Wireless (SSID plus access point) waits for a supplicant; a tunnel is
//! its far end and waits for tunnels.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What the network showed us, from which its identity is derived.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Signals {
    /// The interface kind the network was seen on.
    pub kind: String,
    /// The DHCPv4 server that answered.
    pub server: Option<Ipv4Addr>,
    /// The subnet the lease placed us in.
    pub subnet: Option<(Ipv4Addr, u8)>,
    /// The way out the lease offered.
    pub gateway: Option<Ipv4Addr>,
    /// The router that advertised (its link-local address).
    pub router6: Option<Ipv6Addr>,
    /// The advertised prefixes.
    pub prefixes6: Vec<(Ipv6Addr, u8)>,
    /// The name servers the network offered, either family.
    pub dns: Vec<IpAddr>,
}

impl Signals {
    /// The network's identity, or `None` when nothing identifying has been
    /// seen yet (no offer, or a static-only interface).
    pub fn identity(&self) -> Option<String> {
        let mut basis = String::new();
        match (self.server, self.subnet) {
            (Some(server), Some((net, prefix))) => {
                basis.push_str(&format!("dhcp:{server}|{net}/{prefix}"));
            }
            _ => match (self.router6, self.prefixes6.first()) {
                (Some(router), Some((net, prefix))) => {
                    basis.push_str(&format!("ra:{router}|{net}/{prefix}"));
                }
                _ => return None,
            },
        }
        Some(derive(&self.kind, &basis))
    }
}

/// Masks `address` to its `prefix` bits: the subnet a lease describes.
pub fn subnet_of(address: Ipv4Addr, prefix: u8) -> (Ipv4Addr, u8) {
    let bits = u32::from(address);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    (Ipv4Addr::from(bits & mask), prefix)
}

/// UUID-shaped, like an interface id, so the two kinds of key read alike.
fn derive(kind: &str, basis: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(b"peios-netd-network|");
    h.update(kind.as_bytes());
    h.update(b"|");
    h.update(basis.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

/// What the operator wrote on a network record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    pub id: String,
    /// `Name`: the operator's label.
    pub name: Option<String>,
    /// `Trust`: the operator's word, until the trust pass gives it a
    /// vocabulary.
    pub trust: Option<String>,
    /// `RequestedAddress`: the IPv4 address to ask for next; shared with
    /// netd, which writes the leased address after each lease.
    pub requested_address: Option<Ipv4Addr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_offer_is_the_same_network_and_a_different_one_is_not() {
        let a = Signals {
            kind: "wired".into(),
            server: Some(Ipv4Addr::new(10, 0, 2, 2)),
            subnet: Some(subnet_of(Ipv4Addr::new(10, 0, 2, 15), 24)),
            ..Default::default()
        };
        let mut b = a.clone();
        b.subnet = Some(subnet_of(Ipv4Addr::new(10, 0, 2, 99), 24));
        assert_eq!(a.identity(), b.identity(), "another address in the same subnet");
        b.server = Some(Ipv4Addr::new(10, 0, 3, 1));
        assert_ne!(a.identity(), b.identity(), "another server");
        assert_eq!(a.identity().unwrap().len(), 36);
    }

    #[test]
    fn nothing_identifying_means_no_network_yet() {
        assert_eq!(Signals::default().identity(), None);
        let v6 = Signals {
            kind: "wired".into(),
            router6: Some("fe80::1".parse().unwrap()),
            prefixes6: vec![("2001:db8::".parse().unwrap(), 64)],
            ..Default::default()
        };
        assert!(v6.identity().is_some());
    }

    #[test]
    fn subnets_mask() {
        assert_eq!(
            subnet_of(Ipv4Addr::new(192, 168, 1, 77), 24),
            (Ipv4Addr::new(192, 168, 1, 0), 24)
        );
        assert_eq!(subnet_of(Ipv4Addr::new(10, 1, 2, 3), 0), (Ipv4Addr::new(0, 0, 0, 0), 0));
    }
}
