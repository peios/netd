//! The ICMPv6 neighbour-discovery codec: router solicitations out, router
//! advertisements in.
//!
//! Only the ICMPv6 body is handled here — the kernel owns the IPv6 header
//! and the checksum on a raw ICMPv6 socket. The decoder sees whatever the
//! local network chose to send, so every length is checked and every count
//! is bounded; a malformed option skips that option, a malformed message is
//! `None`.

use std::net::Ipv6Addr;

pub const ROUTER_SOLICIT: u8 = 133;
pub const ROUTER_ADVERT: u8 = 134;

const OPTION_SOURCE_LLA: u8 = 1;
const OPTION_PREFIX_INFO: u8 = 3;
const OPTION_MTU: u8 = 5;
const OPTION_RDNSS: u8 = 25;
const OPTION_DNSSL: u8 = 31;

/// Ceilings on what one advertisement may carry. A router legitimately
/// advertises a handful of each; a hostile one advertises enough to matter.
const MAX_PREFIXES: usize = 16;
const MAX_SERVERS: usize = 16;
const MAX_DOMAINS: usize = 16;

/// A prefix-information option (RFC 4861 §4.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub length: u8,
    /// L: addresses in this prefix are reachable on-link.
    pub on_link: bool,
    /// A: hosts may form addresses from this prefix.
    pub autonomous: bool,
    /// Seconds; `u32::MAX` means forever.
    pub valid: u32,
    pub preferred: u32,
}

/// A recursive-DNS-server option (RFC 8106 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdnss {
    /// Seconds; `u32::MAX` means forever.
    pub lifetime: u32,
    pub servers: Vec<Ipv6Addr>,
}

/// A DNS-search-list option (RFC 8106 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnssl {
    pub lifetime: u32,
    pub domains: Vec<String>,
}

/// A router advertisement, decoded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouterAdvert {
    /// M: addresses are to be had over DHCPv6. Peios treats it as O — the
    /// stateful client is not built, and RFC 8415 makes an information
    /// request legitimate either way.
    pub managed: bool,
    /// O: other configuration (DNS) is to be had over DHCPv6.
    pub other_config: bool,
    /// Seconds this router is a default router for; 0 means it is not one.
    pub router_lifetime: u16,
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInfo>,
    pub rdnss: Vec<Rdnss>,
    pub dnssl: Vec<Dnssl>,
}

impl RouterAdvert {
    /// Decode an ICMPv6 body claiming to be a router advertisement.
    ///
    /// The transport checks are the caller's: that the message arrived with
    /// a hop limit of 255 and from a link-local source (RFC 4861 §6.1.2) is
    /// known only at the socket.
    pub fn decode(body: &[u8]) -> Option<RouterAdvert> {
        if body.len() < 16 || body[0] != ROUTER_ADVERT || body[1] != 0 {
            return None;
        }
        let mut ra = RouterAdvert {
            managed: body[5] & 0x80 != 0,
            other_config: body[5] & 0x40 != 0,
            router_lifetime: u16::from_be_bytes([body[6], body[7]]),
            ..Default::default()
        };
        let mut rest = &body[16..];
        while !rest.is_empty() {
            if rest.len() < 2 {
                return None;
            }
            let (kind, len) = (rest[0], usize::from(rest[1]) * 8);
            // A zero-length option would loop forever; the RFC forbids it.
            if len == 0 || rest.len() < len {
                return None;
            }
            let option = &rest[..len];
            rest = &rest[len..];
            match kind {
                OPTION_PREFIX_INFO if ra.prefixes.len() < MAX_PREFIXES => {
                    if let Some(p) = prefix_info(option) {
                        ra.prefixes.push(p);
                    }
                }
                OPTION_MTU if option.len() == 8 => {
                    ra.mtu = Some(u32::from_be_bytes([
                        option[4], option[5], option[6], option[7],
                    ]));
                }
                OPTION_RDNSS => {
                    if let Some(r) = rdnss(option) {
                        ra.rdnss.push(r);
                    }
                }
                OPTION_DNSSL => {
                    if let Some(d) = dnssl(option) {
                        ra.dnssl.push(d);
                    }
                }
                _ => {}
            }
        }
        Some(ra)
    }
}

fn prefix_info(option: &[u8]) -> Option<PrefixInfo> {
    if option.len() != 32 {
        return None;
    }
    let length = option[2];
    if length > 128 {
        return None;
    }
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&option[16..32]);
    let prefix = Ipv6Addr::from(prefix);
    // A link-local or multicast "prefix" is a misconfiguration or an attack;
    // RFC 4862 §5.5.3 says never to autoconfigure from link-local.
    if prefix.is_multicast() || (prefix.segments()[0] & 0xffc0) == 0xfe80 {
        return None;
    }
    Some(PrefixInfo {
        prefix,
        length,
        on_link: option[3] & 0x80 != 0,
        autonomous: option[3] & 0x40 != 0,
        valid: u32::from_be_bytes([option[4], option[5], option[6], option[7]]),
        preferred: u32::from_be_bytes([option[8], option[9], option[10], option[11]]),
    })
}

fn rdnss(option: &[u8]) -> Option<Rdnss> {
    if option.len() < 24 || !(option.len() - 8).is_multiple_of(16) {
        return None;
    }
    let lifetime = u32::from_be_bytes([option[4], option[5], option[6], option[7]]);
    let servers = option[8..]
        .chunks_exact(16)
        .take(MAX_SERVERS)
        .map(|c| {
            let mut b = [0u8; 16];
            b.copy_from_slice(c);
            Ipv6Addr::from(b)
        })
        .filter(|a| !a.is_unspecified() && !a.is_multicast() && !a.is_loopback())
        .collect();
    Some(Rdnss { lifetime, servers })
}

fn dnssl(option: &[u8]) -> Option<Dnssl> {
    if option.len() < 16 {
        return None;
    }
    let lifetime = u32::from_be_bytes([option[4], option[5], option[6], option[7]]);
    Some(Dnssl {
        lifetime,
        domains: domain_list(&option[8..]),
    })
}

/// A sequence of uncompressed DNS wire names, as RDNSS's sibling and DHCPv6's
/// domain-list option both carry (compression is forbidden in both).
///
/// Shared with the `dhcp6` crate by being written twice — twenty lines do
/// not buy a dependency. A malformed name ends the walk; what parsed before
/// it stands.
pub fn domain_list(mut bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while !bytes.is_empty() && out.len() < MAX_DOMAINS {
        let mut name = String::new();
        loop {
            let Some((&len, rest)) = bytes.split_first() else {
                return out;
            };
            let len = usize::from(len);
            bytes = rest;
            if len == 0 {
                break;
            }
            // 0xC0.. is compression, forbidden here; > 63 is not a label.
            if len > 63 || bytes.len() < len || name.len() + len + 1 > 253 {
                return out;
            }
            let label = &bytes[..len];
            bytes = &bytes[len..];
            if !label.iter().all(|b| b.is_ascii_graphic()) {
                return out;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        }
        if !name.is_empty() {
            out.push(name);
        }
        // Trailing zero padding to the option's 8-byte boundary.
        if bytes.iter().all(|&b| b == 0) {
            return out;
        }
    }
    out
}

/// A router solicitation (RFC 4861 §4.1), with our link-layer address so the
/// router can answer unicast. Checksum is the kernel's on a raw ICMPv6
/// socket.
pub fn solicit(source_mac: Option<&[u8; 6]>) -> Vec<u8> {
    let mut out = vec![ROUTER_SOLICIT, 0, 0, 0, 0, 0, 0, 0];
    if let Some(mac) = source_mac {
        out.extend_from_slice(&[OPTION_SOURCE_LLA, 1]);
        out.extend_from_slice(mac);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An RA as slirp or a home router would send it: one prefix, an MTU,
    /// a DNS server.
    fn sample() -> Vec<u8> {
        let mut b = vec![
            ROUTER_ADVERT,
            0,
            0,
            0,
            64,
            0xc0,
            0x07,
            0x08,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        // Prefix information: fd00::/64, on-link + autonomous.
        b.extend_from_slice(&[3, 4, 64, 0xc0]);
        b.extend_from_slice(&86400u32.to_be_bytes());
        b.extend_from_slice(&14400u32.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0).octets());
        // MTU 1500.
        b.extend_from_slice(&[5, 1, 0, 0]);
        b.extend_from_slice(&1500u32.to_be_bytes());
        // RDNSS: fd00::3, lifetime 1200.
        b.extend_from_slice(&[25, 3, 0, 0]);
        b.extend_from_slice(&1200u32.to_be_bytes());
        b.extend_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3).octets());
        // DNSSL: "lan", lifetime 1200.
        b.extend_from_slice(&[31, 2, 0, 0]);
        b.extend_from_slice(&1200u32.to_be_bytes());
        b.extend_from_slice(&[3, b'l', b'a', b'n', 0, 0, 0, 0]);
        b
    }

    #[test]
    fn a_full_advertisement_decodes() {
        let ra = RouterAdvert::decode(&sample()).unwrap();
        assert!(ra.managed && ra.other_config);
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!(ra.mtu, Some(1500));
        assert_eq!(
            ra.prefixes,
            vec![PrefixInfo {
                prefix: "fd00::".parse().unwrap(),
                length: 64,
                on_link: true,
                autonomous: true,
                valid: 86400,
                preferred: 14400,
            }]
        );
        assert_eq!(
            ra.rdnss[0].servers,
            vec!["fd00::3".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(ra.rdnss[0].lifetime, 1200);
        assert_eq!(ra.dnssl[0].domains, vec!["lan".to_owned()]);
    }

    #[test]
    fn short_wrong_typed_and_zero_length_option_messages_are_refused() {
        assert_eq!(RouterAdvert::decode(&[]), None);
        assert_eq!(RouterAdvert::decode(&[ROUTER_ADVERT, 0, 0, 0]), None);
        let mut wrong_type = sample();
        wrong_type[0] = ROUTER_SOLICIT;
        assert_eq!(RouterAdvert::decode(&wrong_type), None);
        let mut nonzero_code = sample();
        nonzero_code[1] = 1;
        assert_eq!(RouterAdvert::decode(&nonzero_code), None);
        let mut zero_length_option = sample();
        zero_length_option[17] = 0; // the prefix option's length
        assert_eq!(RouterAdvert::decode(&zero_length_option), None);
        let mut truncated = sample();
        truncated.truncate(30);
        assert_eq!(RouterAdvert::decode(&truncated), None);
    }

    #[test]
    fn a_malformed_option_is_skipped_not_fatal() {
        // A prefix claiming length 129 is nonsense; the rest still parses.
        let mut b = sample();
        b[18] = 129;
        let ra = RouterAdvert::decode(&b).unwrap();
        assert!(ra.prefixes.is_empty());
        assert_eq!(ra.mtu, Some(1500));
    }

    #[test]
    fn link_local_and_multicast_prefixes_are_never_accepted() {
        for bad in ["fe80::", "ff02::"] {
            let mut b = vec![
                ROUTER_ADVERT,
                0,
                0,
                0,
                64,
                0,
                0x07,
                0x08,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            b.extend_from_slice(&[3, 4, 64, 0xc0]);
            b.extend_from_slice(&86400u32.to_be_bytes());
            b.extend_from_slice(&14400u32.to_be_bytes());
            b.extend_from_slice(&[0; 4]);
            b.extend_from_slice(&bad.parse::<Ipv6Addr>().unwrap().octets());
            let ra = RouterAdvert::decode(&b).unwrap();
            assert!(ra.prefixes.is_empty(), "{bad} must not be a prefix");
        }
    }

    #[test]
    fn a_solicitation_carries_our_mac() {
        let s = solicit(Some(&[0x52, 0x54, 0, 1, 2, 3]));
        assert_eq!(s[0], ROUTER_SOLICIT);
        assert_eq!(s.len(), 16);
        assert_eq!(&s[8..10], &[1, 1]);
        assert_eq!(solicit(None).len(), 8);
    }

    #[test]
    fn domain_lists_stop_at_malformation_and_lowercase() {
        assert_eq!(domain_list(&[3, b'L', b'A', b'N', 0, 0, 0, 0]), vec!["lan"]);
        assert_eq!(
            domain_list(&[1, b'a', 1, b'b', 0, 2, b'c', b'd', 0]),
            vec!["a.b".to_owned(), "cd".to_owned()]
        );
        // Compression pointer: refused, nothing after it either.
        assert_eq!(domain_list(&[3, b'l', b'a', b'n', 0, 0xc0, 0]), vec!["lan"]);
        // A label running off the end.
        assert!(domain_list(&[9, b'x']).is_empty());
    }
}
