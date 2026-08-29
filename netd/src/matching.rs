//! Which profile claims a link.
//!
//! Every non-empty match key must match; a profile with no keys matches
//! nothing (a profile that claimed every interface by accident would be a
//! worse default than one that claims none). Values are compared
//! case-insensitively with one `*` wildcard allowed anywhere.

use crate::config::{Match, Profile};
use crate::model::{Identity, Link, format_mac};

/// One `*`-glob, case-insensitive.
pub fn glob(pattern: &str, value: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let v = value.to_ascii_lowercase();
    match p.split_once('*') {
        None => p == v,
        Some((head, tail)) => {
            v.len() >= head.len() + tail.len() && v.starts_with(head) && v.ends_with(tail)
        }
    }
}

pub fn matches(m: &Match, link: &Link, identity: &Identity) -> bool {
    let mac = link.mac.as_ref().map(format_mac);
    let keys = [
        (&m.name, Some(link.name.as_str())),
        (&m.mac, mac.as_deref()),
        (&m.path, Some(identity.path.as_str())),
        (&m.driver, Some(identity.driver.as_str())),
        (&m.kind, Some(link.kind.as_str())),
    ];
    let mut any = false;
    for (pattern, value) in keys {
        if let Some(pattern) = pattern {
            any = true;
            match value {
                Some(v) if glob(pattern, v) => {}
                _ => return false,
            }
        }
    }
    any
}

/// The winning profile, if any. `profiles` is already sorted by priority.
pub fn select<'a>(profiles: &'a [Profile], link: &Link, identity: &Identity) -> Option<&'a Profile> {
    profiles.iter().find(|p| matches(&p.matches, link, identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressConfig, DnsConfig};
    use crate::model::LinkKind;

    fn link() -> Link {
        Link {
            index: 2,
            name: "enp0s3".into(),
            mac: Some([0x52, 0x54, 0, 1, 2, 3]),
            up: false,
            carrier: false,
            loopback: false,
            mtu: 1500,
            link_type: 1,
            kind: LinkKind::Ether,
        }
    }

    fn profile(name: &str, priority: u32, m: Match) -> Profile {
        Profile {
            name: name.into(),
            priority,
            managed: true,
            matches: m,
            address: AddressConfig::default(),
            dns: DnsConfig::default(),
        }
    }

    #[test]
    fn globs() {
        assert!(glob("en*", "enp0s3"));
        assert!(glob("*", "anything"));
        assert!(glob("52:54:*", "52:54:00:01:02:03"));
        assert!(!glob("eth*", "enp0s3"));
        assert!(glob("ENP0S3", "enp0s3"));
    }

    #[test]
    fn every_given_key_must_match_and_none_matches_nothing() {
        let id = Identity { path: "pci-0000:00:03.0".into(), driver: "virtio_net".into() };
        let l = link();
        assert!(matches(&Match { driver: Some("virtio_net".into()), ..Default::default() }, &l, &id));
        assert!(!matches(
            &Match { driver: Some("virtio_net".into()), name: Some("eth*".into()), ..Default::default() },
            &l,
            &id
        ));
        assert!(!matches(&Match::default(), &l, &id));
        assert!(matches(&Match { kind: Some("ether".into()), ..Default::default() }, &l, &id));
    }

    #[test]
    fn first_in_priority_order_wins() {
        let id = Identity::default();
        let profiles = vec![
            profile("specific", 200, Match { name: Some("enp0s3".into()), ..Default::default() }),
            profile("any", 100, Match { kind: Some("ether".into()), ..Default::default() }),
        ];
        assert_eq!(select(&profiles, &link(), &id).unwrap().name, "specific");
    }
}
