//! Desired state, diffed against observed state, applied.
//!
//! The one rule: netd owns what it configured and nothing else. Addresses on
//! a managed interface are all netd's (a manual `ip addr add` is reverted —
//! the registry is the truth); routes are netd's only when they carry
//! [`RTPROT_NETD`], so a program's own routes are left alone.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::log;
use crate::model::{Address, Observed, RTPROT_NETD, Route, is_v6_link_local};
use crate::netlink::Rtnl;

/// One IPv6 address the interface should carry, with the flags SLAAC needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredV6 {
    pub address: Ipv6Addr,
    pub prefix: u8,
    /// Keep it, but with a preferred lifetime of zero.
    pub deprecated: bool,
    /// The prefix is not on-link; the kernel must not derive a prefix route.
    pub no_prefix_route: bool,
}

/// What one managed interface should look like.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Desired {
    pub index: u32,
    pub up: bool,
    pub mtu: Option<u32>,
    pub addresses: Vec<(Ipv4Addr, u8)>,
    pub addresses6: Vec<DesiredV6>,
    pub broadcast: Option<Ipv4Addr>,
    /// Gateway for a default route, with its metric.
    pub default_route: Option<(Ipv4Addr, u32)>,
    /// Gateway for the IPv6 default route — a router's link-local.
    pub default_route6: Option<(Ipv6Addr, u32)>,
    /// (destination, prefix, gateway, metric)
    pub routes: Vec<(Ipv4Addr, u8, Ipv4Addr, u32)>,
}

/// Steps the reconciler decided on, in order. Separated from application so
/// tests can assert on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    LinkUp(u32),
    LinkDown(u32),
    Mtu(u32, u32),
    AddAddress(Address, Option<Ipv4Addr>),
    DelAddress(Address),
    AddRoute(Route),
    DelRoute(Route),
}

pub fn plan(observed: &Observed, desired: &Desired) -> Vec<Op> {
    let mut ops = Vec::new();
    let index = desired.index;
    let Some(link) = observed.links.get(&index) else {
        return ops;
    };

    if desired.up && !link.up {
        ops.push(Op::LinkUp(index));
    }
    if let Some(mtu) = desired.mtu {
        if mtu != link.mtu && mtu >= 68 {
            ops.push(Op::Mtu(index, mtu));
        }
    }

    let want: BTreeSet<Address> = desired
        .addresses
        .iter()
        .map(|(a, p)| Address::new(index, IpAddr::V4(*a), *p))
        .chain(desired.addresses6.iter().map(|a| Address {
            index,
            address: IpAddr::V6(a.address),
            prefix: a.prefix,
            deprecated: a.deprecated,
            no_prefix_route: a.no_prefix_route,
            tentative: false,
        }))
        .collect();
    // The kernel's own IPv6 link-local is not ours to manage: every up
    // interface has one, made by the kernel, needed by neighbour discovery.
    // Tentative is erased before comparing — DAD finishing is not a diff.
    let have: BTreeSet<Address> = observed
        .addresses_of(index)
        .filter(|a| match a.address {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => !is_v6_link_local(&v6),
        })
        .cloned()
        .map(|a| Address { tentative: false, ..a })
        .collect();
    let wanted_key = |a: &Address| {
        want.iter()
            .any(|w| w.address == a.address && w.prefix == a.prefix)
    };
    for a in &have {
        // Delete only what no desired address names; a flags-only change
        // (deprecation) is a replacing add, never a delete that would reset
        // standing connections.
        if !wanted_key(a) {
            ops.push(Op::DelAddress(a.clone()));
        }
    }
    for a in &want {
        if !have.contains(a) {
            ops.push(Op::AddAddress(a.clone(), desired.broadcast));
        }
    }

    let mut want_routes: BTreeSet<Route> = desired
        .routes
        .iter()
        .map(|(d, p, g, m)| Route {
            index,
            destination: IpAddr::V4(*d),
            prefix: *p,
            gateway: Some(IpAddr::V4(*g)),
            metric: *m,
            protocol: RTPROT_NETD,
        })
        .collect();
    if let Some((gateway, metric)) = desired.default_route {
        want_routes.insert(Route {
            index,
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix: 0,
            gateway: Some(IpAddr::V4(gateway)),
            metric,
            protocol: RTPROT_NETD,
        });
    }
    if let Some((gateway, metric)) = desired.default_route6 {
        want_routes.insert(Route {
            index,
            destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix: 0,
            gateway: Some(IpAddr::V6(gateway)),
            metric,
            protocol: RTPROT_NETD,
        });
    }
    // Only routes we stamped are ours to remove.
    let have_routes: BTreeSet<Route> = observed
        .routes_of(index)
        .filter(|r| r.protocol == RTPROT_NETD)
        .cloned()
        .collect();
    for r in have_routes.difference(&want_routes) {
        ops.push(Op::DelRoute(r.clone()));
    }
    for r in want_routes.difference(&have_routes) {
        ops.push(Op::AddRoute(r.clone()));
    }

    if !desired.up && link.up {
        ops.push(Op::LinkDown(index));
    }
    ops
}

/// Apply, logging each failure and carrying on: one bad route must not stop
/// the address from landing.
pub fn apply(rtnl: &mut dyn Rtnl, ops: &[Op]) -> usize {
    let mut failures = 0;
    for op in ops {
        let result = match op {
            Op::LinkUp(i) => rtnl.set_link_up(*i, true),
            Op::LinkDown(i) => rtnl.set_link_up(*i, false),
            Op::Mtu(i, m) => rtnl.set_mtu(*i, *m),
            Op::AddAddress(a, b) => rtnl.add_address(a, *b),
            Op::DelAddress(a) => rtnl.del_address(a),
            Op::AddRoute(r) => rtnl.add_route(r),
            Op::DelRoute(r) => rtnl.del_route(r),
        };
        if let Err(e) = result {
            // EEXIST on add and ENOENT/ESRCH on delete mean the kernel got
            // there first (a duplicate event, a race with a dump); not errors.
            let benign = matches!(
                (op, e.raw_os_error()),
                (Op::AddRoute(_) | Op::AddAddress(..), Some(libc::EEXIST))
                    | (
                        Op::DelRoute(_) | Op::DelAddress(_),
                        Some(libc::ENOENT | libc::ESRCH)
                    )
            );
            if !benign {
                failures += 1;
                log::warn(format_args!("reconcile: {op:?} failed: {e}"));
            }
        }
    }
    failures
}

#[cfg(test)]
pub mod fake {
    //! A recording fake of the kernel.
    use super::*;
    use std::io;

    #[derive(Default)]
    pub struct FakeRtnl {
        pub state: Observed,
        pub log: Vec<String>,
    }

    impl Rtnl for FakeRtnl {
        fn dump(&mut self) -> io::Result<Observed> {
            Ok(self.state.clone())
        }
        fn set_link_up(&mut self, index: u32, up: bool) -> io::Result<()> {
            self.log.push(format!("link {index} up={up}"));
            if let Some(l) = self.state.links.get_mut(&index) {
                l.up = up;
                l.carrier = up;
            }
            Ok(())
        }
        fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
            self.log.push(format!("mtu {index} {mtu}"));
            Ok(())
        }
        fn add_address(&mut self, a: &Address, _b: Option<Ipv4Addr>) -> io::Result<()> {
            self.log
                .push(format!("addr add {}/{}", a.address, a.prefix));
            self.state.addresses.push(a.clone());
            Ok(())
        }
        fn del_address(&mut self, a: &Address) -> io::Result<()> {
            self.log
                .push(format!("addr del {}/{}", a.address, a.prefix));
            self.state.addresses.retain(|x| x != a);
            Ok(())
        }
        fn add_route(&mut self, r: &Route) -> io::Result<()> {
            self.log.push(format!(
                "route add {}/{} via {:?} metric {}",
                r.destination, r.prefix, r.gateway, r.metric
            ));
            self.state.routes.push(r.clone());
            Ok(())
        }
        fn del_route(&mut self, r: &Route) -> io::Result<()> {
            self.log
                .push(format!("route del {}/{}", r.destination, r.prefix));
            self.state.routes.retain(|x| x != r);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeRtnl;
    use super::*;
    use crate::model::{Link, LinkKind};

    fn observed() -> Observed {
        let mut o = Observed::default();
        o.links.insert(
            2,
            Link {
                index: 2,
                name: "eth0".into(),
                mac: None,
                up: false,
                carrier: false,
                loopback: false,
                mtu: 1500,
                link_type: 1,
                kind: LinkKind::Ether,
            },
        );
        o
    }

    #[test]
    fn a_fresh_link_is_brought_up_addressed_and_routed() {
        let o = observed();
        let d = Desired {
            index: 2,
            up: true,
            addresses: vec![(Ipv4Addr::new(10, 0, 2, 15), 24)],
            default_route: Some((Ipv4Addr::new(10, 0, 2, 2), 100)),
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert!(matches!(ops[0], Op::LinkUp(2)));
        assert!(matches!(ops[1], Op::AddAddress(..)));
        assert!(matches!(ops[2], Op::AddRoute(ref r) if r.is_default()));
        let mut fake = FakeRtnl {
            state: o,
            log: vec![],
        };
        assert_eq!(apply(&mut fake, &ops), 0);
        // Converged: the second plan is empty.
        assert!(plan(&fake.state, &d).is_empty());
    }

    #[test]
    fn a_manual_address_is_reverted_but_a_foreign_route_is_kept() {
        let mut o = observed();
        o.addresses
            .push(Address::new(2, "192.168.9.9".parse().unwrap(), 24));
        o.routes.push(Route {
            index: 2,
            destination: IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0)),
            prefix: 16,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
            metric: 0,
            protocol: 4, // RTPROT_STATIC: somebody else's
        });
        let d = Desired {
            index: 2,
            up: true,
            addresses: vec![(Ipv4Addr::new(10, 0, 2, 15), 24)],
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert!(ops.iter().any(|o| matches!(o, Op::DelAddress(a) if a.prefix == 24 && a.address.to_string() == "192.168.9.9")));
        assert!(!ops.iter().any(|o| matches!(o, Op::DelRoute(_))));
    }

    #[test]
    fn a_stale_netd_route_is_removed() {
        let mut o = observed();
        o.routes.push(Route {
            index: 2,
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2))),
            metric: 100,
            protocol: RTPROT_NETD,
        });
        let d = Desired {
            index: 2,
            up: true,
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert!(
            ops.iter()
                .any(|o| matches!(o, Op::DelRoute(r) if r.is_default()))
        );
    }

    #[test]
    fn slaac_addresses_and_the_v6_default_route_land_beside_v4() {
        let mut o = observed();
        o.links.get_mut(&2).unwrap().up = true;
        // The kernel's link-local is already there, and must be left alone.
        o.addresses.push(Address::new(
            2,
            "fe80::5054:ff:fe01:203".parse().unwrap(),
            64,
        ));
        let d = Desired {
            index: 2,
            up: true,
            addresses6: vec![DesiredV6 {
                address: "fd00::1234".parse().unwrap(),
                prefix: 64,
                deprecated: false,
                no_prefix_route: false,
            }],
            default_route6: Some(("fe80::2".parse().unwrap(), 100)),
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert!(
            ops.iter().any(
                |op| matches!(op, Op::AddAddress(a, _) if a.address.to_string() == "fd00::1234")
            )
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::AddRoute(r) if r.is_default() && !r.is_v4()))
        );
        assert!(
            !ops.iter().any(|op| matches!(op, Op::DelAddress(_))),
            "the link-local stays: {ops:?}"
        );
        let mut fake = FakeRtnl {
            state: o,
            log: vec![],
        };
        assert_eq!(apply(&mut fake, &ops), 0);
        assert!(plan(&fake.state, &d).is_empty(), "converged");
    }

    #[test]
    fn deprecation_is_a_replacing_add_never_a_delete() {
        let mut o = observed();
        o.links.get_mut(&2).unwrap().up = true;
        o.addresses
            .push(Address::new(2, "fd00::1234".parse().unwrap(), 64));
        let d = Desired {
            index: 2,
            up: true,
            addresses6: vec![DesiredV6 {
                address: "fd00::1234".parse().unwrap(),
                prefix: 64,
                deprecated: true,
                no_prefix_route: false,
            }],
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert!(
            !ops.iter().any(|op| matches!(op, Op::DelAddress(_))),
            "{ops:?}"
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, Op::AddAddress(a, _) if a.deprecated)),
            "the flag change is a replacing add: {ops:?}"
        );
    }

    #[test]
    fn a_foreign_global_v6_address_is_reverted() {
        let mut o = observed();
        o.links.get_mut(&2).unwrap().up = true;
        o.addresses
            .push(Address::new(2, "2001:db8::9".parse().unwrap(), 64));
        let d = Desired {
            index: 2,
            up: true,
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert!(
            ops.iter().any(
                |op| matches!(op, Op::DelAddress(a) if a.address.to_string() == "2001:db8::9")
            )
        );
    }

    #[test]
    fn unmanaged_desired_down_takes_the_link_down_last() {
        let mut o = observed();
        o.links.get_mut(&2).unwrap().up = true;
        let d = Desired {
            index: 2,
            up: false,
            ..Default::default()
        };
        let ops = plan(&o, &d);
        assert_eq!(ops, vec![Op::LinkDown(2)]);
    }
}
