//! Owned storage behind immutable borrowed C views.

use std::ptr;

use netd_abi as abi;
use netd_core::profile::{OnExpiry, Profile};
use netd_core::{DnsScope, InterfaceStatus, LeaseStatus, Level};

/// Every pointer in a view refers to one of these heap allocations. Moving the
/// arena or growing its lists never moves the allocations themselves.
#[derive(Default)]
pub(crate) struct Arena {
    text: Vec<Box<str>>,
    lists: Vec<Box<[abi::Bytes]>>,
}

pub(crate) fn absent() -> abi::Bytes {
    abi::Bytes {
        data: ptr::null(),
        len: 0,
    }
}

pub(crate) fn optional(value: Option<u32>) -> abi::OptionalU32 {
    abi::OptionalU32 {
        present: u32::from(value.is_some()),
        value: value.unwrap_or(0),
    }
}

pub(crate) fn level(value: Level) -> u32 {
    match value {
        Level::Absent => 0,
        Level::Link => 1,
        Level::Addressed => 2,
        Level::Routed => 3,
    }
}

impl Arena {
    pub(crate) fn text(&mut self, value: impl AsRef<str>) -> abi::Bytes {
        let text: Box<str> = value.as_ref().into();
        let view = abi::Bytes {
            data: text.as_ptr(),
            len: text.len(),
        };
        self.text.push(text);
        view
    }

    pub(crate) fn maybe_text(&mut self, value: Option<&str>) -> abi::Bytes {
        value.map_or_else(absent, |value| self.text(value))
    }

    pub(crate) fn strings(
        &mut self,
        values: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> abi::Strings {
        let views: Box<_> = values.into_iter().map(|value| self.text(value)).collect();
        let view = abi::Strings {
            data: views.as_ptr(),
            len: views.len(),
        };
        self.lists.push(views);
        view
    }

    fn lease(&mut self, value: Option<&LeaseStatus>) -> abi::Lease {
        let empty = LeaseStatus::default();
        let lease = value.unwrap_or(&empty);
        abi::Lease {
            present: u32::from(value.is_some()),
            server: self.text(&lease.server),
            state: self.text(&lease.state),
            expires_in: lease.expires_in,
            duration: lease.duration,
            renew_at: lease.renew_at,
            rebind_at: lease.rebind_at,
        }
    }

    pub(crate) fn interface(&mut self, value: &InterfaceStatus) -> abi::Interface {
        abi::Interface {
            ifid: self.text(&value.ifid),
            name: self.text(&value.name),
            mac: self.text(&value.mac),
            path: self.text(&value.path),
            driver: self.text(&value.driver),
            verdict: self.maybe_text(value.verdict.as_deref()),
            rule: self.maybe_text(value.rule.as_deref()),
            profile: self.maybe_text(value.profile.as_deref()),
            network: self.maybe_text(value.network.as_deref()),
            network_name: self.maybe_text(value.network_name.as_deref()),
            network_trust: self.maybe_text(value.network_trust.as_deref()),
            warning: self.maybe_text(value.warning.as_deref()),
            gateway: self.maybe_text(value.gateway.as_deref()),
            gateway6: self.maybe_text(value.gateway6.as_deref()),
            index: value.index,
            up: u32::from(value.up),
            carrier: u32::from(value.carrier),
            level: level(value.level),
            addresses: self.strings(&value.addresses),
            dns: self.strings(&value.dns),
            search: self.strings(&value.search),
            lease: self.lease(value.lease.as_ref()),
        }
    }

    pub(crate) fn scope(&mut self, value: &DnsScope) -> abi::DnsScope {
        abi::DnsScope {
            ifid: self.text(&value.ifid),
            name: self.text(&value.name),
            servers: self.strings(&value.servers),
            domains: self.strings(&value.domains),
            ntp: self.strings(&value.ntp),
            addresses: self.strings(&value.addresses),
            default_route: u32::from(value.default_route),
            exclusive: u32::from(value.exclusive),
            metric: value.metric,
            level: level(value.level),
        }
    }

    pub(crate) fn profile(&mut self, value: &Profile) -> abi::Profile {
        let address = &value.address;
        let dns = &value.dns;
        abi::Profile {
            path: self.text(&value.path),
            enabled: u32::from(value.enabled),
            offered: u32::from(address.offered),
            ipv4: u32::from(address.ipv4),
            ipv6: u32::from(address.ipv6),
            link_local: u32::from(address.link_local),
            temporary: u32::from(address.temporary),
            on_expiry: match address.on_expiry {
                OnExpiry::Drop => 0,
                OnExpiry::Keep => 1,
            },
            route_offered: u32::from(address.route_offered),
            mtu_offered: u32::from(address.mtu_offered),
            announce_hostname: u32::from(address.announce_hostname),
            accept_hostname: u32::from(address.accept_hostname),
            dns_offered: u32::from(dns.offered),
            dns_exclusive: u32::from(dns.exclusive),
            route_metric: optional(address.route_metric),
            mtu: optional(address.mtu),
            dns_default_route: optional(dns.default_route.map(u32::from)),
            gateway: self.maybe_text(address.gateway.map(|ip| ip.to_string()).as_deref()),
            gateway6: self.maybe_text(address.gateway6.map(|ip| ip.to_string()).as_deref()),
            statics: self.strings(
                address
                    .statics
                    .iter()
                    .map(|entry| format!("{}/{}", entry.address, entry.prefix)),
            ),
            dns_servers: self.strings(dns.servers.iter().map(ToString::to_string)),
            dns_domains: self.strings(&dns.domains),
        }
    }
}
