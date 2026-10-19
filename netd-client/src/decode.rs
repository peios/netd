//! Copy immutable views while their libnetd result owner remains alive.

use std::slice;

use netd_abi as abi;

use crate::{
    AddressConfig, DnsConfig, DnsScope, Error, InterfaceStatus, Judgment, LeaseStatus, Level,
    OnExpiry, Outcome, Profile, Snapshot, StaticAddress, Status, invalid,
};

unsafe fn array<'a, T>(pointer: *const T, count: usize) -> &'a [T] {
    if count == 0 {
        return &[];
    }
    // SAFETY: callers only pass valid immutable array views from a live libnetd
    // result. The array and every element stay alive throughout the copy.
    unsafe { slice::from_raw_parts(pointer, count) }
}

pub(crate) unsafe fn text(value: abi::Bytes) -> String {
    // SAFETY: value is a library-owned byte span borrowed from a live result.
    let bytes = unsafe { array(value.data, value.len) };
    std::str::from_utf8(bytes)
        .expect("libnetd returned non-UTF-8 text")
        .to_owned()
}

unsafe fn optional_text(value: abi::Bytes) -> Option<String> {
    // SAFETY: a non-null span is an initialized library-owned string.
    (!value.data.is_null()).then(|| unsafe { text(value) })
}

pub(crate) unsafe fn strings(value: abi::Strings) -> Vec<String> {
    // SAFETY: the array and its spans are all borrowed from the same live result.
    unsafe { array(value.data, value.len) }
        .iter()
        .map(|value| unsafe { text(*value) })
        .collect()
}

fn optional(value: abi::OptionalU32) -> Option<u32> {
    (value.present != 0).then_some(value.value)
}

fn level(value: u32) -> Result<Level, Error> {
    match value {
        0 => Ok(Level::Absent),
        1 => Ok(Level::Link),
        2 => Ok(Level::Addressed),
        3 => Ok(Level::Routed),
        _ => Err(invalid("unknown libnetd readiness level")),
    }
}

unsafe fn lease(value: &abi::Lease) -> Option<LeaseStatus> {
    if value.present == 0 {
        return None;
    }
    // SAFETY: value and both strings belong to the live parent status result.
    Some(unsafe {
        LeaseStatus {
            server: text(value.server),
            state: text(value.state),
            expires_in: value.expires_in,
            duration: value.duration,
            renew_at: value.renew_at,
            rebind_at: value.rebind_at,
        }
    })
}

unsafe fn interface(value: &abi::Interface) -> Result<InterfaceStatus, Error> {
    // SAFETY: every nested span and array is a valid borrow from the live result.
    Ok(unsafe {
        InterfaceStatus {
            ifid: text(value.ifid),
            name: text(value.name),
            index: value.index,
            mac: text(value.mac),
            path: text(value.path),
            driver: text(value.driver),
            verdict: optional_text(value.verdict),
            rule: optional_text(value.rule),
            profile: optional_text(value.profile),
            network: optional_text(value.network),
            network_name: optional_text(value.network_name),
            network_trust: optional_text(value.network_trust),
            warning: optional_text(value.warning),
            up: value.up != 0,
            carrier: value.carrier != 0,
            level: level(value.level)?,
            addresses: strings(value.addresses),
            gateway: optional_text(value.gateway),
            gateway6: optional_text(value.gateway6),
            dns: strings(value.dns),
            search: strings(value.search),
            lease: lease(&value.lease),
        }
    })
}

pub(crate) unsafe fn status(pointer: *const abi::Status) -> Result<Status, Error> {
    // SAFETY: pointer is either null or a view from the live status result.
    let value = unsafe { pointer.as_ref() }.ok_or_else(|| invalid("missing status view"))?;
    // SAFETY: each nested view and span remains borrowed for the entire copy.
    Ok(unsafe {
        Status {
            hostname: text(value.hostname),
            level: level(value.level)?,
            refusal: optional_text(value.refusal),
            interfaces: array(value.interfaces, value.interface_count)
                .iter()
                .map(|value| interface(value))
                .collect::<Result<_, _>>()?,
        }
    })
}

pub(crate) unsafe fn snapshot(pointer: *const abi::Snapshot) -> Result<Snapshot, Error> {
    // SAFETY: pointer is either null or a view from the live snapshot result.
    let value = unsafe { pointer.as_ref() }.ok_or_else(|| invalid("missing snapshot view"))?;
    // SAFETY: all scope and string views remain borrowed for the entire copy.
    Ok(unsafe {
        Snapshot {
            hostname: text(value.hostname),
            scopes: array(value.scopes, value.scope_count)
                .iter()
                .map(|scope| {
                    Ok(DnsScope {
                        ifid: text(scope.ifid),
                        name: text(scope.name),
                        servers: strings(scope.servers),
                        domains: strings(scope.domains),
                        ntp: strings(scope.ntp),
                        addresses: strings(scope.addresses),
                        default_route: scope.default_route != 0,
                        exclusive: scope.exclusive != 0,
                        metric: scope.metric,
                        level: level(scope.level)?,
                    })
                })
                .collect::<Result<_, _>>()?,
        }
    })
}

fn parse<T: std::str::FromStr>(text: &str) -> Result<T, Error> {
    text.parse()
        .map_err(|_| invalid("libnetd returned an invalid address"))
}

fn static_address(text: String) -> Result<StaticAddress, Error> {
    let (address, prefix) = text
        .split_once('/')
        .ok_or_else(|| invalid("missing CIDR prefix"))?;
    Ok(StaticAddress {
        address: parse(address)?,
        prefix: parse(prefix)?,
    })
}

pub(crate) unsafe fn profile(pointer: *const abi::Profile) -> Result<Profile, Error> {
    // SAFETY: pointer is null or a live profile projection from a library result.
    let value = unsafe { pointer.as_ref() }.ok_or_else(|| invalid("missing profile view"))?;
    // SAFETY: all profile strings and arrays belong to that still-live result.
    Ok(unsafe {
        Profile {
            path: text(value.path),
            enabled: value.enabled != 0,
            address: AddressConfig {
                offered: value.offered != 0,
                ipv4: value.ipv4 != 0,
                ipv6: value.ipv6 != 0,
                statics: strings(value.statics)
                    .into_iter()
                    .map(static_address)
                    .collect::<Result<_, _>>()?,
                link_local: value.link_local != 0,
                temporary: value.temporary != 0,
                on_expiry: match value.on_expiry {
                    0 => OnExpiry::Drop,
                    1 => OnExpiry::Keep,
                    _ => return Err(invalid("unknown expiry action")),
                },
                route_offered: value.route_offered != 0,
                gateway: optional_text(value.gateway)
                    .map(|text| parse(&text))
                    .transpose()?,
                gateway6: optional_text(value.gateway6)
                    .map(|text| parse(&text))
                    .transpose()?,
                route_metric: optional(value.route_metric),
                mtu_offered: value.mtu_offered != 0,
                mtu: optional(value.mtu),
                announce_hostname: value.announce_hostname != 0,
                accept_hostname: value.accept_hostname != 0,
            },
            dns: DnsConfig {
                servers: strings(value.dns_servers)
                    .iter()
                    .map(|text| parse(text))
                    .collect::<Result<_, _>>()?,
                domains: strings(value.dns_domains),
                offered: value.dns_offered != 0,
                default_route: optional(value.dns_default_route).map(|value| value != 0),
                exclusive: value.dns_exclusive != 0,
            },
        }
    })
}

pub(crate) unsafe fn judgment(pointer: *const abi::Judgment) -> Result<Judgment, Error> {
    // SAFETY: pointer is either null or a view from the live judgment result.
    let value = unsafe { pointer.as_ref() }.ok_or_else(|| invalid("missing judgment view"))?;
    // SAFETY: the optional profile and rule text are borrowed from the same result.
    Ok(unsafe {
        Judgment {
            outcome: match value.outcome {
                0 => Outcome::Ignore,
                1 => Outcome::Down,
                2 => Outcome::Join(profile(value.profile)?),
                _ => return Err(invalid("unknown policy outcome")),
            },
            rule: text(value.rule),
            backstop: value.backstop != 0,
            conflict: value.conflict != 0,
        }
    })
}
