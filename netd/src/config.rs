//! What the registry says the network should be.
//!
//! Read whole on start and on every watch event. Absent keys mean documented
//! defaults; a malformed value is logged and its default used, never a
//! crash — a typo in one profile must not take the network down.

use std::net::Ipv4Addr;

use libnetd::NETWORK_KEY;
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};

use crate::log;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Match {
    pub name: Option<String>,
    pub mac: Option<String>,
    pub path: Option<String>,
    pub driver: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnLeaseExpiry {
    Drop,
    Keep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAddress {
    pub address: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressConfig {
    pub dhcp4: bool,
    pub statics: Vec<StaticAddress>,
    pub gateway: Option<Ipv4Addr>,
    pub link_local: bool,
    pub on_lease_expiry: OnLeaseExpiry,
    pub route_metric: Option<u32>,
    pub mtu: Option<u32>,
    /// Announce a hostname in DHCP (option 12) and accept one back.
    pub send_hostname: bool,
    pub accept_hostname: bool,
}

impl Default for AddressConfig {
    fn default() -> Self {
        AddressConfig {
            dhcp4: true,
            statics: Vec::new(),
            gateway: None,
            link_local: true,
            on_lease_expiry: OnLeaseExpiry::Drop,
            route_metric: None,
            mtu: None,
            send_hostname: true,
            accept_hostname: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsConfig {
    pub servers: Vec<Ipv4Addr>,
    pub search: Vec<String>,
    pub use_from_dhcp: bool,
    /// `DNSDefaultRoute`: unset means "when the interface has a default
    /// route"; set, it says so outright either way.
    pub default_route: Option<bool>,
    /// `DNSExclusive`: while up, no other interface's servers are consulted.
    pub exclusive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub priority: u32,
    pub managed: bool,
    pub matches: Match,
    pub address: AddressConfig,
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub hostname: Option<String>,
    pub profiles: Vec<Profile>,
    /// `ControlSecurity`, raw self-relative SD, if set.
    pub control_security: Option<Vec<u8>>,
}

fn sz(v: &RegValue) -> Option<String> {
    if v.ty != ValueType::SZ && v.ty != ValueType::EXPAND_SZ {
        return None;
    }
    let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
    String::from_utf8(v.data[..end].to_vec()).ok()
}

fn multi(v: &RegValue) -> Option<Vec<String>> {
    match v.ty {
        ValueType::MULTI_SZ => Some(
            v.data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                .collect(),
        ),
        // Be kind: a single SZ where a list was expected is a one-item list.
        ValueType::SZ => sz(v).map(|s| vec![s]),
        _ => None,
    }
}

fn dword(v: &RegValue) -> Option<u32> {
    (v.ty == ValueType::DWORD && v.data.len() == 4)
        .then(|| u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]))
}

fn read(key: &Key, name: &str) -> Option<RegValue> {
    key.query_value(name.as_bytes(), None).ok()
}

fn read_sz(key: &Key, name: &str) -> Option<String> {
    read(key, name).and_then(|v| sz(&v)).filter(|s| !s.is_empty())
}

fn read_multi(key: &Key, name: &str) -> Vec<String> {
    read(key, name).and_then(|v| multi(&v)).unwrap_or_default()
}

fn read_bool(key: &Key, name: &str, default: bool) -> bool {
    match read(key, name) {
        None => default,
        Some(v) => match (dword(&v), sz(&v)) {
            (Some(d), _) => d != 0,
            (None, Some(s)) => match s.to_ascii_lowercase().as_str() {
                "on" | "yes" | "true" | "1" => true,
                "off" | "no" | "false" | "0" => false,
                _ => default,
            },
            _ => default,
        },
    }
}

fn read_u32(key: &Key, name: &str) -> Option<u32> {
    read(key, name).and_then(|v| dword(&v).or_else(|| sz(&v).and_then(|s| s.parse().ok())))
}

fn open(parent: Option<&Key>, path: &str) -> Option<Key> {
    Key::open(parent, path, KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS, OpenFlags::empty())
        .ok()
}

pub fn parse_cidr(s: &str) -> Option<StaticAddress> {
    let (a, p) = s.split_once('/')?;
    Some(StaticAddress { address: a.trim().parse().ok()?, prefix: p.trim().parse().ok().filter(|p| *p <= 32)? })
}

fn parse_profile(name: &str, key: &Key) -> Profile {
    let matches = match open(Some(key), "Match") {
        Some(m) => Match {
            name: read_sz(&m, "Name"),
            mac: read_sz(&m, "MAC").map(|s| s.to_ascii_lowercase()),
            path: read_sz(&m, "Path"),
            driver: read_sz(&m, "Driver"),
            kind: read_sz(&m, "Type").map(|s| s.to_ascii_lowercase()),
        },
        None => Match::default(),
    };
    let mut address = AddressConfig::default();
    if let Some(a) = open(Some(key), "Address") {
        address.dhcp4 = read_bool(&a, "DHCP4", true);
        address.statics = read_multi(&a, "Static")
            .iter()
            .filter_map(|s| {
                let r = parse_cidr(s);
                if r.is_none() {
                    log::warn(format_args!("profile {name}: ignoring malformed Static address {s:?}"));
                }
                r
            })
            .collect();
        address.gateway = read_sz(&a, "Gateway").and_then(|s| s.parse().ok());
        address.link_local = read_bool(&a, "LinkLocal", true);
        address.on_lease_expiry = match read_sz(&a, "OnLeaseExpiry").as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("keep") => OnLeaseExpiry::Keep,
            _ => OnLeaseExpiry::Drop,
        };
        address.route_metric = read_u32(&a, "RouteMetric");
        address.mtu = read_u32(&a, "MTU");
        address.send_hostname = read_bool(&a, "SendHostname", true);
        address.accept_hostname = read_bool(&a, "AcceptHostname", false);
    }
    let mut dns = DnsConfig { use_from_dhcp: true, ..Default::default() };
    if let Some(d) = open(Some(key), "DNS") {
        dns.servers = read_multi(&d, "Servers").iter().filter_map(|s| s.parse().ok()).collect();
        dns.search = read_multi(&d, "SearchDomains");
        dns.use_from_dhcp = read_bool(&d, "UseFromDHCP", true);
        dns.default_route = read_u32(&d, "DNSDefaultRoute").map(|v| v != 0);
        dns.exclusive = read_bool(&d, "DNSExclusive", false);
    }
    Profile {
        name: name.to_owned(),
        priority: read_u32(key, "Priority").unwrap_or(100),
        managed: read_bool(key, "Managed", true),
        matches,
        address,
        dns,
    }
}

/// Read the whole configuration. A missing root means "no configuration":
/// netd runs with defaults and nothing matches.
pub fn load() -> Config {
    let mut config = Config::default();
    let Some(root) = open(None, NETWORK_KEY) else {
        log::warn(format_args!("{NETWORK_KEY} does not exist; running with no profiles"));
        return config;
    };
    config.hostname = read_sz(&root, "Hostname");
    config.control_security = read(&root, "ControlSecurity")
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);
    if let Some(profiles) = open(Some(&root), "Profiles") {
        for subkey in profiles.subkeys(None) {
            let Ok(subkey) = subkey else { continue };
            let Ok(name) = String::from_utf8(subkey.name.clone()) else { continue };
            if let Some(key) = open(Some(&profiles), &name) {
                config.profiles.push(parse_profile(&name, &key));
            }
        }
    }
    // Highest priority first; ties by name so the order is stable.
    config.profiles.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.name.cmp(&b.name)));
    config
}

/// Open the root with notify rights and arm a subtree watch.
pub fn watch() -> peios::Result<Key> {
    use peios::registry::NotifyFilter;
    let key = Key::open(None, NETWORK_KEY, KeyAccess::NOTIFY, OpenFlags::empty())?;
    key.notify(NotifyFilter::ALL, true)?;
    key.set_nonblocking(true)?;
    Ok(key)
}
