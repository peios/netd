//! The per-interface SLAAC state machine (RFC 4861/4862), clock-injected
//! and socket-free.
//!
//! The caller feeds it time ([`Engine::tick`]) and router advertisements
//! ([`Engine::receive`]) and performs the [`Action`]s it returns; what the
//! interface should look like is read back with [`Engine::addresses`],
//! [`Engine::default_router`] and the DNS accessors. The engine never
//! decides *whether* IPv6 is wanted — that is the profile's call — only
//! what the routers on the link have said and what follows from it.
//!
//! Addresses are stable-privacy (RFC 7217): a keyed digest of the prefix
//! and the interface's stable identity, so the same box on the same network
//! keeps its address across boots without ever putting a MAC on the wire.
//! Temporary addresses (RFC 8981) are formed alongside them per profile.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use crate::packet::{self, RouterAdvert};

/// Initial solicitation interval (RFC 4861 §10, RTR_SOLICITATION_INTERVAL).
const SOLICIT_INTERVAL: Duration = Duration::from_secs(4);
/// Solicitations at that interval before backing off (MAX_RTR_SOLICITATIONS).
const SOLICITS_BEFORE_BACKOFF: u32 = 3;
/// Backoff ceiling while no router answers (RFC 7559 §2).
const MAX_SOLICIT_INTERVAL: Duration = Duration::from_secs(3600);
/// RFC 4862 §5.5.3(e): an unauthenticated advertisement may not cut a
/// prefix's remaining valid lifetime below two hours.
const TWO_HOURS: Duration = Duration::from_secs(7200);
/// RFC 8981 defaults: how long a temporary address is preferred and valid.
const TEMP_PREFERRED: Duration = Duration::from_secs(86_400);
const TEMP_VALID: Duration = Duration::from_secs(172_800);
/// Live temporary addresses per prefix (the current one plus deprecated
/// survivors kept for existing connections).
const MAX_TEMPS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The interface's stable identity — the netd ifid. RFC 7217's
    /// `Net_Iface` parameter, chosen so a kernel rename changes nothing.
    pub interface: String,
    /// The machine's secret key for stable-privacy addresses.
    pub secret: [u8; 32],
    /// Form temporary addresses too (RFC 8981); the profile's call.
    pub temporary: bool,
    /// The MAC for the solicitation's source link-layer option.
    pub mac: Option<[u8; 6]>,
    /// Seed for solicitation jitter and temporary interface identifiers.
    pub seed: u64,
}

/// What the caller must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this ICMPv6 body to all-routers (`ff02::2`), hop limit 255.
    Solicit(Vec<u8>),
    /// Addresses, routes or DNS changed; reconcile and republish.
    Changed,
}

/// One address the interface should carry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DesiredAddress {
    pub address: Ipv6Addr,
    pub prefix: u8,
    /// Past its preferred lifetime: keep it for existing connections, but
    /// nothing new should choose it (preferred lifetime 0 in the kernel).
    pub deprecated: bool,
    /// The prefix is on-link (L): the kernel may derive a prefix route from
    /// the address. Off-link prefixes must not get one.
    pub on_link: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Temp {
    address: Ipv6Addr,
    preferred_until: Instant,
    valid_until: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Prefix {
    on_link: bool,
    /// `None` is forever (a lifetime of `u32::MAX`).
    valid_until: Option<Instant>,
    preferred_until: Option<Instant>,
    stable: Ipv6Addr,
    temps: Vec<Temp>,
}

/// Everything the caller can observe, in one comparable value; `Changed` is
/// emitted exactly when it differs, so no transition can be missed and no
/// no-op can be reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct View {
    addresses: Vec<DesiredAddress>,
    router: Option<Ipv6Addr>,
    dns: Vec<Ipv6Addr>,
    search: Vec<String>,
    mtu: Option<u32>,
    dhcp6: bool,
}

pub struct Engine {
    config: Config,
    rng: u64,
    solicit_at: Option<Instant>,
    solicit_interval: Duration,
    solicits: u32,
    /// Default routers by link-local source, with when they stop being one.
    routers: BTreeMap<Ipv6Addr, Instant>,
    prefixes: BTreeMap<(Ipv6Addr, u8), Prefix>,
    rdnss: BTreeMap<Ipv6Addr, Option<Instant>>,
    dnssl: BTreeMap<String, Option<Instant>>,
    mtu: Option<u32>,
    /// Latched when any router advertises M or O. Cleared only by restart:
    /// the flag is a property of the link's routers, and a link where DHCPv6
    /// stops being offered is a link that bounced.
    dhcp6_wanted: bool,
    /// What the caller last saw; `Changed` is emitted when the current view
    /// differs. Held rather than recomputed around each call because time
    /// alone changes the view — a deprecation is a transition even though
    /// no packet arrived.
    last_view: View,
}

impl Engine {
    pub fn new(config: Config) -> Engine {
        let rng = config.seed | 1;
        Engine {
            config,
            rng,
            solicit_at: None,
            solicit_interval: SOLICIT_INTERVAL,
            solicits: 0,
            routers: BTreeMap::new(),
            prefixes: BTreeMap::new(),
            rdnss: BTreeMap::new(),
            dnssl: BTreeMap::new(),
            mtu: None,
            dhcp6_wanted: false,
            last_view: View::default(),
        }
    }

    /// Begin soliciting.
    pub fn start(&mut self, now: Instant) -> Vec<Action> {
        self.solicits = 0;
        self.solicit_interval = SOLICIT_INTERVAL;
        self.solicit_at = Some(now);
        self.tick(now)
    }

    /// Feed one advertisement, already known to have arrived from a
    /// link-local source with hop limit 255 (the socket's checks).
    pub fn receive(&mut self, now: Instant, source: Ipv6Addr, body: &[u8]) -> Vec<Action> {
        let Some(ra) = RouterAdvert::decode(body) else {
            return Vec::new();
        };

        if ra.router_lifetime > 0 {
            self.routers.insert(
                source,
                now + Duration::from_secs(u64::from(ra.router_lifetime)),
            );
            // A router answered; stop soliciting until they are all gone.
            self.solicit_at = None;
        } else {
            self.routers.remove(&source);
        }
        if ra.managed || ra.other_config {
            self.dhcp6_wanted = true;
        }
        if let Some(mtu) = ra.mtu {
            self.mtu = Some(mtu);
        }
        for p in &ra.prefixes {
            self.receive_prefix(now, p);
        }
        for r in &ra.rdnss {
            for server in &r.servers {
                match r.lifetime {
                    0 => drop(self.rdnss.remove(server)),
                    l => drop(self.rdnss.insert(*server, until(now, l))),
                }
            }
        }
        for d in &ra.dnssl {
            for domain in &d.domains {
                match d.lifetime {
                    0 => drop(self.dnssl.remove(domain)),
                    l => drop(self.dnssl.insert(domain.clone(), until(now, l))),
                }
            }
        }

        self.expire(now);
        self.emit_if_changed(now, Vec::new())
    }

    fn receive_prefix(&mut self, now: Instant, info: &packet::PrefixInfo) {
        // Only autonomous /64s form addresses (RFC 4862 §5.5.3: the
        // interface identifier is 64 bits, anything else is ignored), and a
        // preferred lifetime beyond the valid one is nonsense.
        if !info.autonomous || info.length != 64 || info.preferred > info.valid {
            return;
        }
        let key = (info.prefix, info.length);
        match self.prefixes.get_mut(&key) {
            Some(p) => {
                p.on_link = info.on_link;
                p.preferred_until = until(now, info.preferred);
                // §5.5.3(e): an unauthenticated RA may extend the valid
                // lifetime freely but may not cut what remains below two
                // hours — else one spoofed packet invalidates the address.
                // Forever stays forever unless the new value is also long.
                let remaining = p.valid_until.map(|t| t.saturating_duration_since(now));
                let received = Duration::from_secs(u64::from(info.valid));
                p.valid_until = match (until(now, info.valid), remaining) {
                    (new, Some(rem)) if received > TWO_HOURS || received > rem => new,
                    (_, Some(rem)) if rem <= TWO_HOURS => Some(now + rem),
                    (_, Some(_)) => Some(now + TWO_HOURS),
                    (new, None) if received > TWO_HOURS => new,
                    (_, None) => None,
                };
            }
            None if info.valid > 0 => {
                let stable = self.stable_address(&info.prefix);
                let mut p = Prefix {
                    on_link: info.on_link,
                    valid_until: until(now, info.valid),
                    preferred_until: until(now, info.preferred),
                    stable,
                    temps: Vec::new(),
                };
                if self.config.temporary && info.preferred > 0 {
                    let temp = self.new_temp(now, &info.prefix, &p);
                    p.temps.push(temp);
                }
                self.prefixes.insert(key, p);
            }
            None => {}
        }
    }

    /// Timers: solicitation, and every lifetime.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        self.expire(now);
        let mut actions = Vec::new();
        if let Some(at) = self.solicit_at
            && now >= at
        {
            self.solicits += 1;
            if self.solicits >= SOLICITS_BEFORE_BACKOFF {
                self.solicit_interval = (self.solicit_interval * 2).min(MAX_SOLICIT_INTERVAL);
            }
            self.solicit_at = Some(now + self.jitter(self.solicit_interval));
            actions.push(Action::Solicit(packet::solicit(self.config.mac.as_ref())));
        }
        self.emit_if_changed(now, actions)
    }

    fn emit_if_changed(&mut self, now: Instant, mut actions: Vec<Action>) -> Vec<Action> {
        let view = self.view(now);
        if view != self.last_view {
            self.last_view = view;
            actions.push(Action::Changed);
        }
        actions
    }

    fn expire(&mut self, now: Instant) {
        self.routers.retain(|_, expires| *expires > now);
        // Routers all gone: go back to soliciting (RFC 7559 keeps a host
        // looking, else a rebooted router is never found).
        if self.routers.is_empty() && self.solicit_at.is_none() {
            self.solicits = 0;
            self.solicit_interval = SOLICIT_INTERVAL;
            self.solicit_at = Some(now);
        }
        self.rdnss.retain(|_, e| e.is_none_or(|e| e > now));
        self.dnssl.retain(|_, e| e.is_none_or(|e| e > now));
        self.prefixes
            .retain(|_, p| p.valid_until.is_none_or(|e| e > now));
        // Temporary addresses: drop the invalid, regenerate when the newest
        // has gone deprecated while the prefix itself is still preferred.
        let mut regenerate = Vec::new();
        for (key, p) in &mut self.prefixes {
            p.temps.retain(|t| t.valid_until > now);
            if p.temps.len() > MAX_TEMPS {
                p.temps.drain(..p.temps.len() - MAX_TEMPS);
            }
            let prefix_preferred = p.preferred_until.is_none_or(|e| e > now);
            let newest_preferred = p.temps.last().is_some_and(|t| t.preferred_until > now);
            if self.config.temporary && prefix_preferred && !newest_preferred {
                regenerate.push(*key);
            }
        }
        for key in regenerate {
            let p = self.prefixes.get(&key).expect("chosen above").clone();
            let temp = self.new_temp(now, &key.0, &p);
            self.prefixes
                .get_mut(&key)
                .expect("chosen above")
                .temps
                .push(temp);
        }
    }

    /// When [`Engine::tick`] next wants calling.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut deadline: Option<Instant> = self.solicit_at;
        let mut consider = |t: Option<Instant>| {
            if let Some(t) = t {
                deadline = Some(deadline.map_or(t, |d| d.min(t)));
            }
        };
        for expires in self.routers.values() {
            consider(Some(*expires));
        }
        for p in self.prefixes.values() {
            consider(p.valid_until);
            consider(p.preferred_until);
            for t in &p.temps {
                consider(Some(t.preferred_until));
                consider(Some(t.valid_until));
            }
        }
        for e in self.rdnss.values().chain(self.dnssl.values()) {
            consider(*e);
        }
        deadline
    }

    /// The addresses the interface should carry right now.
    pub fn addresses(&self, now: Instant) -> Vec<DesiredAddress> {
        self.view(now).addresses
    }

    /// The default router to use, if any: the lowest live link-local, so
    /// the choice is stable while the set is.
    pub fn default_router(&self, now: Instant) -> Option<Ipv6Addr> {
        self.routers
            .iter()
            .find(|(_, e)| **e > now)
            .map(|(a, _)| *a)
    }

    /// Whether the routers have said configuration is to be had over DHCPv6
    /// (M or O); the caller runs the information-request client.
    pub fn wants_dhcp6(&self) -> bool {
        self.dhcp6_wanted
    }

    pub fn dns_servers(&self, now: Instant) -> Vec<Ipv6Addr> {
        self.rdnss
            .iter()
            .filter(|(_, e)| e.is_none_or(|e| e > now))
            .map(|(a, _)| *a)
            .collect()
    }

    pub fn search_domains(&self, now: Instant) -> Vec<String> {
        self.dnssl
            .iter()
            .filter(|(_, e)| e.is_none_or(|e| e > now))
            .map(|(d, _)| d.clone())
            .collect()
    }

    /// The link MTU the routers advertised, if any.
    pub fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    fn view(&self, now: Instant) -> View {
        let mut addresses = Vec::new();
        for ((_, length), p) in &self.prefixes {
            if p.valid_until.is_some_and(|e| e <= now) {
                continue;
            }
            let prefix_deprecated = p.preferred_until.is_some_and(|e| e <= now);
            addresses.push(DesiredAddress {
                address: p.stable,
                prefix: *length,
                deprecated: prefix_deprecated,
                on_link: p.on_link,
            });
            for t in &p.temps {
                let valid = match p.valid_until {
                    Some(pe) => t.valid_until.min(pe) > now,
                    None => t.valid_until > now,
                };
                if !valid {
                    continue;
                }
                addresses.push(DesiredAddress {
                    address: t.address,
                    prefix: *length,
                    deprecated: prefix_deprecated || t.preferred_until <= now,
                    on_link: p.on_link,
                });
            }
        }
        addresses.sort();
        View {
            addresses,
            router: self.default_router(now),
            dns: self.dns_servers(now),
            search: self.search_domains(now),
            mtu: self.mtu,
            dhcp6: self.dhcp6_wanted,
        }
    }

    /// RFC 7217: a keyed digest of prefix, interface identity and a
    /// duplication counter. Same box, same network, same address, every
    /// boot — and nothing derivable without the secret.
    fn stable_address(&self, prefix: &Ipv6Addr) -> Ipv6Addr {
        use sha1::{Digest, Sha1};
        for counter in 0u8..8 {
            let mut h = Sha1::new();
            h.update(b"peios-ndp-stable-iid|");
            h.update(self.config.secret);
            h.update(&prefix.octets()[..8]);
            h.update(self.config.interface.as_bytes());
            h.update([counter]);
            let digest = h.finalize();
            let mut iid = [0u8; 8];
            iid.copy_from_slice(&digest[..8]);
            if !reserved_iid(&iid) {
                return join(prefix, &iid);
            }
        }
        // Eight keyed digests all landing in the reserved ranges does not
        // happen; if it somehow does, the all-but-last-bit-set fallback is
        // valid and still per-machine unique enough for a /64 we own.
        join(prefix, &[0, 0, 0, 0, 0, 0, 0, 1])
    }

    fn new_temp(&mut self, now: Instant, prefix: &Ipv6Addr, p: &Prefix) -> Temp {
        let iid = loop {
            let mut iid = [0u8; 8];
            iid[..4].copy_from_slice(&(self.next_random() as u32).to_be_bytes());
            iid[4..].copy_from_slice(&(self.next_random() as u32).to_be_bytes());
            let address = join(prefix, &iid);
            let taken = address == p.stable || p.temps.iter().any(|t| t.address == address);
            if !reserved_iid(&iid) && !taken {
                break iid;
            }
        };
        // Desynchronise regeneration across machines (RFC 8981 §3.8).
        let desync = Duration::from_secs(self.next_random() % 600);
        let preferred = TEMP_PREFERRED - desync;
        let clamp = |cap: Duration, limit: Option<Instant>| match limit {
            Some(l) => (now + cap).min(l),
            None => now + cap,
        };
        Temp {
            address: join(prefix, &iid),
            preferred_until: clamp(preferred, p.preferred_until),
            valid_until: clamp(TEMP_VALID, p.valid_until),
        }
    }

    fn next_random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn jitter(&mut self, interval: Duration) -> Duration {
        // ±10%, so a rack of machines does not solicit in step.
        let millis = interval.as_millis() as u64;
        Duration::from_millis(millis - millis / 10 + self.next_random() % (millis / 5 + 1))
    }
}

fn until(now: Instant, lifetime_seconds: u32) -> Option<Instant> {
    match lifetime_seconds {
        u32::MAX => None,
        s => Some(now + Duration::from_secs(u64::from(s))),
    }
}

fn join(prefix: &Ipv6Addr, iid: &[u8; 8]) -> Ipv6Addr {
    let mut b = prefix.octets();
    b[8..].copy_from_slice(iid);
    Ipv6Addr::from(b)
}

/// RFC 5453: interface identifiers that must not be autoconfigured — the
/// subnet-router anycast (all zero), the ISATAP/proxy range
/// `0200:5EFF:FE00::/40`, and the reserved anycast block
/// `FDFF:FFFF:FFFF:FF80` to `FDFF:FFFF:FFFF:FFFF`.
fn reserved_iid(iid: &[u8; 8]) -> bool {
    iid.iter().all(|&b| b == 0)
        || iid[..4] == [0x02, 0x00, 0x5e, 0xff]
        || (iid[..7] == [0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] && iid[7] >= 0x80)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            interface: "8ecde363-0000-5000-8000-000000000001".into(),
            secret: [7u8; 32],
            temporary: false,
            mac: Some([0x52, 0x54, 0, 1, 2, 3]),
            seed: 42,
        }
    }

    fn advert(prefix: &str, valid: u32, preferred: u32, router_lifetime: u16) -> Vec<u8> {
        let mut b = vec![
            packet::ROUTER_ADVERT,
            0,
            0,
            0,
            64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        b[6..8].copy_from_slice(&router_lifetime.to_be_bytes());
        b.extend_from_slice(&[3, 4, 64, 0xc0]);
        b.extend_from_slice(&valid.to_be_bytes());
        b.extend_from_slice(&preferred.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&prefix.parse::<Ipv6Addr>().unwrap().octets());
        b
    }

    fn router() -> Ipv6Addr {
        "fe80::2".parse().unwrap()
    }

    #[test]
    fn an_advertisement_yields_a_stable_address_and_a_router() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        let actions = e.start(t0);
        assert!(matches!(actions[0], Action::Solicit(_)));
        let actions = e.receive(t0, router(), &advert("fd00::", 86400, 14400, 1800));
        assert_eq!(actions, vec![Action::Changed]);
        let addresses = e.addresses(t0);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].prefix, 64);
        assert!(!addresses[0].deprecated);
        assert!(addresses[0].on_link);
        assert_eq!(addresses[0].address.segments()[0], 0xfd00);
        assert_eq!(e.default_router(t0), Some(router()));
        // The same advertisement again changes nothing.
        assert_eq!(
            e.receive(t0, router(), &advert("fd00::", 86400, 14400, 1800)),
            vec![]
        );
        // And the address is a pure function of prefix + identity + secret.
        let mut e2 = Engine::new(config());
        e2.receive(t0, router(), &advert("fd00::", 86400, 14400, 1800));
        assert_eq!(e2.addresses(t0), e.addresses(t0));
        // A different machine (secret) gets a different address.
        let mut e3 = Engine::new(Config {
            secret: [8u8; 32],
            ..config()
        });
        e3.receive(t0, router(), &advert("fd00::", 86400, 14400, 1800));
        assert_ne!(e3.addresses(t0)[0].address, e.addresses(t0)[0].address);
    }

    #[test]
    fn lifetimes_deprecate_and_then_remove_the_address() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        e.receive(t0, router(), &advert("fd00::", 9000, 600, 1800));
        let after_preferred = t0 + Duration::from_secs(601);
        let actions = e.tick(after_preferred);
        assert!(
            actions.contains(&Action::Changed),
            "deprecation is a change"
        );
        assert!(e.addresses(after_preferred)[0].deprecated);
        let after_valid = t0 + Duration::from_secs(9001);
        let actions = e.tick(after_valid);
        assert!(actions.contains(&Action::Changed));
        assert!(e.addresses(after_valid).is_empty());
    }

    #[test]
    fn a_spoofed_short_lifetime_cannot_kill_the_address() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        e.receive(t0, router(), &advert("fd00::", 86400, 14400, 1800));
        // An attacker's RA with valid=1: remaining is above two hours, so
        // it is clamped to two hours, not one second.
        e.receive(t0, router(), &advert("fd00::", 1, 0, 1800));
        let soon = t0 + Duration::from_secs(2);
        assert_eq!(e.addresses(soon).len(), 1, "the address survives");
        let within_two_hours = t0 + Duration::from_secs(7100);
        assert_eq!(e.addresses(within_two_hours).len(), 1);
        let after_two_hours = t0 + Duration::from_secs(7300);
        e.tick(after_two_hours);
        assert!(e.addresses(after_two_hours).is_empty());
    }

    #[test]
    fn a_zero_router_lifetime_withdraws_the_default_route_only() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        e.receive(t0, router(), &advert("fd00::", 86400, 14400, 1800));
        let actions = e.receive(t0, router(), &advert("fd00::", 86400, 14400, 0));
        assert!(actions.contains(&Action::Changed));
        assert_eq!(e.default_router(t0), None);
        assert_eq!(e.addresses(t0).len(), 1, "the prefix outlives its router");
    }

    #[test]
    fn an_expired_router_restarts_solicitation() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        e.start(t0);
        e.receive(t0, router(), &advert("fd00::", 86400, 14400, 10));
        assert!(e.next_deadline().is_some());
        let later = t0 + Duration::from_secs(11);
        let actions = e.tick(later);
        assert!(actions.contains(&Action::Changed), "the route went");
        // The next tick at its own deadline solicits again.
        let actions = e.tick(e.next_deadline().unwrap());
        assert!(actions.iter().any(|a| matches!(a, Action::Solicit(_))));
    }

    #[test]
    fn temporary_addresses_come_and_go_beside_the_stable_one() {
        let mut e = Engine::new(Config {
            temporary: true,
            ..config()
        });
        let t0 = Instant::now();
        e.receive(t0, router(), &advert("fd00::", u32::MAX, u32::MAX, 1800));
        let addresses = e.addresses(t0);
        assert_eq!(addresses.len(), 2);
        let stable = Engine::new(config()).stable_address(&"fd00::".parse().unwrap());
        let temp = addresses
            .iter()
            .find(|a| a.address != stable)
            .unwrap()
            .clone();
        assert!(!temp.deprecated);
        // A day later the temp is deprecated and a fresh one exists; the
        // old one survives for standing connections.
        let next_day = t0 + TEMP_PREFERRED;
        e.tick(next_day);
        let addresses = e.addresses(next_day);
        assert_eq!(addresses.len(), 3);
        assert!(
            addresses
                .iter()
                .any(|a| a.address == temp.address && a.deprecated)
        );
        assert!(
            addresses
                .iter()
                .any(|a| a.address != stable && a.address != temp.address && !a.deprecated)
        );
        // Two days on, the first temp's valid lifetime is done.
        let later = t0 + TEMP_VALID + Duration::from_secs(1);
        e.tick(later);
        assert!(e.addresses(later).iter().all(|a| a.address != temp.address));
    }

    #[test]
    fn dns_and_search_arrive_and_expire() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        let mut b = advert("fd00::", 86400, 14400, 1800);
        b.extend_from_slice(&[25, 3, 0, 0]);
        b.extend_from_slice(&1200u32.to_be_bytes());
        b.extend_from_slice(&"fd00::3".parse::<Ipv6Addr>().unwrap().octets());
        b.extend_from_slice(&[31, 2, 0, 0]);
        b.extend_from_slice(&1200u32.to_be_bytes());
        b.extend_from_slice(&[3, b'l', b'a', b'n', 0, 0, 0, 0]);
        let actions = e.receive(t0, router(), &b);
        assert!(actions.contains(&Action::Changed));
        assert_eq!(
            e.dns_servers(t0),
            vec!["fd00::3".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(e.search_domains(t0), vec!["lan".to_owned()]);
        let later = t0 + Duration::from_secs(1201);
        let actions = e.tick(later);
        assert!(actions.contains(&Action::Changed));
        assert!(e.dns_servers(later).is_empty());
        assert!(e.search_domains(later).is_empty());
    }

    #[test]
    fn the_managed_flag_wants_dhcp6() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        assert!(!e.wants_dhcp6());
        let mut b = advert("fd00::", 86400, 14400, 1800);
        b[5] = 0x40; // O
        let actions = e.receive(t0, router(), &b);
        assert!(e.wants_dhcp6());
        assert!(actions.contains(&Action::Changed));
    }

    #[test]
    fn solicitation_backs_off_while_nobody_answers() {
        let mut e = Engine::new(config());
        let t0 = Instant::now();
        let actions = e.start(t0);
        assert!(actions.iter().any(|a| matches!(a, Action::Solicit(_))));
        let mut at = t0;
        let mut intervals = Vec::new();
        for _ in 0..6 {
            let next = e.next_deadline().unwrap();
            intervals.push(next.duration_since(at));
            at = next;
            let actions = e.tick(at);
            assert!(actions.iter().any(|a| matches!(a, Action::Solicit(_))));
        }
        // Early solicitations sit near four seconds; later ones back off.
        assert!(intervals[0] < Duration::from_secs(6));
        assert!(intervals[5] > Duration::from_secs(20));
        assert!(intervals.last().unwrap() <= &Duration::from_secs(3960));
    }

    #[test]
    fn reserved_interface_identifiers_are_refused() {
        assert!(reserved_iid(&[0; 8]));
        assert!(reserved_iid(&[0x02, 0x00, 0x5e, 0xff, 0xfe, 0, 0, 1]));
        assert!(reserved_iid(&[
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80
        ]));
        assert!(!reserved_iid(&[
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        ]));
        assert!(!reserved_iid(&[0, 0, 0, 0, 0, 0, 0, 1]));
    }
}
