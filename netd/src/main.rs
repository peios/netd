//! netd — the Peios network manager.
//!
//! One thread, one `poll`. Inputs: rtnetlink multicast, the registry watch,
//! the control socket, one packet socket per DHCP interface, and time. On
//! any of them the loop re-derives what the network should be and reconciles
//! the kernel to it; nothing is done imperatively in a handler.

mod config;
mod control;
mod dhcp;
mod inventory;
mod log;
mod matching;
mod model;
mod netlink;
mod reconcile;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::io::Write;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::process::ExitCode;
use std::time::Instant;

use dhcp4::{Action, Client, Config as DhcpConfig, Lease};
use libnetd::{DnsScope, InterfaceStatus, LeaseStatus, Level, Reply, Request, Snapshot, Status};
use peios::registry::Key;

use config::{Config, OnLeaseExpiry, Profile};
use model::{Identity, Link, LinkKind, Observed};
use netlink::{LinuxRtnl, Rtnl};
use reconcile::Desired;

/// One managed (or at least seen) interface.
struct Interface {
    ifid: String,
    identity: Identity,
    link: Link,
    profile: Option<Profile>,
    enabled: bool,
    dhcp: Option<Dhcp>,
    lease: Option<Lease>,
    /// Set once discovery has gone unanswered; cleared on a lease.
    link_local: Option<Ipv4Addr>,
}

struct Dhcp {
    client: Client,
    socket: dhcp::PacketSocket,
}

impl Interface {
    fn managed(&self) -> bool {
        self.profile.as_ref().is_some_and(|p| p.managed) && !self.link.loopback
    }

    fn metric(&self) -> u32 {
        self.profile
            .as_ref()
            .and_then(|p| p.address.route_metric)
            .unwrap_or(match self.link.kind {
                LinkKind::Wireless => 600,
                _ => 100,
            })
    }

    fn desired(&self) -> Option<Desired> {
        let profile = self.profile.as_ref()?;
        if !self.managed() {
            return None;
        }
        let mut d = Desired { index: self.link.index, ..Default::default() };
        if !self.enabled {
            return Some(d);
        }
        d.up = true;
        d.mtu = profile.address.mtu.or(self.lease.as_ref().and_then(|l| l.mtu.map(u32::from)));
        let metric = self.metric();
        for s in &profile.address.statics {
            d.addresses.push((s.address, s.prefix));
        }
        if let Some(lease) = &self.lease {
            d.addresses.push((lease.address, lease.prefix));
            d.broadcast = lease.broadcast;
            for r in &lease.static_routes {
                if r.prefix > 0 {
                    d.routes.push((r.destination, r.prefix, r.gateway, metric));
                }
            }
        }
        if let Some(ll) = self.link_local {
            if self.lease.is_none() && profile.address.statics.is_empty() {
                d.addresses.push((ll, 16));
            }
        }
        let gateway = profile.address.gateway.or_else(|| self.lease.as_ref().and_then(Lease::gateway));
        if let Some(g) = gateway {
            d.default_route = Some((g, metric));
        }
        Some(d)
    }

    fn level(&self, observed: &Observed) -> Level {
        if !(self.link.up && self.link.carrier) {
            return Level::Absent;
        }
        let addressed = observed.addresses_of(self.link.index).any(|a| !a.address.is_loopback());
        if !addressed {
            return Level::Link;
        }
        let routed = observed.routes_of(self.link.index).any(|r| r.is_default());
        if routed { Level::Routed } else { Level::Addressed }
    }

    fn dns(&self) -> DnsFacts {
        let mut facts = DnsFacts::default();
        if let Some(p) = &self.profile {
            facts.servers.extend(p.dns.servers.iter().copied());
            facts.search.extend(p.dns.search.iter().cloned());
            if p.dns.use_from_dhcp {
                if let Some(l) = &self.lease {
                    facts.servers.extend(l.dns.iter().copied());
                    if !l.search.is_empty() {
                        facts.search.extend(l.search.iter().cloned());
                    } else if let Some(d) = &l.domain {
                        facts.search.push(d.clone());
                    }
                }
            }
        }
        facts
    }
}

/// What an interface contributes to name resolution, before routing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DnsFacts {
    servers: Vec<Ipv4Addr>,
    search: Vec<String>,
}

struct Netd {
    config: Config,
    control: control::ControlObject,
    rtnl: LinuxRtnl,
    observed: Observed,
    interfaces: BTreeMap<u32, Interface>,
    duid: Option<Vec<u8>>,
    hostname_set: Option<String>,
    /// `subscribe` connections, each owed a snapshot whenever it changes.
    subscribers: Vec<UnixStream>,
    last_snapshot: Option<Snapshot>,
}

impl Netd {
    fn link_local_for(mac: Option<&[u8; 6]>, index: u32) -> Ipv4Addr {
        // RFC 3927 §2.1 allows a stable pseudo-random choice seeded by the
        // MAC. No probing yet (PEI-518).
        let seed = mac.map(|m| u32::from_be_bytes([m[2], m[3], m[4], m[5]])).unwrap_or(index * 2654435761);
        let host = 256 + (seed % (65024 - 256)); // 169.254.1.0 .. 169.254.254.255
        Ipv4Addr::new(169, 254, (host >> 8) as u8, host as u8)
    }

    /// Bring the interface table in line with the kernel's link list.
    fn sync_links(&mut self, now: Instant) {
        let seen: Vec<u32> = self.observed.links.keys().copied().collect();
        self.interfaces.retain(|index, _| seen.contains(index));
        for link in self.observed.links.values() {
            let entry = self.interfaces.entry(link.index);
            let interface = entry.or_insert_with(|| {
                let identity = model::read_identity(&link.name);
                let ifid = model::interface_id(&identity, link.mac.as_ref(), &link.name);
                log::info(format_args!("interface {} ({}) is {ifid}", link.name, identity.path));
                Interface {
                    ifid,
                    identity,
                    link: link.clone(),
                    profile: None,
                    enabled: true,
                    dhcp: None,
                    lease: None,
                    link_local: None,
                }
            });
            let had_carrier = interface.link.carrier && interface.link.up;
            interface.link = link.clone();
            let profile = matching::select(&self.config.profiles, link, &interface.identity).cloned();
            if profile != interface.profile {
                log::info(format_args!(
                    "interface {}: profile {}",
                    link.name,
                    profile.as_ref().map(|p| p.name.as_str()).unwrap_or("(none)")
                ));
                // Different intent — a different profile, or the same one
                // edited — so start over rather than trust the old lease.
                interface.stop_dhcp(now);
            }
            interface.profile = profile;
            if !link.loopback {
                interface.enabled = inventory::sync(&inventory::Record {
                    ifid: &interface.ifid,
                    link,
                    identity: &interface.identity,
                    profile: interface.profile.as_ref().map(|p| p.name.as_str()),
                });
            }
            let has_carrier = link.carrier && link.up;
            if had_carrier && !has_carrier {
                log::info(format_args!("interface {}: carrier lost", link.name));
                interface.stop_dhcp(now);
            }
        }
    }

    fn start_dhcp_where_due(&mut self, now: Instant) {
        let hostname = self.config.hostname.clone();
        for interface in self.interfaces.values_mut() {
            let Some((dhcp4, send_hostname)) =
                interface.profile.as_ref().map(|p| (p.address.dhcp4, p.address.send_hostname))
            else {
                continue;
            };
            let wants = interface.managed() && interface.enabled && dhcp4;
            let can = interface.link.up && interface.link.carrier;
            if interface.dhcp.is_some() && !(wants && can) {
                log::info(format_args!("interface {}: dhcp stopping", interface.link.name));
                interface.stop_dhcp(now);
            }
            if wants && can && interface.dhcp.is_none() {
                let Some(mac) = interface.link.mac else { continue };
                let duid = self.duid.get_or_insert_with(|| dhcp::duid(&mac)).clone();
                let socket = match dhcp::PacketSocket::open(interface.link.index, &interface.link.name) {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn(format_args!("interface {}: no packet socket: {e}", interface.link.name));
                        continue;
                    }
                };
                let mut seed = [0u8; 8];
                if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                    use std::io::Read;
                    let _ = f.read_exact(&mut seed);
                }
                let mut client = Client::new(DhcpConfig {
                    chaddr: mac,
                    client_id: dhcp::client_id(&duid, &interface.ifid),
                    hostname: if send_hostname { hostname.clone() } else { None },
                    seed: u64::from_le_bytes(seed) ^ u64::from(interface.link.index),
                });
                let previous = dhcp::remembered(&interface.ifid);
                let actions = client.start(now, previous);
                log::info(format_args!("interface {}: dhcp starting", interface.link.name));
                interface.dhcp = Some(Dhcp { client, socket });
                interface.lease = None;
                interface.perform(actions, now);
            }
        }
    }

    fn reconcile_all(&mut self) {
        for interface in self.interfaces.values() {
            if let Some(desired) = interface.desired() {
                let ops = reconcile::plan(&self.observed, &desired);
                if !ops.is_empty() {
                    log::info(format_args!("interface {}: applying {ops:?}", interface.link.name));
                    reconcile::apply(&mut self.rtnl, &ops);
                }
            }
        }
        // Re-read so levels and the status reply reflect what landed.
        match self.rtnl.dump() {
            Ok(o) => self.observed = o,
            Err(e) => log::warn(format_args!("netlink dump failed: {e}")),
        }
    }

    fn apply_hostname(&mut self) {
        let from_lease = self.interfaces.values().find_map(|i| {
            let accept = i.profile.as_ref().is_some_and(|p| p.address.accept_hostname);
            accept.then(|| i.lease.as_ref().and_then(|l| l.hostname.clone())).flatten()
        });
        let Some(name) = self.config.hostname.clone().or(from_lease) else { return };
        if self.hostname_set.as_deref() == Some(name.as_str()) {
            return;
        }
        // SAFETY: the buffer is live for the call and the length is its own.
        let rc = unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) };
        if rc < 0 {
            log::warn(format_args!("sethostname({name}): {}", std::io::Error::last_os_error()));
        } else {
            log::info(format_args!("hostname is {name}"));
            self.hostname_set = Some(name);
        }
    }

    /// The DNS picture for resolvd: every managed interface with a link,
    /// in metric order.
    fn snapshot(&self) -> Snapshot {
        let mut ordered: Vec<&Interface> = self.interfaces.values().filter(|i| i.managed()).collect();
        ordered.sort_by_key(|i| (i.metric(), i.link.index));
        let mut scopes = Vec::new();
        for i in ordered {
            let level = i.level(&self.observed);
            if level == Level::Absent {
                continue;
            }
            let facts = i.dns();
            let dns = i.profile.as_ref().map(|p| &p.dns);
            scopes.push(DnsScope {
                ifid: i.ifid.clone(),
                name: i.link.name.clone(),
                servers: facts.servers.iter().map(|s| s.to_string()).collect(),
                domains: facts.search,
                addresses: self.observed.addresses_of(i.link.index).map(|a| format!("{}/{}", a.address, a.prefix)).collect(),
                default_route: dns.and_then(|d| d.default_route).unwrap_or(level == Level::Routed),
                exclusive: dns.is_some_and(|d| d.exclusive),
                metric: i.metric(),
                level,
            });
        }
        Snapshot { hostname: self.hostname_set.clone().unwrap_or_default(), scopes }
    }

    /// Send the snapshot to every subscriber if it changed. A subscriber
    /// that cannot take it (closed, or so far behind its buffer is full) is
    /// dropped; it reconnects and gets a fresh one.
    fn publish(&mut self) {
        let snapshot = self.snapshot();
        if self.last_snapshot.as_ref() == Some(&snapshot) {
            return;
        }
        let bytes = Reply::Snapshot(snapshot.clone()).encode();
        self.last_snapshot = Some(snapshot);
        self.subscribers.retain_mut(|s| send_nonblocking(s, &bytes));
    }

    /// The full pass: links, DHCP starts, reconcile, hostname, publish.
    ///
    /// Repeated until a pass leaves the kernel unchanged, because applying
    /// changes what the next decisions see: bringing a link up gives it
    /// carrier, and carrier is what starts DHCP. One pass would leave that
    /// for a later event that, on a virtual NIC, has already happened.
    fn converge(&mut self, now: Instant) {
        for _ in 0..4 {
            self.sync_links(now);
            self.start_dhcp_where_due(now);
            let before = self.observed.clone();
            self.reconcile_all();
            if self.observed == before {
                break;
            }
        }
        self.apply_hostname();
        self.publish();
    }

    fn status(&self) -> Status {
        let now = Instant::now();
        let mut interfaces = Vec::new();
        let mut level = Level::Absent;
        for i in self.interfaces.values() {
            if i.link.loopback {
                continue;
            }
            let l = i.level(&self.observed);
            if i.managed() {
                level = level.max(l);
            }
            let dns = i.dns();
            interfaces.push(InterfaceStatus {
                ifid: i.ifid.clone(),
                name: i.link.name.clone(),
                index: i.link.index,
                mac: i.link.mac.as_ref().map(model::format_mac).unwrap_or_default(),
                path: i.identity.path.clone(),
                driver: i.identity.driver.clone(),
                profile: i.profile.as_ref().map(|p| p.name.clone()),
                managed: i.managed(),
                enabled: i.enabled,
                up: i.link.up,
                carrier: i.link.carrier,
                level: l,
                addresses: self.observed.addresses_of(i.link.index).map(|a| format!("{}/{}", a.address, a.prefix)).collect(),
                gateway: self.observed.routes_of(i.link.index).find(|r| r.is_default()).and_then(|r| r.gateway).map(|g| g.to_string()),
                dns: dns.servers.iter().map(|s| s.to_string()).collect(),
                search: dns.search,
                lease: i.dhcp.as_ref().and_then(|d| {
                    d.client.lease().map(|l| LeaseStatus {
                        server: l.server.to_string(),
                        expires_in: d.client.expires_in(now).unwrap_or(0),
                        state: d.client.state().as_str().to_owned(),
                    })
                }),
            });
        }
        Status { hostname: self.hostname_set.clone().unwrap_or_default(), level, interfaces }
    }

    fn handle_control(&mut self, listener: &UnixListener) {
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(e) => {
                    log::warn(format_args!("control: accept: {e}"));
                    return;
                }
            };
            let Some(request) = control::read_request(&mut stream) else { continue };
            if !self.control.permits(&stream, request.required_right()) {
                control::respond(&mut stream, &Reply::Error("access denied".into()));
                continue;
            }
            let now = Instant::now();
            let reply = match request {
                Request::Status => Reply::Status(self.status()),
                Request::Subscribe => {
                    let snapshot = self.last_snapshot.clone().unwrap_or_else(|| self.snapshot());
                    let bytes = Reply::Snapshot(snapshot).encode();
                    if stream.set_nonblocking(true).is_ok() && send_nonblocking(&mut stream, &bytes) {
                        self.subscribers.push(stream);
                    }
                    continue;
                }
                Request::Reconcile => {
                    self.converge(now);
                    Reply::Ok
                }
                Request::Renew { interface } => {
                    match self.interfaces.values_mut().find(|i| i.link.name == interface || i.ifid == interface) {
                        None => Reply::Error(format!("no interface {interface}")),
                        Some(i) if i.dhcp.is_none() => Reply::Error(format!("{interface} is not using DHCP")),
                        Some(i) => {
                            let actions = i.dhcp.as_mut().map(|d| d.client.renew_now(now)).unwrap_or_default();
                            i.perform(actions, now);
                            Reply::Ok
                        }
                    }
                }
            };
            control::respond(&mut stream, &reply);
        }
    }
}

impl Interface {
    fn stop_dhcp(&mut self, now: Instant) {
        if let Some(mut d) = self.dhcp.take() {
            let actions = d.client.release(now);
            for a in actions {
                if let Action::Send { message, destination } = a {
                    let _ = d.socket.send(&message, destination);
                }
            }
        }
        self.lease = None;
        self.link_local = None;
    }

    /// Carry out the state machine's actions. Returns whether the network
    /// changed in a way that needs a reconcile.
    fn perform(&mut self, actions: Vec<Action>, _now: Instant) -> bool {
        let mut changed = false;
        for action in actions {
            match action {
                Action::Send { message, destination } => {
                    if let Some(d) = &self.dhcp {
                        if let Err(e) = d.socket.send(&message, destination) {
                            log::warn(format_args!("interface {}: dhcp send: {e}", self.link.name));
                        }
                    }
                }
                Action::Bound(lease) => {
                    log::info(format_args!(
                        "interface {}: lease {}/{} from {} for {}s",
                        self.link.name, lease.address, lease.prefix, lease.server, lease.lease_time
                    ));
                    dhcp::remember(&self.ifid, &lease);
                    self.lease = Some(lease);
                    self.link_local = None;
                    changed = true;
                }
                Action::NoOffer => {
                    let wants_ll = self.profile.as_ref().is_some_and(|p| p.address.link_local);
                    if wants_ll && self.link_local.is_none() {
                        let ll = Netd::link_local_for(self.link.mac.as_ref(), self.link.index);
                        log::info(format_args!("interface {}: no DHCP offer; link-local {ll}", self.link.name));
                        self.link_local = Some(ll);
                        changed = true;
                    }
                }
                Action::Lost => {
                    let keep = self.profile.as_ref().is_some_and(|p| p.address.on_lease_expiry == OnLeaseExpiry::Keep);
                    if keep {
                        log::warn(format_args!("interface {}: lease lost; keeping the address (OnLeaseExpiry=Keep)", self.link.name));
                    } else {
                        log::info(format_args!("interface {}: lease lost", self.link.name));
                        self.lease = None;
                        dhcp::forget(&self.ifid);
                        changed = true;
                    }
                }
            }
        }
        changed
    }
}

/// Write one framed message to a nonblocking stream, whole or not at all.
/// A subscriber reads a few hundred bytes a few times an hour; a full
/// socket buffer means it is gone, not slow.
fn send_nonblocking(stream: &mut UnixStream, payload: &[u8]) -> bool {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).is_ok()
}

fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let Ok(socket) = UnixDatagram::unbound() else {
        log::warn(format_args!("could not create the readiness socket"));
        return;
    };
    if let Err(e) = socket.send_to(b"READY=1", &path) {
        log::warn(format_args!("could not notify readiness: {e}"));
    }
}

fn main() -> ExitCode {
    let rtnl = match LinuxRtnl::open() {
        Ok(r) => r,
        Err(e) => {
            log::error(format_args!("rtnetlink: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let listener = match control::listen() {
        Ok(l) => l,
        Err(e) => {
            log::error(format_args!("control socket: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let absorber = match dhcp::Absorber::open() {
        Ok(a) => Some(a),
        Err(e) => {
            log::warn(format_args!("could not bind udp/68 ({e}); servers may see port-unreachable"));
            None
        }
    };
    let config = config::load();
    let mut watch: Option<Key> = match config::watch() {
        Ok(k) => Some(k),
        Err(e) => {
            log::warn(format_args!("registry watch unavailable ({e}); configuration is read once"));
            None
        }
    };
    let control = control::ControlObject::new(config.control_security.as_deref());
    let mut netd = Netd {
        config,
        control,
        rtnl,
        observed: Observed::default(),
        interfaces: BTreeMap::new(),
        duid: None,
        hostname_set: None,
        subscribers: Vec::new(),
        last_snapshot: None,
    };
    match netd.rtnl.dump() {
        Ok(o) => netd.observed = o,
        Err(e) => {
            log::error(format_args!("netlink dump: {e}"));
            return ExitCode::FAILURE;
        }
    }
    log::info(format_args!(
        "{} profile(s), {} link(s)",
        netd.config.profiles.len(),
        netd.observed.links.len()
    ));
    netd.converge(Instant::now());
    notify_ready();

    let mut watch_buffer = vec![0u8; 16384];
    loop {
        let now = Instant::now();
        // Timers.
        let mut deadline: Option<Instant> = None;
        for i in netd.interfaces.values() {
            if let Some(d) = &i.dhcp {
                if let Some(t) = d.client.next_deadline() {
                    deadline = Some(deadline.map_or(t, |x: Instant| x.min(t)));
                }
            }
        }
        let timeout_ms: i32 = match deadline {
            Some(t) => t.saturating_duration_since(now).as_millis().min(i32::MAX as u128) as i32,
            None => -1,
        };

        // Poll set: [rtnl, control, watch?, absorber?, dhcp sockets...]
        let mut fds: Vec<libc::pollfd> = Vec::new();
        fn push(fds: &mut Vec<libc::pollfd>, fd: i32) -> usize {
            fds.push(libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
            fds.len() - 1
        }
        push(&mut fds, netd.rtnl.as_raw_fd());
        push(&mut fds, listener.as_raw_fd());
        let watch_slot = watch.as_ref().map(|w| push(&mut fds, w.as_raw_fd()));
        let absorber_slot = absorber.as_ref().map(|a| push(&mut fds, a.fd().as_raw_fd()));
        let dhcp_fds: Vec<(u32, i32)> = netd
            .interfaces
            .iter()
            .filter_map(|(index, i)| i.dhcp.as_ref().map(|d| (*index, d.socket.fd().as_raw_fd())))
            .collect();
        let dhcp_slots: Vec<(u32, usize)> =
            dhcp_fds.into_iter().map(|(index, fd)| (index, push(&mut fds, fd))).collect();

        // SAFETY: `fds` is a live, exclusively borrowed array for the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::error(format_args!("poll: {e}"));
            return ExitCode::FAILURE;
        }
        let now = Instant::now();
        let mut converge = false;
        let mut reconcile = false;

        if fds[0].revents != 0 && netd.rtnl.drain_events() {
            // Always converge: the state may already have been dumped after
            // an apply without the decisions that follow from it being made.
            match netd.rtnl.dump() {
                Ok(o) => {
                    netd.observed = o;
                    converge = true;
                }
                Err(e) => log::warn(format_args!("netlink dump: {e}")),
            }
        }
        if let Some(slot) = watch_slot {
            if fds[slot].revents != 0 {
                if let Some(w) = &watch {
                    match w.read_watch_events(&mut watch_buffer) {
                        Ok(events) if !events.is_empty() => {
                            // Our own inventory writes come back here too; a
                            // reload is idempotent, so that is merely cheap.
                            // Converge regardless: `Interfaces\<ifid> Enabled`
                            // is read during the pass, not held in Config.
                            let fresh = config::load();
                            if fresh != netd.config {
                                log::info(format_args!("configuration changed"));
                                netd.control = control::ControlObject::new(fresh.control_security.as_deref());
                                netd.config = fresh;
                            }
                            converge = true;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::warn(format_args!("registry watch: {e}; re-arming"));
                            watch = config::watch().ok();
                        }
                    }
                }
            }
        }
        if let Some(slot) = absorber_slot {
            if fds[slot].revents != 0 {
                if let Some(a) = &absorber {
                    a.drain();
                }
            }
        }
        for (index, slot) in &dhcp_slots {
            if fds[*slot].revents == 0 {
                continue;
            }
            if let Some(i) = netd.interfaces.get_mut(index) {
                let messages = i.dhcp.as_ref().map(|d| d.socket.receive()).unwrap_or_default();
                for m in messages {
                    let actions = i.dhcp.as_mut().map(|d| d.client.receive(now, &m)).unwrap_or_default();
                    reconcile |= i.perform(actions, now);
                }
            }
        }
        // Timers, for every client.
        for i in netd.interfaces.values_mut() {
            let actions = i.dhcp.as_mut().map(|d| d.client.tick(now)).unwrap_or_default();
            reconcile |= i.perform(actions, now);
        }
        if fds[1].revents != 0 {
            netd.handle_control(&listener);
        }

        if converge {
            netd.converge(now);
        } else if reconcile {
            netd.reconcile_all();
            netd.apply_hostname();
            netd.publish();
        }
    }
}
