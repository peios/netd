//! The RFC 2131 client state machine, clock-injected and socket-free.
//!
//! The caller feeds it time ([`Client::tick`]) and packets
//! ([`Client::receive`]) and performs the [`Action`]s it returns. Timers are
//! absolute [`Instant`]s the caller polls with [`Client::next_deadline`].
//!
//! Transitions (RFC 2131 §4.4, figure 5):
//!
//! ```text
//! Init ──discover──▶ Selecting ──offer──▶ Requesting ──ack──▶ Bound
//!   ▲                    │ no offer            │ nak            │ T1
//!   │                    ▼                     ▼                ▼
//!   │              (link-local, keep       Init            Renewing ──ack──▶ Bound
//!   │               discovering)                              │ T2
//!   │                                                          ▼
//!   └──────────────── expiry ◀──────────────────────────── Rebinding ──ack──▶ Bound
//!
//! InitReboot ──request(known addr)──▶ Rebooting ──ack──▶ Bound / ──nak──▶ Init
//! ```

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::packet::{Lease, Message, MessageType, option};

/// Where to send a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// Layer-2 broadcast, from 0.0.0.0. The client has no address yet (or is
    /// rebinding and may not trust the old server).
    Broadcast,
    /// Unicast to the server from our bound address. Only in Renewing.
    Unicast { server: Ipv4Addr, from: Ipv4Addr },
}

/// What the caller must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send {
        message: Message,
        destination: Destination,
    },
    /// A lease was obtained or renewed; configure the interface.
    Bound(Lease),
    /// Discovery has gone unanswered for a while. Emitted once per Init
    /// cycle; the client keeps discovering.
    NoOffer,
    /// The lease is gone (expired, or NAKed). Unconfigure the interface.
    Lost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub chaddr: [u8; 6],
    /// Option 61. RFC 4361 form: `0xff` + IAID + DUID.
    pub client_id: Vec<u8>,
    /// Option 12, if the profile wants to announce one.
    pub hostname: Option<String>,
    /// Seed for the retransmission jitter and the XID.
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Init,
    Selecting,
    Requesting,
    Rebooting,
    Bound,
    Renewing,
    Rebinding,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Init => "init",
            State::Selecting => "selecting",
            State::Requesting => "requesting",
            State::Rebooting => "rebooting",
            State::Bound => "bound",
            State::Renewing => "renewing",
            State::Rebinding => "rebinding",
        }
    }
}

/// Discovers before `NoOffer` is reported.
const DISCOVERS_BEFORE_NO_OFFER: u32 = 3;
/// Requests before giving up on an offer.
const MAX_REQUESTS: u32 = 4;
/// Backoff ceiling, RFC 2131 §4.1.
const MAX_BACKOFF: Duration = Duration::from_secs(64);
const FIRST_BACKOFF: Duration = Duration::from_secs(4);
/// Minimum retransmit interval while renewing/rebinding, §4.4.5.
const MIN_RETRANSMIT: Duration = Duration::from_secs(60);

pub struct Client {
    config: Config,
    state: State,
    rng: u64,
    xid: u32,
    started: Instant,
    /// Next retransmission (Selecting/Requesting/Rebooting/Renewing/Rebinding).
    retransmit_at: Option<Instant>,
    backoff: Duration,
    attempts: u32,
    no_offer_reported: bool,
    offer: Option<Message>,
    lease: Option<Lease>,
    /// When the current lease was obtained.
    bound_at: Option<Instant>,
    /// A previously held address to try INIT-REBOOT with.
    reboot_address: Option<Ipv4Addr>,
}

impl Client {
    pub fn new(config: Config) -> Client {
        let rng = config.seed | 1;
        Client {
            config,
            state: State::Init,
            rng,
            xid: 0,
            started: Instant::now(),
            retransmit_at: None,
            backoff: FIRST_BACKOFF,
            attempts: 0,
            no_offer_reported: false,
            offer: None,
            lease: None,
            bound_at: None,
            reboot_address: None,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// Seconds until the lease expires, if bound.
    pub fn expires_in(&self, now: Instant) -> Option<u64> {
        let lease = self.lease.as_ref()?;
        let bound_at = self.bound_at?;
        let expiry = bound_at + Duration::from_secs(u64::from(lease.lease_time));
        Some(expiry.saturating_duration_since(now).as_secs())
    }

    /// Begin. With a remembered address, try INIT-REBOOT first (RFC 2131
    /// §3.2): one round trip if the server still agrees, and the machine
    /// keeps the address it had.
    pub fn start(&mut self, now: Instant, previous: Option<Ipv4Addr>) -> Vec<Action> {
        self.started = now;
        self.lease = None;
        self.bound_at = None;
        self.offer = None;
        self.no_offer_reported = false;
        match previous {
            Some(address) => {
                self.reboot_address = Some(address);
                self.enter_rebooting(now)
            }
            None => self.enter_selecting(now),
        }
    }

    /// Give the address back and stop. The caller unconfigures.
    pub fn release(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if let (Some(lease), State::Bound | State::Renewing | State::Rebinding) =
            (self.lease.clone(), &self.state)
        {
            let mut m = self.base_message(now);
            m.ciaddr = lease.address;
            m.options
                .push(option::MESSAGE_TYPE, [MessageType::Release as u8]);
            m.options.push(option::SERVER_ID, lease.server.octets());
            m.options
                .push(option::CLIENT_ID, self.config.client_id.clone());
            actions.push(Action::Send {
                message: m,
                destination: Destination::Unicast {
                    server: lease.server,
                    from: lease.address,
                },
            });
        }
        self.state = State::Init;
        self.lease = None;
        self.bound_at = None;
        self.retransmit_at = None;
        actions
    }

    /// Force a renewal now (operator request).
    pub fn renew_now(&mut self, now: Instant) -> Vec<Action> {
        match self.state {
            State::Bound | State::Renewing | State::Rebinding => self.enter_renewing(now),
            _ => Vec::new(),
        }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        let mut next = self.retransmit_at;
        if let (Some(lease), Some(bound_at)) = (&self.lease, self.bound_at) {
            let secs = |s: u32| bound_at + Duration::from_secs(u64::from(s));
            let boundary = match self.state {
                State::Bound => Some(secs(lease.t1)),
                State::Renewing => Some(secs(lease.t2)),
                State::Rebinding => Some(secs(lease.lease_time)),
                _ => None,
            };
            next = match (next, boundary) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        next
    }

    /// The clock moved. Fire whatever is due.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        // Lease-time boundaries first: they change state.
        if let (Some(lease), Some(bound_at)) = (self.lease.clone(), self.bound_at) {
            let at = |s: u32| bound_at + Duration::from_secs(u64::from(s));
            match self.state {
                State::Bound if now >= at(lease.t1) => {
                    actions.extend(self.enter_renewing(now));
                }
                State::Renewing if now >= at(lease.t2) => {
                    actions.extend(self.enter_rebinding(now));
                }
                State::Rebinding if now >= at(lease.lease_time) => {
                    self.lease = None;
                    self.bound_at = None;
                    actions.push(Action::Lost);
                    actions.extend(self.enter_selecting(now));
                    return actions;
                }
                _ => {}
            }
        }
        if let Some(at) = self.retransmit_at
            && now >= at
        {
            actions.extend(self.retransmit(now));
        }
        actions
    }

    /// A packet arrived on the interface. Anything not for us is ignored.
    pub fn receive(&mut self, now: Instant, message: &Message) -> Vec<Action> {
        if !message.is_reply || message.xid != self.xid || message.chaddr != self.config.chaddr {
            return Vec::new();
        }
        let Some(kind) = message.message_type() else {
            return Vec::new();
        };
        // Once a server has been chosen, an ACK or NAK must come from it.
        // A stranger who guessed the xid still cannot take the lease away.
        if matches!(kind, MessageType::Ack | MessageType::Nak) {
            let chosen = self.lease.as_ref().map(|l| l.server).or_else(|| {
                self.offer
                    .as_ref()
                    .and_then(|o| o.options.ipv4(option::SERVER_ID))
            });
            if let Some(chosen) = chosen
                && message.options.ipv4(option::SERVER_ID) != Some(chosen)
            {
                return Vec::new();
            }
        }
        match (&self.state, kind) {
            (State::Selecting, MessageType::Offer) => {
                if message.yiaddr.is_unspecified()
                    || message.options.ipv4(option::SERVER_ID).is_none()
                {
                    return Vec::new();
                }
                self.offer = Some(message.clone());
                self.enter_requesting(now)
            }
            (
                State::Requesting | State::Rebooting | State::Renewing | State::Rebinding,
                MessageType::Ack,
            ) => match Lease::from_ack(message) {
                Some(lease) => {
                    self.state = State::Bound;
                    self.retransmit_at = None;
                    self.bound_at = Some(now);
                    self.lease = Some(lease.clone());
                    self.reboot_address = Some(lease.address);
                    vec![Action::Bound(lease)]
                }
                None => Vec::new(),
            },
            (State::Requesting | State::Rebooting, MessageType::Nak) => {
                self.reboot_address = None;
                self.offer = None;
                self.enter_selecting(now)
            }
            (State::Renewing | State::Rebinding, MessageType::Nak) => {
                self.lease = None;
                self.bound_at = None;
                self.reboot_address = None;
                let mut actions = vec![Action::Lost];
                actions.extend(self.enter_selecting(now));
                actions
            }
            _ => Vec::new(),
        }
    }

    // ---- transitions -------------------------------------------------------

    fn enter_selecting(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Selecting;
        self.xid = self.next_random();
        self.attempts = 0;
        self.backoff = FIRST_BACKOFF;
        self.offer = None;
        self.send_discover(now)
    }

    fn enter_requesting(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Requesting;
        self.attempts = 0;
        self.backoff = FIRST_BACKOFF;
        self.send_request_for_offer(now)
    }

    fn enter_rebooting(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Rebooting;
        self.xid = self.next_random();
        self.attempts = 0;
        self.backoff = FIRST_BACKOFF;
        self.send_reboot_request(now)
    }

    fn enter_renewing(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Renewing;
        self.xid = self.next_random();
        self.attempts = 0;
        self.send_renewal(now)
    }

    fn enter_rebinding(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Rebinding;
        self.xid = self.next_random();
        self.attempts = 0;
        self.send_renewal(now)
    }

    fn retransmit(&mut self, now: Instant) -> Vec<Action> {
        match self.state {
            State::Selecting => {
                self.attempts += 1;
                let mut actions = Vec::new();
                if self.attempts >= DISCOVERS_BEFORE_NO_OFFER && !self.no_offer_reported {
                    self.no_offer_reported = true;
                    actions.push(Action::NoOffer);
                }
                actions.extend(self.send_discover(now));
                actions
            }
            State::Requesting => {
                self.attempts += 1;
                if self.attempts >= MAX_REQUESTS {
                    // The offer went stale; start over.
                    self.enter_selecting(now)
                } else {
                    self.send_request_for_offer(now)
                }
            }
            State::Rebooting => {
                self.attempts += 1;
                if self.attempts >= 2 {
                    // Nobody confirmed the old address; discover afresh.
                    self.reboot_address = None;
                    self.enter_selecting(now)
                } else {
                    self.send_reboot_request(now)
                }
            }
            State::Renewing | State::Rebinding => self.send_renewal(now),
            _ => Vec::new(),
        }
    }

    // ---- messages ----------------------------------------------------------

    fn base_message(&self, now: Instant) -> Message {
        let mut m = Message::request(self.xid, self.config.chaddr);
        m.secs = now
            .saturating_duration_since(self.started)
            .as_secs()
            .min(65535) as u16;
        m
    }

    fn parameter_request_list() -> Vec<u8> {
        vec![
            option::SUBNET_MASK,
            option::ROUTER,
            option::DNS,
            option::HOSTNAME,
            option::DOMAIN_NAME,
            option::MTU,
            option::BROADCAST,
            option::NTP,
            option::LEASE_TIME,
            option::RENEWAL_T1,
            option::REBINDING_T2,
            option::DOMAIN_SEARCH,
            option::CLASSLESS_STATIC_ROUTE,
        ]
    }

    fn common_options(&self, m: &mut Message, kind: MessageType) {
        m.options.push(option::MESSAGE_TYPE, [kind as u8]);
        m.options
            .push(option::CLIENT_ID, self.config.client_id.clone());
        m.options
            .push(option::MAX_MESSAGE_SIZE, 1500u16.to_be_bytes());
        m.options.push(
            option::PARAMETER_REQUEST_LIST,
            Self::parameter_request_list(),
        );
        if let Some(h) = &self.config.hostname {
            m.options.push(option::HOSTNAME, h.as_bytes().to_vec());
        }
    }

    fn schedule_backoff(&mut self, now: Instant) {
        // ±1 s jitter, then double, capped (RFC 2131 §4.1).
        let jitter = Duration::from_millis(self.next_random() as u64 % 2000);
        self.retransmit_at = Some(now + self.backoff + jitter - Duration::from_secs(1));
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    fn send_discover(&mut self, now: Instant) -> Vec<Action> {
        let mut m = self.base_message(now);
        m.broadcast = true;
        self.common_options(&mut m, MessageType::Discover);
        if let Some(a) = self.reboot_address {
            m.options.push(option::REQUESTED_IP, a.octets());
        }
        self.schedule_backoff(now);
        vec![Action::Send {
            message: m,
            destination: Destination::Broadcast,
        }]
    }

    fn send_request_for_offer(&mut self, now: Instant) -> Vec<Action> {
        let Some(offer) = self.offer.clone() else {
            return self.enter_selecting(now);
        };
        let mut m = self.base_message(now);
        m.broadcast = true;
        self.common_options(&mut m, MessageType::Request);
        m.options.push(option::REQUESTED_IP, offer.yiaddr.octets());
        if let Some(server) = offer.options.get(option::SERVER_ID) {
            m.options.push(option::SERVER_ID, server.to_vec());
        }
        self.schedule_backoff(now);
        vec![Action::Send {
            message: m,
            destination: Destination::Broadcast,
        }]
    }

    fn send_reboot_request(&mut self, now: Instant) -> Vec<Action> {
        let Some(address) = self.reboot_address else {
            return self.enter_selecting(now);
        };
        let mut m = self.base_message(now);
        m.broadcast = true;
        self.common_options(&mut m, MessageType::Request);
        m.options.push(option::REQUESTED_IP, address.octets());
        self.schedule_backoff(now);
        vec![Action::Send {
            message: m,
            destination: Destination::Broadcast,
        }]
    }

    fn send_renewal(&mut self, now: Instant) -> Vec<Action> {
        let Some(lease) = self.lease.clone() else {
            return Vec::new();
        };
        let Some(bound_at) = self.bound_at else {
            return Vec::new();
        };
        let mut m = self.base_message(now);
        m.ciaddr = lease.address;
        self.common_options(&mut m, MessageType::Request);
        let destination = match self.state {
            State::Renewing => Destination::Unicast {
                server: lease.server,
                from: lease.address,
            },
            _ => Destination::Broadcast,
        };
        // §4.4.5: retransmit at half the remaining time to the next boundary,
        // never more often than every 60 s.
        let boundary = match self.state {
            State::Renewing => lease.t2,
            _ => lease.lease_time,
        };
        let remaining =
            (bound_at + Duration::from_secs(u64::from(boundary))).saturating_duration_since(now);
        self.retransmit_at = Some(now + (remaining / 2).max(MIN_RETRANSMIT));
        vec![Action::Send {
            message: m,
            destination,
        }]
    }

    fn next_random(&mut self) -> u32 {
        // xorshift64*; the jitter and XID need unpredictability, not
        // cryptography.
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

    fn client() -> Client {
        Client::new(Config {
            chaddr: MAC,
            client_id: vec![
                0xff, 0, 0, 0, 1, 0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56,
            ],
            hostname: Some("box".into()),
            seed: 42,
        })
    }

    fn sent(actions: &[Action]) -> Vec<(&Message, Destination)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send {
                    message,
                    destination,
                } => Some((message, *destination)),
                _ => None,
            })
            .collect()
    }

    fn reply(to: &Message, kind: MessageType, address: Ipv4Addr, lease_time: u32) -> Message {
        let mut m = Message::request(to.xid, MAC);
        m.is_reply = true;
        m.yiaddr = address;
        m.options.push(option::MESSAGE_TYPE, [kind as u8]);
        m.options
            .push(option::SERVER_ID, Ipv4Addr::new(10, 0, 2, 2).octets());
        m.options.push(option::LEASE_TIME, lease_time.to_be_bytes());
        m.options.push(option::SUBNET_MASK, [255, 255, 255, 0]);
        m.options.push(option::ROUTER, [10, 0, 2, 2]);
        m
    }

    #[test]
    fn the_happy_path_binds() {
        let mut c = client();
        let t0 = Instant::now();
        let a = c.start(t0, None);
        let s = sent(&a);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].0.message_type(), Some(MessageType::Discover));
        assert_eq!(s[0].1, Destination::Broadcast);
        assert_eq!(*c.state(), State::Selecting);

        let offer = reply(
            s[0].0,
            MessageType::Offer,
            Ipv4Addr::new(10, 0, 2, 15),
            3600,
        );
        let a = c.receive(t0, &offer);
        let s = sent(&a);
        assert_eq!(s[0].0.message_type(), Some(MessageType::Request));
        assert_eq!(
            s[0].0.options.ipv4(option::REQUESTED_IP),
            Some(Ipv4Addr::new(10, 0, 2, 15))
        );
        assert_eq!(*c.state(), State::Requesting);

        let ack = reply(s[0].0, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), 3600);
        let a = c.receive(t0, &ack);
        assert!(matches!(a[0], Action::Bound(_)));
        assert_eq!(*c.state(), State::Bound);
        assert_eq!(c.expires_in(t0), Some(3600));
        // T1 at 1800 s.
        assert_eq!(c.next_deadline(), Some(t0 + Duration::from_secs(1800)));
    }

    #[test]
    fn a_reply_with_the_wrong_xid_is_ignored() {
        let mut c = client();
        let t0 = Instant::now();
        let a = c.start(t0, None);
        let mut offer = reply(
            sent(&a)[0].0,
            MessageType::Offer,
            Ipv4Addr::new(10, 0, 2, 15),
            3600,
        );
        offer.xid ^= 1;
        assert!(c.receive(t0, &offer).is_empty());
        assert_eq!(*c.state(), State::Selecting);
    }

    #[test]
    fn silence_backs_off_and_reports_no_offer_once() {
        let mut c = client();
        let mut now = Instant::now();
        c.start(now, None);
        let mut no_offers = 0;
        let mut gaps = Vec::new();
        for _ in 0..6 {
            let deadline = c.next_deadline().unwrap();
            gaps.push(deadline.saturating_duration_since(now));
            now = deadline;
            let a = c.tick(now);
            no_offers += a.iter().filter(|a| matches!(a, Action::NoOffer)).count();
            assert_eq!(sent(&a).len(), 1);
        }
        assert_eq!(no_offers, 1);
        // Roughly 4, 8, 16, 32, 64, 64 with ±1 s jitter.
        assert!(gaps[0] >= Duration::from_secs(3) && gaps[0] <= Duration::from_secs(5));
        assert!(gaps[4] >= Duration::from_secs(63) && gaps[5] <= Duration::from_secs(65));
    }

    fn bind(c: &mut Client, t0: Instant, lease_time: u32) {
        let a = c.start(t0, None);
        let offer = reply(
            sent(&a)[0].0,
            MessageType::Offer,
            Ipv4Addr::new(10, 0, 2, 15),
            lease_time,
        );
        let a = c.receive(t0, &offer);
        let ack = reply(
            sent(&a)[0].0,
            MessageType::Ack,
            Ipv4Addr::new(10, 0, 2, 15),
            lease_time,
        );
        c.receive(t0, &ack);
        assert_eq!(*c.state(), State::Bound);
    }

    #[test]
    fn t1_renews_by_unicast_t2_rebinds_by_broadcast_and_expiry_loses() {
        let mut c = client();
        let t0 = Instant::now();
        bind(&mut c, t0, 1000);

        let a = c.tick(t0 + Duration::from_secs(500));
        let s = sent(&a);
        assert_eq!(*c.state(), State::Renewing);
        assert!(matches!(s[0].1, Destination::Unicast { .. }));
        assert_eq!(s[0].0.ciaddr, Ipv4Addr::new(10, 0, 2, 15));

        let a = c.tick(t0 + Duration::from_secs(875));
        assert_eq!(*c.state(), State::Rebinding);
        assert_eq!(sent(&a)[0].1, Destination::Broadcast);

        let a = c.tick(t0 + Duration::from_secs(1000));
        assert!(matches!(a[0], Action::Lost));
        assert_eq!(*c.state(), State::Selecting);
        assert!(c.lease().is_none());
    }

    #[test]
    fn a_renewal_ack_rebinds_the_clock() {
        let mut c = client();
        let t0 = Instant::now();
        bind(&mut c, t0, 1000);
        let t1 = t0 + Duration::from_secs(500);
        let a = c.tick(t1);
        let ack = reply(
            sent(&a)[0].0,
            MessageType::Ack,
            Ipv4Addr::new(10, 0, 2, 15),
            1000,
        );
        let a = c.receive(t1, &ack);
        assert!(matches!(a[0], Action::Bound(_)));
        assert_eq!(c.expires_in(t1), Some(1000));
        assert_eq!(c.next_deadline(), Some(t1 + Duration::from_secs(500)));
    }

    #[test]
    fn a_nak_while_renewing_loses_and_rediscovers() {
        let mut c = client();
        let t0 = Instant::now();
        bind(&mut c, t0, 1000);
        let t1 = t0 + Duration::from_secs(500);
        let a = c.tick(t1);
        let nak = reply(sent(&a)[0].0, MessageType::Nak, Ipv4Addr::UNSPECIFIED, 0);
        let a = c.receive(t1, &nak);
        assert!(matches!(a[0], Action::Lost));
        assert_eq!(sent(&a)[0].0.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn init_reboot_asks_for_the_old_address_and_falls_back_to_discover() {
        let mut c = client();
        let t0 = Instant::now();
        let a = c.start(t0, Some(Ipv4Addr::new(10, 0, 2, 15)));
        let s = sent(&a);
        assert_eq!(*c.state(), State::Rebooting);
        assert_eq!(s[0].0.message_type(), Some(MessageType::Request));
        assert!(s[0].0.options.get(option::SERVER_ID).is_none());
        assert_eq!(
            s[0].0.options.ipv4(option::REQUESTED_IP),
            Some(Ipv4Addr::new(10, 0, 2, 15))
        );
        // Confirmed straight to Bound.
        let ack = reply(s[0].0, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), 600);
        let a = c.receive(t0, &ack);
        assert!(matches!(a[0], Action::Bound(_)));

        // And when nobody answers, two tries then discover.
        let mut c = client();
        let mut now = t0;
        c.start(now, Some(Ipv4Addr::new(10, 0, 2, 15)));
        now = c.next_deadline().unwrap();
        c.tick(now);
        assert_eq!(*c.state(), State::Rebooting);
        now = c.next_deadline().unwrap();
        let a = c.tick(now);
        assert_eq!(*c.state(), State::Selecting);
        assert_eq!(sent(&a)[0].0.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn release_sends_a_release_from_the_bound_address() {
        let mut c = client();
        let t0 = Instant::now();
        bind(&mut c, t0, 1000);
        let a = c.release(t0);
        let s = sent(&a);
        assert_eq!(s[0].0.message_type(), Some(MessageType::Release));
        assert_eq!(s[0].0.ciaddr, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(*c.state(), State::Init);
        assert!(c.next_deadline().is_none());
    }
}
