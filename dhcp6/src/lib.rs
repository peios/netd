//! A stateless DHCPv6 client: the information-request exchange of RFC 8415,
//! clock-injected and socket-free, in the same shape as `dhcp4` and `ndp`.
//!
//! Peios acquires IPv6 *addresses* by SLAAC (the `ndp` crate); what remains
//! for DHCPv6 on most networks is configuration — DNS servers and search
//! domains — announced by a router advertisement's M or O flag. Either flag
//! is answered with an INFORMATION-REQUEST: the stateful exchange is not
//! built (second ring, tracked), and §18.2.6 makes the information request
//! legitimate on a managed network too.
//!
//! The caller feeds it time ([`Client::tick`]) and datagrams
//! ([`Client::receive`]) and performs the [`Action`]s it returns. Every
//! message goes to All_DHCP_Relay_Agents_and_Servers (`ff02::1:2`, port
//! 547) from the interface's link-local address, port 546.

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

const INFORMATION_REQUEST: u8 = 11;
const REPLY: u8 = 7;

const OPTION_CLIENT_ID: u16 = 1;
const OPTION_SERVER_ID: u16 = 2;
const OPTION_ORO: u16 = 6;
const OPTION_ELAPSED_TIME: u16 = 8;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_DOMAIN_LIST: u16 = 24;
const OPTION_INFORMATION_REFRESH_TIME: u16 = 32;

/// Retransmission (RFC 8415 §7.6): INF_TIMEOUT doubling to INF_MAX_RT.
const FIRST_RETRANSMIT: Duration = Duration::from_secs(1);
const MAX_RETRANSMIT: Duration = Duration::from_secs(3600);
/// §21.23: refresh default and floor when the server names none.
const REFRESH_DEFAULT: Duration = Duration::from_secs(86_400);
const REFRESH_MINIMUM: Duration = Duration::from_secs(600);

/// Ceilings against a hostile server.
const MAX_SERVERS: usize = 16;
const MAX_DOMAINS: usize = 16;

/// What the network said, once a valid reply arrives.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Info {
    pub dns: Vec<Ipv6Addr>,
    pub search: Vec<String>,
}

/// What the caller must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this DHCPv6 message to `[ff02::1:2]:547`.
    Send(Vec<u8>),
    /// The information changed; republish DNS.
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The machine's DUID, as the `dhcp4` client also uses (RFC 4361 keeps
    /// the two protocols naming the same machine the same way).
    pub duid: Vec<u8>,
    /// Jitter seed.
    pub seed: u64,
}

pub struct Client {
    config: Config,
    rng: u64,
    txid: [u8; 3],
    /// When the running exchange started (for the elapsed-time option).
    started: Option<Instant>,
    retransmit_at: Option<Instant>,
    retransmit_interval: Duration,
    /// When to ask again after an answer (the refresh-time option).
    refresh_at: Option<Instant>,
    info: Option<Info>,
}

impl Client {
    pub fn new(config: Config) -> Client {
        let rng = config.seed | 1;
        Client {
            config,
            rng,
            txid: [0; 3],
            started: None,
            retransmit_at: None,
            retransmit_interval: FIRST_RETRANSMIT,
            refresh_at: None,
            info: None,
        }
    }

    pub fn start(&mut self, now: Instant) -> Vec<Action> {
        self.begin_exchange(now);
        self.tick(now)
    }

    fn begin_exchange(&mut self, now: Instant) {
        let r = self.next_random();
        self.txid = [(r >> 16) as u8, (r >> 8) as u8, r as u8];
        self.started = Some(now);
        self.retransmit_interval = FIRST_RETRANSMIT;
        self.retransmit_at = Some(now);
        self.refresh_at = None;
    }

    /// The information last obtained, if any.
    pub fn info(&self) -> Option<&Info> {
        self.info.as_ref()
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        match (self.retransmit_at, self.refresh_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.refresh_at.is_some_and(|at| now >= at) {
            self.begin_exchange(now);
        }
        if let Some(at) = self.retransmit_at {
            if now >= at {
                actions.push(Action::Send(self.request(now)));
                let jittered = self.jitter(self.retransmit_interval);
                self.retransmit_interval = (self.retransmit_interval * 2).min(MAX_RETRANSMIT);
                self.retransmit_at = Some(now + jittered);
            }
        }
        actions
    }

    /// Feed one datagram from port 547.
    pub fn receive(&mut self, now: Instant, datagram: &[u8]) -> Vec<Action> {
        // Only while an exchange is running; a late duplicate is noise.
        if self.retransmit_at.is_none() {
            return Vec::new();
        }
        let Some(info) = self.parse_reply(datagram) else {
            return Vec::new();
        };
        self.retransmit_at = None;
        self.started = None;
        let refresh = refresh_time(datagram)
            .unwrap_or(REFRESH_DEFAULT)
            .max(REFRESH_MINIMUM);
        self.refresh_at = Some(now + refresh);
        if self.info.as_ref() == Some(&info) {
            return Vec::new();
        }
        self.info = Some(info);
        vec![Action::Changed]
    }

    fn request(&mut self, now: Instant) -> Vec<u8> {
        let mut out = vec![INFORMATION_REQUEST];
        out.extend_from_slice(&self.txid);
        push_option(&mut out, OPTION_CLIENT_ID, &self.config.duid);
        push_option(
            &mut out,
            OPTION_ELAPSED_TIME,
            &elapsed(self.started, now).to_be_bytes(),
        );
        let mut oro = Vec::new();
        for code in [
            OPTION_DNS_SERVERS,
            OPTION_DOMAIN_LIST,
            OPTION_INFORMATION_REFRESH_TIME,
        ] {
            oro.extend_from_slice(&code.to_be_bytes());
        }
        push_option(&mut out, OPTION_ORO, &oro);
        out
    }

    /// A REPLY for our transaction, echoing our client id, with a server id
    /// (§16.10). Anything else is `None`.
    fn parse_reply(&self, datagram: &[u8]) -> Option<Info> {
        if datagram.len() < 4 || datagram[0] != REPLY || datagram[1..4] != self.txid {
            return None;
        }
        let mut client_id_ours = false;
        let mut server_id = false;
        let mut info = Info::default();
        for (code, data) in options(&datagram[4..]) {
            match code {
                OPTION_CLIENT_ID => {
                    if data != self.config.duid.as_slice() {
                        return None;
                    }
                    client_id_ours = true;
                }
                OPTION_SERVER_ID => server_id = !data.is_empty(),
                OPTION_DNS_SERVERS if data.len() % 16 == 0 => {
                    info.dns = data
                        .chunks_exact(16)
                        .take(MAX_SERVERS)
                        .map(|c| {
                            let mut b = [0u8; 16];
                            b.copy_from_slice(c);
                            Ipv6Addr::from(b)
                        })
                        .filter(|a| !a.is_unspecified() && !a.is_multicast() && !a.is_loopback())
                        .collect();
                }
                OPTION_DOMAIN_LIST => info.search = domain_list(data),
                _ => {}
            }
        }
        (client_id_ours && server_id).then_some(info)
    }

    fn next_random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn jitter(&mut self, interval: Duration) -> Duration {
        let millis = interval.as_millis() as u64;
        Duration::from_millis(millis - millis / 10 + self.next_random() % (millis / 5 + 1))
    }
}

/// §21.9: elapsed time is hundredths of a second, saturating.
fn elapsed(started: Option<Instant>, now: Instant) -> u16 {
    let Some(started) = started else { return 0 };
    (now.saturating_duration_since(started).as_millis() / 10).min(u128::from(u16::MAX)) as u16
}

fn push_option(out: &mut Vec<u8>, code: u16, data: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Walk the options region; a truncated option ends the walk.
fn options(mut bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if bytes.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if bytes.len() < 4 + len {
            return None;
        }
        let data = &bytes[4..4 + len];
        bytes = &bytes[4 + len..];
        Some((code, data))
    })
}

fn refresh_time(datagram: &[u8]) -> Option<Duration> {
    let region = datagram.get(4..)?;
    for (code, data) in options(region) {
        if code == OPTION_INFORMATION_REFRESH_TIME && data.len() == 4 {
            let s = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            return Some(Duration::from_secs(u64::from(s)));
        }
    }
    None
}

/// Uncompressed DNS wire names (§21.24 forbids compression). A malformed
/// name ends the walk; what parsed before it stands.
fn domain_list(mut bytes: &[u8]) -> Vec<String> {
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
        if bytes.iter().all(|&b| b == 0) {
            return out;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            duid: vec![0, 3, 0, 1, 1, 2, 3, 4, 5, 6],
            seed: 99,
        }
    }

    fn reply_for(request: &[u8], extra: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut r = vec![REPLY, request[1], request[2], request[3]];
        push_option(&mut r, OPTION_CLIENT_ID, &config().duid);
        push_option(&mut r, OPTION_SERVER_ID, &[0, 1, 0, 0, 0xab, 0xcd]);
        extra(&mut r);
        r
    }

    fn sent(actions: &[Action]) -> Vec<u8> {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Send(m) => Some(m.clone()),
                _ => None,
            })
            .expect("a message was sent")
    }

    #[test]
    fn the_exchange_yields_dns_and_search() {
        let mut c = Client::new(config());
        let t0 = Instant::now();
        let request = sent(&c.start(t0));
        assert_eq!(request[0], INFORMATION_REQUEST);
        let reply = reply_for(&request, |r| {
            push_option(
                r,
                OPTION_DNS_SERVERS,
                &"fd00::3".parse::<Ipv6Addr>().unwrap().octets(),
            );
            push_option(r, OPTION_DOMAIN_LIST, &[3, b'l', b'a', b'n', 0]);
        });
        let actions = c.receive(t0, &reply);
        assert_eq!(actions, vec![Action::Changed]);
        let info = c.info().unwrap();
        assert_eq!(info.dns, vec!["fd00::3".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(info.search, vec!["lan".to_owned()]);
        // Answered: nothing to retransmit, a refresh a day out.
        let soon = t0 + Duration::from_secs(30);
        assert!(c.tick(soon).is_empty());
        let refresh = c.next_deadline().unwrap();
        assert_eq!(refresh.duration_since(t0), REFRESH_DEFAULT);
        // At refresh time, a new exchange begins.
        let actions = c.tick(refresh);
        assert_eq!(sent(&actions)[0], INFORMATION_REQUEST);
    }

    #[test]
    fn wrong_transaction_wrong_client_and_serverless_replies_are_ignored() {
        let mut c = Client::new(config());
        let t0 = Instant::now();
        let request = sent(&c.start(t0));

        let mut wrong_txid = reply_for(&request, |_| {});
        wrong_txid[1] ^= 0xff;
        assert!(c.receive(t0, &wrong_txid).is_empty());

        let mut foreign = vec![REPLY, request[1], request[2], request[3]];
        push_option(&mut foreign, OPTION_CLIENT_ID, &[9, 9, 9]);
        push_option(&mut foreign, OPTION_SERVER_ID, &[0, 1]);
        assert!(c.receive(t0, &foreign).is_empty());

        let mut serverless = vec![REPLY, request[1], request[2], request[3]];
        push_option(&mut serverless, OPTION_CLIENT_ID, &config().duid);
        assert!(c.receive(t0, &serverless).is_empty());

        // Still unanswered, so the retransmit timer stands.
        assert!(c.next_deadline().is_some());
        assert!(c.info().is_none());
    }

    #[test]
    fn retransmission_backs_off_and_reports_elapsed_time() {
        let mut c = Client::new(config());
        let t0 = Instant::now();
        c.start(t0);
        let mut at = t0;
        let mut intervals = Vec::new();
        for _ in 0..5 {
            let next = c.next_deadline().unwrap();
            intervals.push(next.duration_since(at));
            at = next;
            assert!(!sent(&c.tick(at)).is_empty());
        }
        assert!(intervals[1] < Duration::from_secs(2));
        assert!(intervals[4] > Duration::from_secs(5), "{:?}", intervals);
        // The elapsed-time option grows across the exchange.
        let message = sent(&c.tick(c.next_deadline().unwrap()));
        let (_, elapsed) = options(&message[4..])
            .find(|(code, _)| *code == OPTION_ELAPSED_TIME)
            .unwrap();
        assert!(u16::from_be_bytes([elapsed[0], elapsed[1]]) > 0);
    }

    #[test]
    fn a_refresh_floor_defeats_a_hostile_refresh_time() {
        let mut c = Client::new(config());
        let t0 = Instant::now();
        let request = sent(&c.start(t0));
        let reply = reply_for(&request, |r| {
            push_option(r, OPTION_INFORMATION_REFRESH_TIME, &1u32.to_be_bytes());
        });
        c.receive(t0, &reply);
        let refresh = c.next_deadline().unwrap();
        assert_eq!(refresh.duration_since(t0), REFRESH_MINIMUM);
    }

    #[test]
    fn an_unchanged_answer_is_not_a_change() {
        let mut c = Client::new(config());
        let t0 = Instant::now();
        let request = sent(&c.start(t0));
        let reply = reply_for(&request, |r| {
            push_option(
                r,
                OPTION_DNS_SERVERS,
                &"fd00::3".parse::<Ipv6Addr>().unwrap().octets(),
            );
        });
        assert_eq!(c.receive(t0, &reply), vec![Action::Changed]);
        // The refresh exchange later returns the same facts: no action.
        let refresh = c.next_deadline().unwrap();
        let request = sent(&c.tick(refresh));
        let reply = reply_for(&request, |r| {
            push_option(
                r,
                OPTION_DNS_SERVERS,
                &"fd00::3".parse::<Ipv6Addr>().unwrap().octets(),
            );
        });
        assert!(c.receive(refresh, &reply).is_empty());
    }

    /// Structure-aware random testing on the stable toolchain; the
    /// cargo-fuzz target in `fuzz/` is the real campaign.
    /// `DHCP6_FUZZ_ITERS` raises the count.
    #[test]
    fn fuzz_the_client_never_panics_on_arbitrary_replies() {
        let iters: usize = std::env::var("DHCP6_FUZZ_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20_000);
        let mut x: u64 = 0x6cb5_2026_0831_0001;
        let mut next = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut c = Client::new(config());
        let t0 = Instant::now();
        let mut now = t0;
        let request = sent(&c.start(t0));
        let seed = reply_for(&request, |r| {
            push_option(
                r,
                OPTION_DNS_SERVERS,
                &"fd00::3".parse::<Ipv6Addr>().unwrap().octets(),
            );
            push_option(r, OPTION_DOMAIN_LIST, &[3, b'l', b'a', b'n', 0]);
            push_option(r, OPTION_INFORMATION_REFRESH_TIME, &7200u32.to_be_bytes());
        });
        for _ in 0..iters {
            let mut bytes = if next() % 3 == 0 {
                (0..(next() % 120) as usize)
                    .map(|_| next() as u8)
                    .collect::<Vec<u8>>()
            } else {
                seed.clone()
            };
            for _ in 0..1 + next() % 5 {
                if bytes.is_empty() {
                    break;
                }
                let at = (next() % bytes.len() as u64) as usize;
                match next() % 3 {
                    0 => bytes[at] = next() as u8,
                    1 => bytes.truncate(at),
                    _ => bytes.insert(at, next() as u8),
                }
            }
            c.receive(now, &bytes);
            if next() % 4 == 0 {
                now += Duration::from_secs(next() % 10_000);
                c.tick(now);
            }
            if let Some(info) = c.info() {
                assert!(info.dns.len() <= MAX_SERVERS);
                assert!(info.search.len() <= MAX_DOMAINS);
            }
            // Something is always scheduled: a retransmission while
            // unanswered, a refresh once answered.
            assert!(c.next_deadline().is_some());
        }
    }

    #[test]
    fn malformed_options_never_panic_and_end_cleanly() {
        let mut c = Client::new(config());
        let t0 = Instant::now();
        let request = sent(&c.start(t0));
        // An option whose length runs off the end.
        let mut truncated = vec![REPLY, request[1], request[2], request[3]];
        truncated.extend_from_slice(&[0, 23, 0xff, 0xff, 1, 2, 3]);
        assert!(c.receive(t0, &truncated).is_empty());
        assert!(c.receive(t0, &[]).is_empty());
        assert!(c.receive(t0, &[REPLY]).is_empty());
    }
}
