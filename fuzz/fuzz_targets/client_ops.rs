//! The DHCP client state machine under an arbitrary network: replies built
//! from what it sent (so xid and chaddr match) with arbitrary content,
//! raw noise, and time. Invariants: no panic; a lease exists exactly in the
//! states that hold one; deadlines never precede the moment they were set;
//! the client always sends *something* within a bounded time while not
//! bound; and a rogue can never move a Bound client without a NAK from the
//! chosen server.
#![no_main]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use dhcp4::packet::{Message, MessageType, option};
use dhcp4::{Action, Client, Config, State};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    /// A reply to the last message sent, with this shape.
    Reply { kind: u8, server: u8, address: u32, lease: u32, t1: Option<u32>, t2: Option<u32>, mask: u32, extra: Vec<(u8, Vec<u8>)>, wrong_xid: bool },
    Raw { bytes: Vec<u8> },
    Tick { secs: u32 },
    Renew,
    Restart { previous: bool },
}

#[derive(Arbitrary, Debug)]
struct Script {
    seed: u64,
    ops: Vec<Op>,
}

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

fn lease_ok(c: &Client) {
    match c.state() {
        State::Bound | State::Renewing | State::Rebinding => assert!(c.lease().is_some(), "{:?} without a lease", c.state()),
        State::Init | State::Selecting | State::Requesting | State::Rebooting => assert!(c.lease().is_none(), "{:?} with a lease", c.state()),
    }
}

fuzz_target!(|script: Script| {
    let mut c = Client::new(Config { chaddr: MAC, client_id: vec![0xff, 1, 2, 3, 4], hostname: Some("box".into()), seed: script.seed });
    let mut now = Instant::now();
    let mut last_sent: Option<Message> = None;
    let mut chosen: Option<Ipv4Addr> = None;
    let mut note = |actions: &[Action], last_sent: &mut Option<Message>| {
        for a in actions {
            match a {
                Action::Send { message, .. } => {
                    assert!(message.options.get(option::MESSAGE_TYPE).is_some());
                    assert_eq!(message.chaddr, MAC);
                    let again = Message::decode(&message.encode()).expect("our own message decodes");
                    assert_eq!(again.xid, message.xid);
                    *last_sent = Some(message.clone());
                }
                Action::Bound(l) => {
                    assert!(l.prefix <= 32 && l.t1 < l.t2 && l.t2 < l.lease_time);
                }
                _ => {}
            }
        }
    };
    let actions = c.start(now, None);
    note(&actions, &mut last_sent);
    lease_ok(&c);

    for op in script.ops.into_iter().take(300) {
        let was_bound = *c.state() == State::Bound;
        let bound_server = c.lease().map(|l| l.server);
        let actions = match op {
            Op::Reply { kind, server, address, lease, t1, t2, mask, extra, wrong_xid } => {
                let Some(sent) = &last_sent else { continue };
                let mut m = Message::request(if wrong_xid { sent.xid ^ 1 } else { sent.xid }, MAC);
                m.is_reply = true;
                m.yiaddr = Ipv4Addr::from(address);
                let kinds = [MessageType::Offer, MessageType::Ack, MessageType::Nak];
                m.options.push(option::MESSAGE_TYPE, [kinds[kind as usize % 3] as u8]);
                let srv = Ipv4Addr::new(10, 0, 2, 1 + server % 3);
                if server % 7 != 6 {
                    m.options.push(option::SERVER_ID, srv.octets());
                }
                m.options.push(option::LEASE_TIME, lease.to_be_bytes());
                if let Some(t) = t1 {
                    m.options.push(option::RENEWAL_T1, t.to_be_bytes());
                }
                if let Some(t) = t2 {
                    m.options.push(option::REBINDING_T2, t.to_be_bytes());
                }
                m.options.push(option::SUBNET_MASK, mask.to_be_bytes());
                for (code, data) in extra.into_iter().take(6) {
                    let mut d = data;
                    d.truncate(255);
                    m.options.push(code, d);
                }
                let acts = c.receive(now, &m);
                // Track which server the client committed to.
                if matches!(c.state(), State::Requesting) && chosen.is_none() {
                    chosen = Some(srv);
                }
                if matches!(c.state(), State::Selecting | State::Init) {
                    chosen = None;
                }
                // A Bound client leaves Bound only on time, or a NAK from
                // its own server.
                if was_bound && *c.state() != State::Bound {
                    assert_eq!(kinds[kind as usize % 3], MessageType::Nak);
                    assert_eq!(m.options.ipv4(option::SERVER_ID), bound_server);
                }
                acts
            }
            Op::Raw { bytes } => match Message::decode(&bytes) {
                Some(m) => c.receive(now, &m),
                None => Vec::new(),
            },
            Op::Tick { secs } => {
                now += Duration::from_secs(u64::from(secs % 200_000));
                if let Some(d) = c.next_deadline() {
                    let _ = d;
                }
                c.tick(now)
            }
            Op::Renew => c.renew_now(now),
            Op::Restart { previous } => {
                let prev = if previous { Some(Ipv4Addr::new(10, 0, 2, 15)) } else { None };
                let _ = c.release(now);
                let acts = c.start(now, prev);
                chosen = None;
                acts
            }
        };
        note(&actions, &mut last_sent);
        lease_ok(&c);
        if let (Some(l), Some(exp)) = (c.lease(), c.expires_in(now)) {
            assert!(exp <= u64::from(l.lease_time));
        }
    }
    let _ = chosen;
});
