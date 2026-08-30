//! A hostile network: replies the client must ignore, and replies it must
//! survive. Every case here is something a rogue DHCP server on the LAN
//! can send for free.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::client::{Action, Client, Config, State};
use crate::packet::{Message, MessageType, option};

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

fn client() -> Client {
    Client::new(Config { chaddr: MAC, client_id: vec![0xff, 1, 2, 3, 4], hostname: None, seed: 7 })
}

fn sent(actions: &[Action]) -> &Message {
    for a in actions {
        if let Action::Send { message, .. } = a {
            return message;
        }
    }
    panic!("nothing sent: {actions:?}");
}

fn reply(to: &Message, kind: MessageType, address: Ipv4Addr, server: Ipv4Addr, lease_time: u32) -> Message {
    let mut m = Message::request(to.xid, to.chaddr);
    m.is_reply = true;
    m.yiaddr = address;
    m.options.push(option::MESSAGE_TYPE, [kind as u8]);
    m.options.push(option::SERVER_ID, server.octets());
    m.options.push(option::LEASE_TIME, lease_time.to_be_bytes());
    m.options.push(option::SUBNET_MASK, [255, 255, 255, 0]);
    m.options.push(option::ROUTER, server.octets());
    m
}

fn bind(c: &mut Client, now: Instant) -> Message {
    let discover = sent(&c.start(now, None)).clone();
    let offer = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    let request = sent(&c.receive(now, &offer)).clone();
    let ack = reply(&request, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    let actions = c.receive(now, &ack);
    assert!(matches!(actions.as_slice(), [Action::Bound(_)]), "{actions:?}");
    ack
}

#[test]
fn replies_for_someone_else_are_ignored() {
    let mut c = client();
    let now = Instant::now();
    let discover = sent(&c.start(now, None)).clone();
    let good = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    // Wrong xid.
    let mut m = good.clone();
    m.xid ^= 1;
    assert!(c.receive(now, &m).is_empty());
    // Wrong hardware address.
    let mut m = good.clone();
    m.chaddr[5] ^= 1;
    assert!(c.receive(now, &m).is_empty());
    // A request, not a reply.
    let mut m = good.clone();
    m.is_reply = false;
    assert!(c.receive(now, &m).is_empty());
    assert_eq!(*c.state(), State::Selecting);
}

#[test]
fn a_malformed_offer_is_ignored_and_the_first_good_one_taken() {
    let mut c = client();
    let now = Instant::now();
    let discover = sent(&c.start(now, None)).clone();
    // No server identifier: not an offer we can request from.
    let mut m = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    m.options.0.retain(|(c, _)| *c != option::SERVER_ID);
    assert!(c.receive(now, &m).is_empty());
    // Offering 0.0.0.0.
    let m = reply(&discover, MessageType::Offer, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 2, 2), 3600);
    assert!(c.receive(now, &m).is_empty());
    // No message type at all.
    let mut m = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    m.options.0.retain(|(c, _)| *c != option::MESSAGE_TYPE);
    assert!(c.receive(now, &m).is_empty());
    assert_eq!(*c.state(), State::Selecting);
    // Then a real one.
    let m = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    let request = sent(&c.receive(now, &m)).clone();
    assert_eq!(request.options.ipv4(option::SERVER_ID), Some(Ipv4Addr::new(10, 0, 2, 2)));
}

#[test]
fn a_second_server_cannot_steal_the_request() {
    let mut c = client();
    let now = Instant::now();
    let discover = sent(&c.start(now, None)).clone();
    let first = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    let request = sent(&c.receive(now, &first)).clone();
    // A late offer from a rogue with the same xid: we are Requesting now.
    let rogue = reply(&discover, MessageType::Offer, Ipv4Addr::new(192, 168, 66, 66), Ipv4Addr::new(192, 168, 66, 1), 60);
    assert!(c.receive(now, &rogue).is_empty());
    assert_eq!(*c.state(), State::Requesting);
    assert_eq!(request.options.ipv4(option::REQUESTED_IP), Some(Ipv4Addr::new(10, 0, 2, 15)));
}

#[test]
fn an_ack_without_a_usable_lease_is_ignored() {
    let mut c = client();
    let now = Instant::now();
    let discover = sent(&c.start(now, None)).clone();
    let offer = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    let request = sent(&c.receive(now, &offer)).clone();
    // Lease time zero.
    let m = reply(&request, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 0);
    assert!(c.receive(now, &m).is_empty());
    // A classless route with a prefix of 200.
    let mut m = reply(&request, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    m.options.push(option::CLASSLESS_STATIC_ROUTE, [200, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(c.receive(now, &m).is_empty());
    assert_eq!(*c.state(), State::Requesting);
    // A non-contiguous mask falls back to classful rather than nonsense.
    let mut m = reply(&request, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    m.options.0.retain(|(c, _)| *c != option::SUBNET_MASK);
    m.options.push(option::SUBNET_MASK, [255, 0, 255, 0]);
    let actions = c.receive(now, &m);
    match actions.as_slice() {
        [Action::Bound(l)] => assert_eq!(l.prefix, 8),
        other => panic!("{other:?}"),
    }
}

#[test]
fn once_bound_stray_replies_do_nothing() {
    let mut c = client();
    let now = Instant::now();
    let ack = bind(&mut c, now);
    // A NAK or a second ACK with the bound xid, from anyone.
    let nak = reply(&ack, MessageType::Nak, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(192, 168, 66, 1), 0);
    assert!(c.receive(now, &nak).is_empty());
    let other = reply(&ack, MessageType::Ack, Ipv4Addr::new(192, 168, 66, 66), Ipv4Addr::new(192, 168, 66, 1), 60);
    assert!(c.receive(now, &other).is_empty());
    assert_eq!(*c.state(), State::Bound);
    assert_eq!(c.lease().unwrap().address, Ipv4Addr::new(10, 0, 2, 15));
}

#[test]
fn a_renewal_nak_from_a_stranger_needs_the_fresh_xid() {
    let mut c = client();
    let now = Instant::now();
    let ack = bind(&mut c, now);
    let lease = c.lease().unwrap().clone();
    // At T1 the client renews with a new xid.
    let t1 = now + Duration::from_secs(u64::from(lease.t1));
    let renewal = sent(&c.tick(t1)).clone();
    assert_eq!(*c.state(), State::Renewing);
    assert_ne!(renewal.xid, ack.xid);
    // A NAK replaying the old xid is ignored.
    let stale = reply(&ack, MessageType::Nak, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 2, 2), 0);
    assert!(c.receive(t1, &stale).is_empty());
    assert_eq!(*c.state(), State::Renewing);
    assert!(c.lease().is_some());
}

#[test]
fn only_the_chosen_server_may_ack_or_nak() {
    let mut c = client();
    let now = Instant::now();
    let discover = sent(&c.start(now, None)).clone();
    let offer = reply(&discover, MessageType::Offer, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    let request = sent(&c.receive(now, &offer)).clone();
    // A NAK from a different server, right xid: ignored, still Requesting.
    let rogue_nak = reply(&request, MessageType::Nak, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(192, 168, 66, 1), 0);
    assert!(c.receive(now, &rogue_nak).is_empty());
    assert_eq!(*c.state(), State::Requesting);
    // An ACK from a different server handing out a different address: ignored.
    let rogue_ack = reply(&request, MessageType::Ack, Ipv4Addr::new(192, 168, 66, 66), Ipv4Addr::new(192, 168, 66, 1), 60);
    assert!(c.receive(now, &rogue_ack).is_empty());
    // The real one binds.
    let ack = reply(&request, MessageType::Ack, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 3600);
    assert!(matches!(c.receive(now, &ack).as_slice(), [Action::Bound(_)]));
    // At renewal, a NAK from a stranger with the fresh xid is still ignored.
    let t1 = now + Duration::from_secs(u64::from(c.lease().unwrap().t1));
    let renewal = sent(&c.tick(t1)).clone();
    let rogue = reply(&renewal, MessageType::Nak, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(192, 168, 66, 1), 0);
    assert!(c.receive(t1, &rogue).is_empty());
    assert_eq!(*c.state(), State::Renewing);
}

#[test]
fn a_flood_of_offers_costs_nothing_but_the_first() {
    let mut c = client();
    let now = Instant::now();
    let discover = sent(&c.start(now, None)).clone();
    let mut total = 0;
    for i in 0..10_000u32 {
        let offer = reply(&discover, MessageType::Offer, Ipv4Addr::from(0x0a00_0000 | i), Ipv4Addr::new(10, 0, 2, 2), 3600);
        total += c.receive(now, &offer).len();
    }
    // One request, for the first offer; every later one is dropped.
    assert_eq!(total, 1);
    assert_eq!(*c.state(), State::Requesting);
}
