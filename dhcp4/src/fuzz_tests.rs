//! Structure-aware random testing on the stable toolchain; the cargo-fuzz
//! targets in `fuzz/` are the real campaign. `DHCP_FUZZ_ITERS` raises the
//! count.

use std::net::Ipv4Addr;

use crate::packet::{Lease, Message, MessageType, option};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

fn iters() -> usize {
    std::env::var("DHCP_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000)
}

/// A plausible server reply: mostly well-formed, with option contents
/// chosen to hit the parsers (mask, routes, search list, times).
fn random_reply(rng: &mut Rng) -> Message {
    let mut m = Message::request(rng.next() as u32, [rng.byte(); 6]);
    m.is_reply = rng.below(8) != 0;
    m.yiaddr = Ipv4Addr::from(rng.next() as u32);
    let kinds = [MessageType::Offer, MessageType::Ack, MessageType::Nak];
    if rng.below(10) != 0 {
        m.options.push(option::MESSAGE_TYPE, [kinds[rng.below(3)] as u8]);
    }
    if rng.below(10) != 0 {
        m.options.push(option::SERVER_ID, (rng.next() as u32).to_be_bytes());
    }
    if rng.below(10) != 0 {
        m.options.push(option::LEASE_TIME, (rng.next() as u32).to_be_bytes());
    }
    for _ in 0..rng.below(8) {
        let code = match rng.below(10) {
            0 => option::SUBNET_MASK,
            1 => option::ROUTER,
            2 => option::DNS,
            3 => option::DOMAIN_SEARCH,
            4 => option::CLASSLESS_STATIC_ROUTE,
            5 => option::RENEWAL_T1,
            6 => option::REBINDING_T2,
            7 => option::MTU,
            8 => option::HOSTNAME,
            _ => 1 + rng.below(254) as u8, // never PAD or END
        };
        let long = rng.below(10) == 0;
        let len = rng.below(if long { 255 } else { 12 });
        let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        m.options.push(code, data);
    }
    m
}

#[test]
fn fuzz_decode_and_lease_never_panic() {
    let mut rng = Rng(0x0dcb);
    for i in 0..iters() {
        let m = random_reply(&mut rng);
        let bytes = m.encode();
        // An option longer than 255 cannot be encoded faithfully; skip the
        // equality check for those but still decode.
        let faithful = m.options.0.iter().all(|(_, d)| d.len() <= 255);
        let back = Message::decode(&bytes).unwrap_or_else(|| panic!("iteration {i}: our own encoding does not decode"));
        if faithful {
            assert_eq!(back.xid, m.xid);
            assert_eq!(back.yiaddr, m.yiaddr);
            assert_eq!(back.options.0.len(), m.options.0.len(), "iteration {i}");
        }
        let _ = Lease::from_ack(&back);
        let _ = back.message_type();
        // Pure noise and mutations.
        let mut noise = bytes.clone();
        for _ in 0..1 + rng.below(8) {
            let at = rng.below(noise.len());
            noise[at] = rng.byte();
        }
        if let Some(m) = Message::decode(&noise) {
            let _ = Lease::from_ack(&m);
        }
        let junk: Vec<u8> = (0..rng.below(400)).map(|_| rng.byte()).collect();
        if let Some(m) = Message::decode(&junk) {
            let _ = Lease::from_ack(&m);
        }
    }
}

#[test]
fn a_lease_never_has_an_impossible_shape() {
    let mut rng = Rng(0x1ea5);
    for _ in 0..iters() {
        let m = random_reply(&mut rng);
        if let Some(l) = Lease::from_ack(&m) {
            assert!(l.prefix <= 32);
            assert!(l.lease_time > 0);
            assert!(l.t1 < l.lease_time && l.t2 > l.t1 && l.t2 < l.lease_time, "{l:?}");
            for r in &l.static_routes {
                assert!(r.prefix <= 32);
            }
            if let Some(mtu) = l.mtu {
                assert!(mtu >= 68);
            }
        }
    }
}
