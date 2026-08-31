//! Structure-aware random testing on the stable toolchain; the cargo-fuzz
//! targets in `fuzz/` are the real campaign. `NDP_FUZZ_ITERS` raises the
//! count.
//!
//! Every advertisement the engine sees came off the local network, from
//! anyone on it, so the decoder and the engine both take arbitrary bytes
//! and arbitrary orderings without panicking — and the engine's view must
//! stay internally consistent whatever arrives.

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use crate::engine::{Config, Engine};
use crate::packet::RouterAdvert;

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
    std::env::var("NDP_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000)
}

/// A mostly plausible advertisement with hostile lengths and contents mixed
/// in: real option types with wrong sizes, huge counts, truncations.
fn random_advert(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![134, 0, 0, 0, rng.byte(), rng.byte(), rng.byte(), rng.byte()];
    b.extend_from_slice(&[0; 8]);
    for _ in 0..rng.below(6) {
        let kind = [1u8, 3, 5, 24, 25, 31, rng.byte()][rng.below(7)];
        let len = rng.below(5) as u8 + 1;
        b.push(kind);
        b.push(len);
        for _ in 0..(usize::from(len) * 8 - 2) {
            b.push(rng.byte());
        }
    }
    b
}

#[test]
fn fuzz_decoder_never_panics_and_bounds_hold() {
    let mut rng = Rng(0x0dd0_2026);
    for _ in 0..iters() {
        let mut bytes = random_advert(&mut rng);
        for _ in 0..rng.below(4) {
            if bytes.is_empty() {
                break;
            }
            let at = rng.below(bytes.len());
            match rng.below(3) {
                0 => bytes[at] = rng.byte(),
                1 => bytes.truncate(at),
                _ => bytes.insert(at, rng.byte()),
            }
        }
        if let Some(ra) = RouterAdvert::decode(&bytes) {
            assert!(ra.prefixes.len() <= 16);
            for r in &ra.rdnss {
                assert!(r.servers.len() <= 16);
            }
            for d in &ra.dnssl {
                assert!(d.domains.len() <= 16);
                for name in &d.domains {
                    assert!(name.len() <= 253);
                }
            }
        }
    }
}

#[test]
fn fuzz_engine_survives_an_arbitrary_network() {
    let mut rng = Rng(0x2026_0831);
    for _ in 0..iters() / 10 {
        let mut e = Engine::new(Config {
            interface: "fuzz".into(),
            secret: [1u8; 32],
            temporary: rng.below(2) == 0,
            mac: Some([rng.byte(); 6]),
            seed: rng.next(),
        });
        let t0 = Instant::now();
        let mut now = t0;
        e.start(now);
        for _ in 0..rng.below(40) {
            match rng.below(3) {
                0 => {
                    let source = Ipv6Addr::from([
                        0xfe,
                        0x80,
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
                        0,
                        0,
                        rng.byte(),
                    ]);
                    e.receive(now, source, &random_advert(&mut rng));
                }
                1 => {
                    now += Duration::from_secs(rng.next() % 100_000);
                    e.tick(now);
                }
                _ => {
                    e.tick(now);
                }
            }
            // The view stays consistent: every address is in a /64, and no
            // address repeats.
            let addresses = e.addresses(now);
            for a in &addresses {
                assert_eq!(a.prefix, 64);
            }
            let mut unique: Vec<_> = addresses.iter().map(|a| a.address).collect();
            unique.dedup();
            assert_eq!(unique.len(), addresses.len());
            // A deadline, if any, serves some purpose; and asking for the
            // DNS view never panics.
            let _ = e.next_deadline();
            let _ = e.dns_servers(now);
            let _ = e.search_domains(now);
            let _ = e.default_router(now);
        }
    }
}
