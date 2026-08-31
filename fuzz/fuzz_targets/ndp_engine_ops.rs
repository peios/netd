//! The SLAAC engine under an arbitrary network: advertisements with
//! arbitrary content from arbitrary link-local sources, interleaved with
//! time. Invariants: no panic; only /64 addresses, each unique; deadlines
//! and accessors are total.
#![no_main]

use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use ndp::{Config, Engine};

#[derive(Arbitrary, Debug)]
enum Op {
    Advert { source_low: u8, bytes: Vec<u8> },
    Tick { secs: u32 },
}

#[derive(Arbitrary, Debug)]
struct Script {
    seed: u64,
    temporary: bool,
    ops: Vec<Op>,
}

fuzz_target!(|script: Script| {
    let mut e = Engine::new(Config {
        interface: "fuzz".into(),
        secret: [1u8; 32],
        temporary: script.temporary,
        mac: Some([0x52, 0x54, 0, 1, 2, 3]),
        seed: script.seed,
    });
    let mut now = Instant::now();
    e.start(now);
    for op in script.ops.into_iter().take(64) {
        match op {
            Op::Advert { source_low, bytes } => {
                let source = Ipv6Addr::from([
                    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, source_low,
                ]);
                e.receive(now, source, &bytes);
            }
            Op::Tick { secs } => {
                now += Duration::from_secs(u64::from(secs) % 1_000_000);
                e.tick(now);
            }
        }
        let addresses = e.addresses(now);
        for a in &addresses {
            assert_eq!(a.prefix, 64);
        }
        let mut unique: Vec<_> = addresses.iter().map(|a| a.address).collect();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), addresses.len());
        let _ = e.next_deadline();
        let _ = e.default_router(now);
        let _ = e.dns_servers(now);
        let _ = e.search_domains(now);
    }
});
