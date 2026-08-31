//! The stateless DHCPv6 client under an arbitrary network: datagrams with
//! arbitrary content interleaved with time. Invariants: no panic; the
//! answer stays within its bounds; something is always scheduled.
#![no_main]

use std::time::{Duration, Instant};

use dhcp6::{Client, Config};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Datagram { bytes: Vec<u8>, fix_txid: bool },
    Tick { secs: u32 },
}

#[derive(Arbitrary, Debug)]
struct Script {
    seed: u64,
    ops: Vec<Op>,
}

fuzz_target!(|script: Script| {
    let duid = vec![0, 3, 0, 1, 1, 2, 3, 4, 5, 6];
    let mut c = Client::new(Config {
        duid,
        seed: script.seed,
    });
    let mut now = Instant::now();
    let mut txid = [0u8; 3];
    for a in c.start(now) {
        if let dhcp6::Action::Send(m) = a {
            txid.copy_from_slice(&m[1..4]);
        }
    }
    for op in script.ops.into_iter().take(64) {
        match op {
            Op::Datagram {
                mut bytes,
                fix_txid,
            } => {
                // Half the corpus gets the real transaction id, so the
                // validating path is exercised, not just the reject.
                if fix_txid && bytes.len() >= 4 {
                    bytes[1..4].copy_from_slice(&txid);
                }
                c.receive(now, &bytes);
            }
            Op::Tick { secs } => {
                now += Duration::from_secs(u64::from(secs) % 1_000_000);
                for a in c.tick(now) {
                    if let dhcp6::Action::Send(m) = a {
                        txid.copy_from_slice(&m[1..4]);
                    }
                }
            }
        }
        if let Some(info) = c.info() {
            assert!(info.dns.len() <= 16);
            assert!(info.search.len() <= 16);
        }
        assert!(c.next_deadline().is_some());
    }
});
