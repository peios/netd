//! Arbitrary bytes as a router advertisement: decode, check every bound.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(ra) = ndp::RouterAdvert::decode(data) {
        assert!(ra.prefixes.len() <= 16);
        for p in &ra.prefixes {
            assert!(p.length <= 128);
        }
        for r in &ra.rdnss {
            assert!(r.servers.len() <= 16);
        }
        for d in &ra.dnssl {
            assert!(d.domains.len() <= 16);
            for name in &d.domains {
                assert!(name.len() <= 253);
                assert!(name.is_ascii());
            }
        }
    }
    let _ = ndp::packet::domain_list(data);
});
