//! Arbitrary bytes as a DHCP reply: decode, interpret as a lease, re-encode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(m) = dhcp4::Message::decode(data) {
        let _ = m.message_type();
        if let Some(l) = dhcp4::Lease::from_ack(&m) {
            assert!(l.prefix <= 32);
            assert!(l.lease_time > 0 && l.t1 < l.t2 && l.t2 < l.lease_time);
            let _ = l.gateway();
        }
        let again = m.encode();
        let _ = dhcp4::Message::decode(&again).expect("our own encoding decodes");
    }
});
