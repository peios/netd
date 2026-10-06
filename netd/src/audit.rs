//! The record netd writes: `netd.hostname.changed` (`netd.evman`).
//!
//! The machine's name is what every other machine, log line and certificate
//! request knows it by, so a change of it is `essential` (PGSS §6.8):
//! written unconditionally, without asking the emission policy. netd runs as
//! SYSTEM, whose token carries `SeAuditPrivilege`. A record that cannot be
//! written is a warning in the log; the name has already changed.

use std::sync::OnceLock;

use peios::msgpack::Writer;
use peios::security::Sid;
use peios::token::{Token, TokenAccess};

use crate::log;

/// The event type.
pub const HOSTNAME_CHANGED: &str = "netd.hostname.changed";

/// The kernel's hostname as it stands, for the record's `config.text-previous`.
/// `None` if it cannot be read.
pub fn kernel_hostname() -> Option<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    Some(text.strip_suffix('\n').unwrap_or(&text).to_owned())
}

/// The payload of a `netd.hostname.changed` record.
///
/// `previous` is the kernel's name just before netd set `name`, and is left
/// out when it could not be read. `subject` is the binary SID of the
/// principal that acted (PGSS §6.4): a control client whose request made
/// the pass that changed the name, or netd's own user. It is left out only
/// if that SID could not be read.
pub fn hostname_changed_payload(
    name: &str,
    previous: Option<&str>,
    subject: Option<&[u8]>,
) -> peios::Result<Vec<u8>> {
    let mut w = Writer::new();
    w.write_map(1 + u32::from(subject.is_some()));
    w.write_str("config")
        .write_map(2 + u32::from(previous.is_some()))
        .write_str("name")
        .write_str(libnetd::hostname::HOSTNAME_VALUE)
        .write_str("text")
        .write_str(name);
    if let Some(previous) = previous {
        w.write_str("text-previous").write_str(previous);
    }
    if let Some(sid) = subject {
        w.write_str("subject")
            .write_map(1)
            .write_str("token")
            .write_map(1)
            .write_str("sid")
            .write_bin(sid);
    }
    w.to_bytes()
}

/// The user SID of netd's own token, read once: the subject of every change
/// netd makes on its own authority. `None`, with an error logged once, if
/// it cannot be read.
pub fn own_sid() -> Option<&'static Sid> {
    static OWN: OnceLock<Option<Sid>> = OnceLock::new();
    OWN.get_or_init(
        || match Token::open_self(true, TokenAccess::QUERY).and_then(|t| t.user()) {
            Ok(sid) => Some(sid),
            Err(e) => {
                log::error(format_args!(
                    "could not read netd's own identity ({e}); hostname changes are \
                     recorded without a subject"
                ));
                None
            }
        },
    )
    .as_ref()
}

/// Write a `netd.hostname.changed` record, logging rather than returning a
/// failure. `caller` is the control client whose request made the pass;
/// `None` means netd acted on its own authority, and the record names netd.
pub fn hostname_changed(name: &str, previous: Option<&str>, caller: Option<&Sid>) {
    let subject = match caller {
        Some(sid) => Some(sid.as_bytes()),
        None => own_sid().map(|sid| sid.as_bytes()),
    };
    let result = hostname_changed_payload(name, previous, subject)
        .and_then(|payload| peios::event::emit(HOSTNAME_CHANGED, &payload));
    if let Err(e) = result {
        log::warn(format_args!(
            "could not record the hostname change as {HOSTNAME_CHANGED}: {e}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::msgpack::{Reader, Type};
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq)]
    enum V {
        Map(BTreeMap<String, V>),
        Str(String),
        Bin(Vec<u8>),
    }

    fn decode(r: &mut Reader<'_>) -> V {
        match r.peek().expect("a value") {
            Type::Map => {
                let n = r.read_map().unwrap();
                let mut m = BTreeMap::new();
                for _ in 0..n {
                    let k = r.read_str().unwrap().to_owned();
                    let v = decode(r);
                    assert!(m.insert(k, v).is_none(), "a key is written once");
                }
                V::Map(m)
            }
            Type::Str => V::Str(r.read_str().unwrap().to_owned()),
            Type::Bin => V::Bin(r.read_bin().unwrap().to_vec()),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn parse(bytes: &[u8]) -> V {
        let mut r = Reader::new(bytes);
        let v = decode(&mut r);
        assert_eq!(r.remaining(), 0, "one value, nothing after it");
        v
    }

    fn at<'a>(v: &'a V, path: &str) -> Option<&'a V> {
        path.split('.').try_fold(v, |v, key| match v {
            V::Map(m) => m.get(key),
            _ => None,
        })
    }

    fn s(text: &str) -> V {
        V::Str(text.to_owned())
    }

    #[test]
    fn a_change_names_the_setting_both_values_and_who_acted() {
        // netd's own user, SYSTEM, for a change it made itself.
        let own = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let bytes = hostname_changed_payload("ws-01", Some("(none)"), Some(&own)).unwrap();
        let v = parse(&bytes);
        assert_eq!(at(&v, "config.name"), Some(&s("Hostname")));
        assert_eq!(at(&v, "config.text"), Some(&s("ws-01")));
        assert_eq!(at(&v, "config.text-previous"), Some(&s("(none)")));
        assert_eq!(at(&v, "subject.token.sid"), Some(&V::Bin(own.to_vec())));
    }

    #[test]
    fn a_subject_that_could_not_be_read_is_left_out_rather_than_written_empty() {
        let bytes = hostname_changed_payload("ws-03", None, None).unwrap();
        assert_eq!(at(&parse(&bytes), "subject"), None);
    }

    #[test]
    fn a_requested_pass_carries_the_callers_sid_and_an_unread_name_is_left_out() {
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let bytes = hostname_changed_payload("ws-02", None, Some(&sid)).unwrap();
        let v = parse(&bytes);
        assert_eq!(at(&v, "config.text"), Some(&s("ws-02")));
        assert_eq!(at(&v, "config.text-previous"), None);
        assert_eq!(at(&v, "subject.token.sid"), Some(&V::Bin(sid.to_vec())));
    }
}
