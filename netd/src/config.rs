//! What the registry says the network should be — read whole, lowered to
//! neutral trees, and handed to the pure modules.
//!
//! `Machine\System\Network` is PNP's key. netd reads three things from it:
//! the machine-level values (`Hostname`, `ControlSecurity`, `Duid`), the
//! interface layer `Rules\Interface`, and the profile tree `Profiles\`.
//! Both trees are lowered to [`RawKey`] here and built by netd_core's
//! `policy`, so that everything with a law in it is testable without a
//! registry.
//!
//! A malformed generation is refused as a whole by the builder; this module
//! never guesses at a value. A missing root means "no configuration".

use std::io;

use netd_core::NETWORK_KEY;
pub use netd_core::raw::{RawKey, RawValue};
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueRecord, ValueType};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub hostname: Option<String>,
    /// `ControlSecurity`, raw self-relative SD, if set.
    pub control_security: Option<Vec<u8>>,
    /// `Duid`: the machine's DHCPv6 identifier, when the operator (or a
    /// previous netd) has written one.
    pub duid: Option<Vec<u8>>,
    /// `Rules\Interface`, when present.
    pub rules: Option<RawKey>,
    /// `Profiles`, when present.
    pub profiles: Option<RawKey>,
}

/// Bound registry traversal independently of the policy parser's nesting limit.
const MAX_DEPTH: usize = 16;

/// The read operations needed to obtain one complete configuration.
trait Reader: Sized {
    fn value(&self, name: &str) -> io::Result<Option<RegValue>>;
    fn values(&self) -> io::Result<Vec<ValueRecord>>;
    fn names(&self) -> io::Result<Vec<Vec<u8>>>;
    fn child(&self, name: &str) -> io::Result<Option<Self>>;
}

fn optional<T>(result: peios::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn open_read(parent: Option<&Key>, path: &str) -> io::Result<Option<Key>> {
    optional(Key::open(
        parent,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    ))
}

impl Reader for Key {
    fn value(&self, name: &str) -> io::Result<Option<RegValue>> {
        optional(self.query_value(name.as_bytes(), None))
    }

    fn values(&self) -> io::Result<Vec<ValueRecord>> {
        self.query_values_batch(None).map_err(Into::into)
    }

    fn names(&self) -> io::Result<Vec<Vec<u8>>> {
        self.subkeys(None)
            .map(|entry| entry.map(|entry| entry.name).map_err(Into::into))
            .collect()
    }

    fn child(&self, name: &str) -> io::Result<Option<Self>> {
        open_read(Some(self), name)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn text(bytes: &[u8]) -> io::Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| invalid("configuration text is not UTF-8"))
}

fn sz(value: &RegValue) -> io::Result<String> {
    if value.ty != ValueType::SZ && value.ty != ValueType::EXPAND_SZ {
        return Err(invalid("configuration string has a non-string type"));
    }
    let end = value
        .data
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(value.data.len());
    text(&value.data[..end])
}

fn lower_value(ty: ValueType, data: &[u8]) -> io::Result<RawValue> {
    Ok(match ty {
        ValueType::DWORD if data.len() == 4 => RawValue::Int(i64::from(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))),
        ValueType::QWORD if data.len() == 8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(data);
            RawValue::Int(i64::from_le_bytes(bytes))
        }
        ValueType::SZ | ValueType::EXPAND_SZ => {
            let end = data
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(data.len());
            RawValue::Str(text(&data[..end])?)
        }
        ValueType::MULTI_SZ => RawValue::List(
            data.split(|&byte| byte == 0)
                .filter(|part| !part.is_empty())
                .map(text)
                .collect::<io::Result<_>>()?,
        ),
        _ => RawValue::Other,
    })
}

fn read_sz(key: &impl Reader, name: &str) -> io::Result<Option<String>> {
    Ok(key
        .value(name)?
        .as_ref()
        .map(sz)
        .transpose()?
        .filter(|value| !value.is_empty()))
}

/// Read every value and child, or reject the entire tree.
fn read_tree(key: &impl Reader, name: &str, depth: usize) -> io::Result<RawKey> {
    let mut out = RawKey {
        name: name.to_owned(),
        values: Vec::new(),
        children: Vec::new(),
    };
    for record in key.values()? {
        let name = text(&record.name)?;
        if !name.is_empty() {
            out.values
                .push((name, lower_value(record.ty, &record.data)?));
        }
    }
    // Stable ordering makes equivalent reads compare equal.
    out.values.sort_by(|a, b| a.0.cmp(&b.0));
    let mut names = key
        .names()?
        .iter()
        .map(|name| text(name))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    if depth >= MAX_DEPTH && !names.is_empty() {
        return Err(invalid("configuration tree exceeds the read depth limit"));
    }
    for name in names {
        let child = key.child(&name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "enumerated configuration key disappeared",
            )
        })?;
        out.children.push(read_tree(&child, &name, depth + 1)?);
    }
    Ok(out)
}

/// Parses a colon- or plain-hex identifier as written for `Duid` and
/// `ClientId`.
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let digits: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    if s.chars()
        .any(|c| !(c.is_ascii_hexdigit() || c == ':' || c == '-' || c.is_ascii_whitespace()))
    {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

/// Formats an identifier the way `parse_hex` reads it back.
pub fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Read the whole configuration. A missing root means "no configuration":
/// the backstop ignores every interface.
pub fn load() -> io::Result<Config> {
    load_root(open_read(None, NETWORK_KEY)?)
}

fn load_root(root: Option<impl Reader>) -> io::Result<Config> {
    let Some(root) = root else {
        return Ok(Config::default());
    };
    let hostname = read_sz(&root, netd_core::hostname::HOSTNAME_VALUE)?;
    let control_security = match root.value("ControlSecurity")? {
        Some(value) if value.ty != ValueType::BINARY => {
            return Err(invalid("ControlSecurity must be binary"));
        }
        Some(value) if !value.data.is_empty() => Some(value.data),
        _ => None,
    };
    let duid = read_sz(&root, "Duid")?
        .map(|value| parse_hex(&value).ok_or_else(|| invalid("Duid is not a hex identifier")))
        .transpose()?;
    let rules = match root.child("Rules")? {
        Some(rules) => rules
            .child("Interface")?
            .map(|layer| read_tree(&layer, "Interface", 0))
            .transpose()?,
        None => None,
    };
    let profiles = root
        .child("Profiles")?
        .map(|profiles| read_tree(&profiles, "Profiles", 0))
        .transpose()?;
    Ok(Config {
        hostname,
        control_security,
        duid,
        rules,
        profiles,
    })
}

/// Open the root with notify rights and arm a subtree watch.
pub fn watch() -> peios::Result<Key> {
    use peios::registry::NotifyFilter;
    let key = Key::open(None, NETWORK_KEY, KeyAccess::NOTIFY, OpenFlags::empty())?;
    key.notify(NotifyFilter::ALL, true)?;
    key.set_nonblocking(true)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_identifiers_round_trip() {
        let id = vec![0, 3, 0, 1, 0x52, 0x54, 0, 1, 2, 3];
        assert_eq!(parse_hex(&format_hex(&id)).as_deref(), Some(&id[..]));
        assert_eq!(
            parse_hex("0003000152540001"),
            Some(vec![0, 3, 0, 1, 0x52, 0x54, 0, 1])
        );
        assert_eq!(parse_hex("00:0g"), None);
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex(""), None);
    }

    #[test]
    fn values_lower_to_their_neutral_shape() {
        assert_eq!(
            lower_value(ValueType::DWORD, &7u32.to_le_bytes()).unwrap(),
            RawValue::Int(7)
        );
        assert_eq!(
            lower_value(ValueType::SZ, b"wired\0").unwrap(),
            RawValue::Str("wired".into())
        );
        assert_eq!(
            lower_value(ValueType::MULTI_SZ, b"a\0b\0\0").unwrap(),
            RawValue::List(vec!["a".into(), "b".into()])
        );
        assert_eq!(
            lower_value(ValueType::BINARY, b"\x01").unwrap(),
            RawValue::Other
        );
    }
    #[derive(Clone, Default)]
    struct MockKey {
        values: Vec<ValueRecord>,
        children: Vec<(Vec<u8>, Self)>,
        failure: Option<&'static str>,
    }

    impl MockKey {
        fn check(&self, operation: &str) -> io::Result<()> {
            if self.failure == Some(operation) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    operation.to_owned(),
                ));
            }
            Ok(())
        }

        fn with_value(name: &[u8], ty: ValueType, data: &[u8]) -> Self {
            Self {
                values: vec![ValueRecord {
                    name: name.to_vec(),
                    ty,
                    data: data.to_vec(),
                }],
                ..Self::default()
            }
        }

        fn under(self, name: &[u8]) -> Self {
            Self {
                children: vec![(name.to_vec(), self)],
                ..Self::default()
            }
        }
    }

    impl Reader for MockKey {
        fn value(&self, name: &str) -> io::Result<Option<RegValue>> {
            self.check("value")?;
            Ok(self
                .values
                .iter()
                .find(|value| value.name == name.as_bytes())
                .map(|value| RegValue {
                    sequence: 0,
                    ty: value.ty,
                    data: value.data.clone(),
                    layer: Vec::new(),
                }))
        }

        fn values(&self) -> io::Result<Vec<ValueRecord>> {
            self.check("values")?;
            Ok(self.values.clone())
        }

        fn names(&self) -> io::Result<Vec<Vec<u8>>> {
            self.check("names")?;
            Ok(self.children.iter().map(|(name, _)| name.clone()).collect())
        }

        fn child(&self, name: &str) -> io::Result<Option<Self>> {
            self.check("child")?;
            if self.failure == Some("disappeared") {
                return Ok(None);
            }
            Ok(self
                .children
                .iter()
                .find(|(key, _)| key == name.as_bytes())
                .map(|(_, key)| key.clone()))
        }
    }

    #[test]
    fn only_missing_registry_entries_are_optional() {
        assert!(
            optional::<()>(Err(peios::Error::from_raw_os_error(libc::ENOENT)))
                .unwrap()
                .is_none()
        );
        for errno in [libc::EACCES, libc::EIO] {
            assert_eq!(
                optional::<()>(Err(peios::Error::from_raw_os_error(errno)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(errno)
            );
        }
        assert_eq!(load_root(None::<MockKey>).unwrap(), Config::default());
        assert_eq!(
            load_root(Some(MockKey::default())).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn incomplete_reads_never_produce_a_configuration() {
        for operation in ["value", "child"] {
            let key = MockKey {
                failure: Some(operation),
                ..MockKey::default()
            };
            assert_eq!(
                load_root(Some(key)).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        for operation in ["values", "names", "child"] {
            let key = MockKey {
                failure: Some(operation),
                children: vec![(b"wired".to_vec(), MockKey::default())],
                ..MockKey::default()
            }
            .under(b"Profiles");
            assert_eq!(
                load_root(Some(key)).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn disappearing_enumerated_children_reject_the_tree() {
        let key = MockKey {
            failure: Some("disappeared"),
            children: vec![(b"wired".to_vec(), MockKey::default())],
            ..MockKey::default()
        }
        .under(b"Profiles");
        assert_eq!(
            load_root(Some(key)).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn malformed_names_and_text_reject_the_whole_configuration() {
        let malformed = [
            MockKey::with_value(b"Hostname", ValueType::SZ, b"\xff"),
            MockKey::with_value(b"Hostname", ValueType::BINARY, b"host"),
            MockKey::with_value(b"Duid", ValueType::SZ, b"not-hex"),
            MockKey::with_value(b"ControlSecurity", ValueType::SZ, b"descriptor"),
            MockKey::with_value(b"\xff", ValueType::SZ, b"valid").under(b"Profiles"),
            MockKey::with_value(b"Dns", ValueType::MULTI_SZ, b"valid\0\xff\0").under(b"Profiles"),
            MockKey::with_value(b"Name", ValueType::SZ, b"\xff").under(b"Profiles"),
            MockKey::default().under(b"\xff").under(b"Profiles"),
        ];
        for key in malformed {
            assert_eq!(
                load_root(Some(key)).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn depth_limit_rejects_truncation_but_accepts_a_leaf_at_the_limit() {
        let mut key = MockKey::default();
        for _ in 0..MAX_DEPTH {
            key = key.under(b"child");
        }
        assert!(read_tree(&key, "Profiles", 0).is_ok());
        assert_eq!(
            read_tree(&key.under(b"child"), "Profiles", 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn a_complete_read_preserves_every_value_and_stable_order() {
        let key = MockKey::with_value(b"Dns", ValueType::MULTI_SZ, b"one\0two\0\0")
            .under(b"wired")
            .under(b"Profiles");
        let config = load_root(Some(key)).unwrap();
        assert_eq!(
            config.profiles.unwrap().children[0].values,
            vec![(
                "Dns".to_owned(),
                RawValue::List(vec!["one".to_owned(), "two".to_owned()])
            )]
        );
    }
}
