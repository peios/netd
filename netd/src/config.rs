//! What the registry says the network should be — read whole, lowered to
//! neutral trees, and handed to the pure modules.
//!
//! `Machine\System\Network` is PNP's key. netd reads three things from it:
//! the machine-level values (`Hostname`, `ControlSecurity`, `Duid`), the
//! interface layer `Rules\Interface`, and the profile tree `Profiles\`.
//! Both trees are lowered to [`RawKey`] here and built by `policy.rs`, so
//! that everything with a law in it is testable without a registry.
//!
//! A malformed generation is refused as a whole by the builder; this module
//! never guesses at a value. A missing root means "no configuration".

use libnetd::NETWORK_KEY;
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};

use crate::log;

/// A registry value, lowered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawValue {
    Int(i64),
    Str(String),
    List(Vec<String>),
    /// A type the vocabulary has no use for (binary, none). Kept so the
    /// builder can refuse it by name rather than silently drop it.
    Other,
}

/// A registry key, lowered: its name, values and subkeys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawKey {
    pub name: String,
    pub values: Vec<(String, RawValue)>,
    pub children: Vec<RawKey>,
}

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

/// How deep a rule or profile tree may go before the read stops: pnp-core
/// refuses deeper nesting anyway (12), and a cycle is impossible in a
/// registry, so this only bounds a pathological tree.
const MAX_DEPTH: usize = 16;

fn sz(v: &RegValue) -> Option<String> {
    if v.ty != ValueType::SZ && v.ty != ValueType::EXPAND_SZ {
        return None;
    }
    let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
    String::from_utf8(v.data[..end].to_vec()).ok()
}

fn lower_value(ty: ValueType, data: &[u8]) -> RawValue {
    match ty {
        ValueType::DWORD if data.len() == 4 => {
            RawValue::Int(i64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])))
        }
        ValueType::QWORD if data.len() == 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(data);
            RawValue::Int(i64::from_le_bytes(b))
        }
        ValueType::SZ | ValueType::EXPAND_SZ => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            match String::from_utf8(data[..end].to_vec()) {
                Ok(s) => RawValue::Str(s),
                Err(_) => RawValue::Other,
            }
        }
        ValueType::MULTI_SZ => RawValue::List(
            data.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                .collect(),
        ),
        _ => RawValue::Other,
    }
}

fn read(key: &Key, name: &str) -> Option<RegValue> {
    key.query_value(name.as_bytes(), None).ok()
}

fn read_sz(key: &Key, name: &str) -> Option<String> {
    read(key, name)
        .and_then(|v| sz(&v))
        .filter(|s| !s.is_empty())
}

pub fn open(parent: Option<&Key>, path: &str) -> Option<Key> {
    Key::open(
        parent,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    )
    .ok()
}

/// Lowers `key` (named `name`) and everything under it.
fn read_tree(key: &Key, name: &str, depth: usize) -> RawKey {
    let mut out = RawKey {
        name: name.to_owned(),
        values: Vec::new(),
        children: Vec::new(),
    };
    match key.query_values_batch(None) {
        Ok(records) => {
            for r in records {
                let Ok(vname) = String::from_utf8(r.name.clone()) else {
                    continue;
                };
                if vname.is_empty() {
                    // The default value carries nothing in either tree.
                    continue;
                }
                out.values.push((vname, lower_value(r.ty, &r.data)));
            }
        }
        Err(e) => log::warn(format_args!("reading values of {name}: {e}")),
    }
    // A stable order makes two reads of the same tree compare equal.
    out.values.sort_by(|a, b| a.0.cmp(&b.0));
    if depth >= MAX_DEPTH {
        log::warn(format_args!("{name}: tree deeper than {MAX_DEPTH}; the rest is ignored"));
        return out;
    }
    let mut names: Vec<String> = key
        .subkeys(None)
        .filter_map(|s| s.ok())
        .filter_map(|s| String::from_utf8(s.name).ok())
        .collect();
    names.sort();
    for child in names {
        if let Some(k) = open(Some(key), &child) {
            out.children.push(read_tree(&k, &child, depth + 1));
        }
    }
    out
}

/// Parses a colon- or plain-hex identifier as written for `Duid` and
/// `ClientId`.
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let digits: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    if s.chars().any(|c| !(c.is_ascii_hexdigit() || c == ':' || c == '-' || c.is_ascii_whitespace())) {
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
pub fn load() -> Config {
    let mut config = Config::default();
    let Some(root) = open(None, NETWORK_KEY) else {
        log::warn(format_args!(
            "{NETWORK_KEY} does not exist; running with no policy"
        ));
        return config;
    };
    config.hostname = read_sz(&root, "Hostname");
    config.control_security = read(&root, "ControlSecurity")
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);
    config.duid = read_sz(&root, "Duid").and_then(|s| {
        let parsed = parse_hex(&s);
        if parsed.is_none() {
            log::warn(format_args!("Duid {s:?} is not hex; ignoring it"));
        }
        parsed
    });
    if let Some(rules) = open(Some(&root), "Rules") {
        if let Some(layer) = open(Some(&rules), "Interface") {
            config.rules = Some(read_tree(&layer, "Interface", 0));
        }
    }
    if let Some(profiles) = open(Some(&root), "Profiles") {
        config.profiles = Some(read_tree(&profiles, "Profiles", 0));
    }
    config
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
        assert_eq!(parse_hex("0003000152540001"), Some(vec![0, 3, 0, 1, 0x52, 0x54, 0, 1]));
        assert_eq!(parse_hex("00:0g"), None);
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex(""), None);
    }

    #[test]
    fn values_lower_to_their_neutral_shape() {
        assert_eq!(lower_value(ValueType::DWORD, &7u32.to_le_bytes()), RawValue::Int(7));
        assert_eq!(lower_value(ValueType::SZ, b"wired\0"), RawValue::Str("wired".into()));
        assert_eq!(
            lower_value(ValueType::MULTI_SZ, b"a\0b\0\0"),
            RawValue::List(vec!["a".into(), "b".into()])
        );
        assert_eq!(lower_value(ValueType::BINARY, b"\x01"), RawValue::Other);
    }
}
