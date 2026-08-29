//! `Machine\System\Network\Interfaces\<ifid>\` — what netd found, for
//! operators and for `Enabled`, the one value there that is theirs.

use libnetd::NETWORK_KEY;
use peios::registry::{CreateFlags, Key, KeyAccess, ValueType};

use crate::log;
use crate::model::{Identity, Link, format_mac};

pub struct Record<'a> {
    pub ifid: &'a str,
    pub link: &'a Link,
    pub identity: &'a Identity,
    pub profile: Option<&'a str>,
}

const ACCESS: KeyAccess = KeyAccess::QUERY_VALUE
    .union(KeyAccess::SET_VALUE)
    .union(KeyAccess::CREATE_SUB_KEY)
    .union(KeyAccess::ENUMERATE_SUB_KEYS);

fn open_or_create(path: &str) -> peios::Result<Key> {
    Key::create(None, path, ACCESS, CreateFlags::empty(), None, None).map(|(k, _)| k)
}

fn open_or_create_under(parent: &Key, name: &str) -> peios::Result<Key> {
    Key::create(Some(parent), name, ACCESS, CreateFlags::empty(), None, None).map(|(k, _)| k)
}

fn current(key: &Key, name: &str) -> Option<String> {
    let v = key.query_value(name.as_bytes(), None).ok()?;
    let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
    String::from_utf8(v.data[..end].to_vec()).ok()
}

fn set_sz(key: &Key, name: &str, value: &str) {
    if current(key, name).as_deref() == Some(value) {
        return;
    }
    let mut data = value.as_bytes().to_vec();
    data.push(0);
    if let Err(e) = key.set_value(name.as_bytes(), ValueType::SZ, &data).call() {
        log::warn(format_args!("inventory: could not set {name}: {e}"));
    }
}

/// Write the record. Returns `Enabled` (default on; created if absent so an
/// operator can find the knob).
pub fn sync(record: &Record<'_>) -> bool {
    // The registry creates one level per call, so open (or make) each
    // ancestor in turn rather than asking for the leaf by full path.
    let key = match open_or_create(NETWORK_KEY)
        .and_then(|network| open_or_create_under(&network, "Interfaces"))
        .and_then(|interfaces| open_or_create_under(&interfaces, record.ifid))
    {
        Ok(key) => key,
        Err(e) => {
            log::warn(format_args!("inventory: could not open Interfaces\\{}: {e}", record.ifid));
            return true;
        }
    };
    set_sz(&key, "Name", &record.link.name);
    set_sz(&key, "MAC", &record.link.mac.as_ref().map(format_mac).unwrap_or_default());
    set_sz(&key, "Path", &record.identity.path);
    set_sz(&key, "Driver", &record.identity.driver);
    set_sz(&key, "Type", record.link.kind.as_str());
    set_sz(&key, "Profile", record.profile.unwrap_or(""));
    match key.query_value(b"Enabled", None) {
        Ok(v) if v.ty == ValueType::DWORD && v.data.len() == 4 => {
            u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]) != 0
        }
        Ok(_) => true,
        Err(_) => {
            let _ = key.set_value(b"Enabled", ValueType::DWORD, &1u32.to_le_bytes()).call();
            true
        }
    }
}
