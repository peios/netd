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
    let path = format!("{NETWORK_KEY}\\Interfaces\\{}", record.ifid);
    let key = match Key::create(
        None,
        &path,
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        CreateFlags::empty(),
        None,
        None,
    ) {
        Ok((key, _)) => key,
        Err(e) => {
            log::warn(format_args!("inventory: could not open {path}: {e}"));
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
