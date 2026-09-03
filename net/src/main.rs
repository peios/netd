//! `net` — the netd operator command.
//!
//! Talks to netd over its control socket; `rules` and `profiles` read the
//! registry directly, because the interface layer and its profiles are
//! configuration and netd merely executes them. Changing the network is a
//! registry write (`reg`); this command shows state and pokes the daemon.

use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use libnetd::{CONTROL_SOCKET_PATH, Level, NETWORK_KEY, Reply, Request, Status};
use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};

fn usage() -> ExitCode {
    eprintln!(
        "usage: net status\n       net renew <interface>\n       net reconcile\n       net rules\n       net profiles\n       net wait <link|addressed|routed> [timeout-seconds]"
    );
    ExitCode::from(2)
}

fn call(request: &Request) -> Result<Reply, String> {
    let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH)
        .map_err(|e| format!("cannot reach netd at {CONTROL_SOCKET_PATH}: {e}"))?;
    libnetd::call(&mut stream, request).map_err(|e| e.to_string())
}

fn status() -> Result<Status, String> {
    match call(&Request::Status)? {
        Reply::Status(s) => Ok(s),
        Reply::Error(e) => Err(e),
        Reply::Ok | Reply::Snapshot(_) => Err("unexpected reply".into()),
    }
}

fn print_status(s: &Status) {
    println!(
        "hostname   {}",
        if s.hostname.is_empty() {
            "(unset)"
        } else {
            &s.hostname
        }
    );
    println!("readiness  {}", s.level.as_str());
    if let Some(r) = &s.refusal {
        println!("policy     REFUSED: {r} (the last good generation stands)");
    }
    for i in &s.interfaces {
        println!();
        println!("{}  [{}]", i.name, i.ifid);
        let by = i.rule.as_deref().unwrap_or("backstop");
        match (&i.verdict, &i.profile) {
            (Some(v), Some(p)) => println!("  verdict    {v}({p}) by {by}"),
            (Some(v), None) => println!("  verdict    {v} by {by}"),
            (None, _) => println!("  verdict    (none) by {by}"),
        }
        println!(
            "  state      {}{}",
            if i.up { "up" } else { "down" },
            if i.carrier { ", carrier" } else { ", no-carrier" },
        );
        if i.verdict.as_deref() == Some("JOIN") {
            println!("  readiness  {}", i.level.as_str());
        }
        if !i.mac.is_empty() {
            println!("  hardware   {} {} {}", i.mac, i.path, i.driver);
        }
        if let Some(n) = &i.network {
            let mut line = i.network_name.clone().unwrap_or_default();
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&format!("[{n}]"));
            if let Some(t) = &i.network_trust {
                line.push_str(&format!(" trust {t}"));
            }
            println!("  network    {line}");
        }
        for a in &i.addresses {
            println!("  address    {a}");
        }
        if let Some(g) = &i.gateway {
            println!("  gateway    {g}");
        }
        if let Some(g) = &i.gateway6 {
            println!("  gateway6   {g}");
        }
        if !i.dns.is_empty() {
            println!("  dns        {}", i.dns.join(" "));
        }
        if !i.search.is_empty() {
            println!("  search     {}", i.search.join(" "));
        }
        if let Some(l) = &i.lease {
            println!(
                "  lease      {} from {}, {}s left",
                l.state, l.server, l.expires_in
            );
        }
        if let Some(w) = &i.warning {
            println!("  warning    {w}");
        }
    }
}

fn open(path: &str) -> Result<Key, ExitCode> {
    Key::open(
        None,
        path,
        KeyAccess::ENUMERATE_SUB_KEYS | KeyAccess::QUERY_VALUE,
        OpenFlags::empty(),
    )
    .map_err(|e| {
        eprintln!("net: {path}: {e}");
        ExitCode::FAILURE
    })
}

fn sz(key: &Key, name: &str) -> Option<String> {
    let v = key.query_value(name.as_bytes(), None).ok()?;
    let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
    String::from_utf8(v.data[..end].to_vec()).ok()
}

fn dword(key: &Key, name: &str) -> Option<u32> {
    let v = key.query_value(name.as_bytes(), None).ok()?;
    (v.ty == ValueType::DWORD && v.data.len() == 4)
        .then(|| u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]))
}

fn multi(key: &Key, name: &str) -> Vec<String> {
    match key.query_value(name.as_bytes(), None) {
        Ok(v) if v.ty == ValueType::MULTI_SZ => v
            .data
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| String::from_utf8(s.to_vec()).ok())
            .collect(),
        Ok(v) if v.ty == ValueType::SZ => sz(key, name).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Every key under `key`, depth-first, with its path.
fn walk(key: &Key, path: &str, depth: usize, visit: &mut dyn FnMut(&Key, &str, usize)) {
    let mut names: Vec<String> = key
        .subkeys(None)
        .flatten()
        .filter_map(|s| String::from_utf8(s.name).ok())
        .collect();
    names.sort();
    for name in names {
        let Ok(child) = Key::open(
            Some(key),
            &name,
            KeyAccess::ENUMERATE_SUB_KEYS | KeyAccess::QUERY_VALUE,
            OpenFlags::empty(),
        ) else {
            continue;
        };
        let here = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}/{name}")
        };
        visit(&child, &here, depth);
        walk(&child, &here, depth + 1, visit);
    }
}

/// The interface layer, one rule per line: path, priority, conditions,
/// actions. A disabled rule is marked; its subtree is still shown.
fn rules() -> ExitCode {
    let root = match open(&format!("{NETWORK_KEY}\\Rules\\Interface")) {
        Ok(k) => k,
        Err(code) => return code,
    };
    walk(&root, "", 0, &mut |key, path, depth| {
        let mut conditions = Vec::new();
        if let Ok(values) = key.query_values_batch(None) {
            let mut names: Vec<String> = values
                .iter()
                .filter_map(|v| String::from_utf8(v.name.clone()).ok())
                .filter(|n| !matches!(n.as_str(), "Actions" | "Priority" | "Enabled") && !n.is_empty())
                .collect();
            names.sort();
            for n in names {
                let v = multi(key, &n);
                let v = if v.is_empty() {
                    dword(key, &n).map(|d| d.to_string()).unwrap_or_default()
                } else {
                    v.join(",")
                };
                conditions.push(format!("{n}={v}"));
            }
        }
        let actions = multi(key, "Actions");
        let disabled = dword(key, "Enabled") == Some(0);
        println!(
            "{:indent$}{path}{}{}  {}  -> {}",
            "",
            dword(key, "Priority").map(|p| format!(" [{p}]")).unwrap_or_default(),
            if disabled { " (disabled)" } else { "" },
            if conditions.is_empty() {
                "(everything)".to_owned()
            } else {
                conditions.join(" ")
            },
            if actions.is_empty() {
                "NULL".to_owned()
            } else {
                actions.join(", ")
            },
            indent = depth * 2
        );
    });
    ExitCode::SUCCESS
}

/// The profile tree, one profile per line with the values it sets
/// itself; what it inherits is not repeated.
fn profiles() -> ExitCode {
    let root = match open(&format!("{NETWORK_KEY}\\Profiles")) {
        Ok(k) => k,
        Err(code) => return code,
    };
    walk(&root, "", 0, &mut |key, path, depth| {
        let mut settings = Vec::new();
        if let Ok(values) = key.query_values_batch(None) {
            let mut names: Vec<String> = values
                .iter()
                .filter_map(|v| String::from_utf8(v.name.clone()).ok())
                .filter(|n| !n.is_empty() && n != "Enabled")
                .collect();
            names.sort();
            for n in names {
                let v = multi(key, &n);
                let v = if v.is_empty() {
                    dword(key, &n).map(|d| d.to_string()).unwrap_or_else(|| "(none)".into())
                } else {
                    v.join(",")
                };
                settings.push(format!("{n}={v}"));
            }
        }
        let disabled = dword(key, "Enabled") == Some(0);
        println!(
            "{:indent$}{path}{}  {}",
            "",
            if disabled { " (disabled)" } else { "" },
            if settings.is_empty() {
                "(inherits only)".to_owned()
            } else {
                settings.join(" ")
            },
            indent = depth * 2
        );
    });
    ExitCode::SUCCESS
}

fn wait(level: Level, timeout: u64) -> ExitCode {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        match status() {
            Ok(s) if s.level >= level => return ExitCode::SUCCESS,
            Ok(_) => {}
            Err(e) => eprintln!("net: {e}"),
        }
        if std::time::Instant::now() >= deadline {
            eprintln!("net: timed out waiting for {}", level.as_str());
            return ExitCode::FAILURE;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["status"] => match status() {
            Ok(s) => {
                print_status(&s);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("net: {e}");
                ExitCode::FAILURE
            }
        },
        ["renew", interface] => match call(&Request::Renew {
            interface: (*interface).to_owned(),
        }) {
            Ok(Reply::Ok) => ExitCode::SUCCESS,
            Ok(Reply::Error(e)) | Err(e) => {
                eprintln!("net: {e}");
                ExitCode::FAILURE
            }
            Ok(Reply::Status(_) | Reply::Snapshot(_)) => ExitCode::FAILURE,
        },
        ["reconcile"] => match call(&Request::Reconcile) {
            Ok(Reply::Ok) => ExitCode::SUCCESS,
            Ok(Reply::Error(e)) | Err(e) => {
                eprintln!("net: {e}");
                ExitCode::FAILURE
            }
            Ok(Reply::Status(_) | Reply::Snapshot(_)) => ExitCode::FAILURE,
        },
        ["rules"] => rules(),
        ["profiles"] | ["profile", "list"] => profiles(),
        ["wait", level] | ["wait", level, _] => {
            let Some(level) = Level::parse(level) else {
                return usage();
            };
            let timeout = words.get(2).and_then(|t| t.parse().ok()).unwrap_or(60);
            wait(level, timeout)
        }
        _ => usage(),
    }
}
