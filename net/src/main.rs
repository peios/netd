//! `net` — the netd operator command.
//!
//! Talks to netd over its control socket; `rules` and `profiles` read the
//! registry directly, because the interface layer and its profiles are
//! configuration and netd merely executes them. Changing the network is a
//! registry write (`reg`); this command shows state and pokes the daemon.

mod deadline;
mod policy;

use std::time::{Duration, Instant};
use std::process::ExitCode;

use netd_client::{Client, Level, NETWORK_KEY, Status};
use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};

fn usage() -> ExitCode {
    eprintln!(
        "usage: net status\n       net renew <interface>\n       net reconcile\n       net rules\n       net profiles\n       net wait <link|addressed|routed> [timeout-seconds]\n       net policy\n       net policy wait [timeout-seconds]\n       net version"
    );
    ExitCode::from(2)
}

fn version() -> ExitCode {
    println!("net {}", env!("CARGO_PKG_VERSION"));
    ExitCode::SUCCESS
}

/// The daemon bounds pending requests to two seconds; allow scheduling overhead
/// without letting an unavailable daemon stall the operator command indefinitely.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

fn client() -> Result<Client, String> {
    Client::system(CONTROL_TIMEOUT).map_err(|error| error.to_string())
}

fn status() -> Result<Status, String> {
    client()?.status().map_err(|error| error.to_string())
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
            if i.carrier {
                ", carrier"
            } else {
                ", no-carrier"
            },
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
                .filter(|n| {
                    !matches!(n.as_str(), "Actions" | "Priority" | "Enabled") && !n.is_empty()
                })
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
            dword(key, "Priority")
                .map(|p| format!(" [{p}]"))
                .unwrap_or_default(),
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
                    dword(key, &n)
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "(none)".into())
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
    let deadline = match deadline::after(Duration::from_secs(timeout)) {
        Ok(deadline) => deadline,
        Err(error) => return command_result(Err(error.to_owned())),
    };
    loop {
        let Some(budget) = deadline::budget(deadline, Instant::now(), CONTROL_TIMEOUT) else {
            return command_result(Err(format!("timed out waiting for {}", level.as_str())));
        };
        let status = Client::system(budget)
            .and_then(|client| client.status())
            .map_err(|error| error.to_string());
        match status {
            Ok(status) if status.level >= level => return ExitCode::SUCCESS,
            Ok(_) => {}
            Err(error) => eprintln!("net: {error}"),
        }
        if let Some(pause) = deadline::budget(deadline, Instant::now(), Duration::from_millis(500))
        {
            std::thread::sleep(pause);
        }
    }
}

fn command_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("net: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["version"] | ["--version"] => version(),
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
        ["renew", interface] => command_result(
            client().and_then(|client| client.renew(interface).map_err(|error| error.to_string())),
        ),
        ["reconcile"] => command_result(
            client().and_then(|client| client.reconcile().map_err(|error| error.to_string())),
        ),
        ["rules"] => rules(),
        ["policy"] => policy::show(),
        ["policy", "wait"] => policy::wait(std::time::Duration::from_secs(10)),
        ["policy", "wait", seconds] => match seconds.parse::<u64>() {
            Ok(s) => policy::wait(std::time::Duration::from_secs(s)),
            Err(_) => usage(),
        },
        ["profiles"] | ["profile", "list"] => profiles(),
        ["wait", level] | ["wait", level, _] => {
            let Some(level) = Level::parse(level) else {
                return usage();
            };
            let timeout = match words.get(2) {
                Some(value) => match value.parse() {
                    Ok(timeout) => timeout,
                    Err(_) => return usage(),
                },
                None => 60,
            };
            wait(level, timeout)
        }
        _ => usage(),
    }
}
