//! `net` — the netd operator command.
//!
//! Talks to netd over its control socket; `profile` reads the registry
//! directly, because profiles are configuration and netd merely consumes
//! them. Changing the network is a registry write (`reg`); this command
//! shows state and pokes the daemon.

use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use libnetd::{CONTROL_SOCKET_PATH, Level, NETWORK_KEY, Reply, Request, Status};
use peios::registry::{Key, KeyAccess, OpenFlags};

fn usage() -> ExitCode {
    eprintln!(
        "usage: net status\n       net renew <interface>\n       net reconcile\n       net profile list\n       net wait <link|addressed|routed> [timeout-seconds]"
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
        Reply::Ok => Err("unexpected reply".into()),
    }
}

fn print_status(s: &Status) {
    println!("hostname  {}", if s.hostname.is_empty() { "(unset)" } else { &s.hostname });
    println!("level     {}", s.level.as_str());
    for i in &s.interfaces {
        println!();
        println!("{}  [{}]", i.name, i.ifid);
        println!("  profile   {}", i.profile.as_deref().unwrap_or("(none)"));
        println!(
            "  state     {}{}{}{}",
            if i.up { "up" } else { "down" },
            if i.carrier { ", carrier" } else { ", no-carrier" },
            if i.managed { "" } else { ", unmanaged" },
            if i.enabled { "" } else { ", disabled" }
        );
        println!("  level     {}", i.level.as_str());
        if !i.mac.is_empty() {
            println!("  hardware  {} {} {}", i.mac, i.path, i.driver);
        }
        for a in &i.addresses {
            println!("  address   {a}");
        }
        if let Some(g) = &i.gateway {
            println!("  gateway   {g}");
        }
        if !i.dns.is_empty() {
            println!("  dns       {}", i.dns.join(" "));
        }
        if !i.search.is_empty() {
            println!("  search    {}", i.search.join(" "));
        }
        if let Some(l) = &i.lease {
            println!("  lease     {} from {}, {}s left", l.state, l.server, l.expires_in);
        }
    }
}

fn profile_list() -> ExitCode {
    let path = format!("{NETWORK_KEY}\\Profiles");
    let key = match Key::open(None, &path, KeyAccess::ENUMERATE_SUB_KEYS | KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("net: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    for sub in key.subkeys(None).flatten() {
        let name = String::from_utf8_lossy(&sub.name).into_owned();
        let p = Key::open(Some(&key), &name, KeyAccess::QUERY_VALUE, OpenFlags::empty()).ok();
        let priority = p
            .as_ref()
            .and_then(|p| p.query_value(b"Priority", None).ok())
            .filter(|v| v.data.len() == 4)
            .map(|v| u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]))
            .unwrap_or(100);
        println!("{name}\tpriority {priority}");
    }
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
        ["renew", interface] => match call(&Request::Renew { interface: (*interface).to_owned() }) {
            Ok(Reply::Ok) => ExitCode::SUCCESS,
            Ok(Reply::Error(e)) | Err(e) => {
                eprintln!("net: {e}");
                ExitCode::FAILURE
            }
            Ok(Reply::Status(_)) => ExitCode::FAILURE,
        },
        ["reconcile"] => match call(&Request::Reconcile) {
            Ok(Reply::Ok) => ExitCode::SUCCESS,
            Ok(Reply::Error(e)) | Err(e) => {
                eprintln!("net: {e}");
                ExitCode::FAILURE
            }
            Ok(Reply::Status(_)) => ExitCode::FAILURE,
        },
        ["profile", "list"] => profile_list(),
        ["wait", level] | ["wait", level, _] => {
            let Some(level) = Level::parse(level) else { return usage() };
            let timeout = words.get(2).and_then(|t| t.parse().ok()).unwrap_or(60);
            wait(level, timeout)
        }
        _ => usage(),
    }
}
