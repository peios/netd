use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use netd_client::{Client, InterfaceFacts, Level, Outcome, Policy, RawKey, RawValue, Snapshot, Status};
use netd_core::{Reply, Request};

static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);
const TIMEOUT: Duration = Duration::from_secs(2);

struct Server {
    directory: PathBuf,
    path: PathBuf,
    listener: UnixListener,
}

impl Server {
    fn new() -> Self {
        let id = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!("netd-abi-{}-{id}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        Self {
            directory,
            path,
            listener,
        }
    }

    fn client(&self) -> Client {
        Client::new(&self.path, TIMEOUT).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn status_round_trips_through_the_shared_library() {
    let server = Server::new();
    let expected = Status {
        hostname: "workstation".into(),
        level: Level::Routed,
        refusal: Some("last good policy retained".into()),
        interfaces: vec![netd_client::InterfaceStatus {
            ifid: "stable-id".into(),
            name: "eth0".into(),
            index: 7,
            mac: "00:11:22:33:44:55".into(),
            path: "pci/path".into(),
            driver: "driver".into(),
            verdict: Some("JOIN".into()),
            rule: Some("wired".into()),
            profile: Some("office".into()),
            network: Some("network-id".into()),
            network_name: Some("Office".into()),
            network_trust: Some("private".into()),
            warning: Some("diagnostic".into()),
            up: true,
            carrier: true,
            level: Level::Routed,
            addresses: vec!["192.0.2.3/24".into(), "2001:db8::3/64".into()],
            gateway: Some("192.0.2.1".into()),
            gateway6: Some("fe80::1".into()),
            dns: vec!["192.0.2.53".into()],
            search: vec!["example.test".into()],
            lease: Some(netd_client::LeaseStatus {
                server: "192.0.2.2".into(),
                state: "bound".into(),
                expires_in: 60,
                duration: 120,
                renew_at: 60,
                rebind_at: 105,
            }),
        }],
    };
    std::thread::scope(|threads| {
        threads.spawn(|| {
            let (mut peer, _) = server.listener.accept().unwrap();
            peer.set_read_timeout(Some(TIMEOUT)).unwrap();
            assert_eq!(
                Request::decode(&netd_core::recv(&mut peer).unwrap()).unwrap(),
                Request::Status
            );
            netd_core::send(&mut peer, &Reply::Status(expected.clone()).encode()).unwrap();
        });
        assert_eq!(server.client().status().unwrap(), expected);
    });
}

#[test]
fn a_subscription_keeps_partial_framing_across_timeout() {
    let server = Server::new();
    let expected = Snapshot {
        hostname: "box".into(),
        scopes: vec![netd_client::DnsScope {
            ifid: "id".into(),
            name: "eth0".into(),
            servers: vec!["192.0.2.53".into()],
            domains: vec!["example.test".into()],
            ntp: vec!["192.0.2.123".into()],
            addresses: vec!["192.0.2.10/24".into()],
            default_route: true,
            exclusive: true,
            metric: 30,
            level: Level::Routed,
        }],
    };
    let (ready_tx, ready_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    std::thread::scope(|threads| {
        let server = &server;
        let expected = &expected;
        threads.spawn(move || {
            let (mut peer, _) = server.listener.accept().unwrap();
            peer.set_read_timeout(Some(TIMEOUT)).unwrap();
            assert_eq!(
                Request::decode(&netd_core::recv(&mut peer).unwrap()).unwrap(),
                Request::Subscribe
            );
            let body = Reply::Snapshot(expected.clone()).encode();
            let mut frame = (body.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(&body);
            peer.write_all(&frame[..2]).unwrap();
            ready_tx.send(()).unwrap();
            continue_rx.recv_timeout(TIMEOUT).unwrap();
            peer.write_all(&frame[2..]).unwrap();
        });
        let mut subscription = server.client().subscribe().unwrap();
        ready_rx.recv_timeout(TIMEOUT).unwrap();
        assert_eq!(
            subscription
                .next_snapshot(Duration::from_millis(10))
                .unwrap_err()
                .code,
            libc::ETIMEDOUT
        );
        continue_tx.send(()).unwrap();
        assert_eq!(subscription.next_snapshot(TIMEOUT).unwrap(), *expected);
    });
}

#[test]
fn closed_mid_frame_subscription_is_not_reused() {
    let server = Server::new();
    std::thread::scope(|threads| {
        threads.spawn(|| {
            let (mut peer, _) = server.listener.accept().unwrap();
            peer.set_read_timeout(Some(TIMEOUT)).unwrap();
            netd_core::recv(&mut peer).unwrap();
            peer.write_all(&[20, 0, 0, 0, 1]).unwrap();
        });
        let mut subscription = server.client().subscribe().unwrap();
        assert!(subscription.next_snapshot(TIMEOUT).is_err());
        assert_eq!(
            subscription.next_snapshot(TIMEOUT).unwrap_err().code,
            libc::ENOTCONN
        );
    });
}

#[test]
fn command_is_sent_once_and_wrong_reply_kind_is_rejected() {
    let server = Server::new();
    std::thread::scope(|threads| {
        threads.spawn(|| {
            let (mut peer, _) = server.listener.accept().unwrap();
            peer.set_read_timeout(Some(TIMEOUT)).unwrap();
            assert_eq!(
                Request::decode(&netd_core::recv(&mut peer).unwrap()).unwrap(),
                Request::Reconcile
            );
            netd_core::send(&mut peer, &Reply::Status(Status::default()).encode()).unwrap();
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).unwrap(), 0);
        });
        assert_eq!(server.client().reconcile().unwrap_err().code, libc::EINVAL);
    });
}

fn key(name: &str, values: Vec<(&str, RawValue)>, children: Vec<RawKey>) -> RawKey {
    RawKey {
        name: name.into(),
        values: values
            .into_iter()
            .map(|(name, value)| (name.into(), value))
            .collect(),
        children,
    }
}

#[test]
fn configuration_validation_and_policy_preview_use_the_shared_library() {
    let profiles = key(
        "Profiles",
        vec![],
        vec![key(
            "office",
            vec![
                ("Address.Offered", RawValue::Int(1)),
                ("Address.Static", RawValue::Str("192.0.2.5/24".into())),
                ("Route.Gateway", RawValue::Str("192.0.2.1".into())),
                ("Route.Metric", RawValue::Int(42)),
                ("Mtu.Value", RawValue::Int(1400)),
                ("Address.OnExpiry", RawValue::Str("Keep".into())),
                ("Dns.Servers", RawValue::List(vec!["192.0.2.53".into()])),
                ("Dns.Default", RawValue::Int(0)),
            ],
            vec![key("child", vec![], vec![])],
        )],
    );
    let rules = key(
        "Interface",
        vec![],
        vec![key(
            "all",
            vec![("Actions", RawValue::List(vec!["JOIN(OFFICE/CHILD)".into()]))],
            vec![],
        )],
    );
    let policy = Policy::build(Some(&rules), Some(&profiles)).unwrap();
    drop(profiles);
    drop(rules);
    let profiles = policy.profiles().unwrap();
    assert_eq!(profiles.len(), 2);
    let judgment = policy.judge(&InterfaceFacts::default()).unwrap();
    let Outcome::Join(profile) = judgment.outcome else {
        panic!("expected JOIN");
    };
    assert_eq!(profile, profiles[1]);
    assert_eq!(profile.path, "office/child");
    assert_eq!(profile.address.route_metric, Some(42));
    assert_eq!(profile.address.mtu, Some(1400));
    assert_eq!(profile.dns.default_route, Some(false));
    assert_eq!(profile.address.statics[0].address.to_string(), "192.0.2.5");
    assert_eq!(
        netd_client::check_hostname("  workstation  ").unwrap(),
        "workstation"
    );
    assert!(netd_client::check_hostname("not.a.host").is_err());
}
