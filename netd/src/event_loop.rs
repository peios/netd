//! Poll owned sockets, dispatch protocol messages, and advance monotonic timers.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::process::ExitCode;
use std::time::Instant;

use peios::registry::Key;

use crate::{Netd, config, control, dhcp, log, read_configuration_update};
use crate::model::is_v6_link_local;
use crate::netlink::Rtnl;

const WATCH_BUFFER_BYTES: usize = 16 * 1024;

pub(super) fn run(
    mut netd: Netd,
    listener: UnixListener,
    absorber: Option<dhcp::Absorber>,
    mut watch: Option<Key>,
) -> ExitCode {
    let mut clients = control::Clients::default();
    let mut watch_buffer = vec![0u8; WATCH_BUFFER_BYTES];
    loop {
        let now = Instant::now();
        let timeout_ms = poll_timeout(&netd, &clients, now);

        let PollSet {
            mut fds,
            control_slots,
            watch_slot,
            absorber_slot,
            dhcp_slots,
            ndp_slots,
            dhcp6_slots,
        } = PollSet::new(
            &netd,
            &clients,
            &listener,
            watch.as_ref(),
            absorber.as_ref(),
        );

        // SAFETY: `fds` is a live, exclusively borrowed array for the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::error(format_args!("poll: {e}"));
            return ExitCode::FAILURE;
        }
        let now = Instant::now();
        let mut converge = false;
        let mut reconcile = false;

        if fds[0].revents != 0 && netd.rtnl.drain_events() {
            // Always converge: the state may already have been dumped after
            // an apply without the decisions that follow from it being made.
            match netd.rtnl.dump() {
                Ok(o) => {
                    netd.observed = o;
                    converge = true;
                }
                Err(e) => log::warn(format_args!("netlink dump: {e}")),
            }
        }
        converge |= reload(&mut netd, &fds, watch_slot, &mut watch, &mut watch_buffer);
        if let Some(slot) = absorber_slot
            && fds[slot].revents != 0
            && let Some(a) = &absorber
        {
            a.drain();
        }
        reconcile |= receive_dhcp(&mut netd, &fds, &dhcp_slots, now);
        converge |= receive_ndp(&mut netd, &fds, &ndp_slots, now);
        reconcile |= receive_dhcp6(&mut netd, &fds, &dhcp6_slots, now);
        let (timer_converge, timer_reconcile) = tick(&mut netd, now);
        converge |= timer_converge;
        reconcile |= timer_reconcile;
        clients.expire(Instant::now());
        for (fd, slot) in control_slots {
            if fds[slot].revents != 0
                && let Some((stream, request)) = clients.service(fd, Instant::now())
                && let Some((stream, reply)) = netd.handle_control(stream, request)
            {
                clients.reply(stream, &reply, Instant::now());
            }
        }
        if fds[1].revents != 0 {
            clients.accept(&listener, Instant::now());
        }
        if netd.interfaces.values().any(|i| i.rejudge) {
            converge = true;
        }

        if converge {
            netd.converge(now);
        } else if reconcile {
            netd.reconcile_all();
            netd.apply_hostname();
            netd.publish();
        }
    }
}

fn poll_timeout(netd: &Netd, clients: &control::Clients, now: Instant) -> i32 {
    // Timers.
    let mut deadline: Option<Instant> = None;
    let mut consider = |t: Option<Instant>| {
        if let Some(t) = t {
            deadline = Some(deadline.map_or(t, |x: Instant| x.min(t)));
        }
    };
    for i in netd.interfaces.values() {
        if let Some(d) = &i.dhcp {
            consider(d.client.next_deadline());
        }
        if let Some(n) = &i.ndp {
            consider(n.engine.next_deadline());
        }
        if let Some(d) = &i.dhcp6 {
            consider(d.client.next_deadline());
        }
    }
    consider(clients.next_deadline());
    match deadline {
        Some(t) => t
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32,
        None => -1,
    }
}

struct PollSet {
    fds: Vec<libc::pollfd>,
    control_slots: Vec<(i32, usize)>,
    watch_slot: Option<usize>,
    absorber_slot: Option<usize>,
    dhcp_slots: Vec<(u32, usize)>,
    ndp_slots: Vec<(u32, usize)>,
    dhcp6_slots: Vec<(u32, usize)>,
}

impl PollSet {
    fn new(
        netd: &Netd,
        clients: &control::Clients,
        listener: &UnixListener,
        watch: Option<&Key>,
        absorber: Option<&dhcp::Absorber>,
    ) -> Self {
        // Poll set: [rtnl, control, watch?, absorber?, dhcp sockets...]
        let mut fds: Vec<libc::pollfd> = Vec::new();
        fn push(fds: &mut Vec<libc::pollfd>, fd: i32) -> usize {
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
            fds.len() - 1
        }
        push(&mut fds, netd.rtnl.as_raw_fd());
        push(
            &mut fds,
            if clients.can_accept() {
                listener.as_raw_fd()
            } else {
                -1
            },
        );
        let control_slots: Vec<_> = clients
            .fds()
            .into_iter()
            .map(|(fd, events)| {
                let slot = push(&mut fds, fd);
                fds[slot].events = events;
                (fd, slot)
            })
            .collect();
        let watch_slot = watch.as_ref().map(|w| push(&mut fds, w.as_raw_fd()));
        let absorber_slot = absorber
            .as_ref()
            .map(|a| push(&mut fds, a.fd().as_raw_fd()));
        let dhcp_fds: Vec<(u32, i32)> = netd
            .interfaces
            .iter()
            .filter_map(|(index, i)| i.dhcp.as_ref().map(|d| (*index, d.socket.fd().as_raw_fd())))
            .collect();
        let dhcp_slots: Vec<(u32, usize)> = dhcp_fds
            .into_iter()
            .map(|(index, fd)| (index, push(&mut fds, fd)))
            .collect();
        let ndp_fds: Vec<(u32, i32)> = netd
            .interfaces
            .iter()
            .filter_map(|(index, i)| i.ndp.as_ref().map(|n| (*index, n.socket.fd().as_raw_fd())))
            .collect();
        let ndp_slots: Vec<(u32, usize)> = ndp_fds
            .into_iter()
            .map(|(index, fd)| (index, push(&mut fds, fd)))
            .collect();
        let dhcp6_fds: Vec<(u32, i32)> = netd
            .interfaces
            .iter()
            .filter_map(|(index, i)| {
                i.dhcp6
                    .as_ref()
                    .map(|d| (*index, d.socket.fd().as_raw_fd()))
            })
            .collect();
        let dhcp6_slots: Vec<(u32, usize)> = dhcp6_fds
            .into_iter()
            .map(|(index, fd)| (index, push(&mut fds, fd)))
            .collect();

        Self {
            fds,
            control_slots,
            watch_slot,
            absorber_slot,
            dhcp_slots,
            ndp_slots,
            dhcp6_slots,
        }
    }
}

fn reload(
    netd: &mut Netd,
    fds: &[libc::pollfd],
    watch_slot: Option<usize>,
    watch: &mut Option<Key>,
    watch_buffer: &mut [u8],
) -> bool {
    if let Some(slot) = watch_slot
        && fds[slot].revents != 0
        && let Some(w) = watch.as_ref()
    {
        match w.read_watch_events(watch_buffer) {
            Ok(events) if !events.is_empty() => {
                // Our own inventory writes come back here too; a
                // reload is idempotent, so that is merely cheap.
                // Converge regardless: `Interfaces\<ifid> Enabled`
                // is read during the pass, not held in Config.
                if let Ok(fresh) = read_configuration_update() {
                    if fresh != netd.config {
                        log::info(format_args!("configuration changed"));
                        netd.control =
                            control::ControlObject::new(fresh.control_security.as_deref());
                        if fresh.rules != netd.config.rules
                            || fresh.profiles != netd.config.profiles
                        {
                            netd.take_generation(&fresh);
                        }
                        netd.config = fresh;
                    }
                    return true;
                }
            }
            Ok(_) => {}
            Err(e) => {
                log::warn(format_args!("registry watch: {e}; re-arming"));
                *watch = config::watch().ok();
            }
        }
    }
    false
}
fn receive_dhcp(
    netd: &mut Netd,
    fds: &[libc::pollfd],
    slots: &[(u32, usize)],
    now: Instant,
) -> bool {
    let mut reconcile = false;
    for (index, slot) in slots {
        if fds[*slot].revents == 0 {
            continue;
        }
        if let Some(i) = netd.interfaces.get_mut(index) {
            let messages = i
                .dhcp
                .as_ref()
                .map(|d| d.socket.receive())
                .unwrap_or_default();
            for m in messages {
                let actions = i
                    .dhcp
                    .as_mut()
                    .map(|d| d.client.receive(now, &m))
                    .unwrap_or_default();
                reconcile |= i.perform(actions, now);
            }
        }
    }

    reconcile
}

fn receive_ndp(
    netd: &mut Netd,
    fds: &[libc::pollfd],
    slots: &[(u32, usize)],
    now: Instant,
) -> bool {
    let mut converge = false;
    for (index, slot) in slots {
        if fds[*slot].revents == 0 {
            continue;
        }
        if let Some(i) = netd.interfaces.get_mut(index) {
            let messages = i
                .ndp
                .as_ref()
                .map(|n| n.socket.receive())
                .unwrap_or_default();
            for (source, hops, body) in messages {
                // RFC 4861 §6.1.2: a hop limit under 255 crossed a
                // router, and a non-link-local source is not a router
                // on this link. Both are spoofs; both are dropped.
                if hops != 255 || !is_v6_link_local(&source) {
                    continue;
                }
                let actions = i
                    .ndp
                    .as_mut()
                    .map(|n| n.engine.receive(now, source, &body))
                    .unwrap_or_default();
                // Converge, not merely reconcile: a changed RA can call
                // for starting DHCPv6, which is a converge decision.
                converge |= i.perform_ndp(actions);
            }
        }
    }

    converge
}

fn receive_dhcp6(
    netd: &mut Netd,
    fds: &[libc::pollfd],
    slots: &[(u32, usize)],
    now: Instant,
) -> bool {
    let mut reconcile = false;
    for (index, slot) in slots {
        if fds[*slot].revents == 0 {
            continue;
        }
        if let Some(i) = netd.interfaces.get_mut(index) {
            let messages = i
                .dhcp6
                .as_ref()
                .map(|d| d.socket.receive())
                .unwrap_or_default();
            for m in messages {
                let actions = i
                    .dhcp6
                    .as_mut()
                    .map(|d| d.client.receive(now, &m))
                    .unwrap_or_default();
                reconcile |= i.perform_dhcp6(actions);
            }
        }
    }

    reconcile
}

fn tick(netd: &mut Netd, now: Instant) -> (bool, bool) {
    let mut reconcile = false;
    let mut converge = false;
    // Timers, for every client.
    for i in netd.interfaces.values_mut() {
        let actions = i
            .dhcp
            .as_mut()
            .map(|d| d.client.tick(now))
            .unwrap_or_default();
        reconcile |= i.perform(actions, now);
        let actions = i
            .ndp
            .as_mut()
            .map(|n| n.engine.tick(now))
            .unwrap_or_default();
        converge |= i.perform_ndp(actions);
        let actions = i
            .dhcp6
            .as_mut()
            .map(|d| d.client.tick(now))
            .unwrap_or_default();
        reconcile |= i.perform_dhcp6(actions);
    }
    (converge, reconcile)
}
