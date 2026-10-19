//! The control socket: `/run/netd/control.sock`, one request per connection,
//! authorised against the netd control object.
//!
//! The object is `Machine\System\Network\ControlSecurity` when set, else a
//! compiled default — Everyone may query, SYSTEM and Administrators may
//! control. The check is a real KACS access check against the peer's token,
//! never `SO_PEERCRED`, so a deny-only group or a filtered token is judged as
//! the kernel would judge it anywhere else.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use netd_core::{
    CONTROL_SOCKET_PATH, NETD_RUN_DIR, NETWORK_ALL_ACCESS, NETWORK_CONTROL, NETWORK_QUERY, Reply,
    Request,
};
use peios::access::AccessCheck;
use peios::security::{
    AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown,
};
use peios::token::Token;

use crate::log;

const DIRECTORY_MODE: u32 = 0o755;
const SOCKET_MODE: u32 = 0o666;

pub fn listen() -> io::Result<UnixListener> {
    let directory = Path::new(NETD_RUN_DIR);
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(DIRECTORY_MODE))?;
    protect(directory);
    let path = Path::new(CONTROL_SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale {CONTROL_SOCKET_PATH}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    protect(path);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Everyone may connect; the object check decides what they may do. peinit
/// seeds `/run` SYSTEM-only and inheritable, so without this the socket is
/// unreachable by anyone else.
fn protect(path: &Path) {
    use peios::file::SecInfo;
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let descriptor = AclBuilder::new()
        .allow(
            system.as_ref(),
            AccessMask::GENERIC_ALL.bits(),
            AceFlags::empty(),
        )
        .allow(
            everyone.as_ref(),
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits(),
            AceFlags::empty(),
        )
        .build()
        .and_then(|dacl| {
            SdBuilder::new()
                .owner(system.as_ref())
                .group(system.as_ref())
                .dacl(&dacl)
                .build()
        });
    match descriptor {
        Ok(sd) => {
            if let Err(e) = peios::file::set_sd(
                None,
                path,
                SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
                &sd,
                0,
            ) {
                log::error(format_args!(
                    "could not set a descriptor on {}: {e}",
                    path.display()
                ));
            }
        }
        Err(e) => log::warn(format_args!("could not build a descriptor: {e}")),
    }
}

/// The control object's descriptor.
pub struct ControlObject {
    sd: SecurityDescriptor,
}

impl ControlObject {
    pub fn new(configured: Option<&[u8]>) -> ControlObject {
        if let Some(bytes) = configured {
            match SecurityDescriptor::from_validated_bytes(bytes.to_vec()) {
                Ok(sd) => return ControlObject { sd },
                Err(e) => log::warn(format_args!(
                    "ControlSecurity is not a valid descriptor ({e}); using the default"
                )),
            }
        }
        ControlObject {
            sd: Self::default_sd(),
        }
    }

    fn default_sd() -> SecurityDescriptor {
        let system = Sid::well_known(WellKnown::System);
        let administrators = Sid::well_known(WellKnown::Administrators);
        let everyone = Sid::well_known(WellKnown::Everyone);
        AclBuilder::new()
            .allow(system.as_ref(), NETWORK_ALL_ACCESS, AceFlags::empty())
            .allow(
                administrators.as_ref(),
                NETWORK_ALL_ACCESS,
                AceFlags::empty(),
            )
            .allow(
                everyone.as_ref(),
                NETWORK_QUERY | AccessMask::READ_CONTROL.bits(),
                AceFlags::empty(),
            )
            .build()
            .and_then(|dacl| {
                SdBuilder::new()
                    .owner(system.as_ref())
                    .group(system.as_ref())
                    .dacl(&dacl)
                    .build()
            })
            .expect("the compiled default descriptor builds")
    }

    fn mapping() -> GenericMapping {
        let rc = AccessMask::READ_CONTROL.bits();
        GenericMapping::new(
            NETWORK_QUERY | rc,
            NETWORK_CONTROL | rc,
            NETWORK_QUERY,
            NETWORK_ALL_ACCESS,
        )
    }

    /// Whether the peer holds `right`: `Some` if it does, carrying who it
    /// is, so that a change netd makes on its behalf can name it in the
    /// record (`netd.hostname.changed`'s `subject.token.sid`).
    pub fn permits(&self, stream: &UnixStream, right: u32) -> Option<Caller> {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("control: no peer token: {e}"));
                return None;
            }
        };
        let allowed = AccessCheck::new(
            &self.sd,
            AccessMask::from_bits_retain(right),
            Self::mapping(),
        )
        .token(token.as_fd())
        .check()
        .map(|d| d.allowed)
        .unwrap_or(false);
        if !allowed {
            return None;
        }
        // What netd does for the peer is recorded as the peer's (PGSS
        // §6.4), so a peer whose user cannot be read is refused rather than
        // served anonymously.
        match token.user() {
            Ok(sid) => Some(Caller { sid }),
            Err(e) => {
                log::warn(format_args!(
                    "control: cannot read the user of a peer's token ({e}); refusing"
                ));
                None
            }
        }
    }
}

/// A peer the control object admitted.
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    /// The user SID of the peer's token.
    pub sid: Sid,
}

// Pending requests and replies have fixed deadlines, so trickling bytes
// cannot retain a slot forever. Subscribers move to the existing publisher.
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CLIENTS: usize = 64;
const ACCEPT_BATCH: usize = 16;
const IO_CHUNK: usize = 4096;

#[derive(Default)]
pub struct Clients {
    pending: HashMap<RawFd, Client>,
}

struct Client {
    stream: UnixStream,
    deadline: Instant,
    state: State,
}

enum State {
    Reading(Vec<u8>),
    Writing { frame: Vec<u8>, sent: usize },
}

enum Progress {
    Pending,
    Request(Result<Request, netd_core::WireError>),
    Closed,
}

impl Clients {
    pub fn can_accept(&self) -> bool {
        self.pending.len() < MAX_CLIENTS
    }

    pub fn accept(&mut self, listener: &UnixListener, now: Instant) {
        for _ in 0..ACCEPT_BATCH {
            if !self.can_accept() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Err(e) = self.add(stream, now) {
                        log::warn(format_args!("control: nonblocking: {e}"));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::warn(format_args!("control: accept: {e}"));
                    break;
                }
            }
        }
    }

    fn add(&mut self, stream: UnixStream, now: Instant) -> io::Result<()> {
        stream.set_nonblocking(true)?;
        self.pending.insert(
            stream.as_raw_fd(),
            Client {
                stream,
                deadline: now + IO_TIMEOUT,
                state: State::Reading(Vec::with_capacity(4)),
            },
        );
        Ok(())
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|c| c.deadline).min()
    }

    pub fn expire(&mut self, now: Instant) {
        self.pending.retain(|_, c| c.deadline > now);
    }

    pub fn fds(&self) -> Vec<(RawFd, i16)> {
        self.pending
            .iter()
            .map(|(&fd, c)| {
                (
                    fd,
                    match c.state {
                        State::Reading(_) => libc::POLLIN,
                        State::Writing { .. } => libc::POLLOUT,
                    },
                )
            })
            .collect()
    }

    pub fn service(&mut self, fd: RawFd, now: Instant) -> Option<(UnixStream, Request)> {
        let mut client = self.pending.remove(&fd)?;
        if client.deadline <= now {
            return None;
        }
        match client.advance() {
            Progress::Request(Ok(request)) => return Some((client.stream, request)),
            Progress::Request(Err(e)) => client.reply(&Reply::Error(e.to_string()), now),
            Progress::Closed => return None,
            Progress::Pending => {}
        }
        self.pending.insert(fd, client);
        None
    }

    pub fn reply(&mut self, stream: UnixStream, reply: &Reply, now: Instant) {
        // Only streams taken from this collection are returned here, already
        // nonblocking, and a completed request has just freed their slot.
        let mut client = Client {
            stream,
            deadline: now,
            state: State::Reading(Vec::new()),
        };
        client.reply(reply, now);
        self.pending.insert(client.stream.as_raw_fd(), client);
    }
}

impl Client {
    fn reply(&mut self, reply: &Reply, now: Instant) {
        let mut payload = reply.encode();
        if payload.len() > netd_core::MAX_MESSAGE_BYTES {
            payload =
                Reply::Error(netd_core::WireError::TooLarge(payload.len()).to_string()).encode();
        }
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend(payload);
        self.state = State::Writing { frame, sent: 0 };
        self.deadline = now + IO_TIMEOUT;
    }

    fn advance(&mut self) -> Progress {
        match &mut self.state {
            State::Reading(buf) => {
                // Read only the header until its length has been checked.
                let target = if buf.len() < 4 {
                    4
                } else {
                    4 + u32::from_le_bytes(buf[..4].try_into().expect("header")) as usize
                };
                let mut chunk = [0; IO_CHUNK];
                let count = (target - buf.len()).min(chunk.len());
                match self.stream.read(&mut chunk[..count]) {
                    Ok(0) => {
                        return Progress::Request(Err(io::Error::from(
                            io::ErrorKind::UnexpectedEof,
                        )
                        .into()));
                    }
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        return Progress::Pending;
                    }
                    Err(_) => return Progress::Closed,
                }
                if buf.len() >= 4 {
                    let len = u32::from_le_bytes(buf[..4].try_into().expect("header")) as usize;
                    if len > netd_core::MAX_MESSAGE_BYTES {
                        return Progress::Request(Err(netd_core::WireError::TooLarge(len)));
                    }
                    if buf.len() == 4 + len {
                        return Progress::Request(Request::decode(&buf[4..]));
                    }
                }
                Progress::Pending
            }
            State::Writing { frame, sent } => {
                let end = (*sent + IO_CHUNK).min(frame.len());
                match self.stream.write(&frame[*sent..end]) {
                    Ok(0) => Progress::Closed,
                    Ok(n) => {
                        *sent += n;
                        if *sent == frame.len() {
                            Progress::Closed
                        } else {
                            Progress::Pending
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        Progress::Pending
                    }
                    Err(_) => Progress::Closed,
                }
            }
        }
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use std::net::Shutdown;

    fn socket_pair(clients: &mut Clients, now: Instant) -> (RawFd, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        let fd = stream.as_raw_fd();
        clients.add(stream, now).unwrap();
        (fd, peer)
    }

    fn frame(request: &Request) -> Vec<u8> {
        let payload = request.encode();
        let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn idle_and_partial_clients_do_not_delay_a_complete_half_closed_request() {
        let now = Instant::now();
        let mut clients = Clients::default();
        let (idle, _idle_peer) = socket_pair(&mut clients, now);
        let (partial, mut partial_peer) = socket_pair(&mut clients, now);
        partial_peer.write_all(&[12, 0]).unwrap();
        assert!(clients.service(idle, now).is_none());
        assert!(clients.service(partial, now).is_none());
        let (ready, mut ready_peer) = socket_pair(&mut clients, now);
        ready_peer.write_all(&frame(&Request::Status)).unwrap();
        ready_peer.shutdown(Shutdown::Write).unwrap();
        assert!(clients.service(ready, now).is_none()); // header
        let (stream, request) = clients.service(ready, now).unwrap();
        assert!(matches!(request, Request::Status));
        clients.reply(stream, &Reply::Ok, now);
        assert!(clients.service(ready, now).is_none());
        assert!(matches!(
            Reply::decode(&netd_core::recv(&mut ready_peer).unwrap()),
            Ok(Reply::Ok)
        ));
        assert_eq!(clients.pending.len(), 2);
        assert_eq!(clients.next_deadline(), Some(now + IO_TIMEOUT));
    }

    #[test]
    fn trickling_a_partial_header_does_not_extend_the_deadline() {
        let now = Instant::now();
        let mut clients = Clients::default();
        let (fd, mut peer) = socket_pair(&mut clients, now);
        peer.write_all(&[10]).unwrap();
        assert!(clients.service(fd, now + Duration::from_secs(1)).is_none());
        assert_eq!(clients.next_deadline(), Some(now + IO_TIMEOUT));
        clients.expire(now + IO_TIMEOUT);
        assert!(clients.pending.is_empty());
    }

    #[test]
    fn oversized_header_is_rejected_without_reading_its_payload() {
        let now = Instant::now();
        let mut clients = Clients::default();
        let (fd, mut peer) = socket_pair(&mut clients, now);
        peer.write_all(&65_537u32.to_le_bytes()).unwrap();
        assert!(clients.service(fd, now).is_none());
        assert_eq!(clients.fds()[0].1, libc::POLLOUT);
        clients.service(fd, now);
        match Reply::decode(&netd_core::recv(&mut peer).unwrap()).unwrap() {
            Reply::Error(e) => assert_eq!(e, "message of 65537 bytes exceeds the ceiling"),
            _ => panic!("oversized request was accepted"),
        }
        assert!(clients.pending.is_empty());
    }

    #[test]
    fn incomplete_eof_and_invalid_payload_are_answered_as_errors() {
        for bytes in [vec![1, 0], vec![1, 0, 0, 0, 0xc1]] {
            let now = Instant::now();
            let mut clients = Clients::default();
            let (fd, mut peer) = socket_pair(&mut clients, now);
            peer.write_all(&bytes).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            for _ in 0..3 {
                clients.service(fd, now);
            }
            assert!(matches!(
                Reply::decode(&netd_core::recv(&mut peer).unwrap()),
                Ok(Reply::Error(_))
            ));
        }
    }

    #[test]
    fn a_peer_that_does_not_read_cannot_block_other_clients_or_extend_its_write_deadline() {
        let now = Instant::now();
        let mut clients = Clients::default();
        let (fd, mut peer) = socket_pair(&mut clients, now);
        peer.write_all(&frame(&Request::Status)).unwrap();
        clients.service(fd, now);
        let (stream, _) = clients.service(fd, now).unwrap();
        let size: libc::c_int = 1024;
        // SAFETY: live descriptor and an initialized integer option value.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        clients.reply(stream, &Reply::Error("x".repeat(60_000)), now);
        for _ in 0..32 {
            clients.service(fd, now);
        }
        assert!(clients.pending.contains_key(&fd));
        let (other, mut other_peer) = socket_pair(&mut clients, now);
        other_peer.write_all(&frame(&Request::Status)).unwrap();
        clients.service(other, now);
        assert!(clients.service(other, now).is_some());
        clients.expire(now + IO_TIMEOUT);
        assert!(clients.pending.is_empty());
    }

    #[test]
    fn queued_reply_resumes_after_backpressure_without_losing_bytes() {
        let now = Instant::now();
        let mut clients = Clients::default();
        let (fd, mut peer) = socket_pair(&mut clients, now);
        peer.write_all(&frame(&Request::Status)).unwrap();
        clients.service(fd, now);
        let (stream, _) = clients.service(fd, now).unwrap();
        let size: libc::c_int = 1024;
        // SAFETY: live descriptor and initialized integer option value.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let message = "abc".repeat(20_000);
        clients.reply(stream, &Reply::Error(message.clone()), now);
        for _ in 0..32 {
            clients.service(fd, now);
        }
        assert!(clients.pending.contains_key(&fd));
        peer.set_nonblocking(true).unwrap();
        let mut received = Vec::new();
        let mut closed = false;
        for _ in 0..100 {
            clients.service(fd, now);
            let mut chunk = [0; IO_CHUNK];
            match peer.read(&mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("read reply: {e}"),
            }
        }
        assert!(closed);
        let len = u32::from_le_bytes(received[..4].try_into().unwrap()) as usize;
        assert_eq!(received.len(), len + 4);
        match Reply::decode(&received[4..]).unwrap() {
            Reply::Error(actual) => assert_eq!(actual, message),
            _ => panic!("wrong reply"),
        }
    }

    #[test]
    fn pending_capacity_is_released_when_clients_expire() {
        let now = Instant::now();
        let mut clients = Clients::default();
        let mut peers = Vec::new();
        for _ in 0..MAX_CLIENTS {
            peers.push(socket_pair(&mut clients, now).1);
        }
        assert!(!clients.can_accept());
        clients.expire(now + IO_TIMEOUT);
        assert!(clients.can_accept());
        assert!(clients.next_deadline().is_none());
    }
}
