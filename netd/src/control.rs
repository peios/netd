//! The control socket: `/run/netd/control.sock`, one request per connection,
//! authorised against the netd control object.
//!
//! The object is `Machine\System\Network\ControlSecurity` when set, else a
//! compiled default — Everyone may query, SYSTEM and Administrators may
//! control. The check is a real KACS access check against the peer's token,
//! never `SO_PEERCRED`, so a deny-only group or a filtered token is judged as
//! the kernel would judge it anywhere else.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use libnetd::{CONTROL_SOCKET_PATH, NETD_RUN_DIR, NETWORK_ALL_ACCESS, NETWORK_CONTROL, NETWORK_QUERY, Reply, Request};
use peios::access::AccessCheck;
use peios::security::{AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown};
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
        .allow(system.as_ref(), AccessMask::GENERIC_ALL.bits(), AceFlags::empty())
        .allow(everyone.as_ref(), AccessMask::GENERIC_READ.bits() | AccessMask::GENERIC_WRITE.bits() | AccessMask::GENERIC_EXECUTE.bits(), AceFlags::empty())
        .build()
        .and_then(|dacl| SdBuilder::new().owner(system.as_ref()).group(system.as_ref()).dacl(&dacl).build());
    match descriptor {
        Ok(sd) => {
            if let Err(e) = peios::file::set_sd(None, path, SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL, &sd, 0) {
                log::error(format_args!("could not set a descriptor on {}: {e}", path.display()));
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
                Err(e) => log::warn(format_args!("ControlSecurity is not a valid descriptor ({e}); using the default")),
            }
        }
        ControlObject { sd: Self::default_sd() }
    }

    fn default_sd() -> SecurityDescriptor {
        let system = Sid::well_known(WellKnown::System);
        let administrators = Sid::well_known(WellKnown::Administrators);
        let everyone = Sid::well_known(WellKnown::Everyone);
        AclBuilder::new()
            .allow(system.as_ref(), NETWORK_ALL_ACCESS, AceFlags::empty())
            .allow(administrators.as_ref(), NETWORK_ALL_ACCESS, AceFlags::empty())
            .allow(everyone.as_ref(), NETWORK_QUERY | AccessMask::READ_CONTROL.bits(), AceFlags::empty())
            .build()
            .and_then(|dacl| SdBuilder::new().owner(system.as_ref()).group(system.as_ref()).dacl(&dacl).build())
            .expect("the compiled default descriptor builds")
    }

    fn mapping() -> GenericMapping {
        let rc = AccessMask::READ_CONTROL.bits();
        GenericMapping::new(NETWORK_QUERY | rc, NETWORK_CONTROL | rc, NETWORK_QUERY, NETWORK_ALL_ACCESS)
    }

    /// Whether the peer holds `right`.
    pub fn permits(&self, stream: &UnixStream, right: u32) -> bool {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("control: no peer token: {e}"));
                return false;
            }
        };
        AccessCheck::new(&self.sd, AccessMask::from_bits_retain(right), Self::mapping())
            .token(token.as_fd())
            .check()
            .map(|d| d.allowed)
            .unwrap_or(false)
    }
}

/// Read one request, or answer with an error and return `None`.
pub fn read_request(stream: &mut UnixStream) -> Option<Request> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let bytes = match libnetd::recv(stream) {
        Ok(b) => b,
        Err(e) => {
            let _ = libnetd::send(stream, &Reply::Error(e.to_string()).encode());
            return None;
        }
    };
    match Request::decode(&bytes) {
        Ok(r) => Some(r),
        Err(e) => {
            let _ = libnetd::send(stream, &Reply::Error(e.to_string()).encode());
            None
        }
    }
}

pub fn respond(stream: &mut UnixStream, reply: &Reply) {
    if let Err(e) = libnetd::send(stream, &reply.encode()) {
        log::warn(format_args!("control: reply failed: {e}"));
    }
}
