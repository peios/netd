//! Sockets and persistence around the `ndp` and `dhcp6` state machines,
//! and the sysctls that make netd the only RA listener.
//!
//! Router advertisements arrive on a raw ICMPv6 socket filtered to type 134
//! and bound to the interface; solicitations leave it for all-routers with
//! a hop limit of 255, as RFC 4861 requires. DHCPv6 runs over an ordinary
//! UDP socket bound to the interface's link-local address on port 546.
//! The kernel's own RA processing is switched off with `accept_ra = 0` so
//! there is exactly one place deciding what an RA means.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv6Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use netd_core::NETD_STATE_DIR;

use crate::log;

#[path = "ipv6_datagram.rs"]
mod datagram;

/// `ICMP6_FILTER` (RFC 3542): absent from the libc crate, value 1 on Linux.
const ICMP6_FILTER: libc::c_int = 1;

const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
const ALL_DHCP_AGENTS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2);
const DHCP6_CLIENT_PORT: u16 = 546;
const DHCP6_SERVER_PORT: u16 = 547;

/// One interface's router-discovery socket.
pub struct Icmp6Socket {
    fd: OwnedFd,
    ifindex: u32,
}

impl Icmp6Socket {
    pub fn open(ifindex: u32, ifname: &str) -> io::Result<Icmp6Socket> {
        // SAFETY: plain socket creation.
        let raw = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::IPPROTO_ICMPV6,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Filter: router advertisements only. A set bit blocks; clear the
        // one for type 134.
        let mut filter = [0xffff_ffffu32; 8];
        filter[(134 >> 5) as usize] &= !(1u32 << (134 & 31));
        set(&fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter)?;
        // RFC 4861: neighbour-discovery messages travel with hop limit 255,
        // and anything that arrives with less has crossed a router — a
        // spoof by definition. 255 out; the received value read per packet.
        set(&fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &255i32)?;
        set(&fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, &1i32)?;
        bind_to_device(&fd, ifname)?;
        Ok(Icmp6Socket { fd, ifindex })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Send a solicitation to all-routers.
    pub fn solicit(&self, body: &[u8]) -> io::Result<()> {
        send_to(&self.fd, body, ALL_ROUTERS, 0, self.ifindex)
    }

    /// Every pending message: source, received hop limit, ICMPv6 body.
    pub fn receive(&self) -> Vec<(Ipv6Addr, u8, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            match datagram::receive(self.fd(), true) {
                Ok(packet) => out.push((packet.source, packet.hops.unwrap_or(0), packet.body)),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::InvalidData
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        out
    }
}

/// One interface's stateless-DHCPv6 socket, bound to its link-local
/// address so two interfaces' clients never share a port.
pub struct Dhcp6Socket {
    fd: OwnedFd,
    ifindex: u32,
}

impl Dhcp6Socket {
    pub fn open(ifindex: u32, ifname: &str, link_local: Ipv6Addr) -> io::Result<Dhcp6Socket> {
        // SAFETY: plain socket creation.
        let raw = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        bind_to_device(&fd, ifname)?;
        // SAFETY: `sin6` is fully initialised for the stated length.
        unsafe {
            let mut sin6: libc::sockaddr_in6 = zeroed();
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = DHCP6_CLIENT_PORT.to_be();
            sin6.sin6_addr.s6_addr = link_local.octets();
            sin6.sin6_scope_id = ifindex;
            let rc = libc::bind(
                fd.as_raw_fd(),
                (&sin6 as *const libc::sockaddr_in6).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Dhcp6Socket { fd, ifindex })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn send(&self, payload: &[u8]) -> io::Result<()> {
        send_to(
            &self.fd,
            payload,
            ALL_DHCP_AGENTS,
            DHCP6_SERVER_PORT,
            self.ifindex,
        )
    }

    pub fn receive(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            match datagram::receive(self.fd(), false) {
                Ok(packet) => out.push(packet.body),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::InvalidData
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        out
    }
}

fn set<T>(fd: &OwnedFd, level: libc::c_int, option: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live, initialised T for the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn bind_to_device(fd: &OwnedFd, ifname: &str) -> io::Result<()> {
    // SAFETY: the name is a live buffer of the stated length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr().cast(),
            ifname.len() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn send_to(fd: &OwnedFd, payload: &[u8], to: Ipv6Addr, port: u16, scope: u32) -> io::Result<()> {
    // SAFETY: `sin6` is fully initialised; the payload lives for the call.
    let sent = unsafe {
        let mut sin6: libc::sockaddr_in6 = zeroed();
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_port = port.to_be();
        sin6.sin6_addr.s6_addr = to.octets();
        sin6.sin6_scope_id = scope;
        libc::sendto(
            fd.as_raw_fd(),
            payload.as_ptr().cast(),
            payload.len(),
            0,
            (&sin6 as *const libc::sockaddr_in6).cast(),
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The machine's secret for stable-privacy addresses (RFC 7217), created
/// once and kept beside the DUID. Losing it renumbers the machine; that is
/// all.
pub fn secret() -> io::Result<[u8; 32]> {
    let path = PathBuf::from(NETD_STATE_DIR).join("secret");
    if let Ok(bytes) = std::fs::read(&path)
        && bytes.len() == 32
    {
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        return Ok(s);
    }
    let s = read_entropy(std::fs::File::open("/dev/urandom")?)?;
    if let Err(e) = std::fs::create_dir_all(NETD_STATE_DIR).and_then(|_| std::fs::write(&path, s)) {
        log::warn(format_args!(
            "could not persist the address secret at {}: {e}",
            path.display()
        ));
    }
    Ok(s)
}

fn read_entropy(mut source: impl io::Read) -> io::Result<[u8; 32]> {
    let mut secret = [0; 32];
    source.read_exact(&mut secret)?;
    Ok(secret)
}

/// Switch the kernel's own RA processing off, everywhere: netd is the RA
/// listener on Peios, and two listeners with two opinions is how a machine
/// ends up with addresses nobody configured. `default` covers interfaces
/// yet to appear; existing ones are named. The kernel still creates
/// link-local addresses and answers neighbour solicitations — that is the
/// protocol, not policy.
pub fn kernel_ra_off() {
    write_sysctl("all");
    write_sysctl("default");
    if let Ok(entries) = std::fs::read_dir("/proc/sys/net/ipv6/conf") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name != "all"
                && name != "default"
            {
                write_sysctl(name);
            }
        }
    }
}

/// The per-interface switch, for interfaces that appear later. `default`
/// already covers them; this is belt and braces against an interface that
/// existed before netd started.
pub fn kernel_ra_off_for(ifname: &str) {
    write_sysctl(ifname);
}

fn write_sysctl(conf: &str) {
    let path = format!("/proc/sys/net/ipv6/conf/{conf}/accept_ra");
    if let Err(e) = std::fs::write(&path, "0") {
        // A kernel without IPv6 has no file here; that is not an error
        // worth a warning per interface.
        if conf == "all" {
            log::warn(format_args!("could not set {path}: {e}"));
        }
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn incomplete_entropy_never_produces_an_address_secret() {
        assert_eq!(
            read_entropy(&[9u8; 31][..]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(read_entropy(&[9u8; 32][..]).unwrap(), [9; 32]);
    }
}
