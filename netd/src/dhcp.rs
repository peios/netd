//! Sockets and persistence around the `dhcp4` state machine.
//!
//! Before an interface has an address nothing but a packet socket can send
//! from 0.0.0.0, so every broadcast goes out through `AF_PACKET` with a
//! hand-built IP+UDP header. Once bound, a renewal is unicast from the lease
//! address through an ordinary, transient UDP socket so the kernel does the
//! ARP. Replies of both kinds are read off the packet socket, which sees
//! everything on the interface and carries a BPF filter for UDP port 68.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use dhcp4::packet::{CLIENT_PORT, SERVER_PORT};
use dhcp4::{Destination, Message};
use libnetd::NETD_STATE_DIR;

use crate::log;

const ETH_P_IP: u16 = 0x0800;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// One interface's packet socket.
pub struct PacketSocket {
    fd: OwnedFd,
    ifindex: u32,
    ifname: String,
}

impl PacketSocket {
    pub fn open(ifindex: u32, ifname: &str) -> io::Result<PacketSocket> {
        // SAFETY: plain socket creation.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                (ETH_P_IP as libc::c_int).to_be(),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        attach_filter(fd.as_fd())?;
        // SAFETY: zeroed sockaddr_ll is a valid starting point.
        let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (ETH_P_IP).to_be();
        addr.sll_ifindex = ifindex as i32;
        // SAFETY: `addr` is a fully initialised sockaddr_ll of the stated size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PacketSocket {
            fd,
            ifindex,
            ifname: ifname.to_owned(),
        })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Send per the state machine's instruction.
    pub fn send(&self, message: &Message, destination: Destination) -> io::Result<()> {
        let payload = message.encode();
        match destination {
            Destination::Broadcast => self.send_broadcast(&payload),
            Destination::Unicast { server, from } => {
                send_unicast(&self.ifname, from, server, &payload)
            }
        }
    }

    fn send_broadcast(&self, payload: &[u8]) -> io::Result<()> {
        let datagram = ip_udp(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            CLIENT_PORT,
            SERVER_PORT,
            payload,
        );
        // SAFETY: zeroed sockaddr_ll is a valid starting point.
        let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_IP.to_be();
        addr.sll_ifindex = self.ifindex as i32;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&BROADCAST_MAC);
        // SAFETY: buffer and address are live for the call.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                datagram.as_ptr().cast(),
                datagram.len(),
                0,
                (&addr as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read every pending datagram, yielding the DHCP messages among them.
    pub fn receive(&self) -> Vec<Message> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: `buf` is a live writable buffer of the stated length.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                break;
            }
            if let Some(payload) = udp_payload(&buf[..n as usize])
                && let Some(m) = Message::decode(payload)
            {
                out.push(m);
            }
        }
        out
    }
}

/// Classic BPF for "udp dst port 68" on a cooked IPv4 packet.
fn attach_filter(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }
    const fn op(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }
    let program = [
        op(0x30, 0, 0, 9),      // ldb [9]            protocol
        op(0x15, 0, 6, 17),     // jeq #17 (udp)      else fail
        op(0x28, 0, 0, 6),      // ldh [6]            fragment offset
        op(0x45, 4, 0, 0x1fff), // jset #0x1fff       fragment -> fail
        op(0xb1, 0, 0, 0),      // ldxb 4*([0]&0xf)   ihl
        op(0x48, 0, 0, 2),      // ldh [x+2]          udp dst port
        op(0x15, 0, 1, 68),     // jeq #68            else fail
        op(0x06, 0, 0, 0xffff), // ret #65535
        op(0x06, 0, 0, 0),      // ret #0
    ];
    let fprog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };
    // SAFETY: `fprog` and `program` outlive the call; SO_ATTACH_FILTER copies.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&fprog as *const SockFprog).cast(),
            size_of::<SockFprog>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4+UDP datagram. The UDP checksum is left zero, which IPv4 permits.
fn ip_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut out = Vec::with_capacity(total);
    out.push(0x45);
    out.push(0x10); // DSCP as dhclient sends it
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]); // id
    out.extend_from_slice(&[0x40, 0]); // DF
    out.push(64); // ttl
    out.push(17); // udp
    out.extend_from_slice(&[0, 0]); // checksum placeholder
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    let sum = checksum(&out[..20]).to_be_bytes();
    out[10] = sum[0];
    out[11] = sum[1];
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

/// The UDP payload of a cooked IPv4 packet addressed to port 68, if that is
/// what this is. The BPF filter already agrees; this is defence against a
/// short read.
fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if packet[9] != 17 || packet.len() < ihl + 8 {
        return None;
    }
    let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    if dport != CLIENT_PORT {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]));
    let end = (ihl + udp_len).min(packet.len());
    packet.get(ihl + 8..end)
}

/// Unicast a renewal from the lease address, bound to the interface. A
/// transient socket: the reply is read off the packet socket, so nothing
/// needs to stay listening.
fn send_unicast(ifname: &str, from: Ipv4Addr, server: Ipv4Addr, payload: &[u8]) -> io::Result<()> {
    use std::net::{SocketAddrV4, UdpSocket};
    // SAFETY: plain socket creation.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh, owned fd.
    let socket = unsafe { UdpSocket::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    // SAFETY: option value is a live c_int.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr().cast(),
            ifname.len() as libc::socklen_t,
        );
    }
    // A bind to a port below 1024 meets the port reservation for 1–1023,
    // which the shipped seed grants to SYSTEM — netd's identity.
    bind_udp(&socket, SocketAddrV4::new(from, CLIENT_PORT))?;
    socket.send_to(payload, SocketAddrV4::new(server, SERVER_PORT))?;
    Ok(())
}

fn bind_udp(socket: &std::net::UdpSocket, addr: std::net::SocketAddrV4) -> io::Result<()> {
    // SAFETY: zeroed sockaddr_in is a valid starting point.
    let mut sin: libc::sockaddr_in = unsafe { zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = addr.port().to_be();
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from(*addr.ip()).to_be(),
    };
    // SAFETY: `sin` is fully initialised for the stated length.
    let rc = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&sin as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A socket that absorbs unicast replies to port 68 so the kernel does not
/// answer servers with ICMP port-unreachable. Its contents are irrelevant;
/// the packet sockets see the same datagrams.
pub struct Absorber(std::net::UdpSocket);

impl Absorber {
    pub fn open() -> io::Result<Absorber> {
        // SAFETY: plain socket creation.
        let raw = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, owned fd.
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(raw) };
        let one: libc::c_int = 1;
        // SAFETY: option value is a live c_int.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&one as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        bind_udp(
            &socket,
            std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT),
        )?;
        Ok(Absorber(socket))
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    pub fn drain(&self) {
        let mut buf = [0u8; 2048];
        while self.0.recv_from(&mut buf).is_ok() {}
    }
}

// ---- persistence ------------------------------------------------------------

/// The machine's DUID (RFC 8415 DUID-LL from the first MAC seen), created
/// once and kept. RFC 4361 client ids are built on it, so a NIC swap in the
/// same slot keeps the same identity at the server.
pub fn duid(first_mac: &[u8; 6]) -> Vec<u8> {
    let path = PathBuf::from(NETD_STATE_DIR).join("duid");
    if let Ok(bytes) = std::fs::read(&path)
        && bytes.len() >= 4
    {
        return bytes;
    }
    let mut d = vec![0, 3, 0, 1]; // DUID-LL, hardware type ethernet
    d.extend_from_slice(first_mac);
    if let Err(e) = std::fs::create_dir_all(NETD_STATE_DIR).and_then(|_| std::fs::write(&path, &d))
    {
        log::warn(format_args!(
            "could not persist the DUID at {}: {e}",
            path.display()
        ));
    }
    d
}

/// RFC 4361 client identifier: type 255, IAID, DUID.
pub fn client_id(duid: &[u8], ifid: &str) -> Vec<u8> {
    let mut iaid = [0u8; 4];
    for (i, b) in ifid.bytes().enumerate() {
        iaid[i % 4] ^= b;
    }
    let mut id = vec![0xff];
    id.extend_from_slice(&iaid);
    id.extend_from_slice(duid);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ip_header_checksums_and_the_payload_comes_back() {
        let d = ip_udp(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, 68, 67, b"hello");
        assert_eq!(checksum(&d[..20]), 0);
        // A reply to port 68 parses; our own to 67 does not.
        let mut reply = ip_udp(
            Ipv4Addr::new(10, 0, 2, 2),
            Ipv4Addr::BROADCAST,
            67,
            68,
            b"hello",
        );
        assert_eq!(udp_payload(&reply), Some(&b"hello"[..]));
        assert_eq!(udp_payload(&d), None);
        reply.truncate(25);
        assert_eq!(udp_payload(&reply), None);
    }

    #[test]
    fn client_ids_are_rfc4361_shaped() {
        let id = client_id(&[0, 3, 0, 1, 1, 2, 3, 4, 5, 6], "abcd");
        assert_eq!(id[0], 0xff);
        assert_eq!(id.len(), 1 + 4 + 10);
    }
}
