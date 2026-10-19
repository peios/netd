//! Receive complete IPv6 datagrams and validate their optional hop-limit metadata.

use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, BorrowedFd};

pub(super) struct Datagram {
    pub source: Ipv6Addr,
    pub hops: Option<u8>,
    pub body: Vec<u8>,
}

/// The protocol decoders accept at most this many bytes per incoming message.
const MAX_DATAGRAM_BYTES: usize = 4096;

pub(super) fn receive(fd: BorrowedFd<'_>, require_hops: bool) -> io::Result<Datagram> {
    let mut body = [0u8; MAX_DATAGRAM_BYTES];
    // cmsghdr elements give CMSG_FIRSTHDR/CMSG_NXTHDR their required alignment.
    // SAFETY: these C structures contain only integers and raw pointers; zero is valid.
    let (mut control, mut source, mut message) = unsafe {
        (
            zeroed::<[libc::cmsghdr; 4]>(),
            zeroed::<libc::sockaddr_in6>(),
            zeroed::<libc::msghdr>(),
        )
    };
    let mut vector = libc::iovec {
        iov_base: body.as_mut_ptr().cast(),
        iov_len: body.len(),
    };
    message.msg_name = (&mut source as *mut libc::sockaddr_in6).cast();
    message.msg_namelen = size_of_val(&source) as libc::socklen_t;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);
    // SAFETY: all message pointers refer to live, exclusively borrowed buffers of
    // the stated capacities; the kernel does not retain any of these pointers.
    let count = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut message, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    validate_envelope(&message, &source)?;
    // SAFETY: recvmsg filled the aligned control buffer, which remains live here.
    let hops = unsafe { hop_limit(&message)? };
    if require_hops && hops.is_none() {
        return Err(invalid("missing IPv6 hop limit"));
    }
    Ok(Datagram {
        source: Ipv6Addr::from(source.sin6_addr.s6_addr),
        hops,
        body: body[..count as usize].to_vec(),
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_envelope(message: &libc::msghdr, source: &libc::sockaddr_in6) -> io::Result<()> {
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(invalid("truncated IPv6 datagram or metadata"));
    }
    if message.msg_namelen as usize != size_of::<libc::sockaddr_in6>()
        || source.sin6_family as libc::c_int != libc::AF_INET6
    {
        return Err(invalid("invalid IPv6 source address"));
    }
    Ok(())
}

/// # Safety
/// The message must refer to a live, aligned control buffer filled by recvmsg.
unsafe fn hop_limit(message: &libc::msghdr) -> io::Result<Option<u8>> {
    let mut hops = None;
    // SAFETY: recvmsg supplies bounded CMSG records in the aligned control buffer.
    // CMSG_NXTHDR checks the next header fits; the payload length is checked below
    // before reading it. The buffer lives for this entire traversal.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::IPPROTO_IPV6
                && (*header).cmsg_type == libc::IPV6_HOPLIMIT
            {
                if (*header).cmsg_len != libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize {
                    return Err(invalid("invalid IPv6 hop-limit size"));
                }
                let value = libc::CMSG_DATA(header)
                    .cast::<libc::c_int>()
                    .read_unaligned();
                hops = Some(u8::try_from(value).map_err(|_| invalid("invalid IPv6 hop limit"))?);
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    Ok(hops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsFd;
    use std::time::Duration;

    #[test]
    fn truncated_packet_is_rejected_and_following_packet_is_preserved() {
        let receiver = UdpSocket::bind("[::1]:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sender = UdpSocket::bind("[::1]:0").unwrap();
        sender
            .send_to(
                &vec![7; MAX_DATAGRAM_BYTES + 1],
                receiver.local_addr().unwrap(),
            )
            .unwrap();
        sender
            .send_to(b"complete", receiver.local_addr().unwrap())
            .unwrap();
        assert_eq!(
            receive(receiver.as_fd(), false).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(receive(receiver.as_fd(), false).unwrap().body, b"complete");
    }

    #[test]
    fn hop_limit_uses_aligned_metadata_and_missing_metadata_is_rejected() {
        let receiver = UdpSocket::bind("[::1]:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sender = UdpSocket::bind("[::1]:0").unwrap();
        sender
            .send_to(b"no metadata", receiver.local_addr().unwrap())
            .unwrap();
        assert_eq!(
            receive(receiver.as_fd(), true).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        let enabled: libc::c_int = 1;
        // SAFETY: receiver owns a live IPv6 socket and enabled has the stated size.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVHOPLIMIT,
                    (&enabled as *const libc::c_int).cast(),
                    size_of_val(&enabled) as libc::socklen_t,
                )
            },
            0
        );
        sender
            .send_to(b"metadata", receiver.local_addr().unwrap())
            .unwrap();
        let packet = receive(receiver.as_fd(), true).unwrap();
        assert_eq!(packet.source, Ipv6Addr::LOCALHOST);
        assert!(packet.hops.is_some_and(|value| value > 0));
    }

    #[test]
    fn truncated_metadata_and_invalid_source_are_rejected() {
        // SAFETY: the C structures contain only integer and raw pointer fields.
        let (mut message, mut source): (libc::msghdr, libc::sockaddr_in6) = unsafe { zeroed() };
        source.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        message.msg_namelen = size_of_val(&source) as libc::socklen_t;
        message.msg_flags = libc::MSG_CTRUNC;
        assert!(validate_envelope(&message, &source).is_err());
        message.msg_flags = 0;
        message.msg_namelen -= 1;
        assert!(validate_envelope(&message, &source).is_err());
    }
}
