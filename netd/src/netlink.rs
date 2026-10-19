//! rtnetlink, behind a trait so the rest of netd can be driven by a fake.
//!
//! The real implementation is deliberately simple: it dumps the whole state
//! when asked and applies one change per request with an ACK. netd re-dumps
//! after any multicast event rather than folding events into its model — the
//! state is small and a dump is one round trip, which is cheaper to get right
//! than incremental updates from a stream that can overflow.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, RawFd};

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_REPLACE,
    NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{
    AddressAttribute, AddressFlags, AddressHeader, AddressHeaderFlags, AddressMessage,
    AddressScope, CacheInfo,
};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkHeader, LinkLayerType, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::model::{Address, Link, LinkKind, Observed, Route};

const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV4_ROUTE: u32 = 7;
const RTNLGRP_IPV6_IFADDR: u32 = 9;
const RTNLGRP_IPV6_ROUTE: u32 = 11;

/// What netd asks of the kernel.
pub trait Rtnl {
    fn dump(&mut self) -> io::Result<Observed>;
    fn set_link_up(&mut self, index: u32, up: bool) -> io::Result<()>;
    fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()>;
    fn add_address(&mut self, address: &Address, broadcast: Option<Ipv4Addr>) -> io::Result<()>;
    fn del_address(&mut self, address: &Address) -> io::Result<()>;
    fn add_route(&mut self, route: &Route) -> io::Result<()>;
    fn del_route(&mut self, route: &Route) -> io::Result<()>;
}

/// The kernel's rtnetlink.
pub struct LinuxRtnl {
    socket: Socket,
    /// Multicast subscriber; separate so dumps never interleave with events.
    events: Socket,
    sequence: u32,
}

impl LinuxRtnl {
    pub fn open() -> io::Result<LinuxRtnl> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        let mut events = Socket::new(NETLINK_ROUTE)?;
        events.bind_auto()?;
        for group in [
            RTNLGRP_LINK,
            RTNLGRP_IPV4_IFADDR,
            RTNLGRP_IPV4_ROUTE,
            RTNLGRP_IPV6_IFADDR,
            RTNLGRP_IPV6_ROUTE,
        ] {
            events.add_membership(group)?;
        }
        events.set_non_blocking(true)?;
        Ok(LinuxRtnl {
            socket,
            events,
            sequence: 1,
        })
    }

    /// Consume pending events; `true` if there were any.
    pub fn drain_events(&mut self) -> bool {
        let mut any = false;
        let mut buf = vec![0u8; 65536];
        loop {
            match self.events.recv(&mut &mut buf[..], 0) {
                Ok(0) => break,
                Ok(_) => any = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // ENOBUFS: we missed some; a dump follows anyway.
                Err(_) => {
                    any = true;
                    break;
                }
            }
        }
        any
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.sequence
    }

    fn send(&mut self, payload: RouteNetlinkMessage, flags: u16) -> io::Result<u32> {
        let sequence = self.next_sequence();
        let mut header = NetlinkHeader::default();
        header.flags = flags;
        header.sequence_number = sequence;
        let mut message = NetlinkMessage::new(header, NetlinkPayload::from(payload));
        message.finalize();
        let mut buf = vec![0u8; message.buffer_len()];
        message.serialize(&mut buf);
        let kernel = SocketAddr::new(0, 0);
        self.socket.send_to(&buf, &kernel, 0)?;
        Ok(sequence)
    }

    /// Read replies to `sequence` until DONE (dump) or the ACK (request).
    fn receive(
        &mut self,
        sequence: u32,
        mut each: impl FnMut(RouteNetlinkMessage),
    ) -> io::Result<()> {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match self.socket.recv(&mut &mut buf[..], libc::MSG_TRUNC) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n > buf.len() {
                return Err(invalid_reply("truncated netlink datagram"));
            }
            if decode_reply(&buf[..n], sequence, &mut each)? {
                return Ok(());
            }
        }
    }

    fn request(&mut self, payload: RouteNetlinkMessage, flags: u16) -> io::Result<()> {
        let sequence = self.send(payload, NLM_F_REQUEST | NLM_F_ACK | flags)?;
        self.receive(sequence, |_| {})
    }

    fn dump_links(&mut self, out: &mut Observed) -> io::Result<()> {
        let sequence = self.send(
            RouteNetlinkMessage::GetLink(LinkMessage::default()),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;
        self.receive(sequence, |m| {
            if let RouteNetlinkMessage::NewLink(l) = m {
                let link = link_from_message(&l);
                out.links.insert(link.index, link);
            }
        })
    }

    fn dump_addresses(&mut self, out: &mut Observed, family: AddressFamily) -> io::Result<()> {
        let mut m = AddressMessage::default();
        m.header.family = family;
        let sequence = self.send(
            RouteNetlinkMessage::GetAddress(m),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;
        self.receive(sequence, |m| {
            if let RouteNetlinkMessage::NewAddress(a) = m
                && let Some(address) = address_from_message(&a)
            {
                out.addresses.push(address);
            }
        })
    }

    fn dump_routes(&mut self, out: &mut Observed, family: AddressFamily) -> io::Result<()> {
        let mut m = RouteMessage::default();
        m.header.address_family = family;
        let sequence = self.send(RouteNetlinkMessage::GetRoute(m), NLM_F_REQUEST | NLM_F_DUMP)?;
        self.receive(sequence, |m| {
            if let RouteNetlinkMessage::NewRoute(r) = m
                && let Some(route) = route_from_message(&r)
            {
                out.routes.push(route);
            }
        })
    }
}

fn link_from_message(l: &LinkMessage) -> Link {
    let mut name = String::new();
    let mut mac = None;
    let mut mtu = 0;
    for attribute in &l.attributes {
        match attribute {
            LinkAttribute::IfName(n) => name = n.clone(),
            LinkAttribute::Address(a) if a.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(a);
                mac = Some(m);
            }
            LinkAttribute::Mtu(m) => mtu = *m,
            _ => {}
        }
    }
    let flags = l.header.flags;
    let loopback = flags.contains(LinkFlags::Loopback);
    let link_type: u16 = l.header.link_layer_type.into();
    let kind = if loopback {
        LinkKind::Loopback
    } else if l.header.link_layer_type == LinkLayerType::Ether {
        if crate::model::is_wireless(&name) {
            LinkKind::Wireless
        } else {
            LinkKind::Ether
        }
    } else {
        LinkKind::Other
    };
    Link {
        index: l.header.index,
        name,
        mac,
        up: flags.contains(LinkFlags::Up),
        carrier: flags.contains(LinkFlags::LowerUp),
        loopback,
        mtu,
        link_type,
        kind,
    }
}

fn address_from_message(a: &AddressMessage) -> Option<Address> {
    let mut local = None;
    let mut address = None;
    let mut flags = AddressFlags::empty();
    for attribute in &a.attributes {
        match attribute {
            AddressAttribute::Local(ip) => local = Some(*ip),
            AddressAttribute::Address(ip) => address = Some(*ip),
            AddressAttribute::Flags(f) => flags = *f,
            _ => {}
        }
    }
    // For IPv4 the interface's own address is IFA_LOCAL; IFA_ADDRESS is the
    // peer on point-to-point links. IPv6 carries only IFA_ADDRESS.
    let ip = match local.or(address)? {
        ip @ IpAddr::V6(_) => address.unwrap_or(ip),
        ip => ip,
    };
    Some(Address {
        index: a.header.index,
        address: ip,
        prefix: a.header.prefix_len,
        deprecated: flags.contains(AddressFlags::Deprecated),
        no_prefix_route: flags.contains(AddressFlags::Noprefixroute),
        // The header's eight bits carry it too; the attribute is authoritative
        // when present and absent on kernels old enough not to send it.
        tentative: flags.contains(AddressFlags::Tentative)
            || a.header.flags.contains(AddressHeaderFlags::Tentative),
    })
}

fn route_from_message(r: &RouteMessage) -> Option<Route> {
    if r.header.table != RouteHeader::RT_TABLE_MAIN || r.header.kind != RouteType::Unicast {
        return None;
    }
    let mut destination = match r.header.address_family {
        AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        _ => return None,
    };
    let mut gateway = None;
    let mut oif = None;
    let mut metric = 0;
    for attribute in &r.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(d)) => destination = IpAddr::V4(*d),
            RouteAttribute::Destination(RouteAddress::Inet6(d)) => destination = IpAddr::V6(*d),
            RouteAttribute::Gateway(RouteAddress::Inet(g)) => gateway = Some(IpAddr::V4(*g)),
            RouteAttribute::Gateway(RouteAddress::Inet6(g)) => gateway = Some(IpAddr::V6(*g)),
            RouteAttribute::Oif(i) => oif = Some(*i),
            RouteAttribute::Priority(p) => metric = *p,
            _ => {}
        }
    }
    Some(Route {
        index: oif?,
        destination,
        prefix: r.header.destination_prefix_length,
        gateway,
        metric,
        protocol: r.header.protocol.into(),
    })
}

fn address_message(address: &Address, broadcast: Option<Ipv4Addr>) -> AddressMessage {
    match address.address {
        IpAddr::V4(ip) => {
            let mut m = AddressMessage::default();
            m.header = AddressHeader {
                family: AddressFamily::Inet,
                prefix_len: address.prefix,
                flags: Default::default(),
                scope: if ip.is_link_local() {
                    AddressScope::Link
                } else {
                    AddressScope::Universe
                },
                index: address.index,
            };
            m.attributes.push(AddressAttribute::Local(IpAddr::V4(ip)));
            m.attributes.push(AddressAttribute::Address(IpAddr::V4(ip)));
            let broadcast = broadcast.unwrap_or_else(|| {
                let mask = if address.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(address.prefix))
                };
                Ipv4Addr::from(u32::from(ip) | !mask)
            });
            if address.prefix < 31 {
                m.attributes.push(AddressAttribute::Broadcast(broadcast));
            }
            m
        }
        IpAddr::V6(ip) => {
            let mut m = AddressMessage::default();
            m.header = AddressHeader {
                family: AddressFamily::Inet6,
                prefix_len: address.prefix,
                flags: Default::default(),
                scope: if crate::model::is_v6_link_local(&ip) {
                    AddressScope::Link
                } else {
                    AddressScope::Universe
                },
                index: address.index,
            };
            m.attributes.push(AddressAttribute::Address(IpAddr::V6(ip)));
            if address.no_prefix_route {
                m.attributes
                    .push(AddressAttribute::Flags(AddressFlags::Noprefixroute));
            }
            // Lifetimes are netd's to manage, so the kernel is told forever
            // — except that deprecation *is* expressed as a lifetime: a
            // preferred lifetime of zero is how an address is kept for
            // standing connections while source selection stops choosing
            // it. Always explicit, so a replace changes it back.
            let mut cache = CacheInfo::default();
            cache.ifa_preferred = if address.deprecated { 0 } else { u32::MAX };
            cache.ifa_valid = u32::MAX;
            m.attributes.push(AddressAttribute::CacheInfo(cache));
            m
        }
    }
}

fn route_message(route: &Route) -> RouteMessage {
    let mut m = RouteMessage::default();
    m.header = RouteHeader {
        address_family: match route.destination {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        },
        destination_prefix_length: route.prefix,
        source_prefix_length: 0,
        tos: 0,
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: RouteProtocol::from(route.protocol),
        scope: if route.gateway.is_some() {
            RouteScope::Universe
        } else {
            RouteScope::Link
        },
        kind: RouteType::Unicast,
        flags: Default::default(),
    };
    if route.prefix > 0 {
        m.attributes
            .push(RouteAttribute::Destination(RouteAddress::from(
                route.destination,
            )));
    }
    if let Some(g) = route.gateway {
        m.attributes
            .push(RouteAttribute::Gateway(RouteAddress::from(g)));
    }
    m.attributes.push(RouteAttribute::Oif(route.index));
    if route.metric > 0 {
        m.attributes.push(RouteAttribute::Priority(route.metric));
    }
    m
}

impl Rtnl for LinuxRtnl {
    fn dump(&mut self) -> io::Result<Observed> {
        let mut out = Observed::default();
        self.dump_links(&mut out)?;
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            self.dump_addresses(&mut out, family)?;
            self.dump_routes(&mut out, family)?;
        }
        Ok(out)
    }

    fn set_link_up(&mut self, index: u32, up: bool) -> io::Result<()> {
        let mut m = LinkMessage::default();
        m.header = LinkHeader {
            interface_family: AddressFamily::Unspec,
            index,
            link_layer_type: LinkLayerType::Netrom,
            flags: if up {
                LinkFlags::Up
            } else {
                LinkFlags::empty()
            },
            change_mask: LinkFlags::Up,
        };
        self.request(RouteNetlinkMessage::SetLink(m), 0)
    }

    fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
        let mut m = LinkMessage::default();
        m.header.index = index;
        m.attributes.push(LinkAttribute::Mtu(mtu));
        self.request(RouteNetlinkMessage::SetLink(m), 0)
    }

    fn add_address(&mut self, address: &Address, broadcast: Option<Ipv4Addr>) -> io::Result<()> {
        let m = address_message(address, broadcast);
        self.request(
            RouteNetlinkMessage::NewAddress(m),
            NLM_F_CREATE | NLM_F_REPLACE,
        )
    }

    fn del_address(&mut self, address: &Address) -> io::Result<()> {
        let m = address_message(address, None);
        self.request(RouteNetlinkMessage::DelAddress(m), 0)
    }

    fn add_route(&mut self, route: &Route) -> io::Result<()> {
        let m = route_message(route);
        // IPv4 EXCL rejects any route at this prefix/metric, even on a
        // different interface. APPEND keeps those routes and admits a distinct
        // nexthop; an exact duplicate still returns EEXIST.
        let flags = if route.is_v4() {
            NLM_F_CREATE | NLM_F_APPEND
        } else {
            NLM_F_CREATE | NLM_F_EXCL
        };
        self.request(RouteNetlinkMessage::NewRoute(m), flags)
    }

    fn del_route(&mut self, route: &Route) -> io::Result<()> {
        let m = route_message(route);
        self.request(RouteNetlinkMessage::DelRoute(m), 0)
    }
}

impl AsRawFd for LinuxRtnl {
    fn as_raw_fd(&self) -> RawFd {
        self.events.as_raw_fd()
    }
}

fn invalid_reply(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Decode one complete datagram; only a successful DONE/ACK completes the request.
fn decode_reply(
    bytes: &[u8],
    sequence: u32,
    each: &mut impl FnMut(RouteNetlinkMessage),
) -> io::Result<bool> {
    if bytes.is_empty() {
        return Err(invalid_reply("empty netlink reply"));
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes[offset..])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let length = message.header.length as usize;
        if length < 16 || length > bytes.len() - offset {
            return Err(invalid_reply("invalid netlink message length"));
        }
        if message.header.sequence_number == sequence {
            if message.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "interrupted netlink dump",
                ));
            }
            match message.payload {
                NetlinkPayload::Done(done) => {
                    check_reply_code(done.code)?;
                    return Ok(true);
                }
                NetlinkPayload::Error(error) => {
                    check_reply_code(error.code.map_or(0, |code| code.get()))?;
                    return Ok(true);
                }
                NetlinkPayload::InnerMessage(message) => each(message),
                NetlinkPayload::Overrun(_) => return Err(invalid_reply("netlink receive overrun")),
                _ => {}
            }
        }
        // Netlink messages are padded to four bytes; the final message can omit padding.
        offset += (length + 3) & !3;
    }
    Ok(false)
}

fn check_reply_code(code: i32) -> io::Result<()> {
    if code == 0 {
        return Ok(());
    }
    let errno = code
        .checked_neg()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_reply("invalid netlink error code"))?;
    Err(io::Error::from_raw_os_error(errno))
}

#[cfg(test)]
mod reply_tests {
    use super::*;
    use netlink_packet_core::DoneMessage;

    fn done(code: i32, flags: u16, sequence: u32) -> Vec<u8> {
        let mut payload = DoneMessage::default();
        payload.code = code;
        let mut header = NetlinkHeader::default();
        header.flags = flags;
        header.sequence_number = sequence;
        let mut message =
            NetlinkMessage::<RouteNetlinkMessage>::new(header, NetlinkPayload::Done(payload));
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        bytes
    }

    #[test]
    fn interrupted_dump_is_not_a_complete_snapshot() {
        let error = decode_reply(&done(0, NLM_F_DUMP_INTR, 7), 7, &mut |_| {}).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(!decode_reply(&done(0, NLM_F_DUMP_INTR, 8), 7, &mut |_| {}).unwrap());
        assert!(decode_reply(&done(0, 0, 7), 7, &mut |_| {}).unwrap());
    }

    #[test]
    fn failed_done_message_is_not_success() {
        assert_eq!(
            decode_reply(&done(-libc::ENOBUFS, 0, 7), 7, &mut |_| {})
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOBUFS)
        );
        assert_eq!(
            decode_reply(&done(i32::MIN, 0, 7), 7, &mut |_| {})
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(decode_reply(&done(0, 0, 7)[..10], 7, &mut |_| {}).is_err());
    }
}
