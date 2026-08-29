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
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST,
    NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressHeader, AddressMessage, AddressScope};
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
        for group in [RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE] {
            events.add_membership(group)?;
        }
        events.set_non_blocking(true)?;
        Ok(LinuxRtnl { socket, events, sequence: 1 })
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
            let n = match self.socket.recv(&mut &mut buf[..], 0) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let mut offset = 0;
            while offset < n {
                let bytes = &buf[offset..n];
                let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                let length = message.header.length as usize;
                if length == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "zero-length netlink message"));
                }
                if message.header.sequence_number == sequence {
                    match message.payload {
                        NetlinkPayload::Done(_) => return Ok(()),
                        NetlinkPayload::Error(e) => {
                            return match e.code {
                                None => Ok(()),
                                Some(code) => Err(io::Error::from_raw_os_error(-code.get())),
                            };
                        }
                        NetlinkPayload::InnerMessage(m) => each(m),
                        _ => {}
                    }
                }
                offset += length;
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

    fn dump_addresses(&mut self, out: &mut Observed) -> io::Result<()> {
        let mut m = AddressMessage::default();
        m.header.family = AddressFamily::Inet;
        let sequence =
            self.send(RouteNetlinkMessage::GetAddress(m), NLM_F_REQUEST | NLM_F_DUMP)?;
        self.receive(sequence, |m| {
            if let RouteNetlinkMessage::NewAddress(a) = m {
                if let Some(address) = address_from_message(&a) {
                    out.addresses.push(address);
                }
            }
        })
    }

    fn dump_routes(&mut self, out: &mut Observed) -> io::Result<()> {
        let mut m = RouteMessage::default();
        m.header.address_family = AddressFamily::Inet;
        let sequence =
            self.send(RouteNetlinkMessage::GetRoute(m), NLM_F_REQUEST | NLM_F_DUMP)?;
        self.receive(sequence, |m| {
            if let RouteNetlinkMessage::NewRoute(r) = m {
                if let Some(route) = route_from_message(&r) {
                    out.routes.push(route);
                }
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
        if crate::model::is_wireless(&name) { LinkKind::Wireless } else { LinkKind::Ether }
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
    for attribute in &a.attributes {
        match attribute {
            AddressAttribute::Local(ip) => local = Some(*ip),
            AddressAttribute::Address(ip) => address = Some(*ip),
            _ => {}
        }
    }
    // For IPv4 the interface's own address is IFA_LOCAL; IFA_ADDRESS is the
    // peer on point-to-point links.
    let ip = local.or(address)?;
    Some(Address { index: a.header.index, address: ip, prefix: a.header.prefix_len })
}

fn route_from_message(r: &RouteMessage) -> Option<Route> {
    if r.header.table != RouteHeader::RT_TABLE_MAIN || r.header.kind != RouteType::Unicast {
        return None;
    }
    let mut destination = Ipv4Addr::UNSPECIFIED;
    let mut gateway = None;
    let mut oif = None;
    let mut metric = 0;
    for attribute in &r.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(d)) => destination = *d,
            RouteAttribute::Gateway(RouteAddress::Inet(g)) => gateway = Some(*g),
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
    let IpAddr::V4(ip) = address.address else {
        unreachable!("netd v1 manages IPv4 addresses only")
    };
    let mut m = AddressMessage::default();
    m.header = AddressHeader {
        family: AddressFamily::Inet,
        prefix_len: address.prefix,
        flags: Default::default(),
        scope: if ip.is_link_local() { AddressScope::Link } else { AddressScope::Universe },
        index: address.index,
    };
    m.attributes.push(AddressAttribute::Local(IpAddr::V4(ip)));
    m.attributes.push(AddressAttribute::Address(IpAddr::V4(ip)));
    let broadcast = broadcast.unwrap_or_else(|| {
        let mask = if address.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(address.prefix)) };
        Ipv4Addr::from(u32::from(ip) | !mask)
    });
    if address.prefix < 31 {
        m.attributes.push(AddressAttribute::Broadcast(broadcast));
    }
    m
}

fn route_message(route: &Route) -> RouteMessage {
    let mut m = RouteMessage::default();
    m.header = RouteHeader {
        address_family: AddressFamily::Inet,
        destination_prefix_length: route.prefix,
        source_prefix_length: 0,
        tos: 0,
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: RouteProtocol::from(route.protocol),
        scope: if route.gateway.is_some() { RouteScope::Universe } else { RouteScope::Link },
        kind: RouteType::Unicast,
        flags: Default::default(),
    };
    if route.prefix > 0 {
        m.attributes.push(RouteAttribute::Destination(RouteAddress::Inet(route.destination)));
    }
    if let Some(g) = route.gateway {
        m.attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(g)));
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
        self.dump_addresses(&mut out)?;
        self.dump_routes(&mut out)?;
        Ok(out)
    }

    fn set_link_up(&mut self, index: u32, up: bool) -> io::Result<()> {
        let mut m = LinkMessage::default();
        m.header = LinkHeader {
            interface_family: AddressFamily::Unspec,
            index,
            link_layer_type: LinkLayerType::Netrom,
            flags: if up { LinkFlags::Up } else { LinkFlags::empty() },
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
        self.request(RouteNetlinkMessage::NewAddress(m), NLM_F_CREATE | NLM_F_REPLACE)
    }

    fn del_address(&mut self, address: &Address) -> io::Result<()> {
        let m = address_message(address, None);
        self.request(RouteNetlinkMessage::DelAddress(m), 0)
    }

    fn add_route(&mut self, route: &Route) -> io::Result<()> {
        let m = route_message(route);
        self.request(RouteNetlinkMessage::NewRoute(m), NLM_F_CREATE | NLM_F_EXCL)
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
