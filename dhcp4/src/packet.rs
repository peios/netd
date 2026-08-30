//! DHCPv4 message codec.

use std::net::Ipv4Addr;

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const FLAG_BROADCAST: u16 = 0x8000;
/// The fixed part of a BOOTP message, before the cookie.
const FIXED_LEN: usize = 236;

/// Option codes this client speaks.
pub mod option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const MTU: u8 = 26;
    pub const BROADCAST: u8 = 28;
    pub const NTP: u8 = 42;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    pub const MESSAGE: u8 = 56;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const RENEWAL_T1: u8 = 58;
    pub const REBINDING_T2: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const DOMAIN_SEARCH: u8 = 119;
    pub const CLASSLESS_STATIC_ROUTE: u8 = 121;
    pub const END: u8 = 255;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    fn from_u8(v: u8) -> Option<MessageType> {
        Some(match v {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Ack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            8 => MessageType::Inform,
            _ => return None,
        })
    }
}

/// An ordered list of options; first occurrence of a code wins on lookup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options(pub Vec<(u8, Vec<u8>)>);

impl Options {
    pub fn get(&self, code: u8) -> Option<&[u8]> {
        self.0.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_slice())
    }

    pub fn push(&mut self, code: u8, data: impl Into<Vec<u8>>) {
        self.0.push((code, data.into()));
    }

    pub fn message_type(&self) -> Option<MessageType> {
        self.get(option::MESSAGE_TYPE)
            .and_then(|v| v.first().copied())
            .and_then(MessageType::from_u8)
    }

    pub fn ipv4(&self, code: u8) -> Option<Ipv4Addr> {
        self.get(code).and_then(ipv4_at)
    }

    pub fn ipv4_list(&self, code: u8) -> Vec<Ipv4Addr> {
        self.get(code)
            .map(|v| v.chunks_exact(4).filter_map(ipv4_at).collect())
            .unwrap_or_default()
    }

    pub fn u32(&self, code: u8) -> Option<u32> {
        self.get(code)
            .filter(|v| v.len() == 4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn u16(&self, code: u8) -> Option<u16> {
        self.get(code)
            .filter(|v| v.len() == 2)
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
    }

    pub fn string(&self, code: u8) -> Option<String> {
        self.get(code).and_then(|v| {
            let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
            std::str::from_utf8(&v[..end]).ok().map(str::to_owned)
        })
    }
}

fn ipv4_at(v: &[u8]) -> Option<Ipv4Addr> {
    (v.len() >= 4).then(|| Ipv4Addr::new(v[0], v[1], v[2], v[3]))
}

/// One DHCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub is_reply: bool,
    pub xid: u32,
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub options: Options,
}

impl Message {
    pub fn request(xid: u32, chaddr: [u8; 6]) -> Message {
        Message {
            is_reply: false,
            xid,
            secs: 0,
            broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            options: Options::default(),
        }
    }

    pub fn message_type(&self) -> Option<MessageType> {
        self.options.message_type()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(300);
        out.push(if self.is_reply { BOOTREPLY } else { BOOTREQUEST });
        out.push(HTYPE_ETHERNET);
        out.push(6);
        out.push(0); // hops
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        let flags = if self.broadcast { FLAG_BROADCAST } else { 0 };
        out.extend_from_slice(&flags.to_be_bytes());
        for a in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&a.octets());
        }
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&[0u8; 10]); // chaddr padding
        out.extend_from_slice(&[0u8; 64]); // sname
        out.extend_from_slice(&[0u8; 128]); // file
        out.extend_from_slice(&MAGIC_COOKIE);
        for (code, data) in &self.options.0 {
            // A value longer than 255 would need RFC 3396 splitting; nothing we
            // send is that long, so refuse rather than emit a malformed option.
            let data = &data[..data.len().min(255)];
            out.push(*code);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        out.push(option::END);
        // BOOTP's minimum: pad to 300 so ancient relays are not upset.
        while out.len() < 300 {
            out.push(0);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Message> {
        if bytes.len() < FIXED_LEN + 4 {
            return None;
        }
        let op = bytes[0];
        if bytes[1] != HTYPE_ETHERNET || bytes[2] != 6 {
            return None;
        }
        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let secs = u16::from_be_bytes([bytes[8], bytes[9]]);
        let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
        let ip = |o: usize| Ipv4Addr::new(bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]);
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&bytes[28..34]);
        if bytes[FIXED_LEN..FIXED_LEN + 4] != MAGIC_COOKIE {
            return None;
        }
        let mut options = Options::default();
        let mut i = FIXED_LEN + 4;
        while i < bytes.len() {
            let code = bytes[i];
            i += 1;
            match code {
                option::PAD => continue,
                option::END => break,
                _ => {}
            }
            let len = *bytes.get(i)? as usize;
            i += 1;
            let data = bytes.get(i..i + len)?;
            options.push(code, data);
            i += len;
        }
        Some(Message {
            is_reply: op == BOOTREPLY,
            xid,
            secs,
            broadcast: flags & FLAG_BROADCAST != 0,
            ciaddr: ip(12),
            yiaddr: ip(16),
            siaddr: ip(20),
            giaddr: ip(24),
            chaddr,
            options,
        })
    }
}

/// A classless static route (option 121).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticRoute {
    pub destination: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
}

/// What an ACK gave us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub server: Ipv4Addr,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub search: Vec<String>,
    pub hostname: Option<String>,
    pub mtu: Option<u16>,
    pub broadcast: Option<Ipv4Addr>,
    pub ntp: Vec<Ipv4Addr>,
    pub static_routes: Vec<StaticRoute>,
    /// Seconds.
    pub lease_time: u32,
    pub t1: u32,
    pub t2: u32,
}

impl Lease {
    /// Interpret an ACK. `None` if it lacks the fields a lease needs.
    pub fn from_ack(message: &Message) -> Option<Lease> {
        let o = &message.options;
        let address = message.yiaddr;
        if address.is_unspecified() {
            return None;
        }
        let server = o.ipv4(option::SERVER_ID)?;
        let lease_time = o.u32(option::LEASE_TIME)?;
        // Shorter than a few seconds cannot hold T1 < T2 < lease, and is a
        // server that wants us to spin: not a lease.
        if lease_time < 4 {
            return None;
        }
        // A mask must be contiguous ones; anything else is a malformed
        // server and gets the classful default rather than a wrong prefix.
        let prefix = o
            .ipv4(option::SUBNET_MASK)
            .map(u32::from)
            .filter(|m| *m != 0 && (m | (m - 1)) == u32::MAX)
            .map(|m| m.count_ones() as u8)
            .unwrap_or_else(|| classful_prefix(address));
        let mut static_routes = Vec::new();
        if let Some(v) = o.get(option::CLASSLESS_STATIC_ROUTE) {
            let mut i = 0;
            while i < v.len() {
                let prefix = v[i];
                i += 1;
                // RFC 3442: 0..=32. A larger byte is a malformed option, and
                // the whole option is discarded rather than guessed at.
                if prefix > 32 {
                    return None;
                }
                let octets = (prefix as usize).div_ceil(8);
                let mut dst = [0u8; 4];
                let d = v.get(i..i + octets)?;
                dst[..octets].copy_from_slice(d);
                i += octets;
                let gw = v.get(i..i + 4)?;
                i += 4;
                static_routes.push(StaticRoute {
                    destination: Ipv4Addr::from(dst),
                    prefix,
                    gateway: Ipv4Addr::new(gw[0], gw[1], gw[2], gw[3]),
                });
            }
        }
        // RFC 3442: when classless routes are present, option 3 is ignored.
        let routers = if static_routes.is_empty() {
            o.ipv4_list(option::ROUTER)
        } else {
            Vec::new()
        };
        // T1 < T2 < lease, whatever the server said. lease_time >= 4 here,
        // so the defaults (lease/2, 7/8 lease) always fit; an explicit value
        // is honoured only where it leaves room for the other.
        let t1 = o
            .u32(option::RENEWAL_T1)
            .filter(|t| *t > 0 && *t < lease_time - 2)
            .unwrap_or(lease_time / 2);
        let t2_default = ((u64::from(lease_time) * 7 / 8) as u32).max(t1 + 1).min(lease_time - 1);
        let t2 = o
            .u32(option::REBINDING_T2)
            .filter(|t| *t > t1 && *t < lease_time)
            .unwrap_or(t2_default);
        Some(Lease {
            address,
            prefix,
            server,
            routers,
            dns: o.ipv4_list(option::DNS),
            domain: o.string(option::DOMAIN_NAME),
            search: o.get(option::DOMAIN_SEARCH).map(decode_domain_search).unwrap_or_default(),
            hostname: o.string(option::HOSTNAME),
            mtu: o.u16(option::MTU).filter(|m| *m >= 68),
            broadcast: o.ipv4(option::BROADCAST),
            ntp: o.ipv4_list(option::NTP),
            static_routes,
            lease_time,
            t1,
            t2,
        })
    }

    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.routers.first().copied().or_else(|| {
            self.static_routes
                .iter()
                .find(|r| r.prefix == 0)
                .map(|r| r.gateway)
        })
    }
}

fn classful_prefix(a: Ipv4Addr) -> u8 {
    match a.octets()[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

/// RFC 3397 domain search list: DNS-encoded names with compression pointers.
fn decode_domain_search(v: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < v.len() {
        let mut labels = Vec::new();
        let mut p = pos;
        let mut jumped = false;
        let mut hops = 0;
        loop {
            let Some(&len) = v.get(p) else { return out };
            if len == 0 {
                if !jumped {
                    pos = p + 1;
                }
                break;
            }
            if len & 0xC0 == 0xC0 {
                let Some(&lo) = v.get(p + 1) else { return out };
                if !jumped {
                    pos = p + 2;
                }
                p = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                jumped = true;
                hops += 1;
                if hops > 16 {
                    return out;
                }
                continue;
            }
            let Some(label) = v.get(p + 1..p + 1 + usize::from(len)) else { return out };
            labels.push(String::from_utf8_lossy(label).into_owned());
            p += 1 + usize::from(len);
        }
        if !labels.is_empty() {
            out.push(labels.join("."));
        }
        if !jumped && pos == p {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack() -> Message {
        let mut m = Message::request(0x1234, [1, 2, 3, 4, 5, 6]);
        m.is_reply = true;
        m.yiaddr = Ipv4Addr::new(10, 0, 2, 15);
        m.options.push(option::MESSAGE_TYPE, [MessageType::Ack as u8]);
        m.options.push(option::SERVER_ID, Ipv4Addr::new(10, 0, 2, 2).octets());
        m.options.push(option::LEASE_TIME, 86400u32.to_be_bytes());
        m.options.push(option::SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0).octets());
        m.options.push(option::ROUTER, Ipv4Addr::new(10, 0, 2, 2).octets());
        m.options.push(option::DNS, {
            let mut v = Ipv4Addr::new(10, 0, 2, 3).octets().to_vec();
            v.extend(Ipv4Addr::new(1, 1, 1, 1).octets());
            v
        });
        m.options.push(option::DOMAIN_NAME, b"lan".to_vec());
        m
    }

    #[test]
    fn a_message_round_trips() {
        let m = ack();
        let bytes = m.encode();
        assert_eq!(bytes.len(), 300);
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn a_lease_is_read_from_an_ack() {
        let l = Lease::from_ack(&ack()).unwrap();
        assert_eq!(l.address, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(l.prefix, 24);
        assert_eq!(l.gateway(), Some(Ipv4Addr::new(10, 0, 2, 2)));
        assert_eq!(l.dns.len(), 2);
        assert_eq!(l.domain.as_deref(), Some("lan"));
        assert_eq!(l.t1, 43200);
        assert_eq!(l.t2, 75600);
    }

    #[test]
    fn classless_routes_override_the_router_option() {
        let mut m = ack();
        // 10.1.0.0/16 via 10.0.2.9, then default via 10.0.2.7
        m.options.push(
            option::CLASSLESS_STATIC_ROUTE,
            vec![16, 10, 1, 10, 0, 2, 9, 0, 10, 0, 2, 7],
        );
        let l = Lease::from_ack(&m).unwrap();
        assert!(l.routers.is_empty());
        assert_eq!(l.static_routes.len(), 2);
        assert_eq!(l.static_routes[0].destination, Ipv4Addr::new(10, 1, 0, 0));
        assert_eq!(l.gateway(), Some(Ipv4Addr::new(10, 0, 2, 7)));
    }

    #[test]
    fn an_ack_without_a_server_id_is_not_a_lease() {
        let mut m = ack();
        m.options.0.retain(|(c, _)| *c != option::SERVER_ID);
        assert!(Lease::from_ack(&m).is_none());
    }

    #[test]
    fn domain_search_decodes_with_compression() {
        // "example.com" then "sub" + pointer to "example.com"
        let v = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 3, b's', b'u',
            b'b', 0xC0, 0,
        ];
        assert_eq!(decode_domain_search(&v), vec!["example.com", "sub.example.com"]);
    }

    #[test]
    fn garbage_does_not_decode() {
        assert!(Message::decode(&[0u8; 10]).is_none());
        let mut bytes = ack().encode();
        bytes[FIXED_LEN] = 0; // break the cookie
        assert!(Message::decode(&bytes).is_none());
    }
}
