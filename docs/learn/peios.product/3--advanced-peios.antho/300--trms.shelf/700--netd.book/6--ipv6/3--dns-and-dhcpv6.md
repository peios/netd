---
title: DNS and DHCPv6
description: The DNS servers and search domains routers advertise, and the stateless DHCPv6 information-request client netd runs when routers ask for it — when it starts, what it sends, what reply it accepts, and when it asks again.
---

Router advertisements and DHCPv6 information replies supply resolver facts.
netd tracks their lifetimes and publishes the accepted facts to resolvd.

## RDNSS and DNSSL [*v6dns.rdnss-dnssl-lifetimes]

Each server of an RDNSS option, and each domain of a DNSSL option, is held for
the option's lifetime from the moment the advertisement arrived. `0xFFFFFFFF`
is forever, and a lifetime of zero removes that server or domain at once. A
server or domain advertised again has its lifetime replaced.

## Stateless DHCPv6

Peios gets IPv6 addresses by SLAAC alone. DHCPv6 is used for configuration
only: an INFORMATION-REQUEST (RFC 8415 §18.2.6) for DNS servers and search
domains. The stateful address exchange is not implemented, and an
advertisement's M flag is treated as O.

### When it runs [*dhcp6.start-stop]

A DHCPv6 client starts on an interface once its router-discovery engine has
seen an advertisement with M or O (§6.1), provided the interface has a
non-tentative link-local address and a MAC, and its socket opens. netd logs
`interface <name>: dhcpv6 information request`. It stops with router
discovery.

### The socket

UDP, bound with `SO_BINDTODEVICE` to the interface and to its link-local
address on port 546, so two interfaces' clients never share a port. Messages
go to `ff02::1:2` port 547.

### The request [*dhcp6.information-request]

An INFORMATION-REQUEST (type 11) with a random 3-byte transaction id and these
options:

| Option | Content |
|---|---|
| 1, client identifier | the machine's DUID (§5.7) |
| 8, elapsed time | hundredths of a second since this exchange began, capped at 65535 |
| 6, option request | 23 (DNS servers), 24 (domain list), 32 (information refresh time) |

The first is sent when the exchange begins. Retransmissions follow after 1 s,
doubling up to 3600 s, each with a jitter of ±10%, and never stop until a
reply is accepted. [*dhcp6.retransmit-schedule]

### The reply [*dhcp6.reply-acceptance]

A datagram is accepted only while an exchange is running, and only when:

- it is a REPLY (type 7) with the exchange's transaction id;
- it carries a client identifier equal to the machine's DUID;
- it carries a non-empty server identifier.

Anything else is ignored, and retransmission continues. From an accepted
reply, option 23 gives the DNS servers — when its length is a whole number of
addresses, up to 16, with unspecified, multicast and loopback addresses
dropped — and option 24 the search domains, read as a DNSSL's are (§6.1).

### Refresh [*dhcp6.refresh-time]

After a reply, the client asks again after the reply's information refresh
time (option 32), or one day when there is none, but never sooner than 600 s.
Each refresh is a new exchange with a new transaction id.

An answer that differs from the last logs `dhcpv6 answered` and leads to a
reconcile and a publish. An identical one changes nothing.

## Where these go

Advertised and DHCPv6 servers and domains reach name resolution only through
the profile's `Dns.Offered`, including link-local servers with the interface
supplied by their DNS scope (§8.3). They are always part of what a network has
shown for its identity and its record (§7).
