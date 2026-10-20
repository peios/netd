---
title: Router Discovery
description: How netd takes router advertisements away from the kernel, when it solicits and how often, which advertisements it accepts, and how it chooses a default router.
---

Router discovery supplies IPv6 prefixes, routes, and resolver information.
netd validates advertisements before passing them to the discovery engine.

## The kernel's RA handling is off [*rdisc.kernel-accept-ra-off]

netd writes `0` to `/proc/sys/net/ipv6/conf/<name>/accept_ra` for `all`, for
`default`, and for every interface listed there, at startup before any link is
brought up (§2.1). It writes it again for each non-loopback interface the
first time it sees it. A missing file — a kernel without IPv6 — is a warning
only for `all`.

The kernel still creates link-local addresses and answers neighbor
solicitations. That is the protocol, not policy. Everything an advertisement
could configure is netd's to decide.

## When router discovery runs [*rdisc.start-stop]

On every full pass, for each joined interface:

- it **wants** router discovery when its profile has `Address.Offered`
  and IPv6 in its families;
- it **can** run it when it is up with carrier and the kernel's
  link-local address on it has finished duplicate address detection. A
  tentative address cannot source a solicitation.

Running discovery that is not wanted or possible is stopped (`ipv6 stopping`):
the engine and any DHCPv6 client are discarded, and the next reconcile removes
their addresses and route. Nothing is sent on the wire, because neither
protocol has a goodbye. An interface that wants and can run it starts it
(`soliciting routers`), provided its ICMPv6 socket opens — otherwise netd logs
`no icmpv6 socket` and tries again on the next pass.

## The socket [*rdisc.socket]

One raw ICMPv6 socket per interface, bound to it with `SO_BINDTODEVICE`,
filtered to receive only type 134 (router advertisement), sending with a
multicast hop limit of 255, and asking for each received packet's hop limit.
The kernel computes and checks ICMPv6 checksums.

## Solicitation [*rdisc.solicitation-schedule]

A router solicitation is type 133, code 0, with a source link-layer address
option carrying the interface's MAC, sent to `ff02::2` with hop limit 255.

The first is sent as soon as discovery starts. The interval is 4 s for the
next two, then doubles before each later one, up to 3600 s. Each interval
carries a jitter of ±10%. So solicitations go at about 0, 4, 8, 16, 32, 64, …
s.

Soliciting stops when an advertisement arrives with a router lifetime above
zero. It begins again, from the first interval, as soon as every default
router has expired. [*rdisc.solicit-again-when-routers-gone]

## Which advertisements count [*rdisc.acceptance]

An advertisement is dropped unless it arrived with hop limit 255 and from
a link-local source ([RFC 4861
§6.1.2](https://datatracker.ietf.org/doc/html/rfc4861#section-6.1.2)). A lower
hop limit has crossed a
router, and a non-link-local source is not a router on this link.
[*rdisc.hop-limit-and-source-checks]

It is then decoded. The whole advertisement is refused when:

- it is shorter than 16 bytes, or its type is not 134 or its code not 0;
- an option has length zero, or runs past the end of the message.

[*rdisc.malformed-advertisement-refused]

Within an accepted advertisement, an option that does not parse is skipped and
the rest stand:

| Option | Accepted when | Limits |
|---|---|---|
| Prefix information (3) | 32 bytes long; prefix length ≤ 128; the prefix neither multicast nor link-local | the first 16 per advertisement |
| MTU (5) | 8 bytes long | |
| RDNSS (25) | at least 24 bytes, and a whole number of addresses | 16 servers per option; unspecified, multicast,  and loopback addresses dropped |
| DNSSL (31) | at least 16 bytes | 16 domains per option; names uncompressed, lower-cased, labels of printable ASCII, 253 characters at most; a malformed name ends the list |

[*rdisc.option-acceptance]

Any other option is ignored. So are the advertisement's hop limit, reachable
time and retransmission timer.

## What an advertisement does [*rdisc.effects]

- **Router lifetime above zero**: the source becomes, or stays, a default
  router until that many seconds from now. **Zero**: the source is
  removed as a default router. Its prefixes, servers, and domains stay.
- **M or O flag**: stateless DHCPv6 is wanted (§6.3). Once set it stays
  set until discovery restarts; a later advertisement without the flags
  does not withdraw it. [*rdisc.m-or-o-latches-dhcpv6]
- **MTU option**: remembered as the link's advertised MTU. It is used only
  with `Mtu.Offered`, only when no lease gave one, and only when it is at
  least 68 (§4.2, §4.3).
- **Prefixes**: §6.2. **RDNSS and DNSSL**: §6.3.

Whenever what the interface should carry changes — an address, its
deprecation, the default router, the servers, the domains, the MTU, the DHCPv6
flag — netd runs a full pass. That includes a change caused by time alone: a
lifetime running out is a change.

## The default router [*rdisc.default-router-is-lowest-address]

Of the routers whose lifetime has not run out, netd uses the one with the
numerically lowest link-local address, so the choice is stable while the set
is. Router preference (RFC 4191) is not read.

## Receiving datagrams

The receive path reads at most 4096 bytes per datagram. It rejects truncated
bodies, truncated ancillary data, incomplete IPv6 source addresses, and
missing or malformed hop-limit metadata. Rejected datagrams do not stop the
receive loop. DHCPv6 uses the same bounded receive path without requiring
hop-limit metadata.
