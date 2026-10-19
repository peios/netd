---
title: Sockets
description: The sockets behind netd's DHCPv4 client — the per-interface packet socket and its filter, the broadcast path from 0.0.0.0, the unicast path from the lease address, and the udp/68 absorber.
---

Before an interface has an address, nothing but a packet socket can send from
`0.0.0.0`. So every DHCPv4 broadcast leaves through `AF_PACKET`, with an IPv4
and UDP header netd builds itself, and every reply is read from the same
socket.

## The packet socket [*dhcp4-sockets.packet-socket]

One per running client: `AF_PACKET`, `SOCK_DGRAM`, protocol `ETH_P_IP`, bound
to the interface. A classic BPF filter
passes only an IPv4 UDP datagram that is not a fragment and is addressed to
port 68. It refuses both a non-zero fragment offset and the more-fragments
flag; the don't-fragment flag is allowed. Everything read is checked again for
an IPv4 header and UDP port 68, then decoded as a DHCP message.

The socket sees every frame on the interface that passes the filter, so it
receives both broadcast replies and replies unicast to the lease address.

## The broadcast path [*dhcp4-sockets.broadcast-frame]

DISCOVER, REQUEST in Requesting and Rebooting, and REQUEST in Rebinding go out
on the packet socket to Ethernet `ff:ff:ff:ff:ff:ff`, as one IPv4 datagram:

| Field | Value |
|---|---|
| source | `0.0.0.0` |
| destination | `255.255.255.255` |
| TOS | `0x10` |
| identification | 0 |
| flags | don't-fragment |
| TTL | 64 |
| UDP ports | 68 → 67 |
| UDP checksum | 0 (none, which IPv4 permits) |

## The unicast path [*dhcp4-sockets.unicast-renewal]

REQUEST in Renewing, and RELEASE, go out on a transient `AF_INET` UDP socket
with `SO_REUSEADDR` and `SO_BINDTODEVICE` set to the interface, bound to the
lease address on port 68, sent to the server on port 67, and closed. The
kernel resolves the server's link-layer address. The reply is read from the
packet socket.

Binding port 68 meets the kernel's port reservation for ports 1 to 1023, which
the shipped seed grants to SYSTEM, netd's identity.

## The absorber [*dhcp4-sockets.absorber]

At startup netd binds one more UDP socket, to `0.0.0.0:68` with
`SO_REUSEADDR`, and discards whatever arrives on it. Its only purpose is that
a server's unicast reply finds a bound port, so the kernel does not answer it
with ICMP port-unreachable. The packet sockets see the same datagrams. If it
cannot be bound, netd runs without it (§2.1).
