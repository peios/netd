---
title: Replies and Leases
description: Which DHCPv4 replies the client accepts, the server-identity lock, what makes an OFFER or an ACK acceptable, and how an ACK is read into a lease — prefix, routes, T1 and T2, and the options kept.
---

The DHCPv4 client accepts replies only when they match its exchange and
contain a usable lease. The checks below define those boundaries.

## Which replies are looked at [*dhcp4-lease.reply-filter]

A received message is ignored unless all of these hold:

- it is a BOOTREPLY;
- its transaction id is the client's current one;
- its `chaddr` is the interface's MAC;
- it carries a message type (option 53) the client knows.

## The server lock [*dhcp4-lease.server-lock]

Once a server has been chosen — the server of the lease held, or else the
server identifier of the offer being requested — an ACK or NAK is accepted
only if its option 54 names that server. A stranger who guesses the
transaction id cannot take a lease away or substitute one.

In Rebooting, with no lease and no offer, no server has been chosen, so an ACK
or NAK from any server is accepted.

## What each state accepts [*dhcp4-lease.state-table]

| State | Message | Result |
|---|---|---|
| Selecting | OFFER with a non-zero `yiaddr` and a server identifier | taken: Requesting. The first acceptable OFFER wins; there is no comparison between offers. |
| Selecting | OFFER without either | ignored |
| Requesting, Rebooting, Renewing, Rebinding | ACK that reads as a lease (below) | Bound, with the lease |
| Requesting, Rebooting, Renewing, Rebinding | ACK that does not read as a lease | ignored; retransmission continues |
| Requesting, Rebooting | NAK | Selecting; the previous address and the offer are forgotten |
| Renewing, Rebinding | NAK | the lease is lost (§5.4); Selecting |
| any other combination | | ignored |

An ACK in Renewing or Rebinding that grants a different address replaces the
lease. The next reconcile removes the old address and adds the new.

## Reading an ACK [*dhcp4-lease.ack-requirements]

An ACK is a lease only when it has:

- a non-zero `yiaddr`;
- a server identifier (option 54);
- a lease time (option 51) of exactly 4 bytes, and at least 4 seconds.

A lease time under 4 s is refused: it cannot hold T1 < T2 < lease, and a
server asking for it wants the client to spin.

### The prefix [*dhcp4-lease.prefix]

From the subnet mask (option 1) when it is a non-zero run of contiguous ones.
Otherwise, absent or malformed, from the address's class: /8 for a first octet
up to 127, /16 up to 191, /24 above.

### Routes [*dhcp4-lease.routes]

Classless static routes (option 121, RFC 3442) are read as a sequence of
prefix length, the significant destination octets, and a 4-byte gateway. In
[source `23af1f6`
](https://github.com/peios/netd/blob/23af1f6b84f3764d9327eb009ced56b2a16b7aa8/dhcp4/src/packet.rs),
a prefix length above 32, or an entry running past the end of the option,
makes the whole ACK fail to read as a lease: it is ignored like any other
unusable ACK.

The [proposed source
correction](https://github.com/peios/netd/blob/98f46343f6cdff62b1d9fcb886baf383c3943ac5/dhcp4/src/packet.rs)
instead discards the entire malformed optional route list, including any valid
entries before the malformed one, and keeps an otherwise-valid lease. The
existing router-option (3) fallback then applies; without that option, the
lease has no routes or gateway. This recovery does not relax whole-message or
option framing, the mandatory lease requirements above, or the client and
server-identity checks. It describes the proposed source policy, not a
released package or installed image, and does not assert an RFC requirement to
recover malformed route lists.

When the decoded classless route list is nonempty, the router option (3) is
ignored. The lease's gateway is the first router of option 3, or, when
classless routes are present, the gateway of the classless route with prefix
0.

### T1 and T2 [*dhcp4-lease.t1-t2]

- **T1** is option 58 when it is above 0 and below the lease time minus
  2. Otherwise it is half the lease time.
- **T2** is option 59 when it is above T1 and below the lease time.
  Otherwise it is seven-eighths of the lease time, rounded down, raised to
  at least T1 + 1 and capped at the lease time minus 1.

So T1 < T2 < the lease time always holds, whatever the server sent.

### Other options kept [*dhcp4-lease.options-kept]

| Option | Kept as |
|---|---|
| 6 | DNS servers, every 4-byte entry |
| 15 | the domain name: the bytes up to the first NUL; dropped if not UTF-8 |
| 119 | the domain search list, RFC 1035 names with compression pointers followed, at most 16 jumps per name |
| 12 | the hostname offered: the bytes up to the first NUL; dropped if not UTF-8 |
| 26 | the MTU, when it is at least 68 |
| 28 | the broadcast address |
| 42 | NTP servers, every 4-byte entry |

Where an option appears twice, its first occurrence is used. Nothing else in
the ACK is kept.

How each of these is used — and whether, by the profile — is in §4.2
(addresses, routes, MTU), §8.3 (DNS and NTP) and §8.4 (the hostname).

## The record of a lease

A lease is logged as `interface <name>: lease <address>/<prefix> from
<server> for <seconds>s`. Binding clears the interface's link-local
address and its warning, and marks the interface for re-judgment,
because the network might now be identifiable (§7.1).
[*dhcp4-lease.bound-clears-link-local-and-warning]
