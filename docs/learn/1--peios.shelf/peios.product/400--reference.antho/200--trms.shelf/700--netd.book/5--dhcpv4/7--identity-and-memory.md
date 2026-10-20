---
title: Identity and Memory
description: How netd names the machine and each interface to a DHCP server — the DUID and the per-interface client identifier — and how it remembers which address a network gave it.
---

A DHCP server recognizes a client by its client identifier, and a reservation
on the server matches on it. netd keeps the identifier stable across boots and
NIC swaps in the same slot, and remembers per network what it was given.

## The DUID [*dhcp4-memory.duid]

The machine's DHCP unique identifier, shared by DHCPv4, and DHCPv6 (RFC 4361),
is decided once per netd process, the first time a client needs it:

1. the registry's `Machine\System\Network Duid`, as hex, when it is set
   and parses;
2. otherwise the file `/var/state/netd/duid`, when it holds at least 4
   bytes;
3. otherwise a new DUID-LL: `00 03 00 01` followed by the MAC of the
   interface whose client is starting. It is written to
   `/var/state/netd/duid`; a failure to write is logged and changes
   nothing else.

When the registry's `Duid` is absent, empty or not hex, the result of 2 or 3
is written to it, as colon-separated lower-case hex, replacing a value that
was not hex. [*dhcp4-memory.duid-written-back]

Hex in `Duid` (and `ClientId`) can be written with `:`, `-` or spaces between
digits, or none. A value with any other character, an odd number of digits, or
no digits is not hex.

## The client identifier [*dhcp4-memory.client-id]

Per interface, `Interfaces\<id> ClientId`:

- when the value is set and is non-empty hex, it is sent as written;
- when it is absent, the identifier is generated and written back:
  `ff`, then a 4-byte IAID, then the DUID. The IAID is the interface id's
  text folded into 4 bytes by XOR, byte *i* of the text into byte
  *i* mod 4;
- when it is set but not hex, netd logs `<id>: ClientId "<value>" is
  not hex; regenerating`, where `<id>` is the interface id, generates
  one, and overwrites the value.

`ClientId` is a value both netd and the operator write. Writing it is how an
operator makes netd present the identifier a server reservation expects. It is
read when a client starts, so it takes effect at the next start (a carrier
loss, a profile edit, a restart of netd).

## The address a network gave [*dhcp4-memory.requested-address]

While an interface holds a lease on an identified network (§7.1), netd writes
the lease address to that network's `Networks\<id> RequestedAddress` whenever
it differs from what is there.

When a client starts, it takes as its previous address (§5.1):

1. the `RequestedAddress` of the network identified on the
   interface, when there is one; otherwise
2. the `RequestedAddress` of the network the interface's `Status
   LastNetwork` names (§8.1).

With one, the client opens with an INIT-REBOOT REQUEST for it. A server that
agrees answers with an ACK and the machine keeps the address in one round
trip. One that refuses answers with a NAK and the client discovers afresh.
Silence for two transmissions does the same (§5.2).

`RequestedAddress` is also the operator's: writing it is a soft reservation,
an address the client asks for first and the server can refuse.
[*dhcp4-memory.requested-address-is-a-soft-reservation]

Nothing about a lease itself — its timers, its server, its options — is
persisted. A machine that reboots asks for its address again.
