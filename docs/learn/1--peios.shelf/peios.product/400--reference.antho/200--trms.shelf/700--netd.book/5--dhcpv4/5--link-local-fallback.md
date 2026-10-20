---
title: Link-local Fallback
description: The 169.254/16 address netd self-assigns when DHCPv4 discovery goes unanswered — when, which address, and when it goes.
---

With `Address.LinkLocal` in the interface's profile, an interface whose DHCPv4
discovery goes unanswered gets an IPv4 link-local address (RFC 3927), so two
machines on a cable with no server can still reach each other.

## When [*linklocal.when]

At the client's "nobody answered" report (§5.2), about 28 s after discovery
began, netd logs `interface <name>: no DHCP offer; link-local <address>` and
the interface desires the address. Discovery carries on throughout.

The address is desired at prefix 16 only while no lease is held and the
profile has no `Address.Static` entry of either family (§4.2). A profile
with a static address therefore never shows one, even after the report.
[*linklocal.not-beside-a-lease-or-static]

## Which address [*linklocal.address-derivation]

A pure function of the interface, so it is the same every time:

- the seed is the last four bytes of the MAC, read as a big-endian
  32-bit number, or, for a link with no MAC, the interface index times
  2654435761, wrapping at 32 bits;
- the host part is 256 plus the seed modulo 64768;
- the address is `169.254.<host / 256>.<host % 256>`.

That lands in 169.254.1.0 to 169.254.254.255, the range RFC 3927 allows for
self-assignment.

netd does not probe for a conflicting holder or announce the address (RFC 3927
§2.2 and §2.4). Two machines whose MACs share their last four bytes choose the
same address.

## When it goes [*linklocal.dropped-on-lease-or-stop]

The link-local address is forgotten when a lease binds, and when the client is
stopped (§5.4). The next reconcile removes it, because netd owns every IPv4
address on a joined interface (§4.3).
