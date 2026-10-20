---
title: Identification
description: How netd decides which network is on the other side of an interface — the signals, the identity derived from them, when identification runs, and what a newly identified network does.
---

netd has to say "this is the same network as last time" with nothing on the
wire that says so. The identity is a guess from what the network has offered,
recorded with every signal it was made from, so that a later proof can replace
the guess without changing the record's key.

## Signals [*netid.signals]

What a joined interface's network has shown, at the moment of the pass:

| Signal | From |
|---|---|
| kind | the interface's `Interface.Kind` |
| server | the DHCPv4 lease's server identifier |
| subnet | the lease address masked to the lease prefix |
| gateway | the lease's gateway (§5.3) |
| router | the default router router discovery chose (§6.1) |
| prefixes | the subnet, then every non-deprecated autoconfigured address's prefix, each once |
| DNS servers | the lease's, then the routers' RDNSS servers, link-local ones included |

## The identity [*netid.derivation]

- With a lease (a server and a subnet), the basis is
  `dhcp:<server>|<subnet>/<prefix>`.
- Otherwise, with a default router and at least one autoconfigured
  prefix, the basis is `ra:<router>|<prefix>/<length>`, using the first
  prefix.
- Otherwise there is no identity yet: nothing has been offered, or the
  interface is static only.

The network id is a SHA-1 digest of the bytes `peios-netd-network|`, the kind,
`|`, and the basis, stamped and written as a version 5 UUID exactly as an
interface id is (§4.1).

So two leases from the same server in the same subnet are the same network,
whatever the address. A different server, a different subnet, or a different
kind of interface is a different network. An IPv4 lease always wins over the
IPv6 basis, so a dual-stack network is identified by its DHCPv4 server.
[*netid.same-server-and-subnet-same-network]

## When [*netid.when]

Identification is the first step of every full pass (§2.2). It runs only on a
joined interface that is up with carrier, and only when the signals yield an
identity.

For each identity it creates or refreshes the network's record (§7.2) and
reads back what the operator wrote on it. While a lease is held, it writes the
lease address to the record's `RequestedAddress` (§5.7).

## A newly identified network [*netid.new-network-rejudges]

When the identity differs from the network the interface already had —
including when it had none — netd logs
`interface <name>: network <name or id>`, with ` (trust <trust>)` when the
record has one. It then marks the interface for re-judgment, so the same pass
judges it with the `Network.*` facts present (§3.3). A rule conditioned on
`Network.Name` or `Network.Trust` takes effect then. If it moves the interface
to another profile, the interface's clients restart under that profile (§3.3).

The network an interface stands on is kept while it has carrier, even
when a profile switch restarts the clients that identified it. A switch
that its own identification triggered would otherwise forget the network
and switch back. Losing carrier forgets it (§4.1).
[*netid.sticky-while-carrier]

The interface's `Status Network` names the identified network (§8.1). The
kernel reads it to give the packet layers their `Network.*` facts (PKM §6.5),
so it never names a network the link is not on.
