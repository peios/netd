---
title: The Resolver Channel
description: netd's side of the network-manager channel of PSPU §6.9 — the subscribe request, the snapshot and every scope field, how DNS facts are merged from profile and offer, and when snapshots are sent.
---

The channel's contract — that a resolver subscribes, and receives whole
snapshots, never deltas — is PSPU §6.9. This article is netd's half of it.

## Subscribing [*snapshot.subscribe]

A `subscribe` request on the control socket (§9.2), which needs the query
right, is answered with a snapshot at once, and the connection is kept:
switched to non-blocking and added to the subscriber list. It is the one
request that does not end its connection.

The first snapshot is the last one published, or, before any has been, one
computed on the spot.

## When snapshots are sent [*snapshot.sent-on-change]

At every publish (§2.2) netd computes the snapshot and compares it with the
last one sent. If it differs, it is sent to every subscriber. If it is equal,
nothing is sent.

A subscriber that cannot take the whole frame at once — closed, or so far
behind that its socket buffer is full — is dropped. A resolver reconnects and
receives a fresh snapshot. [*snapshot.slow-subscriber-dropped]

## The snapshot [*snapshot.contents]

A reply map with `ok` = true, `kind` = `snapshot`, `hostname` — the name netd
last set (§8.4), empty if none — and `scopes`: one scope per joined interface
whose level is above `absent`, ordered by the interface's metric, then its
kernel index. [*snapshot.scope-order-and-membership]

Each scope:

| Field | Content |
|---|---|
| `ifid` | the interface id |
| `name` | the kernel name |
| `servers` | DNS servers, as text, in the order to try them (below) |
| `domains` | search domains, likewise |
| `ntp` | the lease's NTP servers (option 42) |
| `addresses` | every address the kernel holds on the interface, `address/prefix`, link-local ones included |
| `default_route` | the profile's `Dns.Default` when set; otherwise whether the interface's level is `routed` |
| `exclusive` | the profile's `Dns.Exclusive` |
| `metric` | the interface's metric (§4.2) |
| `level` | the interface's level (§8.2) |

[*snapshot.scope-fields]

## Merging DNS facts [*snapshot.dns-merge]

Servers, in this order:

1. the profile's `Dns.Servers`, always;
2. with `Dns.Offered`: the lease's servers (option 6);
3. with `Dns.Offered`: the routers' RDNSS servers, including link-local IPv6;
4. with `Dns.Offered`: the DHCPv6 reply's servers, including link-local IPv6.

Domains, in this order:

1. the profile's `Dns.Domains`, always;
2. with `Dns.Offered`: the lease's domain search list (option 119) if it
   is not empty, otherwise its domain name (option 15);
3. with `Dns.Offered`: the routers' DNSSL domains;
4. with `Dns.Offered`: the DHCPv6 reply's domains.

Each list removes duplicates across the entire list, retaining the first
occurrence and the source order above. This includes repeated values with
other values between them.
[*snapshot.first-occurrence-deduplication]

The containing scope supplies the interface for link-local IPv6 servers.
resolvd uses its index on UDP and TCP upstream sockets; the address text does
not need a zone suffix. Deploy this publication change with a resolver that
supports interface-scoped upstreams (resolvd TRM §4.7).

NTP servers are reported whatever `Dns.Offered` says. Whether to believe
a lease's time servers is timed's decision, made against its own
registry value. A snapshot describes what the network said.
[*snapshot.ntp-regardless-of-dns-offered]

The same merge feeds the `dns` and `search` fields of the status reply (§9.2),
for every non-loopback interface, joined or not.
