---
title: Readiness
description: The four readiness levels, how netd computes one for each interface and for the machine, and how the machine level reaches peinit and the registry.
---

"The network is up" means different things to different services, so netd
reports a level, not a flag. Levels are ordered: `absent` < `link` <
`addressed` < `routed`.

## An interface's level [*readiness.interface-level]

From the kernel's state after the last reconcile:

| Level | When |
|---|---|
| `absent` | the interface is not up, or has no carrier |
| `link` | up with carrier, and no usable address |
| `addressed` | a usable address, and no default route |
| `routed` | a usable address, and a default route on the interface |

A **usable** address is any IPv4 address other than a loopback one — a 169.254
link-local address counts, because it is the outcome of address acquisition —
and any IPv6 address that is neither loopback nor link-local. Every up
interface has an IPv6 link-local address, so counting one would make
`addressed` mean nothing. Deprecated and tentative addresses count.
[*readiness.usable-address]

A **default route** is any route with prefix length 0, of either family,
in the main table, out of the interface. It need not be one of netd's.
[*readiness.any-default-route-counts]

## The machine's level [*readiness.machine-level]

The highest level among joined interfaces, or `absent` when none is joined. An
`IGNORE` d or `DOWN` interface contributes nothing, whatever state it is in.

## Publishing it [*readiness.publish-on-change]

At every publish (§2.2) netd computes the machine level. When it differs from
the last one published — and at the first publish after startup, which
precedes `READY=1` — netd:

1. logs `machine readiness is <level>`;
2. sends the complete readiness set below in one datagram on the notify
   socket named by `NOTIFY_SOCKET`;
3. writes `Readiness` on `Machine\System\Network`.

The notify set is determined by the highest machine level:

| Machine level | `LEVEL` values, in wire order |
|---|---|
| `absent` | `absent` |
| `link` | `link` |
| `addressed` | `link`, `addressed` |
| `routed` | `link`, `addressed`, `routed` |

Each value has its own `LEVEL=` line in the same datagram. The highest level
comes last, so an older manager that retains only the last value continues to
see the highest level. Upgrade peinit before or alongside netd to make every
member available to dependents.

The set is sent only on a change. The notify channel is lossy by design and
unacknowledged (PSPU §4.16), and a level is a statement of a current
condition, so a lost one is corrected by the next change.

Each joined interface's own level is written as `Status Readiness` (§8.1).

## What peinit makes of it [*readiness.peinit-matches-the-published-level]

peinit records the set netd last sent against the sending service, and
resolves the `network` role to that service. A dependency on `network:<level>`
waits until the service is active and its published set contains the requested
level (peinit TRM §7.5).

A DHCPv4 lease that installs an address and default route in the same pass
takes the highest machine level directly from `link` to `routed`. The notify
datagram contains `link`, `addressed` and `routed`, so both
`network:addressed` and `network:routed` dependents can start. peinit needs no
knowledge of network level ordering; netd publishes every condition that
holds. Losing the link replaces this set with `absent`, preventing new starts
on any of the three previous conditions. Dependents already running keep
running.

The registry, log, and control status continue to report the highest machine
level. `net wait <level>` polls over the control socket and succeeds when that
level is at least the one named (§10.1).
