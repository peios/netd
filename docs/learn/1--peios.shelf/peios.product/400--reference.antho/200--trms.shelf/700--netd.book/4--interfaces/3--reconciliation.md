---
title: Reconciliation
description: How netd diffs an interface's desired state against the kernel's and applies the difference — what counts as netd's, the order of operations, how each is phrased to rtnetlink, and which failures are benign.
---

Reconciliation compares desired interface state with a complete kernel
snapshot. It orders changes so addresses and routes converge without
removing state owned by another route manager.

## What netd owns [*reconcile.ownership]

On an interface with a desired state:

- **Every IPv4 address**, including a 169.254 address, and **every IPv6
  address except a link-local one** is netd's. An address netd does not
  desire is removed, whoever added it.
  [*reconcile.foreign-address-removed]
- **A route is netd's only if it carries routing protocol 200**
  (`RTPROT_NETD`). netd stamps it on every route it adds, and removes no
  route without it. [*reconcile.foreign-route-kept]
- **The kernel's IPv6 link-local addresses** (`fe80::/10`) are never
  compared, added, or removed. Every up interface has one, and neighbor
  discovery needs it.

Only routes in the main table, of unicast type and with an output interface,
are read from the kernel at all.

## The plan [*reconcile.plan-order]

For each interface with a desired state, netd plans these operations, in this
order:

1. **Link up**, if it is desired up and is down.
2. **MTU**, if one is desired, differs from the link's, and is at least
   68.
3. **Address deletions**: every address netd owns whose address and
   prefix length together match no desired address.
4. **Address additions**: every desired address the kernel does not hold
   with the same flags, in ascending address order, IPv4 before IPv6.
5. **Route deletions**: every protocol-200 route on the interface that is
   not desired.
6. **Route additions**: every desired route the kernel does not hold.
7. **Link down**, if it is desired down and is up — last, after its
   addresses, and routes have gone.

Addresses compare by address and prefix length, plus the two flags netd
sets: deprecated and no-prefix-route. A tentative flag (duplicate address
detection still running) is erased before comparing. A change of flags
alone is therefore an addition of the same address, which replaces it
(below), never a delete and re-add that would reset standing connections.
[*reconcile.flag-change-is-a-replace]

An IPv4 address's broadcast address is not compared. An address keeps the
broadcast it was added with: a lease whose broadcast changes, or a lease that
arrives after a static was added, changes nothing on an address the interface
already holds.

Routes compare on everything: destination, prefix length, gateway, metric, and
protocol. A change of metric or gateway is a deletion and an addition. For
IPv6 routes, configured metric zero uses the kernel default of 1024: netd
sends and compares that effective value, so an unchanged route converges. IPv4
metric zero and all nonzero metrics are unchanged. The configured
`Route.Metric` still controls DNS scope ordering.

An interface whose desired state the kernel already matches gets an empty
plan, and nothing is sent. [*reconcile.converged-plan-is-empty]

## Applying [*reconcile.apply]

Operations are applied one at a time, each as an rtnetlink request with an
acknowledgment:

| Operation | Request |
|---|---|
| link up or down | `RTM_SETLINK` changing only `IFF_UP` |
| MTU | `RTM_SETLINK` with `IFLA_MTU` |
| address add | `RTM_NEWADDR` with `NLM_F_CREATE` and `NLM_F_REPLACE` |
| address delete | `RTM_DELADDR` |
| IPv4 route add | `RTM_NEWROUTE` with `NLM_F_CREATE` and `NLM_F_APPEND`, main table, protocol 200 |
| IPv6 route add | `RTM_NEWROUTE` with `NLM_F_CREATE` and `NLM_F_EXCL`, main table, protocol 200 |
| route delete | `RTM_DELROUTE` |

IPv4 route additions append a distinct gateway/interface at the configured
metric. Two joined interfaces might therefore both hold default routes at the
same metric; adding one preserves the other, and withdrawing one removes
only its own route. Exact duplicates remain `EEXIST`. Equal-metric route
selection follows the kernel's routing behavior; set distinct metrics when
one interface should have a defined preference.
[*reconcile.equal-metric-ipv4-routes]

How addresses are phrased:

- An **IPv4** address carries `IFA_LOCAL` and `IFA_ADDRESS` set to
  itself, link scope for 169.254/16 and universe scope otherwise. Below
  a /31 it also carries a broadcast address: the broadcast of the lease
  the interface holds, if that lease gave one, otherwise the address's
  own subnet's all-ones address. The lease's broadcast goes on every
  IPv4 address added while the lease is held, statics included.
- An **IPv6** address carries universe scope and, when its prefix is not
  on-link, `IFA_F_NOPREFIXROUTE`. Its lifetimes are netd's to manage, so
  the kernel is told a valid lifetime of forever and a preferred lifetime
  of forever, or of zero when the address is deprecated. Source address
  selection then stops choosing a deprecated address, and connections
  already using it keep it. [*reconcile.ipv6-lifetimes-forever-or-deprecated]

A route with a gateway has universe scope, and one without has link scope. A
route carries a metric only when it is above zero.

A failed operation is logged as `reconcile: <operation> failed: <error>`
and the rest of the plan carries on, so one bad route never stops an
address landing. `EEXIST` on an add and `ENOENT` or `ESRCH` on a delete
mean the kernel got there first, and are not logged.
[*reconcile.failure-carries-on]

After every interface's plan is applied, netd dumps the kernel's state again,
so readiness and the status reply describe what actually landed.
