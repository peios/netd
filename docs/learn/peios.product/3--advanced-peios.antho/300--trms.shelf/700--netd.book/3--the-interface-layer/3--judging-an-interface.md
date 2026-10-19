---
title: Judging an Interface
description: The facts netd gives the interface layer, when an interface is judged, how a verdict and its attribution are read off the evaluation, conflicts, and what a change of verdict does.
---

netd evaluates interface facts against the accepted policy generation. The
result determines whether it ignores, stops, or configures that interface.

## The facts [*judgment.facts]

An interface is judged on a snapshot carrying only interface and network
facts:

| Fact | Value |
|---|---|
| `Interface` | the kernel's name for the link |
| `Interface.Kind` | `wired`, `wireless`, `loopback`,  or `other` (§4.1) |
| `Interface.Id` | the interface id (§4.1) |
| `Interface.Mac` | the hardware address, when the link has a 6-byte one |
| `Interface.Path` | the bus path; absent when sysfs gives none |
| `Interface.Driver` | the driver; absent when sysfs gives none |
| `Network.Id` | the id of the network identified on the link (§7.1); absent until one is |
| `Network.Name` | the record's `Name`; absent when unset or empty |
| `Network.Trust` | the record's `Trust`; absent when unset or empty |
| `Network.Kind` | the interface's kind, once a network is identified; absent before |

A fact the interface lacks is absent, which makes a condition on it false,
never an error.

## When an interface is judged [*judgment.when]

Every non-loopback interface is judged on every full pass (§2.2).
Loopback is never judged and never managed: it has no verdict, no record
under `Interfaces\`, and netd never changes it.
[*judgment.loopback-never-judged]

## The verdict [*judgment.verdict]

`pnp-core` evaluates the forest and netd reads the result:

- `JOIN(i)`: the profile the forest's `i` th `JOIN` names, looked up
  case-insensitively. netd stands the interface in that profile.
- `DOWN`: the interface is kept administratively down.
- anything else, including the backstop: `IGNORE`.

The attribution is the evaluation's: the path of the rule that spoke, or
`backstop` when none did.

## Conflicts [*judgment.conflict-ignores-and-names-both]

When the evaluation reports a conflict — the highest-priority candidates tie
and name different profiles — netd does not choose. The interface's outcome is
`IGNORE`, its attribution is the tied rules' paths, sorted and joined with
` vs `, and its warning is `rules <a> vs <b> tie; the interface is ignored`.
The first time an interface meets a conflict, netd logs a warning.

A conflict reaches an interface in two ways. A generation taken at startup is
not checked for ties (§2.1), and an interface that appears after a generation
was taken is judged against it with no check. A generation built at runtime
that ties on an interface already present is refused instead (§3.2).

## A change of verdict [*judgment.change-restarts-clients]

The outcome compares the verdict **and the profile's resolved values**. When
either differs from the interface's previous outcome, netd logs the new
verdict and its rule, and stops the interface's clients:

- the DHCPv4 client sends a RELEASE if it holds a lease (§5.4) and is
  discarded, along with its lease and any link-local address;
- router discovery and DHCPv6 are discarded, and their addresses go at
  the next reconcile.

The pass then starts whatever clients the new outcome wants. Editing any value
of the profile an interface stands in is a change of outcome, so it restarts
the interface's clients against the new profile, rather than trusting a lease
obtained under the old one.

## What each verdict does

| Verdict | Clients | Desired state (§4.2) |
|---|---|---|
| `JOIN(profile)` | started as the profile asks | up, with the profile's addresses and routes |
| `DOWN` | none | down, carrying no addresses,  and no netd routes |
| `IGNORE` | none | none: netd plans nothing for the interface |

[*judgment.verdict-effects]

An `IGNORE` d interface is left exactly as it is. If it was joined before, the
addresses and routes netd gave it stay where they are, because nothing desires
their removal. [*judgment.ignore-leaves-what-was-there]
